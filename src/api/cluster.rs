//! Browser administration uses sessions/CSRF; node exchange uses separate, revocable identities.
use super::*;
use crate::cluster::{Role, history, protocol};
use anyhow::Context;

pub(super) fn routes(app: App) -> Router<App> {
    let nodes = Router::new()
        .route("/cluster/v1/sync", post(sync))
        .route("/cluster/v2/sync", post(sync_v2))
        .route("/cluster/v2/artifacts/{hash}", get(activation_artifact))
        .route(
            "/cluster/v1/admission",
            post(admission).layer(DefaultBodyLimit::max(4096)),
        )
        .route("/cluster/v1/artifacts/{hash}", get(artifact))
        .layer(DefaultBodyLimit::max(4 * 1024 * 1024))
        .layer(middleware::from_fn_with_state(app, node_guard));
    Router::new()
        .route("/admin/cluster", get(overview))
        .route("/admin/cluster/nodes", post(save_node))
        .route(
            "/admin/cluster/activation",
            get(activation_status).post(stage_activation),
        )
        .route("/admin/cluster/activation/abort", post(abort_activation))
        .route("/admin/cluster/activation/view", get(activation_view))
        .route(
            "/admin/cluster/activation/recover",
            post(recover_activation),
        )
        .merge(nodes)
}
async fn activation_view(State(app): State<App>, h: HeaderMap) -> ApiResult<Json<Value>> {
    let user = super::admin::administrator(&app, &h, false).await?;
    let c = app.control.as_ref().ok_or(Error(
        StatusCode::SERVICE_UNAVAILABLE,
        "Configuration unavailable".into(),
    ))?;
    Ok(Json(c.activation_view(user.username, true).await?))
}
async fn activation_status(State(app): State<App>, h: HeaderMap) -> ApiResult<Json<Value>> {
    super::admin::administrator(&app, &h, false).await?;
    let c = coordinator(&app)?;
    let activation = c.activation_journal().await?;
    Ok(Json(
        json!({"committed_revision":activation.as_ref().map(|j|j.current().revision),"activation":activation,"installed_revision":c.snapshot().revision,"smtp_ready":c.cluster_ready()}),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivationStage {
    revision: i64,
    settings: crate::control::Settings,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivationCommand {
    epoch: crate::cluster::activation::Epoch,
}
async fn stage_activation(
    State(app): State<App>,
    h: HeaderMap,
    Json(body): Json<ActivationStage>,
) -> ApiResult<Json<Value>> {
    let actor = super::admin::administrator(&app, &h, true).await?;
    let journal = coordinator(&app)?
        .stage_activation_session(
            body.revision,
            body.settings,
            actor.username,
            message::digest(token(&h).unwrap().as_bytes()),
        )
        .await
        .map_err(|e| Error(StatusCode::CONFLICT, e.to_string()))?;
    Ok(Json(json!({"activation":journal,"staged":true})))
}
async fn abort_activation(
    State(app): State<App>,
    h: HeaderMap,
    Json(body): Json<ActivationCommand>,
) -> ApiResult<Json<Value>> {
    let actor = super::admin::administrator(&app, &h, true).await?;
    let journal = coordinator(&app)?
        .abort_activation_session(
            body.epoch,
            actor.username,
            message::digest(token(&h).unwrap().as_bytes()),
        )
        .await
        .map_err(|e| Error(StatusCode::CONFLICT, e.to_string()))?;
    Ok(Json(json!({"activation":journal})))
}
async fn recover_activation(
    State(app): State<App>,
    h: HeaderMap,
    Json(body): Json<ActivationCommand>,
) -> ApiResult<Json<Value>> {
    let actor = super::admin::administrator(&app, &h, true).await?;
    let journal = coordinator(&app)?
        .recover_activation_session(
            body.epoch,
            actor.username,
            message::digest(token(&h).unwrap().as_bytes()),
        )
        .await
        .map_err(|e| Error(StatusCode::CONFLICT, e.to_string()))?;
    Ok(Json(json!({"activation":journal})))
}
fn coordinator(app: &App) -> ApiResult<Arc<crate::control::Controller>> {
    if !app
        .config
        .cluster
        .as_ref()
        .is_some_and(|c| c.role == Role::Coordinator)
    {
        return Err(Error(
            StatusCode::NOT_FOUND,
            "Coordination service deactivated.".into(),
        ));
    }
    app.control.clone().ok_or(Error(
        StatusCode::SERVICE_UNAVAILABLE,
        "Coordinator unavailable.".into(),
    ))
}
async fn node(app: &App, h: &HeaderMap) -> ApiResult<String> {
    coordinator(app)?;
    let id = h
        .get("x-noisefence-node")
        .and_then(|v| v.to_str().ok())
        .filter(|v| crate::cluster::valid_id(v))
        .ok_or(Error(
            StatusCode::UNAUTHORIZED,
            "Node identity required.".into(),
        ))?;
    let key = h
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .filter(|v| v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or(Error(
            StatusCode::UNAUTHORIZED,
            "Node identity required.".into(),
        ))?;
    let id = id.to_owned();
    let query = id.clone();
    let hash = crate::message::digest(key.as_bytes());
    let expected = app
        .store
        .read(move |db| {
            Ok(db
                .query_row(
                    "SELECT token_hash FROM cluster_nodes WHERE id=?1 AND enabled=1",
                    [query],
                    |r| r.get::<_, String>(0),
                )
                .optional()?)
        })
        .await?;
    if expected.as_ref().is_none_or(|v| {
        v.len() != hash.len() || v.bytes().zip(hash.bytes()).fold(0, |a, (x, y)| a | (x ^ y)) != 0
    }) {
        return Err(Error(
            StatusCode::UNAUTHORIZED,
            "Identity of node refused.".into(),
        ));
    }
    Ok(id)
}
async fn node_guard(State(app): State<App>, request: Request, next: Next) -> Response {
    let permit = match app.cluster_capacity.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            return Error(
                StatusCode::TOO_MANY_REQUESTS,
                "Synchronization at capacity.".into(),
            )
            .into_response();
        }
    };
    if let Err(e) = node(&app, request.headers()).await {
        return e.into_response();
    }
    let _permit = permit;
    match tokio::time::timeout(Duration::from_secs(30), next.run(request)).await {
        Ok(response) => response,
        Err(_) => Error(
            StatusCode::GATEWAY_TIMEOUT,
            "Synchronization expired.".into(),
        )
        .into_response(),
    }
}
async fn sync(
    State(app): State<App>,
    h: HeaderMap,
    Json(request): Json<protocol::Poll>,
) -> ApiResult<Json<protocol::Reply>> {
    let (reply, _) = sync_exchange(app, h, request, false, None).await?;
    Ok(Json(reply))
}
async fn sync_v2(
    State(app): State<App>,
    h: HeaderMap,
    Json(request): Json<crate::cluster::activation::transport::Request>,
) -> ApiResult<Json<crate::cluster::activation::transport::Reply>> {
    use crate::cluster::activation::transport;
    if request.protocol != transport::PROTOCOL || request.poll.build != env!("CARGO_PKG_VERSION") {
        return Err(Error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Unsupported activation protocol or build".into(),
        ));
    }
    let (data, activation) =
        sync_exchange(app, h, request.poll, true, request.acknowledgement).await?;
    Ok(Json(transport::Reply {
        protocol: transport::PROTOCOL.into(),
        data,
        activation,
    }))
}
async fn sync_exchange(
    app: App,
    h: HeaderMap,
    mut request: protocol::Poll,
    coordinated: bool,
    acknowledgement: Option<crate::cluster::activation::Acknowledgement>,
) -> ApiResult<(protocol::Reply, Option<crate::cluster::activation::Journal>)> {
    use crate::cluster::activation::{Journal, Phase, transport::Peer};
    let id = node(&app, &h).await?;
    let credential = message::digest(
        h.get(header::AUTHORIZATION)
            .unwrap()
            .to_str()
            .unwrap()
            .strip_prefix("Bearer ")
            .unwrap()
            .as_bytes(),
    );
    let control = coordinator(&app)?;
    if !protocol::compatible_build(&request.build)
        || request.digest.len() > 64
        || request.results.len() > 32
        || !crate::config::valid_domain(&request.status.hostname)
    {
        return Err(Error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Incompatible node version or report.".into(),
        ));
    }
    request.status.last_error = request
        .status
        .last_error
        .map(|s| crate::delivery_log::sanitize(&s, 400).0);
    request.status.build = Some(request.build.clone());
    let activation = control.activation_journal().await?;
    if !coordinated && activation.is_some() {
        return Err(Error(
            StatusCode::CONFLICT,
            "This cluster requires coordinated activation".into(),
        ));
    }
    let publication = control.publication().await?;
    let bundle = if let Some(j) = &activation {
        j.current().clone()
    } else {
        publication.bundle.for_build(&request.build)?
    };
    let owner = id.clone();
    let revision = request.revision;
    let digest = request.digest;
    let peer = coordinated.then(|| Peer {
        seen: now(),
        build: request.build.clone(),
        revision,
        digest: digest.clone(),
        credential: credential.clone(),
    });
    let status = serde_json::to_string(&request.status).map_err(anyhow::Error::from)?;
    let (receipts,commands,activation)=app.store.run(move|db| {
        ensure!(db.query_row("SELECT EXISTS(SELECT 1 FROM cluster_nodes WHERE id=?1 AND enabled=1 AND token_hash=?2)",params![owner,credential],|r|r.get::<_,bool>(0))?,"Node identity revoked");
        let receipts=history::ingest(db,&owner,request.records,now())?;
        let tx=db.transaction()?;
        ensure!(tx.query_row("SELECT EXISTS(SELECT 1 FROM cluster_nodes WHERE id=?1 AND enabled=1 AND token_hash=?2)",params![owner,credential],|r|r.get::<_,bool>(0))?,"Node identity revoked");
        let mut journal=Journal::read(&tx)?;
        ensure!(coordinated || journal.is_none(),"Cluster enrolled during legacy synchronization");
        if let Some(j)=&journal {
            let r=j.rollout().context("Missing activation rollout")?;
            ensure!(owner!=j.owner() && r.participants().contains_key(&owner),"Node is not an enrolled activation participant");
            if let Some(ack)=&acknowledgement {
                if ack.epoch==*r.epoch() {
                    if r.phase()!=Phase::Aborted {journal=Some(Journal::acknowledge(&tx,&owner,ack,now())?);}
                } else {ensure!(ack.epoch.sequence<r.epoch().sequence,"Unknown activation receipt");}
            }
        } else {ensure!(acknowledgement.is_none(),"Previously enrolled node cannot return to legacy synchronization");}
        if let Some(peer)=peer {peer.save(&tx,&owner)?;}
        tx.execute("UPDATE cluster_nodes SET last_seen=?2,applied_revision=?3,applied_digest=?4,status=?5 WHERE id=?1 AND enabled=1",params![owner,now(),revision,digest,status])?;
        for r in request.results {
            ensure!(uuid::Uuid::parse_str(&r.id).is_ok() && ["done","expired","conflict"].contains(&r.result.as_str()),"Invalid command receipt");
            tx.execute("UPDATE cluster_commands SET result=?3,finished=?4 WHERE id=?1 AND node_id=?2 AND finished IS NULL",params![r.id,owner,r.result,now()])?;
        }
        tx.execute("UPDATE cluster_commands SET result='expired',finished=?1 WHERE finished IS NULL AND expires<?1",[now()])?;
        let commands=tx.prepare("SELECT id,message_id,recipient,command,username,expires FROM cluster_commands WHERE node_id=?1 AND finished IS NULL ORDER BY created LIMIT 32")?.query_map([&owner],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,String>(4)?,r.get::<_,i64>(5)?)))?.map(|r| {let (id,message_id,recipient,command,username,expires)=r?;Ok(history::Command{id,message_id,recipient,command:serde_json::from_str(&command)?,username,expires})}).collect::<anyhow::Result<Vec<_>>>()?;
        tx.execute("DELETE FROM cluster_commands WHERE finished<?1",[now()-30*86400])?;
        tx.commit()?;Ok((receipts,commands,journal))
    }).await?;
    let config = publication.config.clone();
    let key_config = if let Some(j) = &activation {
        let r = j.rollout().context("Missing activation rollout")?;
        crate::cluster::artifacts::materialize(
            &control.base,
            if r.phase() == Phase::Aborted {
                r.base()
            } else {
                r.candidate()
            },
            false,
        )?
    } else {
        config.clone()
    };
    let owner = id.clone();
    let budget = request.budget;
    let (credits, secrets) = tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
        Ok((
            crate::cluster::budget::grant(&config, &owner, &budget, now())?,
            protocol::secrets(&key_config)?,
        ))
    })
    .await
    .map_err(anyhow::Error::from)??;
    node(&app, &h).await?;
    if !coordinated && control.snapshot().revision != publication.bundle.revision {
        return Err(Error(
            StatusCode::CONFLICT,
            "Modified configuration; resume synchronization.".into(),
        ));
    }
    Ok((
        protocol::Reply {
            protocol: "noisefence-cluster-1".into(),
            node_id: id,
            server_time: now(),
            bundle,
            receipts,
            commands,
            credits,
            secrets,
        },
        activation,
    ))
}
async fn activation_artifact(
    State(app): State<App>,
    h: HeaderMap,
    Path(hash): Path<String>,
) -> ApiResult<Response> {
    let id = node(&app, &h).await?;
    let control = coordinator(&app)?;
    let journal = control.activation_journal().await?.ok_or(Error(
        StatusCode::NOT_FOUND,
        "No activation artifacts".into(),
    ))?;
    if !crate::compatibility::valid_hash(&hash)
        || !journal
            .rollout()
            .is_some_and(|r| r.participants().contains_key(&id))
    {
        return Err(Error(
            StatusCode::NOT_FOUND,
            "Unknown activation artifact".into(),
        ));
    }
    let (path, size) = journal
        .bundles()
        .into_iter()
        .find_map(|b| {
            b.files
                .iter()
                .find(|(_, f)| f.sha256 == hash)
                .map(|(name, f)| {
                    (
                        crate::cluster::artifacts::directory(&control.base.data_dir, b).join(name),
                        f.size,
                    )
                })
        })
        .ok_or(Error(
            StatusCode::NOT_FOUND,
            "Unknown activation artifact".into(),
        ))?;
    let file = tokio::fs::File::open(path)
        .await
        .map_err(anyhow::Error::from)?;
    if file.metadata().await.map_err(anyhow::Error::from)?.len() != size {
        return Err(Error(
            StatusCode::CONFLICT,
            "Frozen model size changed".into(),
        ));
    }
    node(&app, &h).await?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_owned()),
            (header::CONTENT_LENGTH, size.to_string()),
        ],
        axum::body::Body::from_stream(tokio_util::io::ReaderStream::new(file)),
    )
        .into_response())
}
async fn artifact(
    State(app): State<App>,
    h: HeaderMap,
    Path(hash): Path<String>,
) -> ApiResult<Response> {
    node(&app, &h).await?;
    let publication = coordinator(&app)?.publication().await?;
    let name = publication
        .bundle
        .files
        .iter()
        .find(|(_, f)| f.sha256 == hash)
        .map(|(name, _)| name)
        .ok_or(Error(StatusCode::NOT_FOUND, "Unknown model.".into()))?;
    let file = tokio::fs::File::open(&publication.paths[name])
        .await
        .map_err(anyhow::Error::from)?;
    let size = file.metadata().await.map_err(anyhow::Error::from)?.len();
    if size != publication.bundle.files[name].size {
        return Err(Error(
            StatusCode::CONFLICT,
            "Modified model; reload manifest.".into(),
        ));
    }
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_owned()),
            (header::CONTENT_LENGTH, size.to_string()),
        ],
        axum::body::Body::from_stream(tokio_util::io::ReaderStream::new(file)),
    )
        .into_response())
}
async fn overview(State(app): State<App>, h: HeaderMap) -> ApiResult<Json<Value>> {
    super::admin::administrator(&app, &h, false).await?;
    let nodes=app.store.read(|db|{
        let mut q=db.prepare("SELECT id,name,enabled,created,last_seen,applied_revision,applied_digest,status,version FROM cluster_nodes ORDER BY id")?;
        let mut rows=q.query([])?;let mut out=Vec::new();
        while let Some(r)=rows.next()? {
            let status:Value=serde_json::from_str(&r.get::<_,String>(7)?)?;
            out.push(json!({"id":r.get::<_,String>(0)?,"name":r.get::<_,String>(1)?,"enabled":r.get::<_,bool>(2)?,"created":r.get::<_,i64>(3)?,"last_seen":r.get::<_,Option<i64>>(4)?,"applied_revision":r.get::<_,Option<i64>>(5)?,"applied_digest":r.get::<_,Option<String>>(6)?,"status":status,"version":r.get::<_,i64>(8)?}));
        }
        Ok(out)
    }).await?;
    let commands=app.store.read(|db|{
        let mut q=db.prepare("SELECT id,node_id,recipient,command,created,result,finished FROM cluster_commands ORDER BY created DESC LIMIT 50")?;
        Ok(q.query_map([],|r|Ok(json!({"id":r.get::<_,String>(0)?,"node_id":r.get::<_,String>(1)?,"recipient":r.get::<_,String>(2)?,"command":r.get::<_,String>(3)?,"created":r.get::<_,i64>(4)?,"result":r.get::<_,Option<String>>(5)?,"finished":r.get::<_,Option<i64>>(6)?})))?.collect::<rusqlite::Result<Vec<_>>>()?)
    }).await?;
    let publication = if app
        .config
        .cluster
        .as_ref()
        .is_some_and(|c| c.role == Role::Coordinator)
    {
        Some(coordinator(&app)?.publication().await?)
    } else {
        None
    };
    let replication = crate::ha::status(&app.store).await?;
    let standby = std::fs::read(app.config.data_dir.join("ha-standby-status.json"))
        .ok()
        .filter(|v| v.len() <= 16384)
        .and_then(|v| serde_json::from_slice::<Value>(&v).ok());
    Ok(Json(
        json!({"recovery_console":app.config.console_only,"replication":replication,"standby":standby,"role":app.config.cluster.as_ref().map(|c|c.role),"node_id":app.config.cluster.as_ref().map(|c|&c.node_id),"revision":publication.as_ref().map(|p|p.bundle.revision),"digest":publication.as_ref().map(|p|&p.bundle.digest),"nodes":nodes,"commands":commands,"max_stale_seconds":app.config.cluster.as_ref().map(|c|c.max_stale_seconds),"queue_replication":app.config.replication.is_some()}),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeEdit {
    id: String,
    name: String,
    enabled: bool,
    version: i64,
    #[serde(default)]
    rotate: bool,
}
async fn save_node(
    State(app): State<App>,
    h: HeaderMap,
    Json(body): Json<NodeEdit>,
) -> ApiResult<Json<Value>> {
    let actor = super::admin::administrator(&app, &h, true).await?;
    coordinator(&app)?;
    if !crate::cluster::valid_id(&body.id)
        || body.id == app.config.cluster.as_ref().unwrap().node_id
        || body.name.is_empty()
        || body.name.len() > 100
        || body.name.chars().any(char::is_control)
    {
        return Err(Error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Invalid node name or identifier.".into(),
        ));
    }
    let secret = (body.version < 0 || body.rotate).then(random_token);
    let hash = secret.as_ref().map(|s| message::digest(s.as_bytes()));
    let session_hash = message::digest(token(&h).unwrap().as_bytes());
    let id = body.id.clone();
    let version=app.store.run(move|db| {
        let tx=db.transaction()?;
        ensure!(tx.query_row("SELECT EXISTS(SELECT 1 FROM users u JOIN sessions s ON s.username=u.username WHERE u.username=?1 AND u.admin=1 AND u.disabled=0 AND s.token_hash=?2 AND s.expires>?3)",params![actor.username,session_hash,now()],|r|r.get::<_,bool>(0))?,"Expiration of the admin session");
        let previous=tx.query_row("SELECT version FROM cluster_nodes WHERE id=?1",[&body.id],|r|r.get::<_,i64>(0)).optional()?;
        ensure!(previous.unwrap_or(-1)==body.version,"The node has been modified elsewhere; reload.");
        if previous.is_none() {
            ensure!(tx.query_row("SELECT COUNT(*) FROM cluster_nodes",[],|r|r.get::<_,i64>(0))?<16,"Maximum 16 knots.");
            tx.execute("INSERT INTO cluster_nodes(id,name,token_hash,enabled,created) VALUES(?1,?2,?3,?4,?5)",params![body.id,body.name,hash,body.enabled,now()])?;
        } else {
            tx.execute("UPDATE cluster_nodes SET name=?2,enabled=?3,token_hash=COALESCE(?4,token_hash),version=version+1 WHERE id=?1",params![body.id,body.name,body.enabled,hash])?;
        }
        if !body.enabled {tx.execute("UPDATE cluster_commands SET result='revoked',finished=?2 WHERE node_id=?1 AND finished IS NULL",params![body.id,now()])?;}
        tx.execute("INSERT INTO audit(created,username,action,object_id) VALUES(?1,?2,'cluster_node',?3)",params![now(),actor.username,body.id])?;
        let version=tx.query_row("SELECT version FROM cluster_nodes WHERE id=?1",[&body.id],|r|r.get::<_,i64>(0))?;
        tx.commit()?;Ok(version)
    }).await.map_err(|e|Error(StatusCode::CONFLICT,e.to_string()))?;
    Ok(Json(json!({"id":id,"version":version,"credential":secret})))
}

async fn admission(
    State(app): State<App>,
    Json(request): Json<crate::smtp_admission::runtime::Request>,
) -> ApiResult<Json<crate::smtp_admission::Decision>> {
    // node_guard authenticates the separate, revocable node identity first.
    request.validate()?;
    let config = coordinator(&app)?.snapshot().config.clone();
    if config.recipient(&request.recipient).is_none() {
        return Err(Error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Recipient not accepted".into(),
        ));
    }
    Ok(Json(
        app.store
            .admission
            .local(
                &app.store,
                config.smtp_admission.clone().unwrap_or_default(),
                request,
            )
            .await,
    ))
}
