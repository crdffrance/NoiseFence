//! Pair-scoped replication API. It is separate from browser and worker identities.
use super::*;
use crate::ha::{Runtime, replica};
use http_body_util::BodyExt;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

pub(super) fn routes(app: App) -> Router<App> {
    Router::new()
        .route("/v1/ping", post(ping))
        .route(
            "/v1/body/{id}",
            post(body).layer(DefaultBodyLimit::disable()),
        )
        .route(
            "/v1/manifest",
            post(manifest).layer(DefaultBodyLimit::max(3 * 1024 * 1024)),
        )
        .layer(middleware::from_fn_with_state(app, guard))
}
async fn ping(State(app): State<App>) -> ApiResult<Json<replica::Receipt>> {
    let r = runtime(&app)?;
    let space = crate::store::available_bytes(&app.store.root)?;
    let used = app
        .store
        .read(|db| {
            Ok(db.query_row(
                "SELECT COALESCE(SUM(bytes),0) FROM ha_blobs WHERE present=1",
                [],
                |r| r.get::<_, u64>(0),
            )?)
        })
        .await?;
    if space <= r.minimum_free_bytes.saturating_add(r.max_message_bytes)
        || used.saturating_add(r.max_message_bytes) > r.settings.max_replica_bytes
    {
        return Err(Error(
            StatusCode::INSUFFICIENT_STORAGE,
            "Replica reserve unavailable".into(),
        ));
    }
    Ok(Json(replica::receipt(&r, "ping".into(), 0)))
}
fn runtime(app: &App) -> ApiResult<Arc<Runtime>> {
    app.store.replication.get().cloned().ok_or(Error(
        StatusCode::SERVICE_UNAVAILABLE,
        "Replication is not configured".into(),
    ))
}
fn authenticated(runtime: &Runtime, request: &Request) -> bool {
    let header = |name: &str| request.headers().get(name).and_then(|h| h.to_str().ok());
    let key = header("authorization").and_then(|s| s.strip_prefix("Bearer "));
    key.is_some_and(|key| {
        key.len() == runtime.key.len()
            && key
                .bytes()
                .zip(runtime.key.bytes())
                .fold(0, |v, (a, b)| v | (a ^ b))
                == 0
    }) && header("x-noisefence-node") == Some(&runtime.settings.peer_id)
        && (runtime.settings.allow_loopback_http
            || header("x-noisefence-machine")
                .is_some_and(|v| v != runtime.machine && crate::compatibility::valid_hash(v)))
}
async fn guard(State(app): State<App>, request: Request, next: Next) -> Response {
    let runtime = match runtime(&app) {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    if !authenticated(&runtime, &request) {
        return Error(StatusCode::UNAUTHORIZED, "Replica identity refused".into()).into_response();
    }
    // Bound waiting requests independently of outbound slots to avoid pair deadlocks.
    let _slot = match runtime.receivers.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            return Error(StatusCode::TOO_MANY_REQUESTS, "Replica writer busy".into())
                .into_response();
        }
    };
    let _permit =
        match tokio::time::timeout(Duration::from_secs(2), runtime.serial.clone().lock_owned())
            .await
        {
            Ok(p) => p,
            Err(_) => {
                return Error(StatusCode::TOO_MANY_REQUESTS, "Replica writer busy".into())
                    .into_response();
            }
        };
    match tokio::time::timeout(
        Duration::from_secs(runtime.settings.timeout_seconds),
        next.run(request),
    )
    .await
    {
        Ok(r) => r,
        Err(_) => Error(
            StatusCode::GATEWAY_TIMEOUT,
            "Replica operation expired".into(),
        )
        .into_response(),
    }
}
struct Partial(std::path::PathBuf);
impl Drop for Partial {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
async fn body(
    State(app): State<App>,
    Path(id): Path<String>,
    request: Request,
) -> ApiResult<Json<replica::Receipt>> {
    store_body(app, id, request).await.map(Json).map_err(|e| {
        Error(
            StatusCode::SERVICE_UNAVAILABLE,
            crate::delivery_log::sanitize(&e.to_string(), 240).0,
        )
    })
}
async fn store_body(
    app: App,
    id: String,
    mut request: Request,
) -> anyhow::Result<replica::Receipt> {
    let runtime = app
        .store
        .replication
        .get()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("Replication disabled"))?;
    ensure!(replica::valid_id(&id), "Invalid replica identifier");
    let hash = request
        .headers()
        .get("x-noisefence-sha256")
        .and_then(|h| h.to_str().ok())
        .filter(|h| crate::compatibility::valid_hash(h))
        .ok_or(anyhow::anyhow!("Invalid body digest"))?
        .to_owned();
    let bytes = request
        .headers()
        .get("x-noisefence-bytes")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.parse::<u64>().ok())
        .filter(|n| *n <= runtime.max_message_bytes)
        .ok_or_else(|| anyhow::anyhow!("Invalid body size"))?;
    let owner = runtime.settings.peer_id.clone();
    let key = id.clone();
    let peer = owner.clone();
    let (used, previous) = app
        .store
        .read(move |db| {
            let used: u64 = db.query_row(
                "SELECT COALESCE(SUM(bytes),0) FROM ha_blobs WHERE present=1",
                [],
                |r| r.get(0),
            )?;
            let previous: Option<(String, u64, bool)> = db
                .query_row(
                    "SELECT hash,bytes,present FROM ha_blobs WHERE owner=?1 AND id=?2",
                    params![peer, key],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            Ok((used, previous))
        })
        .await?;
    let path = replica::body_path(&app.store, &owner, &id);
    if let Some((old_hash, old_bytes, present)) = previous {
        ensure!(
            present && old_hash == hash && old_bytes == bytes,
            "Immutable replica body conflict"
        );
        let existing = path.clone();
        let expected = hash.clone();
        if tokio::task::spawn_blocking(move || {
            crate::cluster::artifacts::file_digest(&existing)
                .is_ok_and(|(n, h)| n == bytes && h == expected)
        })
        .await?
        {
            return Ok(replica::receipt(&runtime, id, 0));
        }
    }
    ensure!(
        used.saturating_add(bytes) <= runtime.settings.max_replica_bytes
            && crate::store::available_bytes(&app.store.root)?
                > runtime
                    .minimum_free_bytes
                    .saturating_add(bytes.saturating_mul(2)),
        "Replica disk reserve unavailable"
    );
    let dir = path.parent().unwrap();
    tokio::fs::create_dir_all(dir).await?;
    let temporary = dir.join(format!(".partial-{}", uuid::Uuid::new_v4()));
    let _partial = Partial(temporary.clone());
    let mut file = tokio::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)
        .await?;
    let mut count = 0_u64;
    let mut digest = Sha256::new();
    while let Some(frame) = request.body_mut().frame().await {
        let frame = frame.map_err(|_| anyhow::anyhow!("Replica body interrupted"))?;
        if let Ok(data) = frame.into_data() {
            count = count.saturating_add(data.len() as u64);
            ensure!(count <= bytes, "Replica body exceeds manifest");
            digest.update(&data);
            file.write_all(&data).await?;
        }
    }
    ensure!(
        count == bytes && hex::encode(digest.finalize()) == hash,
        "Replica checksum mismatch"
    );
    file.sync_all().await?;
    drop(file);
    tokio::fs::rename(&temporary, &path).await?;
    let directory = dir.to_path_buf();
    tokio::task::spawn_blocking(move || std::fs::File::open(directory)?.sync_all()).await??;
    let key = id.clone();
    app.store.run(move|db| {db.execute("INSERT INTO ha_blobs(owner,id,hash,bytes,updated) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(owner,id) DO UPDATE SET updated=excluded.updated",params![owner,key,hash,bytes,now()])?;Ok(())}).await?;
    Ok(replica::receipt(&runtime, id, 0))
}
async fn manifest(
    State(app): State<App>,
    Json(manifest): Json<replica::Manifest>,
) -> ApiResult<Json<replica::Receipt>> {
    let r = replica::ingest(&app.store, runtime(&app)?, manifest).await?;
    Ok(Json(r))
}
