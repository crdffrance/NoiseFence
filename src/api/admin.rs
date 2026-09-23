use super::*;
use crate::control::{Controller, Settings};

pub(super) fn routes() -> Router<App> {
    Router::new()
        .route("/domains", get(domains))
        .route("/admin/config", get(configuration).post(apply))
        .route("/admin/rbl/test", post(test_rbl))
        .route("/admin/admission", get(admission_status))
        .route("/admin/research-archive", get(research_archive_status))
        .route("/admin/config/validate", post(validate_configuration))
        .route("/admin/keys", get(managed_keys).post(save_managed_key))
        .route("/preferences", get(preferences).post(save_preferences))
        .route("/preferences/activation", get(preference_activation))
        .route("/admin/revisions", get(revisions))
        .route("/admin/revisions/{id}", get(revision))
        .route("/admin/users", get(users).post(save_user))
        .route("/admin/audit", get(audit))
        .route("/admin/queue", get(queue))
        .route("/admin/queue/retry", post(retry))
        .route("/admin/protection", get(protection_status))
        .route("/admin/protection/keys/{provider}", post(protection_key))
}
pub(super) async fn administrator(app: &App, h: &HeaderMap, write: bool) -> ApiResult<User> {
    let user = authenticated(app, h).await?;
    if !user.admin {
        return Err(Error(
            StatusCode::FORBIDDEN,
            "Administrator access required.".into(),
        ));
    }
    if write {
        origin(app, h)?;
        csrf(&user, h)?;
    }
    Ok(user)
}
fn controller(app: &App) -> ApiResult<Arc<Controller>> {
    app.control.clone().ok_or(Error(
        StatusCode::SERVICE_UNAVAILABLE,
        "Administration of the configuration not available on this instance.".into(),
    ))
}
async fn domains(State(app): State<App>, h: HeaderMap) -> ApiResult<Json<Value>> {
    let user = authenticated(&app, &h).await?;
    // Only expose configured domains within the viewer's grants. Message queries independently
    // recheck the database ACL, including disabled accounts, for each visible recipient.
    let configured: Vec<String> = app
        .control
        .as_ref()
        .map(|c| {
            c.snapshot()
                .settings
                .domains
                .iter()
                .map(|d| d.name.clone())
                .collect()
        })
        .unwrap_or_else(|| app.config.domains.iter().map(|d| d.name.clone()).collect());
    let names: Vec<_> = configured
        .into_iter()
        .filter(|name| {
            user.admin
                || user.addresses.iter().any(|a| {
                    a.rsplit_once('@')
                        .is_some_and(|(_, domain)| domain.eq_ignore_ascii_case(name))
                })
        })
        .collect();
    Ok(Json(json!(names)))
}
async fn configuration(State(app): State<App>, h: HeaderMap) -> ApiResult<Json<Value>> {
    administrator(&app, &h, false).await?;
    let control = controller(&app)?;
    let s = control.snapshot();
    let mut tag = s.settings.clone();
    tag.filters.mode = crate::config::Mode::Tag;
    tag.actions = Some(crate::actions::Policy {
        spam: crate::actions::Action::Tag,
        malware: crate::actions::Action::Tag,
        publicity: crate::actions::Action::Deliver,
        quarantine_days: 14,
    });
    let tag_ready = control.effective_settings(&tag).await.is_ok();
    let mut pub_tag = tag.clone();
    pub_tag.mailing = Some(crate::mailing::Policy::default());
    pub_tag.actions = Some(crate::actions::Policy {
        spam: crate::actions::Action::Deliver,
        malware: crate::actions::Action::Deliver,
        publicity: crate::actions::Action::Tag,
        quarantine_days: 14,
    });
    let pub_tag_ready = control.effective_settings(&pub_tag).await.is_ok();
    let mut availability = (*control.base).clone();
    availability.provider_credentials = s.config.provider_credentials.clone();
    availability.credential_generation = s.config.credential_generation.clone();
    Ok(Json(json!({"revision":s.revision,"settings":s.settings,
        "available":Settings::available(&availability),
        "actions":crate::actions::Policy::from_config(&s.config),"rules":crate::rules::CATALOG,
        "native_rules":crate::native_filter::content_rules::RULES,
        "threshold_locked":control.base.filter.semantic.is_some() || control.base.fusion.as_ref().is_some_and(|f| f.mode == crate::fusion::runtime::Mode::Decision),"tag_ready":tag_ready,
        "sensitivity_locked":crate::custom_filtering::sensitivity_locked(&s.config),"sensitivity_levels":crate::custom_filtering::LEVELS,
        "mailing_available":control.base.mailing.is_some(),"pub_tag_ready":pub_tag_ready,
        "hostname":control.base.hostname,"version":env!("CARGO_PKG_VERSION"),
        "tls_required":true,"max_connections":control.base.smtp.max_connections,
        "processing":control.base.smtp.max_processing,"relay_workers":control.base.relay.workers,
        "max_message_bytes":control.base.smtp.max_message_bytes})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Apply {
    revision: i64,
    settings: Settings,
    #[serde(default)]
    installation_models_sha256: Option<String>,
}
async fn apply(
    State(app): State<App>,
    h: HeaderMap,
    Json(body): Json<Apply>,
) -> ApiResult<Json<Value>> {
    let user = administrator(&app, &h, true).await?;
    let control = controller(&app)?;
    if body.revision != control.snapshot().revision {
        return Err(Error(
            StatusCode::CONFLICT,
            "Configuration modified in another session. Reload settings.".into(),
        ));
    }
    if control.activation_journal().await?.is_some() {
        let token_hash = message::digest(token(&h).unwrap().as_bytes());
        let journal = if let Some(digest) = body.installation_models_sha256 {
            control
                .stage_installation_models_session(
                    body.revision,
                    body.settings,
                    user.username,
                    token_hash,
                    digest,
                )
                .await
        } else {
            control
                .stage_activation_session(body.revision, body.settings, user.username, token_hash)
                .await
        }
        .map_err(|e| {
            Error(
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("Staging refused: {e}"),
            )
        })?;
        let epoch = journal.rollout().unwrap().epoch();
        return Ok(Json(
            json!({"revision":epoch.revision,"staged":true,"epoch":epoch}),
        ));
    }
    if body.installation_models_sha256.is_some() {
        return Err(Error(
            StatusCode::CONFLICT,
            "Enroll coordinated activation before selecting installation models.".into(),
        ));
    }
    let id = control
        .apply_session(
            body.revision,
            body.settings,
            user.username,
            message::digest(token(&h).unwrap().as_bytes()),
        )
        .await
        .map_err(|e| {
            tracing::warn!(error=%e,"console configuration refused");
            Error(
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("Setup refused: {e}"),
            )
        })?;
    Ok(Json(json!({"revision":id,"staged":false})))
}
async fn revisions(State(app): State<App>, h: HeaderMap) -> ApiResult<Json<Value>> {
    administrator(&app, &h, false).await?;
    let data=app.store.read(|db| {
        let mut q=db.prepare("SELECT id,created,username FROM console_revisions ORDER BY id DESC LIMIT 100")?;
        Ok(q.query_map([],|r|Ok(json!({"id":r.get::<_,i64>(0)?,"created":r.get::<_,i64>(1)?,"username":r.get::<_,String>(2)?})))?.collect::<rusqlite::Result<Vec<_>>>()?)
    }).await?;
    Ok(Json(json!(data)))
}
async fn revision(
    State(app): State<App>,
    h: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    administrator(&app, &h, false).await?;
    let control = controller(&app)?;
    if id == 0 {
        return Ok(Json(json!(Settings::from_config(&control.base))));
    }
    let raw = app
        .store
        .run(move |db| {
            Ok(db
                .query_row(
                    "SELECT settings FROM console_revisions WHERE id=?1",
                    [id],
                    |r| r.get::<_, String>(0),
                )
                .optional()?)
        })
        .await?
        .ok_or(Error(StatusCode::NOT_FOUND, "Revision not found.".into()))?;
    let mut settings: Settings = serde_json::from_str(&raw).map_err(anyhow::Error::from)?;
    settings.hydrate(&control.base);
    Ok(Json(json!(settings)))
}
async fn users(State(app): State<App>, h: HeaderMap) -> ApiResult<Json<Value>> {
    administrator(&app, &h, false).await?;
    let data=app.store.read(|db| {
        let mut q=db.prepare("SELECT u.username,u.admin,u.disabled,COALESCE(v.version,0) FROM users u LEFT JOIN console_user_versions v ON v.username=u.username ORDER BY u.username LIMIT 1000")?;
        let mut rows=q.query([])?;let mut out=Vec::new();
        while let Some(r)=rows.next()? {
            let username:String=r.get(0)?;
            let mut grants=db.prepare("SELECT address FROM grants WHERE username=?1 ORDER BY address")?;
            let addresses=grants.query_map([&username],|r|r.get::<_,String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
            out.push(json!({"username":username,"admin":r.get::<_,bool>(1)?,"disabled":r.get::<_,bool>(2)?,"version":r.get::<_,i64>(3)?,"addresses":addresses}));
        } Ok(out)
    }).await?;
    Ok(Json(json!(data)))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Account {
    username: String,
    admin: bool,
    disabled: bool,
    addresses: Vec<String>,
    password: Option<String>,
    version: i64,
}
async fn save_user(
    State(app): State<App>,
    h: HeaderMap,
    Json(mut body): Json<Account>,
) -> ApiResult<Json<Value>> {
    let actor = administrator(&app, &h, true).await?;
    let invalid = || {
        Error(
            StatusCode::BAD_REQUEST,
            "Invalid account: check the ID, access and password (12 to 128 bytes).".into(),
        )
    };
    super::onboarding::grants(&app.effective(), &body.username, &mut body.addresses)
        .map_err(|_| invalid())?;
    if body
        .password
        .as_ref()
        .is_some_and(|p| !(12..=128).contains(&p.len()))
        || (body.version < 0 && body.password.is_none())
    {
        return Err(invalid());
    }
    let hash = if let Some(password) = body.password.take() {
        let permit = app.hashing.clone().try_acquire_owned().map_err(|_| {
            Error(
                StatusCode::TOO_MANY_REQUESTS,
                "Try again in a few moments.".into(),
            )
        })?;
        Some(
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                hash_password(&password)
            })
            .await
            .map_err(anyhow::Error::from)??,
        )
    } else {
        None
    };
    let target = body.username.clone();
    app.store.run(move|db| {
        let tx=db.transaction()?;
        let authorized:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM users WHERE username=?1 AND admin=1 AND disabled=0)",[&actor.username],|r|r.get(0))?;
        ensure!(authorized,"Administrator rights revoked.");
        let current=tx.query_row("SELECT COALESCE(v.version,0) FROM users u LEFT JOIN console_user_versions v ON v.username=u.username WHERE u.username=?1",[&body.username],|r|r.get::<_,i64>(0)).optional()?;
        ensure!(current.unwrap_or(-1)==body.version,"Account modified elsewhere or already existing. Reload the accounts.");
        ensure!(body.username!=actor.username || (body.admin && !body.disabled),"You cannot disable your own admin access.");
        if current.is_none() {
            let count:i64=tx.query_row("SELECT COUNT(*) FROM users",[],|r|r.get(0))?;
            ensure!(count<1000,"Maximum of 1,000 accounts reached.");
            tx.execute("INSERT INTO users(username,password,admin,disabled) VALUES(?1,?2,?3,?4)",params![body.username,hash,body.admin,body.disabled])?;
        } else {
            tx.execute("UPDATE users SET admin=?2,disabled=?3,password=COALESCE(?4,password) WHERE username=?1",params![body.username,body.admin,body.disabled,hash])?;
        }
        let admins:i64=tx.query_row("SELECT COUNT(*) FROM users WHERE admin=1 AND disabled=0",[],|r|r.get(0))?;
        ensure!(admins>0,"The last administrator must remain active.");
        tx.execute("DELETE FROM grants WHERE username=?1",[&body.username])?;
        for address in body.addresses {tx.execute("INSERT INTO grants(username,address) VALUES(?1,?2)",params![body.username,address])?;}
        tx.execute("INSERT INTO console_user_versions(username,version) VALUES(?1,1) ON CONFLICT(username) DO UPDATE SET version=version+1",[&body.username])?;
        tx.execute("DELETE FROM sessions WHERE username=?1",[&body.username])?;
        tx.execute("INSERT INTO audit(created,username,action,object_id) VALUES(?1,?2,'account',?3)",params![now(),actor.username,body.username])?;
        tx.commit()?;Ok(())
    }).await.map_err(|e|Error(StatusCode::CONFLICT,e.to_string()))?;
    Ok(Json(json!({"ok":true,"username":target})))
}
async fn audit(State(app): State<App>, h: HeaderMap) -> ApiResult<Json<Value>> {
    administrator(&app, &h, false).await?;
    Ok(Json(json!(app.store.read(|db|{
        let mut q=db.prepare("SELECT created,username,action,object_id FROM audit ORDER BY id DESC LIMIT 200")?;
        Ok(q.query_map([],|r|Ok(json!({"created":r.get::<_,i64>(0)?,"username":r.get::<_,String>(1)?,"action":r.get::<_,String>(2)?,"object":r.get::<_,String>(3)?})))?.collect::<rusqlite::Result<Vec<_>>>()?)
    }).await?)))
}
async fn queue(State(app): State<App>, h: HeaderMap) -> ApiResult<Json<Value>> {
    administrator(&app, &h, false).await?;
    Ok(Json(json!(app.store.read(|db|{
        let mut q=db.prepare("SELECT d.id,d.message_id,d.address,d.status,d.attempts,d.next_attempt,d.error,m.created,o.node_id,EXISTS(SELECT 1 FROM cluster_commands c WHERE c.message_id=m.id AND c.recipient=d.address AND c.finished IS NULL) FROM deliveries d JOIN messages m ON m.id=d.message_id LEFT JOIN cluster_origin o ON o.message_id=m.id WHERE d.status IN ('pending','sending','failed') ORDER BY m.created LIMIT 200")?;
        Ok(q.query_map([],|r|Ok(json!({"id":r.get::<_,i64>(0)?,"message_id":r.get::<_,String>(1)?,"address":r.get::<_,String>(2)?,"status":r.get::<_,String>(3)?,"attempts":r.get::<_,i64>(4)?,"next_attempt":r.get::<_,i64>(5)?,"error":r.get::<_,Option<String>>(6)?,"created":r.get::<_,i64>(7)?,"node_id":r.get::<_,Option<String>>(8)?,"pending_command":r.get::<_,bool>(9)?})))?.collect::<rusqlite::Result<Vec<_>>>()?)
    }).await?)))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Retry {
    id: i64,
}
async fn retry(
    State(app): State<App>,
    h: HeaderMap,
    Json(body): Json<Retry>,
) -> ApiResult<Json<Value>> {
    let actor = administrator(&app, &h, true).await?;
    let command = app.store
        .run(move |db| {
            let tx = db.transaction()?;
            let allowed: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM users WHERE username=?1 AND admin=1 AND disabled=0)",
                [&actor.username],
                |r| r.get(0),
            )?;
            ensure!(allowed, "Access revoked.");
            let remote: Option<(String,String,String)> = tx.query_row(
                "SELECT o.node_id,d.message_id,d.address FROM deliveries d JOIN cluster_origin o ON o.message_id=d.message_id WHERE d.id=?1 AND d.status='pending'", [body.id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))
            ).optional()?;
            if let Some((node,message,recipient)) = remote {
                ensure!(tx.query_row("SELECT EXISTS(SELECT 1 FROM cluster_nodes WHERE id=?1 AND enabled=1)", [&node], |r| r.get::<_,bool>(0))?, "Node revoked.");
                tx.execute("UPDATE cluster_commands SET result='expired',finished=?1 WHERE finished IS NULL AND expires<?1", [now()])?;
                let id = uuid::Uuid::new_v4().to_string();
                tx.execute("INSERT INTO cluster_commands(id,node_id,message_id,recipient,command,username,created,expires) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)", params![id,node,message,recipient,serde_json::to_string(&crate::cluster::history::Operation::Retry)?,actor.username,now(),now()+300])?;
                tx.execute("INSERT INTO audit(created,username,action,object_id) VALUES(?1,?2,'cluster_retry_queued',?3)", params![now(),actor.username,id])?;
                tx.commit()?;
                return Ok(Some(id));
            }
            let changed = tx.execute(
                "UPDATE deliveries SET next_attempt=?2 WHERE id=?1 AND status='pending' AND NOT EXISTS(SELECT 1 FROM cluster_origin WHERE message_id=deliveries.message_id)",
                params![body.id, now()],
            )?;
            ensure!(
                changed == 1,
                "Only a pending delivery can be tried again."
            );
            tx.execute(
                "INSERT INTO audit(created,username,action,object_id) VALUES(?1,?2,'retry',?3)",
                params![now(), actor.username, body.id.to_string()],
            )?;
            tx.commit()?;
            Ok(None)
        })
        .await
        .map_err(|e| Error(StatusCode::CONFLICT, e.to_string()))?;
    Ok(Json(
        json!({"ok":true,"status":if command.is_some(){"queued"}else{"done"},"command_id":command}),
    ))
}

async fn protection_status(State(app): State<App>, h: HeaderMap) -> ApiResult<Json<Value>> {
    administrator(&app, &h, false).await?;
    let control = controller(&app)?;
    let snapshot = control.snapshot();
    let settings = snapshot.config.protection.as_ref();
    let base = control.base.protection.as_ref();
    let root = app.store.root.clone();
    let resident_keys = snapshot.config.provider_credentials.clone();
    let bound = snapshot.config.credential_generation.is_some();
    let staged_generation = control.activation_journal().await?.and_then(|j| {
        j.rollout()
            .filter(|r| {
                matches!(
                    r.phase(),
                    crate::cluster::activation::Phase::Preparing
                        | crate::cluster::activation::Phase::Committed
                )
            })
            .and_then(|r| r.candidate().credential_generation.clone())
    });
    let (keys, loaded_keys, pending_keys, usage) =
        tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
            use crate::protection::providers::{Provider, quota_usage_with_key, read_key};
            let staged = staged_generation
                .as_deref()
                .map(|h| crate::credentials::generations::load(&root, h))
                .transpose()?;
            let mut saved = json!({});
            let mut loaded = json!({});
            let mut pending = json!({});
            let mut usage = json!({});
            for provider in [Provider::Crdf, Provider::Virustotal] {
                let name = provider.name();
                let current = resident_keys.as_ref().and_then(|keys| keys.get(name));
                let source = if bound || staged.is_some() {
                    staged
                        .as_ref()
                        .map_or(current, |s| s.get(name))
                        .map(str::to_owned)
                } else {
                    read_key(&root, provider).ok()
                };
                saved[name] = json!(source.is_some());
                loaded[name] = json!(current.is_some());
                pending[name] = json!(source.as_deref() != current);
                usage[name] = json!(quota_usage_with_key(&root, provider, current).ok());
            }
            Ok((saved, loaded, pending, usage))
        })
        .await
        .map_err(|_| {
            Error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Condition of the connectors not available.".into(),
            )
        })??;
    use crate::protection::Provider;
    Ok(Json(json!({
        "available":base.is_some(), "enabled":settings.is_some(), "revision":snapshot.revision,
        "keys":keys, "loaded_keys":loaded_keys, "pending_keys":pending_keys, "observation_only":true, "usage":usage,
        "quotas":settings.map(|s|json!({"crdf":s.quota(Provider::Crdf,&s.policy),"virustotal":s.quota(Provider::Virustotal,&s.policy)})),
        "bootstrap_quotas":base.map(|s|json!({"crdf":s.bootstrap_quota(Provider::Crdf),"virustotal":s.bootstrap_quota(Provider::Virustotal)})),
        "capacity":base.map(|s|json!({"timeout_ms":s.timeout_ms,"max_parallel":s.max_parallel,"max_indicators":12}))
    })))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectionKey {
    #[serde(default)]
    revision: Option<i64>,
    key: String,
}
async fn protection_key(
    State(app): State<App>,
    h: HeaderMap,
    Path(provider): Path<String>,
    Json(body): Json<ProtectionKey>,
) -> ApiResult<Json<Value>> {
    let user = administrator(&app, &h, true).await?;
    let control = controller(&app)?;
    if control.base.protection.is_none() {
        return Err(Error(
            StatusCode::CONFLICT,
            "Protection not installed on the server.".into(),
        ));
    }
    let provider = crate::protection::Provider::parse(&provider)
        .map_err(|_| Error(StatusCode::BAD_REQUEST, "Unknown provider.".into()))?;
    if !(16..=256).contains(&body.key.len()) || !body.key.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(Error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Expected key: 16 to 256 characters without space.".into(),
        ));
    }
    if control.activation_journal().await?.is_some() {
        let revision = body.revision.ok_or_else(|| {
            Error(
                StatusCode::CONFLICT,
                "Refresh settings before staging a provider key.".into(),
            )
        })?;
        let journal = control.stage_credential_session(revision, provider.name().into(), Some(body.key),
            user.username, message::digest(token(&h).unwrap().as_bytes())).await
            .map_err(|_| Error(StatusCode::CONFLICT, "Unable to stage the provider key. Refresh settings and check activation status.".into()))?;
        let epoch = journal.rollout().unwrap().epoch();
        return Ok(Json(
            json!({"saved":true,"staged":true,"active":false,"revision":epoch.revision,"epoch":epoch}),
        ));
    }
    let root = app.store.root.clone();
    let hash = message::digest(token(&h).unwrap().as_bytes());
    app.store.run(move|db|{
        let tx=db.transaction()?;
        let allowed:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM users u JOIN sessions s ON s.username=u.username WHERE u.username=?1 AND u.admin=1 AND u.disabled=0 AND s.token_hash=?2 AND s.expires>?3)",params![user.username,hash,now()],|r|r.get(0))?;
        anyhow::ensure!(allowed,"Administrative session expired");
        anyhow::ensure!(crate::cluster::activation::Journal::read(&tx)?.is_none(), "Use coordinated credential staging");
        crate::protection::save_key(&root,provider,&body.key)?;
        tx.execute("INSERT INTO audit(created,username,action,object_id) VALUES(?1,?2,'provider_key',?3)",params![now(),user.username,provider.name()])?;
        tx.commit()?;Ok(())
    }).await?;
    Ok(Json(json!({"saved":true})))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RblTest {
    settings: crate::rbl::Settings,
    ip: std::net::IpAddr,
}
async fn test_rbl(
    State(app): State<App>,
    h: HeaderMap,
    Json(body): Json<RblTest>,
) -> ApiResult<Json<Value>> {
    administrator(&app, &h, true).await?;
    let c = controller(&app)?;
    crate::management::validate_rbl(&body.settings, &c.base)
        .map_err(|e| Error(StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?;
    static TEST: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);
    let _permit = TEST.try_acquire().map_err(|_| {
        Error(
            StatusCode::TOO_MANY_REQUESTS,
            "A DNS test is already underway.".into(),
        )
    })?;
    let runtime = crate::rbl::Runtime::new(Some(&body.settings), None)?;
    let report = runtime
        .check(body.ip, crate::config::Mode::Observe, false)
        .await;
    Ok(Json(json!({"report":report,"draft":true})))
}
async fn preferences(State(app): State<App>, h: HeaderMap) -> ApiResult<Json<Value>> {
    let user = authenticated(&app, &h).await?;
    let c = controller(&app)?;
    let s = c.snapshot();
    let global = crate::actions::Policy::from_config(&s.config);
    let default_profile = crate::custom_filtering::Profile {
        id: "personal".into(),
        name: "Personal preferences".into(),
        threshold: None,
        require_corroboration: true,
        spam: global.spam,
        publicity: global.publicity,
        review: crate::actions::Action::Deliver,
        quarantine_days: global.quarantine_days,
    };
    let mut defaults = std::collections::BTreeMap::from([("*".to_owned(), default_profile)]);
    if let Some(policy) = &s.config.custom_filtering {
        for binding in &policy.bindings {
            if (binding.scope == "*"
                || binding.scope.strip_prefix("*@").is_some_and(|d| {
                    user.addresses
                        .iter()
                        .any(|a| a.rsplit_once('@').is_some_and(|(_, domain)| domain == d))
                })
                || crate::preferences::permitted(&binding.scope, user.admin, &user.addresses))
                && let Some(profile) = policy.profiles.iter().find(|p| p.id == binding.profile)
            {
                defaults.insert(binding.scope.clone(), profile.clone());
            }
        }
    }
    let mut settings = s.settings.preferences.clone();
    settings
        .mailboxes
        .retain(|scope, _| crate::preferences::permitted(scope, user.admin, &user.addresses));
    let scopes: Vec<_> = if user.admin {
        s.config
            .domains
            .iter()
            .map(|d| format!("*@{}", d.name))
            .collect()
    } else {
        user.addresses
    };
    Ok(Json(
        json!({"revision":s.revision,"settings":settings,"defaults":defaults,"scopes":scopes,"mode":s.config.filter.mode,"sensitivity_locked":crate::custom_filtering::sensitivity_locked(&s.config)}),
    ))
}
async fn preference_activation(State(app): State<App>, h: HeaderMap) -> ApiResult<Json<Value>> {
    let user = authenticated(&app, &h).await?;
    Ok(Json(
        controller(&app)?
            .activation_view(user.username, false)
            .await?,
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreferenceEdit {
    revision: i64,
    scope: String,
    preference: Option<crate::preferences::Preference>,
}
async fn save_preferences(
    State(app): State<App>,
    h: HeaderMap,
    Json(body): Json<PreferenceEdit>,
) -> ApiResult<Json<Value>> {
    let user = authenticated(&app, &h).await?;
    origin(&app, &h)?;
    csrf(&user, &h)?;
    if !crate::preferences::permitted(&body.scope, user.admin, &user.addresses) {
        return Err(Error(
            StatusCode::FORBIDDEN,
            "This address is not allowed.".into(),
        ));
    }
    let c = controller(&app)?;
    if c.snapshot().revision != body.revision {
        return Err(Error(
            StatusCode::CONFLICT,
            "Modified configuration. Reload preferences.".into(),
        ));
    }
    if c.activation_journal().await?.is_some() {
        let journal = c
            .stage_preferences_session(
                body.revision,
                body.scope,
                body.preference,
                user.username,
                message::digest(token(&h).unwrap().as_bytes()),
            )
            .await
            .map_err(|e| Error(StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?;
        let epoch = journal.rollout().unwrap().epoch();
        // No global settings, participant IDs, model fingerprints or other scopes.
        return Ok(Json(json!({"revision":epoch.revision,"staged":true})));
    }
    let id = c
        .apply_preferences(
            body.revision,
            body.scope,
            body.preference,
            user.username,
            message::digest(token(&h).unwrap().as_bytes()),
        )
        .await
        .map_err(|e| Error(StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?;
    Ok(Json(json!({"revision":id,"staged":false})))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidateConfiguration {
    settings: Settings,
}
async fn validate_configuration(
    State(app): State<App>,
    h: HeaderMap,
    Json(mut body): Json<ValidateConfiguration>,
) -> ApiResult<Json<Value>> {
    administrator(&app, &h, true).await?;
    let c = controller(&app)?;
    body.settings.hydrate(&c.base);
    c.effective_settings(&body.settings)
        .await
        .map_err(|e| Error(StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?;
    Ok(Json(json!({"settings":body.settings})))
}
async fn managed_keys(State(app): State<App>, h: HeaderMap) -> ApiResult<Json<Value>> {
    administrator(&app, &h, false).await?;
    let c = controller(&app)?;
    let snapshot = c.snapshot();
    let present = |name: &str| {
        if snapshot.config.credential_generation.is_some() {
            snapshot
                .config
                .provider_credentials
                .as_ref()
                .is_some_and(|k| k.get(name).is_some())
        } else {
            crate::management::key_present(&c.base.data_dir, name)
                || if name == "spamhaus" {
                    c.base.filter.spamhaus_key_env.is_some()
                } else {
                    c.base.llm.is_some()
                }
        }
    };
    Ok(Json(
        json!({"spamhaus":present("spamhaus"),"scaleway":present("scaleway"),"scaleway_available":c.base.llm.is_some()}),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagedKey {
    revision: i64,
    provider: String,
    key: String,
}
async fn save_managed_key(
    State(app): State<App>,
    h: HeaderMap,
    Json(body): Json<ManagedKey>,
) -> ApiResult<Json<Value>> {
    let user = administrator(&app, &h, true).await?;
    if !matches!(body.provider.as_str(), "spamhaus" | "scaleway")
        || !(16..=256).contains(&body.key.len())
        || !body.key.bytes().all(|b| {
            if body.provider == "spamhaus" {
                b.is_ascii_alphanumeric()
            } else {
                b.is_ascii_graphic()
            }
        })
    {
        return Err(Error(StatusCode::UNPROCESSABLE_ENTITY,"Invalid key provider or format (16 to 256 characters without space; DQS: letters and numbers).".into()));
    }

    let c = controller(&app)?;
    if c.snapshot().revision != body.revision {
        return Err(Error(
            StatusCode::CONFLICT,
            "Modified configuration. Reload settings.".into(),
        ));
    }
    if body.provider == "scaleway" && c.base.llm.is_none() {
        return Err(Error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Scaleway connector not installed.".into(),
        ));
    }
    if c.activation_journal().await?.is_some() {
        let journal = c.stage_credential_session(body.revision, body.provider, Some(body.key),
            user.username, message::digest(token(&h).unwrap().as_bytes())).await
            .map_err(|_| Error(StatusCode::CONFLICT, "Unable to stage the provider key. Refresh settings and check activation status.".into()))?;
        let epoch = journal.rollout().unwrap().epoch();
        return Ok(Json(
            json!({"saved":true,"staged":true,"active":false,"revision":epoch.revision,"epoch":epoch}),
        ));
    }
    let hash = message::digest(token(&h).unwrap().as_bytes());
    let root = c.base.data_dir.clone();
    let username = user.username.clone();
    app.store.run(move|db|{let tx=db.transaction()?;
        let allowed:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM users u JOIN sessions s ON s.username=u.username WHERE u.username=?1 AND u.admin=1 AND u.disabled=0 AND s.token_hash=?2 AND s.expires>?3)",params![username,hash,now()],|r|r.get(0))?;
        anyhow::ensure!(allowed,"Administrative session expired");
        let current:i64=tx.query_row("SELECT COALESCE(MAX(id),0) FROM console_revisions",[],|r|r.get(0))?;anyhow::ensure!(current==body.revision,"Configuration changed.");
        anyhow::ensure!(crate::cluster::activation::Journal::read(&tx)?.is_none(), "Use coordinated credential staging");
        crate::management::save_key(&root,&body.provider,&body.key)?;
        tx.execute("INSERT INTO audit(created,username,action,object_id) VALUES(?1,?2,'provider_key',?3)",params![now(),username,body.provider])?;tx.commit()?;Ok(())}).await?;
    let snapshot = c.snapshot();
    match c
        .apply(snapshot.revision, snapshot.settings.clone(), user.username)
        .await
    {
        Ok(revision) => Ok(Json(
            json!({"saved":true,"active":true,"revision":revision}),
        )),
        Err(_) => Ok(Json(
            json!({"saved":true,"active":false,"message":"Saved key. Reapply the configuration to load it into the engine."}),
        )),
    }
}

async fn admission_status(State(app): State<App>, h: HeaderMap) -> ApiResult<Json<Value>> {
    administrator(&app, &h, false).await?;
    let counts = app.store.read(|db| {
        Ok(db.prepare("SELECT mode,status,SUM(count) FROM smtp_admission_counts_v2 WHERE day>=?1 GROUP BY mode,status ORDER BY mode,status")?
            .query_map([now()/86400-29], |r| Ok(json!({"mode":r.get::<_,String>(0)?,"status":r.get::<_,String>(1)?,"count":r.get::<_,i64>(2)?})))?
            .collect::<rusqlite::Result<Vec<_>>>()?)
    }).await?;
    Ok(Json(
        json!({"version":crate::smtp_admission::VERSION,"counts":counts,"period_days":30,"shared":app.config.cluster.is_some()}),
    ))
}

async fn research_archive_status(State(app): State<App>, h: HeaderMap) -> ApiResult<Json<Value>> {
    administrator(&app, &h, false).await?;
    let runtime = app.store.archive.clone();
    let local = tokio::task::spawn_blocking(move || runtime.status())
        .await
        .map_err(|e| anyhow::anyhow!(e))??;
    let nodes = app
        .store
        .read(|db| {
            let rows = db
                .prepare(
                    "SELECT id,last_seen,status FROM cluster_nodes WHERE enabled=1 ORDER BY id",
                )?
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, String>(2)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows
                .into_iter()
                .map(|(id, last_seen, status)| {
                    let s: Value = serde_json::from_str(&status).unwrap_or(Value::Null);
                    json!({"node_id":id,"last_seen":last_seen,"status":s.get("research_archive")})
                })
                .collect::<Vec<_>>())
        })
        .await?;
    Ok(Json(
        json!({"local":{"node_id":app.config.cluster.as_ref().map(|c|c.node_id.as_str()).unwrap_or("local"),"last_seen":now(),"status":local},"workers":nodes}),
    ))
}
