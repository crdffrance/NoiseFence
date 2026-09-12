use super::*;
use crate::control::{Controller, Settings};

pub(super) fn routes() -> Router<App> {
    Router::new()
        .route("/domains", get(domains))
        .route("/admin/config", get(configuration).post(apply))
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
            "Accès administrateur requis.".into(),
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
        "Administration de la configuration indisponible sur cette instance.".into(),
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
    let tag_ready = tag.effective(&control.base).is_ok();
    let mut pub_tag = tag.clone();
    pub_tag.mailing = Some(crate::mailing::Policy::default());
    pub_tag.actions = Some(crate::actions::Policy {
        spam: crate::actions::Action::Deliver,
        malware: crate::actions::Action::Deliver,
        publicity: crate::actions::Action::Tag,
        quarantine_days: 14,
    });
    let pub_tag_ready = pub_tag.effective(&control.base).is_ok();
    Ok(Json(json!({"revision":s.revision,"settings":s.settings,
        "available":Settings::from_config(&control.base).filters,
        "actions":crate::actions::Policy::from_config(&s.config),"rules":crate::rules::CATALOG,
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
            "Configuration modifiée dans une autre session. Rechargez les réglages.".into(),
        ));
    }
    let id = control
        .apply(body.revision, body.settings, user.username)
        .await
        .map_err(|e| {
            tracing::warn!(error=%e,"console configuration refused");
            Error(
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("Configuration refusée : {e}"),
            )
        })?;
    Ok(Json(json!({"revision":id})))
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
        .ok_or(Error(StatusCode::NOT_FOUND, "Révision introuvable.".into()))?;
    Ok(Json(
        serde_json::from_str(&raw).map_err(anyhow::Error::from)?,
    ))
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
        Error(StatusCode::BAD_REQUEST,"Compte invalide : vérifiez l’identifiant, les accès et le mot de passe (12 à 128 octets).".into())
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
                "Réessayez dans quelques instants.".into(),
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
        ensure!(authorized,"Droits administrateur révoqués.");
        let current=tx.query_row("SELECT COALESCE(v.version,0) FROM users u LEFT JOIN console_user_versions v ON v.username=u.username WHERE u.username=?1",[&body.username],|r|r.get::<_,i64>(0)).optional()?;
        ensure!(current.unwrap_or(-1)==body.version,"Compte modifié ailleurs ou déjà existant. Rechargez les comptes.");
        ensure!(body.username!=actor.username || (body.admin && !body.disabled),"Vous ne pouvez pas désactiver votre propre accès administrateur.");
        if current.is_none() {
            let count:i64=tx.query_row("SELECT COUNT(*) FROM users",[],|r|r.get(0))?;
            ensure!(count<1000,"Maximum de 1 000 comptes atteint.");
            tx.execute("INSERT INTO users(username,password,admin,disabled) VALUES(?1,?2,?3,?4)",params![body.username,hash,body.admin,body.disabled])?;
        } else {
            tx.execute("UPDATE users SET admin=?2,disabled=?3,password=COALESCE(?4,password) WHERE username=?1",params![body.username,body.admin,body.disabled,hash])?;
        }
        let admins:i64=tx.query_row("SELECT COUNT(*) FROM users WHERE admin=1 AND disabled=0",[],|r|r.get(0))?;
        ensure!(admins>0,"Le dernier administrateur doit rester actif.");
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
        let mut q=db.prepare("SELECT d.id,d.message_id,d.address,d.status,d.attempts,d.next_attempt,d.error,m.created FROM deliveries d JOIN messages m ON m.id=d.message_id WHERE d.status IN ('pending','sending','failed') ORDER BY m.created LIMIT 200")?;
        Ok(q.query_map([],|r|Ok(json!({"id":r.get::<_,i64>(0)?,"message_id":r.get::<_,String>(1)?,"address":r.get::<_,String>(2)?,"status":r.get::<_,String>(3)?,"attempts":r.get::<_,i64>(4)?,"next_attempt":r.get::<_,i64>(5)?,"error":r.get::<_,Option<String>>(6)?,"created":r.get::<_,i64>(7)?})))?.collect::<rusqlite::Result<Vec<_>>>()?)
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
    app.store
        .run(move |db| {
            let tx = db.transaction()?;
            let allowed: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM users WHERE username=?1 AND admin=1 AND disabled=0)",
                [&actor.username],
                |r| r.get(0),
            )?;
            ensure!(allowed, "Accès révoqué.");
            let changed = tx.execute(
                "UPDATE deliveries SET next_attempt=?2 WHERE id=?1 AND status='pending'",
                params![body.id, now()],
            )?;
            ensure!(
                changed == 1,
                "Seule une livraison en attente peut être réessayée."
            );
            tx.execute(
                "INSERT INTO audit(created,username,action,object_id) VALUES(?1,?2,'retry',?3)",
                params![now(), actor.username, body.id.to_string()],
            )?;
            tx.commit()?;
            Ok(())
        })
        .await
        .map_err(|e| Error(StatusCode::CONFLICT, e.to_string()))?;
    Ok(Json(json!({"ok":true})))
}

async fn protection_status(State(app): State<App>, h: HeaderMap) -> ApiResult<Json<Value>> {
    administrator(&app, &h, false).await?;
    let control = controller(&app)?;
    let snapshot = control.snapshot();
    let settings = snapshot.config.protection.as_ref();
    let base = control.base.protection.as_ref();
    let root = app.store.root.clone();
    let (keys, usage) = tokio::task::spawn_blocking(move || {
        use crate::protection::{Provider, key_present, quota_usage};
        (json!({"crdf":key_present(&root,Provider::Crdf),"virustotal":key_present(&root,Provider::Virustotal)}),
         json!({"crdf":quota_usage(&root,Provider::Crdf).ok(),"virustotal":quota_usage(&root,Provider::Virustotal).ok()}))
    }).await.map_err(|_|Error(StatusCode::SERVICE_UNAVAILABLE,"État des connecteurs indisponible.".into()))?;
    use crate::protection::Provider;
    Ok(Json(json!({
        "available":base.is_some(), "enabled":settings.is_some(), "revision":snapshot.revision,
        "keys":keys, "observation_only":true, "usage":usage,
        "quotas":settings.map(|s|json!({"crdf":s.quota(Provider::Crdf,&s.policy),"virustotal":s.quota(Provider::Virustotal,&s.policy)})),
        "bootstrap_quotas":base.map(|s|json!({"crdf":s.bootstrap_quota(Provider::Crdf),"virustotal":s.bootstrap_quota(Provider::Virustotal)})),
        "capacity":base.map(|s|json!({"timeout_ms":s.timeout_ms,"max_parallel":s.max_parallel,"max_indicators":12}))
    })))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectionKey {
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
            "Protection non installée sur le serveur.".into(),
        ));
    }
    let provider = crate::protection::Provider::parse(&provider)
        .map_err(|_| Error(StatusCode::BAD_REQUEST, "Fournisseur inconnu.".into()))?;
    if !(16..=256).contains(&body.key.len()) || !body.key.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(Error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Clé attendue : 16 à 256 caractères sans espace.".into(),
        ));
    }
    let root = app.store.root.clone();
    let hash = message::digest(token(&h).unwrap().as_bytes());
    app.store.run(move|db|{
        let tx=db.transaction()?;
        let allowed:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM users u JOIN sessions s ON s.username=u.username WHERE u.username=?1 AND u.admin=1 AND u.disabled=0 AND s.token_hash=?2 AND s.expires>?3)",params![user.username,hash,now()],|r|r.get(0))?;
        anyhow::ensure!(allowed,"Administrative session expired");
        crate::protection::save_key(&root,provider,&body.key)?;
        tx.execute("INSERT INTO audit(created,username,action,object_id) VALUES(?1,?2,'provider_key',?3)",params![now(),user.username,provider.name()])?;
        tx.commit()?;Ok(())
    }).await?;
    Ok(Json(json!({"saved":true})))
}
