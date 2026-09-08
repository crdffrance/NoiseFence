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
}
async fn administrator(app: &App, h: &HeaderMap, write: bool) -> ApiResult<User> {
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
    let tag_ready = tag.effective(&control.base).is_ok();
    Ok(Json(json!({"revision":s.revision,"settings":s.settings,
        "available":Settings::from_config(&control.base).filters,
        "threshold_locked":control.base.filter.semantic.is_some(),"tag_ready":tag_ready,
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
    if body.username.is_empty()
        || body.username.len() > 100
        || !body
            .username
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-@".contains(&b))
        || body.addresses.len() > 1000
    {
        return Err(invalid());
    }
    let cfg = app.effective();
    for address in &mut body.addresses {
        let Some((local, domain)) = address.rsplit_once('@') else {
            return Err(invalid());
        };
        if !(local == "*" || crate::config::valid_address(address))
            || !cfg
                .domains
                .iter()
                .any(|d| d.name.eq_ignore_ascii_case(domain))
        {
            return Err(invalid());
        }
        let normalized = if local == "*" {
            format!("*@{}", domain.to_ascii_lowercase())
        } else {
            cfg.recipient(address)
                .map(|r| r.destination)
                .ok_or_else(invalid)?
        };
        *address = normalized;
    }
    body.addresses.sort();
    body.addresses.dedup();
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
