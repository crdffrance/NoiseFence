use super::*;
use crate::mfa as factor;

pub fn routes() -> Router<App> {
    Router::new()
        .route("/mfa", get(status))
        .route("/mfa/enroll", post(enroll))
        .route("/mfa/confirm", post(confirm))
        .route("/mfa/disable", post(disable))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Challenge {
    password: String,
    #[serde(default)]
    code: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Confirm {
    code: String,
}
fn key(app: &App) -> ApiResult<Arc<factor::Key>> {
    app.mfa_key.clone().ok_or_else(|| {
        Error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Second facteur indisponible.".into(),
        )
    })
}
async fn status(State(app): State<App>, h: HeaderMap) -> ApiResult<Json<Value>> {
    let user = authenticated(&app, &h).await?;
    Ok(Json(app.store.run(move|db|Ok(json!({
        "enabled":db.query_row("SELECT EXISTS(SELECT 1 FROM mfa_credentials WHERE username=?1 AND enabled=1)",[&user.username],|r|r.get::<_,bool>(0))?,
        "recovery_remaining":db.query_row("SELECT COUNT(*) FROM mfa_recovery WHERE username=?1",[&user.username],|r|r.get::<_,i64>(0))?,
        "recommended":user.admin
    }))).await?))
}
async fn reauthenticate(app: &App, user: &User, password: String) -> ApiResult<()> {
    if password.len() > 128 {
        return Err(Error(
            StatusCode::BAD_REQUEST,
            "Mot de passe incorrect.".into(),
        ));
    }
    let name = user.username.clone();
    let hash = app
        .store
        .run(move |db| {
            ensure!(
                factor::attempt(db, &name, now())?,
                "Challenge rate exceeded"
            );
            Ok(db.query_row(
                "SELECT password FROM users WHERE username=?1 AND disabled=0",
                [name],
                |r| r.get::<_, String>(0),
            )?)
        })
        .await
        .map_err(|_| {
            Error(
                StatusCode::TOO_MANY_REQUESTS,
                "Trop de tentatives. Réessayez dans dix minutes.".into(),
            )
        })?;
    let permit = app.hashing.clone().try_acquire_owned().map_err(|_| {
        Error(
            StatusCode::TOO_MANY_REQUESTS,
            "Réessayez dans quelques instants.".into(),
        )
    })?;
    let valid = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        verify(&password, &hash)
    })
    .await
    .map_err(anyhow::Error::from)?;
    if !valid {
        return Err(Error(
            StatusCode::BAD_REQUEST,
            "Mot de passe incorrect.".into(),
        ));
    }
    Ok(())
}
async fn enroll(
    State(app): State<App>,
    h: HeaderMap,
    Json(body): Json<Challenge>,
) -> ApiResult<Json<Value>> {
    origin(&app, &h)?;
    let user = authenticated(&app, &h).await?;
    csrf(&user, &h)?;
    reauthenticate(&app, &user, body.password).await?;
    let secret = factor::secret();
    let encoded = factor::base32(&secret);
    let sealed = key(&app)?.seal(&user.username, &secret)?;
    let session = message::digest(token(&h).unwrap().as_bytes());
    let name = user.username;
    let saved=app.store.run(move|db|{
        let tx=db.transaction()?;
        let allowed:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM sessions WHERE token_hash=?1 AND username=?2 AND expires>?3)",params![session,name,now()],|r|r.get(0))?;
        let enabled:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM mfa_credentials WHERE username=?1 AND enabled=1)",[&name],|r|r.get(0))?;
        if !allowed||enabled{return Ok(false)}
        tx.execute("INSERT INTO mfa_credentials(username,secret,pending_until) VALUES(?1,?2,?3) ON CONFLICT(username) DO UPDATE SET secret=excluded.secret,pending_until=excluded.pending_until,last_step=-1 WHERE enabled=0",params![name,sealed,now()+600])?;
        tx.commit()?;Ok(true)
    }).await?;
    if !saved {
        return Err(Error(
            StatusCode::CONFLICT,
            "Second facteur déjà actif ou session expirée.".into(),
        ));
    }
    Ok(Json(
        json!({"secret":encoded,"issuer":"NoiseFence","digits":6,"period":30,"expires_in":600}),
    ))
}
async fn confirm(
    State(app): State<App>,
    h: HeaderMap,
    Json(body): Json<Confirm>,
) -> ApiResult<Json<Value>> {
    origin(&app, &h)?;
    let user = authenticated(&app, &h).await?;
    csrf(&user, &h)?;
    if body.code.len() != 6 {
        return Err(Error(
            StatusCode::BAD_REQUEST,
            "Code à six chiffres requis.".into(),
        ));
    }
    let key = key(&app)?;
    let codes = factor::recovery();
    let saved_codes = codes.clone();
    let session = message::digest(token(&h).unwrap().as_bytes());
    let success=app.store.run(move|db|{
        if !factor::attempt(db,&user.username,now())?{return Ok(false)}
        let tx=db.transaction()?;
        let allowed:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM sessions WHERE token_hash=?1 AND username=?2 AND expires>?3)",params![session,user.username,now()],|r|r.get(0))?;
        if !allowed{return Ok(false)}
        let encrypted=tx.query_row("SELECT secret FROM mfa_credentials WHERE username=?1 AND enabled=0 AND pending_until>?2",params![user.username,now()],|r|r.get::<_,Vec<u8>>(0)).optional()?;
        let Some(encrypted)=encrypted else{return Ok(false)};
        let secret=key.open_secret(&user.username,&encrypted)?;
        let Some(step)=factor::matched_step(&secret,&body.code,now(),-1) else{return Ok(false)};
        tx.execute("UPDATE mfa_credentials SET enabled=1,pending_until=0,last_step=?2 WHERE username=?1",params![user.username,step])?;
        tx.execute("DELETE FROM mfa_recovery WHERE username=?1",[&user.username])?;
        for code in saved_codes {tx.execute("INSERT INTO mfa_recovery VALUES(?1,?2)",params![user.username,message::digest(code.as_bytes())])?;}
        // Invalidate all sessions, including this one. No pre-enrollment cookie gains MFA trust.
        tx.execute("DELETE FROM sessions WHERE username=?1",[&user.username])?;
        tx.execute("INSERT INTO audit(created,username,action,object_id) VALUES(?1,?2,'mfa_enabled','')",params![now(),user.username])?;
        // Older binaries must fail closed instead of silently bypassing the second factor.
        tx.execute_batch("PRAGMA user_version=4")?;tx.commit()?;Ok(true)
    }).await?;
    if !success {
        return Err(Error(
            StatusCode::BAD_REQUEST,
            "Code incorrect, configuration expirée ou trop de tentatives.".into(),
        ));
    }
    Ok(Json(
        json!({"enabled":true,"recovery_codes":codes,"reauthenticate":true}),
    ))
}
async fn disable(
    State(app): State<App>,
    h: HeaderMap,
    Json(body): Json<Challenge>,
) -> ApiResult<Json<Value>> {
    origin(&app, &h)?;
    let user = authenticated(&app, &h).await?;
    csrf(&user, &h)?;
    reauthenticate(&app, &user, body.password).await?;
    let key = key(&app)?;
    let session = message::digest(token(&h).unwrap().as_bytes());
    let success=app.store.run(move|db|{
        let tx=db.transaction()?;
        let allowed:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM sessions WHERE token_hash=?1 AND username=?2 AND expires>?3)",params![session,user.username,now()],|r|r.get(0))?;
        if !allowed || factor::consume(&tx,&key,&user.username,&body.code,now())?!=Some(true){return Ok(false)}
        tx.execute("DELETE FROM mfa_credentials WHERE username=?1",[&user.username])?;
        tx.execute("DELETE FROM mfa_recovery WHERE username=?1",[&user.username])?;
        tx.execute("DELETE FROM sessions WHERE username=?1",[&user.username])?;
        tx.execute("INSERT INTO audit(created,username,action,object_id) VALUES(?1,?2,'mfa_disabled','')",params![now(),user.username])?;tx.commit()?;Ok(true)
    }).await?;
    if !success {
        return Err(Error(
            StatusCode::BAD_REQUEST,
            "Un nouveau code valide ou un code de secours est requis.".into(),
        ));
    }
    Ok(Json(json!({"enabled":false,"reauthenticate":true})))
}
