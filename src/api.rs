mod admin;
use crate::{
    config::Config,
    message, now,
    store::{Store, User},
};
use anyhow::{Result, ensure};
use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng},
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Query, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use rusqlite::{OptionalExtension, params};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use tower_http::services::ServeDir;

#[derive(Clone)]
pub struct App {
    pub config: Arc<Config>,
    pub store: Store,
    control: Option<Arc<crate::control::Controller>>,
    limiter: Arc<Mutex<HashMap<String, (i64, u32)>>>,
    hashing: Arc<tokio::sync::Semaphore>,
    dummy_hash: Arc<String>,
}
#[derive(Debug)]
pub struct Error(StatusCode, String);
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error":self.1}))).into_response()
    }
}
impl From<anyhow::Error> for Error {
    fn from(e: anyhow::Error) -> Self {
        tracing::error!(error=%e,"API operation failed");
        Self(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Service temporairement indisponible.".into(),
        )
    }
}
type ApiResult<T> = std::result::Result<T, Error>;
pub fn hash_password(password: &str) -> Result<String> {
    ensure!(
        (12..=128).contains(&password.len()),
        "password must be 12..128 bytes"
    );
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
        .map_err(|e| anyhow::anyhow!(e.to_string()))?
        .to_string())
}
fn verify(password: &str, hash: &str) -> bool {
    PasswordHash::new(hash).ok().is_some_and(|h| {
        Argon2::default()
            .verify_password(password.as_bytes(), &h)
            .is_ok()
    })
}
pub fn random_token() -> String {
    use rand::RngCore;
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}
fn token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|p| p.trim().strip_prefix("noisefence_session="))
        .filter(|t| t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit()))
}
fn origin(app: &App, h: &HeaderMap) -> ApiResult<()> {
    if h.get(header::ORIGIN).and_then(|v| v.to_str().ok()) != Some(&app.config.web.public_origin) {
        return Err(Error(
            StatusCode::FORBIDDEN,
            "Origine de la demande refusée.".into(),
        ));
    }
    Ok(())
}
fn csrf(user: &User, h: &HeaderMap) -> ApiResult<()> {
    let supplied = h
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if supplied.len() != user.csrf.len()
        || supplied
            .bytes()
            .zip(user.csrf.bytes())
            .fold(0, |a, (x, y)| a | (x ^ y))
            != 0
    {
        return Err(Error(
            StatusCode::FORBIDDEN,
            "Session de formulaire expirée.".into(),
        ));
    }
    Ok(())
}
fn cookie(app: &App, value: &str, age: u32) -> String {
    format!(
        "noisefence_session={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={age}{}",
        if app.config.web.secure_cookies {
            "; Secure"
        } else {
            ""
        }
    )
}
async fn authenticated(app: &App, h: &HeaderMap) -> ApiResult<User> {
    let hash = token(h)
        .map(|t| message::digest(t.as_bytes()))
        .ok_or(Error(StatusCode::UNAUTHORIZED, "Connexion requise.".into()))?;
    app.store.run(move|db|{
        let user=db.query_row("SELECT u.username,u.admin,s.csrf FROM sessions s JOIN users u ON u.username=s.username WHERE s.token_hash=?1 AND s.expires>?2 AND u.disabled=0",params![hash,now()],|r|Ok((r.get::<_,String>(0)?,r.get::<_,bool>(1)?,r.get::<_,String>(2)?))).optional()?;
        let Some((username,admin,csrf))=user else{return Ok(None);};
        let mut q=db.prepare("SELECT address FROM grants WHERE username=?1 ORDER BY address")?;
        let addresses=q.query_map([&username],|r|r.get(0))?.collect::<rusqlite::Result<Vec<String>>>()?;
        Ok(Some(User{username,admin,csrf,addresses}))
    }).await?.ok_or(Error(StatusCode::UNAUTHORIZED,"Connexion requise.".into()))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Login {
    username: String,
    password: String,
}
async fn login(
    State(app): State<App>,
    h: HeaderMap,
    Json(body): Json<Login>,
) -> ApiResult<Response> {
    origin(&app, &h)?;
    if body.username.len() > 100 || body.password.len() > 128 {
        return Err(Error(
            StatusCode::UNAUTHORIZED,
            "Identifiant ou mot de passe incorrect.".into(),
        ));
    }
    {
        let mut limiter = app.limiter.lock().unwrap();
        limiter.retain(|_, (expiry, _)| *expiry > now());
        let global = limiter.entry(String::new()).or_insert((now() + 60, 0));
        global.1 += 1;
        if global.1 > 100 {
            return Err(Error(
                StatusCode::TOO_MANY_REQUESTS,
                "Trop de tentatives. Réessayez plus tard.".into(),
            ));
        }
        let attempts = limiter
            .entry(body.username.clone())
            .or_insert((now() + 600, 0));
        attempts.1 += 1;
        if attempts.1 > 10 {
            return Err(Error(
                StatusCode::TOO_MANY_REQUESTS,
                "Trop de tentatives. Réessayez plus tard.".into(),
            ));
        }
    }
    let username = body.username.clone();
    let saved = app
        .store
        .run(move |db| {
            Ok(db
                .query_row(
                    "SELECT password FROM users WHERE username=?1 AND disabled=0",
                    [username],
                    |r| r.get::<_, String>(0),
                )
                .optional()?)
        })
        .await?;
    let hash = saved.clone().unwrap_or_else(|| app.dummy_hash.to_string());
    let permit = app.hashing.clone().try_acquire_owned().map_err(|_| {
        Error(
            StatusCode::TOO_MANY_REQUESTS,
            "Réessayez dans quelques instants.".into(),
        )
    })?;
    let valid = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        verify(&body.password, &hash)
    })
    .await
    .map_err(|_| {
        Error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Connexion indisponible.".into(),
        )
    })?;
    if !valid || saved.is_none() {
        return Err(Error(
            StatusCode::UNAUTHORIZED,
            "Identifiant ou mot de passe incorrect.".into(),
        ));
    }
    let session = random_token();
    let token_hash = message::digest(session.as_bytes());
    let csrf_token = random_token();
    let username = body.username;
    let previous = token(&h).map(|t| message::digest(t.as_bytes()));
    app.store
        .run(move |db| {
            let tx = db.transaction()?;
            if let Some(hash) = previous {
                tx.execute("DELETE FROM sessions WHERE token_hash=?1", [hash])?;
            }
            tx.execute("DELETE FROM sessions WHERE username=?1", [&username])?;
            tx.execute(
                "INSERT INTO sessions(token_hash,username,csrf,expires) VALUES(?1,?2,?3,?4)",
                params![token_hash, username, csrf_token, now() + 8 * 3600],
            )?;
            tx.execute(
                "INSERT INTO audit(created,username,action,object_id) VALUES(?1,?2,'login','')",
                params![now(), username],
            )?;
            tx.commit()?;
            Ok(())
        })
        .await?;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        format!("noisefence_session={session}").parse().unwrap(),
    );
    let user = authenticated(&app, &headers).await?;
    Ok((
        [(header::SET_COOKIE, cookie(&app, &session, 8 * 3600))],
        Json(user),
    )
        .into_response())
}
async fn me(State(app): State<App>, h: HeaderMap) -> ApiResult<Json<User>> {
    Ok(Json(authenticated(&app, &h).await?))
}
async fn logout(State(app): State<App>, h: HeaderMap) -> ApiResult<Response> {
    origin(&app, &h)?;
    let user = authenticated(&app, &h).await?;
    csrf(&user, &h)?;
    let token_hash = message::digest(token(&h).unwrap().as_bytes());
    app.store
        .run(move |db| {
            db.execute("DELETE FROM sessions WHERE token_hash=?1", [token_hash])?;
            Ok(())
        })
        .await?;
    Ok((
        [(header::SET_COOKIE, cookie(&app, "", 0))],
        Json(json!({"ok":true})),
    )
        .into_response())
}
#[derive(Deserialize)]
struct Search {
    #[serde(default)]
    q: String,
    #[serde(default = "all")]
    filter: String,
    #[serde(default)]
    offset: u32,
    #[serde(default)]
    domain: String,
}
fn all() -> String {
    "all".into()
}
async fn messages(
    State(app): State<App>,
    h: HeaderMap,
    Query(q): Query<Search>,
) -> ApiResult<Json<Vec<crate::store::VisibleMail>>> {
    let user = authenticated(&app, &h).await?;
    if q.q.len() > 600
        || q.offset > 10_000_000
        || (!q.domain.is_empty() && !crate::config::valid_domain(&q.domain))
        || ![
            "all",
            "spam",
            "publicity",
            "review",
            "incomplete",
            "pending",
            "quarantined",
            "legitimate",
        ]
        .contains(&q.filter.as_str())
    {
        return Err(Error(StatusCode::BAD_REQUEST, "Recherche invalide.".into()));
    }
    Ok(Json(
        app.store
            .list_scoped(
                user.username,
                q.q,
                q.filter,
                q.offset,
                app.effective().filter.threshold,
                q.domain,
            )
            .await?,
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QuarantineRequest {
    recipient: String,
    action: crate::quarantine::Command,
}
async fn quarantine(
    State(app): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<QuarantineRequest>,
) -> ApiResult<Json<Value>> {
    origin(&app, &h)?;
    let user = authenticated(&app, &h).await?;
    csrf(&user, &h)?;
    if uuid::Uuid::parse_str(&id).is_err() || !crate::config::valid_address(&body.recipient) {
        return Err(Error(StatusCode::NOT_FOUND, "Message introuvable.".into()));
    }
    let hash = message::digest(token(&h).unwrap().as_bytes());
    match app.store.quarantine_action(user.username, hash, id, body.recipient, body.action).await? {
        crate::quarantine::Change::Done => Ok(Json(json!({"ok":true,"status":match body.action {
            crate::quarantine::Command::Release => "pending",
            crate::quarantine::Command::Delete => "discarded",
        }}))),
        crate::quarantine::Change::NotFound => Err(Error(StatusCode::NOT_FOUND, "Message introuvable.".into())),
        crate::quarantine::Change::Conflict => Err(Error(StatusCode::CONFLICT, "Ce destinataire n’est plus en quarantaine ou sa conservation a expiré. Rechargez les messages.".into())),
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Feedback {
    spam: Option<bool>,
    category: Option<crate::mailing::FeedbackCategory>,
}
async fn feedback(
    State(app): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<Feedback>,
) -> ApiResult<Json<Value>> {
    origin(&app, &h)?;
    let user = authenticated(&app, &h).await?;
    csrf(&user, &h)?;
    if uuid::Uuid::parse_str(&id).is_err() {
        return Err(Error(StatusCode::NOT_FOUND, "Message introuvable.".into()));
    }
    if let Some(category) = body.category {
        if body
            .spam
            .is_some_and(|spam| spam != (category == crate::mailing::FeedbackCategory::Spam))
        {
            return Err(Error(
                StatusCode::BAD_REQUEST,
                "Correction contradictoire.".into(),
            ));
        }
        app.store
            .feedback_category(user.username, id, category)
            .await
    } else if let Some(spam) = body.spam {
        app.store.feedback(user.username, id, spam).await
    } else {
        return Err(Error(StatusCode::BAD_REQUEST, "Catégorie requise.".into()));
    }
    .map_err(|_| Error(StatusCode::NOT_FOUND, "Message introuvable.".into()))?;
    Ok(Json(json!({"ok":true})))
}
async fn stats(
    State(app): State<App>,
    h: HeaderMap,
    Query(q): Query<Search>,
) -> ApiResult<Json<Value>> {
    let user = authenticated(&app, &h).await?;
    let username = user.username;
    if !q.domain.is_empty() && !crate::config::valid_domain(&q.domain) {
        return Err(Error(StatusCode::BAD_REQUEST, "Domaine invalide.".into()));
    }
    let config = app.effective();
    let threshold = config.filter.threshold;
    let domain = q.domain;
    let mut result=app.store.read(move|db|{let (received,flagged,pending,publicity,quarantined)=db.query_row(&format!("SELECT COUNT(DISTINCT m.id),COUNT(DISTINCT CASE WHEN COALESCE(json_extract(m.scan,'$.decision.outcome')='unwanted',json_extract(m.scan,'$.complete')=1 AND json_extract(m.scan,'$.score')>=?3) THEN m.id END),COUNT(DISTINCT CASE WHEN d.status IN ('pending','sending') THEN m.id END),COUNT(DISTINCT CASE WHEN COALESCE(json_extract(m.scan,'$.decision.outcome')='legitimate',json_extract(m.scan,'$.complete')=1 AND json_extract(m.scan,'$.score')<?3) AND {publicity} THEN m.id END),COUNT(DISTINCT CASE WHEN d.status='quarantined' THEN m.id END) FROM messages m JOIN deliveries d ON d.message_id=m.id JOIN console_access g ON g.delivery_id=d.id WHERE g.username=?1 AND (m.created>=?2 OR m.raw_present=1) AND (?4='' OR lower(substr(d.address,-length(?4)-1))='@'||lower(?4) OR lower(substr(d.destination,-length(?4)-1))='@'||lower(?4))",publicity=crate::mailing::PUBLICITY_SQL),params![username,now()-30*86400,threshold,domain],|r|Ok((r.get::<_,i64>(0)?,r.get::<_,i64>(1)?,r.get::<_,i64>(2)?,r.get::<_,i64>(3)?,r.get::<_,i64>(4)?)))?;Ok(json!({"received":received,"flagged":flagged,"pending":pending,"publicity":publicity,"quarantined":quarantined}))}).await?;
    result["mode"] = serde_json::to_value(config.filter.mode).unwrap();
    result["threshold"] = json!(threshold);
    result["decision_source"] = json!(if config
        .fusion
        .as_ref()
        .is_some_and(|f| f.mode == crate::fusion::runtime::Mode::Decision)
    {
        "fusion"
    } else {
        "legacy"
    });
    Ok(Json(result))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswordChange {
    current_password: String,
    new_password: String,
}
async fn password(
    State(app): State<App>,
    h: HeaderMap,
    Json(body): Json<PasswordChange>,
) -> ApiResult<Json<Value>> {
    origin(&app, &h)?;
    let user = authenticated(&app, &h).await?;
    csrf(&user, &h)?;
    if body.current_password.len() > 128 || !(12..=128).contains(&body.new_password.len()) {
        return Err(Error(
            StatusCode::BAD_REQUEST,
            "Le nouveau mot de passe doit contenir 12 à 128 octets.".into(),
        ));
    }
    let name = user.username.clone();
    let old = app
        .store
        .run(move |db| {
            Ok(db.query_row(
                "SELECT password FROM users WHERE username=?1",
                [name],
                |r| r.get::<_, String>(0),
            )?)
        })
        .await?;
    let permit = app.hashing.clone().try_acquire_owned().map_err(|_| {
        Error(
            StatusCode::TOO_MANY_REQUESTS,
            "Réessayez dans quelques instants.".into(),
        )
    })?;
    let hash = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        ensure!(verify(&body.current_password, &old), "wrong password");
        hash_password(&body.new_password)
    })
    .await
    .map_err(|_| {
        Error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Service indisponible.".into(),
        )
    })?
    .map_err(|_| {
        Error(
            StatusCode::BAD_REQUEST,
            "Mot de passe actuel incorrect.".into(),
        )
    })?;
    app.store
        .run(move |db| {
            let tx = db.transaction()?;
            tx.execute(
                "UPDATE users SET password=?2 WHERE username=?1",
                params![user.username, hash],
            )?;
            tx.execute("DELETE FROM sessions WHERE username=?1", [user.username])?;
            tx.commit()?;
            Ok(())
        })
        .await?;
    Ok(Json(json!({"ok":true})))
}
async fn health() -> Json<Value> {
    Json(json!({"status":"ok"}))
}
async fn metrics(State(app): State<App>, h: HeaderMap) -> ApiResult<Json<Value>> {
    let user = authenticated(&app, &h).await?;
    if !user.admin {
        return Err(Error(
            StatusCode::FORBIDDEN,
            "Accès administrateur requis.".into(),
        ));
    }
    let mut result=app.store.read(|db|{let (queued,failed,oldest)=db.query_row("SELECT SUM(status IN ('pending','sending')),SUM(status='failed'),MIN(CASE WHEN status IN ('pending','sending') THEN COALESCE(p.released_at,m.created) END) FROM deliveries d JOIN messages m ON m.id=d.message_id LEFT JOIN delivery_policy p ON p.delivery_id=d.id",[],|r|Ok((r.get::<_,Option<i64>>(0)?.unwrap_or(0),r.get::<_,Option<i64>>(1)?.unwrap_or(0),r.get::<_,Option<i64>>(2)?)))?;let (count,incomplete,p95)=db.query_row("SELECT COUNT(*),COALESCE(SUM(json_extract(scan,'$.complete')=0),0),COALESCE(MAX(json_extract(scan,'$.elapsed_ms')),0) FROM messages WHERE created>?1",[now()-3600],|r|Ok((r.get::<_,i64>(0)?,r.get::<_,i64>(1)?,r.get::<_,i64>(2)?)))?;Ok(json!({"queued_deliveries":queued,"unnotified_failures":failed,"oldest_pending_age_seconds":oldest.map(|t|now()-t),"received_last_hour":count,"incomplete_last_hour":incomplete,"max_analysis_ms_last_hour":p95}))}).await?;
    result["quarantined_deliveries"] = json!(
        app.store
            .read(|db| Ok(db.query_row(
                "SELECT COUNT(*) FROM deliveries WHERE status='quarantined'",
                [],
                |r| r.get::<_, i64>(0)
            )?))
            .await?
    );
    result["disk_available_bytes"] = json!(crate::store::available_bytes(&app.store.root)?);
    if let Some(config) = &app.effective().llm {
        let path = app.store.root.join("llm-budget.sqlite3");
        let mut usage = tokio::task::spawn_blocking(move || -> anyhow::Result<Value> {
            if path.exists() {
                crate::llm::Budget::open(&path)?.current()
            } else {
                Ok(json!({"accounted_micro_eur":0,"requests":0}))
            }
        })
        .await
        .map_err(anyhow::Error::from)??;
        usage["monthly_budget_micro_eur"] = json!(config.monthly_budget_micro_eur);
        usage["model"] = json!(config.model);
        usage["pricing_checked_at"] = json!(config.pricing_checked_at);
        result["llm_budget"] = usage;
    }
    Ok(Json(result))
}
async fn security_headers(req: Request, next: Next) -> Response {
    let mut response = next.run(req).await;
    let h = response.headers_mut();
    h.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    h.insert("x-content-type-options", "nosniff".parse().unwrap());
    h.insert("referrer-policy", "no-referrer".parse().unwrap());
    h.insert("x-frame-options", "DENY".parse().unwrap());
    h.insert("content-security-policy","default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'".parse().unwrap());
    response
}
impl App {
    fn effective(&self) -> Arc<Config> {
        self.control
            .as_ref()
            .map(|c| c.snapshot().config.clone())
            .unwrap_or_else(|| self.config.clone())
    }
}
pub fn router(config: Arc<Config>, store: Store) -> Result<Router> {
    router_controlled(config, store, None)
}
pub fn router_controlled(
    config: Arc<Config>,
    store: Store,
    control: Option<Arc<crate::control::Controller>>,
) -> Result<Router> {
    let app = App {
        config: config.clone(),
        store,
        control,
        limiter: Arc::new(Mutex::new(HashMap::new())),
        hashing: Arc::new(tokio::sync::Semaphore::new(4)),
        dummy_hash: Arc::new(hash_password(&random_token())?),
    };
    let api = Router::new()
        .route("/login", post(login))
        .route("/logout", post(logout))
        .route("/me", get(me))
        .route("/messages", get(messages))
        .route("/messages/{id}/feedback", post(feedback))
        .route("/messages/{id}/quarantine", post(quarantine))
        .route("/stats", get(stats))
        .route("/password", post(password))
        .route("/metrics", get(metrics))
        .merge(admin::routes());
    Ok(Router::new()
        .nest("/api/v1", api)
        .route("/healthz", get(health))
        .fallback_service(
            ServeDir::new(&config.web.static_dir).append_index_html_on_directories(true),
        )
        .layer(DefaultBodyLimit::max(128 * 1024))
        .layer(middleware::from_fn(security_headers))
        .with_state(app))
}
pub async fn create_user(
    store: &Store,
    username: String,
    password: String,
    addresses: Vec<String>,
    admin: bool,
) -> Result<()> {
    ensure!(
        !username.is_empty()
            && username.len() <= 100
            && username
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "._-@".contains(c)),
        "invalid username"
    );
    let hash = tokio::task::spawn_blocking(move || hash_password(&password)).await??;
    store
        .run(move |db| {
            let tx = db.transaction()?;
            tx.execute(
                "INSERT INTO users(username,password,admin) VALUES(?1,?2,?3)",
                params![username, hash, admin],
            )?;
            for address in addresses {
                tx.execute(
                    "INSERT INTO grants(username,address) VALUES(?1,?2)",
                    params![username, address],
                )?;
            }
            tx.commit()?;
            Ok(())
        })
        .await
}
pub async fn serve(
    listener: tokio::net::TcpListener,
    config: Arc<Config>,
    store: Store,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    serve_controlled(listener, config, store, None, shutdown).await
}
pub async fn serve_controlled(
    listener: tokio::net::TcpListener,
    config: Arc<Config>,
    store: Store,
    control: Option<Arc<crate::control::Controller>>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    axum::serve(listener, router_controlled(config, store, control)?)
        .with_graceful_shutdown(async move {
            let _ = shutdown.changed().await;
            tokio::time::sleep(Duration::from_millis(10)).await;
        })
        .await?;
    Ok(())
}
