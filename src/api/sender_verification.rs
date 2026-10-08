//! Public capability endpoints are isolated from authenticated console sessions.
use super::*;
static CAPTCHA_CAPACITY: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(4);
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Proof {
    token: String,
    #[serde(default)]
    captcha: String,
}
pub(super) fn routes() -> Router<App> {
    Router::new()
        .route("/sender-verification/info", post(info))
        .route("/sender-verification/confirm", post(confirm))
        .layer(DefaultBodyLimit::max(4096))
}
fn gate(app: &App, h: &HeaderMap, proof: &Proof) -> ApiResult<()> {
    origin(app, h)?;
    if proof.token.len() > 128 {
        return Err(Error(
            StatusCode::BAD_REQUEST,
            "Invalid verification link".into(),
        ));
    }
    let mut limits = app.limiter.lock().unwrap();
    limits.retain(|_, (expiry, _)| *expiry > now());
    for (key, maximum) in [
        ("verification:global".into(), 120),
        (
            format!("verification:{}", message::digest(proof.token.as_bytes())),
            12,
        ),
    ] {
        let value = limits.entry(key).or_insert((now() + 60, 0));
        if value.1 >= maximum {
            return Err(Error(
                StatusCode::TOO_MANY_REQUESTS,
                "Please wait before trying again".into(),
            ));
        }
        value.1 += 1;
    }
    Ok(())
}
fn unavailable(_: anyhow::Error) -> Error {
    Error(StatusCode::UNPROCESSABLE_ENTITY,"Verification unavailable, expired, or already completed. Contact the recipient if necessary.".into())
}
async fn info(
    State(app): State<App>,
    h: HeaderMap,
    Json(proof): Json<Proof>,
) -> ApiResult<Json<Value>> {
    gate(&app, &h, &proof)?;
    let cfg = app.effective();
    let s = crate::traffic::settings(&cfg)
        .filter(|s| s.verification.enabled && cfg.filter.mode != crate::config::Mode::Observe)
        .ok_or_else(|| unavailable(anyhow::anyhow!("disabled")))?;
    let id = app
        .store
        .run(move |db| crate::traffic::verification::authorize(db, &proof.token, now()))
        .await
        .map_err(unavailable)?;
    Ok(Json(json!({"id":id,"site_key":s.verification.site_key})))
}
async fn confirm(
    State(app): State<App>,
    h: HeaderMap,
    Json(proof): Json<Proof>,
) -> ApiResult<Json<Value>> {
    gate(&app, &h, &proof)?;
    let _permit = CAPTCHA_CAPACITY.try_acquire().map_err(|_| {
        Error(
            StatusCode::TOO_MANY_REQUESTS,
            "Verification busy; try again shortly".into(),
        )
    })?;
    crate::traffic::verification::confirm(&app.store, &app.effective(), proof.token, proof.captcha)
        .await
        .map_err(unavailable)?;
    Ok(Json(json!({"confirmed":true})))
}
pub(super) async fn page() -> axum::response::Html<&'static str> {
    axum::response::Html(include_str!("sender_verification.html"))
}
