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
        .route("/sender-verification/challenge", post(challenge))
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
    Ok(Json(
        json!({"id":id,"provider":s.verification.captcha_provider,"site_key":s.verification.site_key}),
    ))
}
async fn challenge(
    State(app): State<App>,
    h: HeaderMap,
    Json(proof): Json<Proof>,
) -> ApiResult<Json<Value>> {
    gate(&app, &h, &proof)?;
    let permit = CAPTCHA_CAPACITY.try_acquire().map_err(|_| {
        Error(
            StatusCode::TOO_MANY_REQUESTS,
            "Verification busy; try again shortly".into(),
        )
    })?;
    let cfg = app.effective();
    let s = crate::traffic::settings(&cfg)
        .filter(|s| s.verification.enabled && cfg.filter.mode != crate::config::Mode::Observe)
        .ok_or_else(|| unavailable(anyhow::anyhow!("disabled")))?;
    if s.verification.captcha_provider != crate::traffic::verification::CaptchaProvider::SelfHosted
    {
        return Err(unavailable(anyhow::anyhow!("not local")));
    }
    let token = proof.token.clone();
    app.store
        .read(move |db| crate::traffic::verification::authorize(db, &token, now()))
        .await
        .map_err(unavailable)?;
    let (permit, prepared) = tokio::task::spawn_blocking(move || {
        crate::traffic::verification::captcha::prepare().map(|prepared| (permit, prepared))
    })
    .await
    .map_err(anyhow::Error::from)?
    .map_err(unavailable)?;
    let result = app
        .store
        .run(move |db| {
            let _permit = permit;
            crate::traffic::verification::captcha::save(db, &proof.token, now(), prepared)
        })
        .await
        .map_err(unavailable)?;
    Ok(Json(
        serde_json::to_value(result).map_err(anyhow::Error::from)?,
    ))
}
async fn confirm(
    State(app): State<App>,
    h: HeaderMap,
    Json(proof): Json<Proof>,
) -> ApiResult<Json<Value>> {
    gate(&app, &h, &proof)?;
    let permit = CAPTCHA_CAPACITY.try_acquire().map_err(|_| {
        Error(
            StatusCode::TOO_MANY_REQUESTS,
            "Verification busy; try again shortly".into(),
        )
    })?;
    let store = app.store.clone();
    let cfg = app.effective();
    // The permit follows the work, including a durable commit after HTTP cancellation.
    tokio::spawn(async move {
        let _permit = permit;
        crate::traffic::verification::confirm(&store, &cfg, proof.token, proof.captcha).await
    })
    .await
    .map_err(anyhow::Error::from)?
    .map_err(unavailable)?;
    Ok(Json(json!({"confirmed":true})))
}
pub(super) async fn page(State(app): State<App>) -> Response {
    let turnstile = crate::traffic::settings(&app.effective()).is_some_and(|s| {
        s.verification.captcha_provider == crate::traffic::verification::CaptchaProvider::Turnstile
    });
    let mut response =
        axum::response::Html(include_str!("sender_verification.html")).into_response();
    let policy = if turnstile {
        "default-src 'none'; script-src 'self' https://challenges.cloudflare.com; style-src 'unsafe-inline'; img-src data:; frame-src https://challenges.cloudflare.com; connect-src 'self' https://challenges.cloudflare.com; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
    } else {
        "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; img-src data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
    };
    response
        .headers_mut()
        .insert("content-security-policy", policy.parse().unwrap());
    response
}

pub(super) async fn script() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("sender_verification.js"),
    )
}
