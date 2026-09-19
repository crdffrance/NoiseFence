use super::*;
use crate::quality::evaluation;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Sample {
    since: i64,
    until: i64,
    count: usize,
    #[serde(default)]
    domain: String,
    #[serde(default)]
    purpose: evaluation::Purpose,
    #[serde(default)]
    cohort: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Label {
    risk: evaluation::Risk,
    kind: Option<crate::quality::Kind>,
}
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Page {
    offset: usize,
}
async fn list(State(app): State<App>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let user = authenticated(&app, &headers).await?;
    let cohorts = crate::quality::workflow::cohorts(&app.store, user.username.clone()).await?;
    let start = evaluation::observation_start(&app.store, user.username.clone()).await?;
    Ok(Json(
        json!({"cohorts":cohorts,"batches":evaluation::batches(&app.store,user.username).await?,
        "observation_start":start,"observation_only":true,"candidate_configured":app.effective().quality.as_ref().is_some_and(|q|q.candidate.is_some())}),
    ))
}
async fn create(
    State(app): State<App>,
    headers: HeaderMap,
    Json(body): Json<Sample>,
) -> ApiResult<Json<Value>> {
    origin(&app, &headers)?;
    let user = authenticated(&app, &headers).await?;
    csrf(&user, &headers)?;
    let maximum = if user.admin { 5000 } else { 200 };
    if !(1..=maximum).contains(&body.count) {
        return Err(Error(
            StatusCode::BAD_REQUEST,
            format!("Choose from 1 to {maximum} messages."),
        ));
    }
    let id = evaluation::sample_with_purpose(
        &app.store,
        user.username,
        body.since,
        body.until,
        body.count,
        body.domain,
        body.purpose,
        body.cohort,
    )
    .await
    .map_err(|_| {
        Error(
            StatusCode::BAD_REQUEST,
            "Sample not available: check the period, domain, number and messages available.".into(),
        )
    })?;
    Ok(Json(json!({"id":id})))
}
async fn members(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(page): Query<Page>,
) -> ApiResult<Json<Vec<Value>>> {
    let user = authenticated(&app, &headers).await?;
    Ok(Json(
        evaluation::members_page(&app.store, user.username, id, page.offset)
            .await
            .map_err(|_| Error(StatusCode::NOT_FOUND, "Sample not found.".into()))?,
    ))
}
async fn label(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<Label>,
) -> ApiResult<Json<Value>> {
    origin(&app, &headers)?;
    let user = authenticated(&app, &headers).await?;
    csrf(&user, &headers)?;
    evaluation::label(&app.store, user.username, id, body.risk, body.kind)
        .await
        .map_err(|_| Error(StatusCode::NOT_FOUND, "Message not found.".into()))?;
    Ok(Json(json!({"ok":true})))
}
async fn readiness(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let user = authenticated(&app, &headers).await?;
    Ok(Json(
        evaluation::readiness(&app.store, user.username, id)
            .await
            .map_err(|_| Error(StatusCode::NOT_FOUND, "Sample not found.".into()))?,
    ))
}
async fn reliability(
    State(app): State<App>,
    headers: HeaderMap,
    Query(options): Query<crate::reliability::Options>,
) -> ApiResult<Json<Value>> {
    let user = authenticated(&app, &headers).await?;
    options
        .validate()
        .map_err(|_| Error(StatusCode::BAD_REQUEST, "Invalid period or domain.".into()))?;
    let mut report = crate::reliability::audit(&app.store, user.username, options).await?;
    if user.admin {
        let config = app.effective();
        let (antivirus, signatures) = tokio::join!(
            crate::reliability::health::check(config.antivirus.as_ref()),
            crate::reliability::health::check(config.signatures.as_ref())
        );
        report["system"] = json!({"antivirus":antivirus,"signatures":signatures,"proton":crate::reliability::proton::checklist(&config),
            "quality_candidate_configured":config.quality.as_ref().is_some_and(|q|q.candidate.is_some()),
            "native_bayes_configured":config.native_filter.as_ref().is_some_and(|n|n.bayes_model.is_some())});
    }
    Ok(Json(report))
}
async fn jobs(State(app): State<App>, h: HeaderMap) -> ApiResult<Json<Value>> {
    let user = super::admin::administrator(&app, &h, false).await?;
    let mut value = crate::quality::workflow::list(&app.store, user.username).await?;
    if let Some(control) = &app.control {
        let snapshot = control.snapshot();
        value["revision"] = json!(snapshot.revision);
        value["selection"] = json!(snapshot.settings.quality_candidate);
    }
    Ok(Json(value))
}
async fn enqueue(
    State(app): State<App>,
    h: HeaderMap,
    Json(body): Json<crate::quality::workflow::Request>,
) -> ApiResult<Json<Value>> {
    let user = super::admin::administrator(&app, &h, true).await?;
    if crate::cluster::is_worker(&app.config) {
        return Err(Error(
            StatusCode::CONFLICT,
            "Use the coordinator console.".into(),
        ));
    }
    let id = crate::quality::workflow::enqueue(&app.store, user.username, body)
        .await
        .map_err(|e| Error(StatusCode::BAD_REQUEST, e.to_string()))?;
    Ok(Json(json!({"id":id})))
}
async fn cancel(
    State(app): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let user = super::admin::administrator(&app, &h, true).await?;
    crate::quality::workflow::cancel(&app.store, user.username, id)
        .await
        .map_err(|_| {
            Error(
                StatusCode::CONFLICT,
                "Only your queued jobs can be cancelled.".into(),
            )
        })?;
    Ok(Json(json!({"ok":true})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Select {
    revision: i64,
    job: Option<String>,
}
async fn select(
    State(app): State<App>,
    h: HeaderMap,
    Json(body): Json<Select>,
) -> ApiResult<Json<Value>> {
    let user = super::admin::administrator(&app, &h, true).await?;
    let control = app.control.clone().ok_or(Error(
        StatusCode::SERVICE_UNAVAILABLE,
        "Configuration is unavailable.".into(),
    ))?;
    let selection = if let Some(id) = body.job {
        crate::quality::workflow::candidate(
            &app.store,
            &app.config.data_dir,
            user.username.clone(),
            id,
        )
        .await
        .map_err(|_| {
            Error(
                StatusCode::BAD_REQUEST,
                "Candidate unavailable, expired or changed.".into(),
            )
        })?
    } else {
        crate::quality::workflow::Selection::default()
    };
    if let Some(path) = selection.path(&app.config.data_dir)? {
        let model = crate::quality::Model::load(&path)?;
        if model.artifacts_sha256 != control.snapshot().engine.quality_artifacts_sha256() {
            return Err(Error(StatusCode::CONFLICT,"Candidate belongs to a different detector cohort. Train on the current configuration before observing it.".into()));
        }
    }
    let mut settings = control.snapshot().settings.clone();
    settings.quality_candidate = Some(selection);
    let revision=control.apply_session(body.revision,settings,user.username,message::digest(token(&h).unwrap_or("").as_bytes())).await.map_err(|_|Error(StatusCode::CONFLICT,"Unable to activate shadow candidate. Refresh the configuration and check compatibility.".into()))?;
    Ok(Json(json!({"revision":revision,"observation_only":true})))
}
async fn release_readiness(
    State(app): State<App>,
    h: HeaderMap,
) -> ApiResult<Json<crate::quality::qualification::Readiness>> {
    let user = authenticated(&app, &h).await?;
    let current = if let Some(control) = &app.control {
        control.snapshot().engine.quality_artifacts_sha256()
    } else {
        String::new()
    };
    Ok(Json(
        crate::quality::qualification::inspect(&app.store, user.username, current).await?,
    ))
}

pub(super) fn routes() -> Router<App> {
    Router::new()
        .route("/quality/jobs", get(jobs).post(enqueue))
        .route("/quality/jobs/{id}/cancel", post(cancel))
        .route("/quality/candidate", post(select))
        .route("/quality/reliability", get(reliability))
        .route("/quality/release-readiness", get(release_readiness))
        .route("/quality/samples", get(list).post(create))
        .route("/quality/samples/{id}", get(members))
        .route("/quality/samples/{id}/readiness", get(readiness))
        .route("/messages/{id}/quality-label", post(label))
}
