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
    let start = evaluation::observation_start(&app.store, user.username.clone()).await?;
    Ok(Json(
        json!({"batches":evaluation::batches(&app.store,user.username).await?,
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
    if !(1..=200).contains(&body.count) {
        return Err(Error(
            StatusCode::BAD_REQUEST,
            "Choisissez de 1 à 200 messages.".into(),
        ));
    }
    let id=evaluation::sample(&app.store,user.username,body.since,body.until,body.count,body.domain).await
        .map_err(|_|Error(StatusCode::BAD_REQUEST,"Échantillon indisponible : vérifiez la période, le domaine, le nombre et les messages accessibles.".into()))?;
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
            .map_err(|_| Error(StatusCode::NOT_FOUND, "Échantillon introuvable.".into()))?,
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
        .map_err(|_| Error(StatusCode::NOT_FOUND, "Message introuvable.".into()))?;
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
            .map_err(|_| Error(StatusCode::NOT_FOUND, "Échantillon introuvable.".into()))?,
    ))
}
async fn reliability(
    State(app): State<App>,
    headers: HeaderMap,
    Query(options): Query<crate::reliability::Options>,
) -> ApiResult<Json<Value>> {
    let user = authenticated(&app, &headers).await?;
    options.validate().map_err(|_| {
        Error(
            StatusCode::BAD_REQUEST,
            "Période ou domaine invalide.".into(),
        )
    })?;
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
pub(super) fn routes() -> Router<App> {
    Router::new()
        .route("/quality/reliability", get(reliability))
        .route("/quality/samples", get(list).post(create))
        .route("/quality/samples/{id}", get(members))
        .route("/quality/samples/{id}/readiness", get(readiness))
        .route("/messages/{id}/quality-label", post(label))
}
