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
pub(super) fn routes() -> Router<App> {
    Router::new()
        .route("/quality/samples", get(list).post(create))
        .route("/quality/samples/{id}", get(members))
        .route("/quality/samples/{id}/readiness", get(readiness))
        .route("/messages/{id}/quality-label", post(label))
}
