use super::*;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Label {
    domain: String,
    class: Option<crate::adaptive::Class>,
}
async fn get_labels(
    State(app): State<App>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let user = authenticated(&app, &headers).await?;
    Ok(Json(
        crate::adaptive::data::labels(&app.store, user.username, id)
            .await
            .map_err(|_| Error(StatusCode::NOT_FOUND, "Message introuvable.".into()))?,
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
    crate::adaptive::data::label(&app.store, user.username, id, body.domain, body.class)
        .await
        .map_err(|_| Error(StatusCode::NOT_FOUND, "Message introuvable.".into()))?;
    Ok(Json(json!({"ok":true,"observation_only":true})))
}
pub(super) fn routes() -> Router<App> {
    Router::new().route("/messages/{id}/adaptive-label", get(get_labels).post(label))
}
