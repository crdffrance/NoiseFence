use super::*;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SourceQuery {
    source: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Prepare {
    revision: i64,
    catalog_sha256: Option<String>,
    edit: crate::identity::management::Edit,
}
fn capacity(app: &App) -> ApiResult<tokio::sync::OwnedSemaphorePermit> {
    app.identity_capacity
        .clone()
        .try_acquire_owned()
        .map_err(|_| {
            Error(
                StatusCode::TOO_MANY_REQUESTS,
                "Directory workspace busy; retry shortly.".into(),
            )
        })
}
pub(super) async fn view(
    State(app): State<App>,
    h: HeaderMap,
    Query(query): Query<SourceQuery>,
) -> ApiResult<Json<Value>> {
    let actor = administrator(&app, &h, false).await?;
    let _permit = capacity(&app)?;
    let control = controller(&app)?;
    let result = control
        .identity_directory(
            actor.username,
            message::digest(token(&h).unwrap().as_bytes()),
            query.source,
        )
        .await?;
    Ok(Json(
        serde_json::to_value(result).map_err(anyhow::Error::from)?,
    ))
}
pub(super) async fn prepare(
    State(app): State<App>,
    h: HeaderMap,
    request: Request,
) -> ApiResult<Json<Value>> {
    // Authenticate and reserve bounded capacity BEFORE reading a large upload.
    let actor = administrator(&app, &h, true).await?;
    let _permit = capacity(&app)?;
    let bytes = tokio::time::timeout(
        Duration::from_secs(30),
        axum::body::to_bytes(
            request.into_body(),
            crate::identity::directory::MAX_BYTES + 65536,
        ),
    )
    .await
    .map_err(|_| {
        Error(
            StatusCode::REQUEST_TIMEOUT,
            "Directory upload timed out.".into(),
        )
    })?
    .map_err(|_| {
        Error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "Directory upload exceeds 16 MiB plus request metadata.".into(),
        )
    })?;
    let body: Prepare = tokio::task::spawn_blocking(move || serde_json::from_slice(&bytes))
        .await
        .map_err(anyhow::Error::from)?
        .map_err(|_| {
            Error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Invalid directory request. Use the documented source format.".into(),
            )
        })?;
    let control = controller(&app)?;
    let current = control.snapshot();
    if body.revision != current.revision
        || body.catalog_sha256 != current.config.identity.as_ref().map(|s| s.sha256.clone())
    {
        return Err(Error(
            StatusCode::CONFLICT,
            "The directory or configuration changed. Reload before importing.".into(),
        ));
    }
    let result=control.prepare_identity_directory(body.revision,body.catalog_sha256,body.edit,actor.username,message::digest(token(&h).unwrap().as_bytes())).await.map_err(|error| {
        let detail=error.downcast_ref::<crate::identity::management::InvalidEdit>().map(ToString::to_string).unwrap_or_else(|| "Directory preparation refused. Check available storage and the current session; reload before retrying.".into());
        Error(StatusCode::UNPROCESSABLE_ENTITY,detail)
    })?;
    Ok(Json(
        serde_json::to_value(result).map_err(anyhow::Error::from)?,
    ))
}

pub(super) async fn synchronize(
    State(app): State<App>,
    h: HeaderMap,
    request: Request,
) -> ApiResult<(StatusCode, Json<Value>)> {
    synchronize_provider(app, h, request, false).await
}
pub(super) async fn synchronize_okta(
    State(app): State<App>,
    h: HeaderMap,
    request: Request,
) -> ApiResult<(StatusCode, Json<Value>)> {
    synchronize_provider(app, h, request, true).await
}
async fn synchronize_provider(
    app: App,
    h: HeaderMap,
    request: Request,
    okta: bool,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let actor = administrator(&app, &h, true).await?;
    let _permit = capacity(&app)?;
    let bytes = tokio::time::timeout(
        Duration::from_secs(10),
        axum::body::to_bytes(request.into_body(), 16384),
    )
    .await
    .map_err(|_| {
        Error(
            StatusCode::REQUEST_TIMEOUT,
            "Directory request timed out.".into(),
        )
    })?
    .map_err(|_| {
        Error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "Directory synchronization request too large.".into(),
        )
    })?;
    let invalid = || {
        Error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Invalid directory synchronization request.".into(),
        )
    };
    let control = controller(&app)?;
    let session = message::digest(token(&h).unwrap().as_bytes());
    let result = if okta {
        let body: crate::identity::sync::OktaInput = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        control.synchronize_okta(body, actor.username, session).await
    } else {
        let body: crate::identity::sync::EntraInput = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        control.synchronize_entra(body, actor.username, session).await
    }.map_err(|_|Error(StatusCode::CONFLICT,"Synchronization refused. Check the source, configured domains, credentials format, current revision and existing jobs.".into()))?;
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({"id":result.id,"deadline":result.deadline,"state":"running"})),
    ))
}
pub(super) async fn sync_status(
    State(app): State<App>,
    h: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let actor = administrator(&app, &h, false).await?;
    let _permit = capacity(&app)?;
    let result = controller(&app)?
        .identity_sync_status(
            id,
            actor.username,
            message::digest(token(&h).unwrap().as_bytes()),
        )
        .await
        .map_err(|_| {
            Error(
                StatusCode::NOT_FOUND,
                "Directory synchronization receipt unavailable.".into(),
            )
        })?;
    Ok(Json(
        serde_json::to_value(result).map_err(anyhow::Error::from)?,
    ))
}
