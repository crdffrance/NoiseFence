use super::*;
use crate::control::identity_connections::{Collect, Save};
fn refused(_: anyhow::Error) -> Error {
    Error(StatusCode::CONFLICT,"Directory connection operation refused. Reload connection status before retrying; check the source, credential lifetime, vault and administrator session.".into())
}
async fn body<T: serde::de::DeserializeOwned>(request: Request) -> ApiResult<T> {
    let bytes = tokio::time::timeout(
        Duration::from_secs(10),
        axum::body::to_bytes(request.into_body(), 65536),
    )
    .await
    .map_err(|_| {
        Error(
            StatusCode::REQUEST_TIMEOUT,
            "Connection request timed out.".into(),
        )
    })?
    .map_err(|_| {
        Error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "Connection request exceeds 64 KiB.".into(),
        )
    })?;
    serde_json::from_slice(&bytes).map_err(|_| {
        Error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Invalid directory connection request.".into(),
        )
    })
}
pub(super) async fn list(State(app): State<App>, h: HeaderMap) -> ApiResult<Json<Value>> {
    let actor = administrator(&app, &h, false).await?;
    let _permit = super::identity::capacity(&app)?;
    let view = controller(&app)?
        .directory_connections(
            actor.username,
            message::digest(token(&h).unwrap().as_bytes()),
        )
        .await
        .map_err(refused)?;
    Ok(Json(
        serde_json::to_value(view).map_err(anyhow::Error::from)?,
    ))
}
pub(super) async fn save(
    State(app): State<App>,
    h: HeaderMap,
    request: Request,
) -> ApiResult<Json<Value>> {
    // Role, Origin, CSRF and capacity are checked before reading any secret.
    let actor = administrator(&app, &h, true).await?;
    let _permit = super::identity::capacity(&app)?;
    let input: Save = body(request).await?;
    let view = controller(&app)?
        .save_directory_connection(
            input,
            actor.username,
            message::digest(token(&h).unwrap().as_bytes()),
        )
        .await
        .map_err(refused)?;
    Ok(Json(
        serde_json::to_value(view).map_err(anyhow::Error::from)?,
    ))
}
pub(super) async fn revoke(
    State(app): State<App>,
    h: HeaderMap,
    request: Request,
) -> ApiResult<Json<Value>> {
    let actor = administrator(&app, &h, true).await?;
    let _permit = super::identity::capacity(&app)?;
    let reference: crate::identity::connections::Reference = body(request).await?;
    let view = controller(&app)?
        .revoke_directory_connection(
            reference,
            actor.username,
            message::digest(token(&h).unwrap().as_bytes()),
        )
        .await
        .map_err(refused)?;
    Ok(Json(
        serde_json::to_value(view).map_err(anyhow::Error::from)?,
    ))
}
pub(super) async fn collect(
    State(app): State<App>,
    h: HeaderMap,
    request: Request,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let actor = administrator(&app, &h, true).await?;
    let _permit = super::identity::capacity(&app)?;
    let input: Collect = body(request).await?;
    let result = controller(&app)?
        .collect_directory_connection(
            input,
            actor.username,
            message::digest(token(&h).unwrap().as_bytes()),
        )
        .await
        .map_err(refused)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({"id":result.id,"deadline":result.deadline,"state":"running"})),
    ))
}

pub(super) async fn schedule(
    State(app): State<App>,
    h: HeaderMap,
    request: Request,
) -> ApiResult<Json<Value>> {
    let actor = administrator(&app, &h, true).await?;
    let _permit = super::identity::capacity(&app)?;
    let input: crate::control::identity_schedule::Save = body(request).await?;
    let view = controller(&app)?
        .save_directory_schedule(
            input,
            actor.username,
            message::digest(token(&h).unwrap().as_bytes()),
        )
        .await
        .map_err(refused)?;
    Ok(Json(
        serde_json::to_value(view).map_err(anyhow::Error::from)?,
    ))
}
pub(super) async fn stop_schedule(
    State(app): State<App>,
    h: HeaderMap,
    request: Request,
) -> ApiResult<Json<Value>> {
    let actor = administrator(&app, &h, true).await?;
    let _permit = super::identity::capacity(&app)?;
    let input: crate::control::identity_schedule::Stop = body(request).await?;
    let view = controller(&app)?
        .stop_directory_schedule(
            input,
            actor.username,
            message::digest(token(&h).unwrap().as_bytes()),
        )
        .await
        .map_err(refused)?;
    Ok(Json(
        serde_json::to_value(view).map_err(anyhow::Error::from)?,
    ))
}

/// Uploads use the same administrator/Origin/CSRF and durable receipt boundaries
/// as live collectors. Capacity is reserved before reading or decoding bytes.
pub(super) async fn upload_ad(
    State(app): State<App>,
    h: HeaderMap,
    request: Request,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let actor = administrator(&app, &h, true).await?;
    let _permit = super::identity::capacity(&app)?;
    let bytes = tokio::time::timeout(
        Duration::from_secs(10),
        axum::body::to_bytes(
            request.into_body(),
            crate::identity::connectors::ad::MAX_ENVELOPE_BYTES + 65536,
        ),
    )
    .await
    .map_err(|_| Error(StatusCode::REQUEST_TIMEOUT, "AD upload timed out.".into()))?
    .map_err(|_| {
        Error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "AD upload exceeds 23 MiB plus request metadata.".into(),
        )
    })?;
    let input = tokio::task::spawn_blocking(move || {
        serde_json::from_slice::<crate::control::identity_connections::AdUpload>(&bytes)
    })
    .await
    .map_err(anyhow::Error::from)?
    .map_err(|_| {
        Error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Invalid signed AD export request.".into(),
        )
    })?;
    let result = controller(&app)?
        .upload_ad_directory(
            input,
            actor.username,
            message::digest(token(&h).unwrap().as_bytes()),
        )
        .await
        .map_err(refused)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({"id":result.id,"deadline":result.deadline,"state":"running"})),
    ))
}
