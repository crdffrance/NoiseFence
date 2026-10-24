//! Validate and explain a delegated draft without applying it or reading mail.
use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    revision: i64,
    scope: String,
    recipient: String,
    preference: Option<crate::preferences::Preference>,
}
fn authorize(user: &User, scope: &str, recipient: &str) -> ApiResult<()> {
    let within_scope = scope == recipient
        || scope.strip_prefix("*@").is_some_and(|d| {
            recipient
                .rsplit_once('@')
                .is_some_and(|(_, domain)| domain == d)
        });
    if !within_scope
        || !crate::preferences::permitted(scope, user.admin, &user.addresses)
        || !crate::preferences::permitted(recipient, user.admin, &user.addresses)
    {
        return Err(Error(
            StatusCode::FORBIDDEN,
            "Choose an authorized original recipient inside the edited scope.".into(),
        ));
    }
    Ok(())
}
pub(super) async fn preview(
    State(app): State<App>,
    h: HeaderMap,
    Json(body): Json<Request>,
) -> ApiResult<Json<Value>> {
    let user = authenticated(&app, &h).await?;
    origin(&app, &h)?;
    csrf(&user, &h)?;
    authorize(&user, &body.scope, &body.recipient)?;
    if body.recipient.starts_with("*@") || !crate::config::valid_address(&body.recipient) {
        return Err(Error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Enter one original mailbox address, not a wildcard.".into(),
        ));
    }
    let c = controller(&app)?;
    let snapshot = c.snapshot();
    if snapshot.revision != body.revision {
        return Err(Error(
            StatusCode::CONFLICT,
            "Configuration changed; reload preferences before reviewing.".into(),
        ));
    }
    let recipient = snapshot
        .config
        .recipient(&body.recipient)
        .filter(|r| r.address == body.recipient)
        .ok_or_else(|| {
            Error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "This original recipient is not accepted by the installed routing policy.".into(),
            )
        })?;
    static PREVIEW: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);
    let _permit = PREVIEW.try_acquire().map_err(|_| {
        Error(
            StatusCode::TOO_MANY_REQUESTS,
            "Another preference preview is running; retry shortly.".into(),
        )
    })?;
    crate::preferences::validate_traffic_edit(
        &snapshot.config,
        &body.scope,
        body.preference.as_ref(),
    )
    .map_err(|e| Error(StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?;
    let mut settings = snapshot.settings.clone();
    if let Some(p) = &body.preference {
        settings
            .preferences
            .mailboxes
            .insert(body.scope.clone(), p.clone());
    } else {
        settings.preferences.mailboxes.remove(&body.scope);
    }
    let proposed = c
        .effective_settings(&settings)
        .await
        .map_err(|e| Error(StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?;
    let checked_at = now();
    let result = json!({"schema":"preference-preview-1","revision":body.revision,"checked_at":checked_at,"scope":body.scope,"recipient":recipient.address,"mode":snapshot.config.filter.mode,
        "removing":body.preference.is_none(),"installed":crate::preferences::preview::inspect(&snapshot.config,&recipient,checked_at),"draft":crate::preferences::preview::inspect(&proposed,&recipient,checked_at)});
    // Revocation and a concurrent activation cannot turn a stale preview into a current one.
    let current_user = authenticated(&app, &h).await?;
    authorize(&current_user, &body.scope, &body.recipient)?;
    if c.snapshot().revision != body.revision {
        return Err(Error(
            StatusCode::CONFLICT,
            "Configuration changed during review; reload preferences.".into(),
        ));
    }
    Ok(Json(result))
}
