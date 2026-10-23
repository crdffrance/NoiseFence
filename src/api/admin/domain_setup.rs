//! Read-only domain setup checks. No settings, queue entries or DNS records are written.
use super::*;
use crate::recipient_verification::{Runtime, Settings as Verification, Verdict};

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Check {
    Configuration,
    Dns,
    Recipient,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    revision: i64,
    settings: Settings,
    domain: String,
    check: Check,
    recipient: Option<String>,
}

pub(super) async fn check(
    State(app): State<App>,
    h: HeaderMap,
    Json(mut body): Json<Request>,
) -> ApiResult<Json<Value>> {
    administrator(&app, &h, true).await?;
    let control = controller(&app)?;
    let snapshot = control.snapshot();
    if snapshot.revision != body.revision {
        return Err(Error(
            StatusCode::CONFLICT,
            "Configuration changed; reload before checking the draft.".into(),
        ));
    }
    // One bounded operation per process, including draft validation. The permit is
    // released on cancellation; the handler does not spawn background probes.
    static CHECK: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);
    let _permit = CHECK.try_acquire().map_err(|_| {
        Error(
            StatusCode::TOO_MANY_REQUESTS,
            "A domain check is already running; retry shortly.".into(),
        )
    })?;
    body.settings.hydrate(&control.base);
    let mut config = control
        .effective_settings(&body.settings)
        .await
        .map_err(|e| Error(StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?;
    if !config.domains.iter().any(|d| d.name == body.domain) {
        return Err(Error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Choose an enabled domain in this draft.".into(),
        ));
    }
    let result = match body.check {
        Check::Configuration => json!({"check":"configuration", "status":"valid"}),
        Check::Dns => {
            let result = tokio::time::timeout(
                Duration::from_secs(5),
                snapshot.engine.authenticator.mx_lookup(
                    format!("{}.", body.domain),
                    None::<
                        &mail_auth::common::cache::NoCache<
                            Box<str>,
                            mail_auth::RecordSet<mail_auth::MX>,
                        >,
                    >,
                ),
            )
            .await;
            match result {
                Ok(Ok(records)) => mx_result(
                    records
                        .rrset
                        .iter()
                        .flat_map(|mx| {
                            mx.exchanges
                                .iter()
                                .map(move |host| (mx.preference, host.to_string()))
                        })
                        .collect(),
                    &config.hostname,
                ),
                // No DNS response, including NXDOMAIN, proves neither routing nor delivery.
                _ => {
                    json!({"check":"dns", "status":"unavailable", "records":[], "local_mx_present":false, "truncated":false})
                }
            }
        }
        Check::Recipient => {
            let address = body
                .recipient
                .as_deref()
                .filter(|a| {
                    crate::config::valid_address(a)
                        && a.rsplit_once('@')
                            .is_some_and(|(_, d)| d.eq_ignore_ascii_case(&body.domain))
                })
                .ok_or_else(|| {
                    Error(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "Enter one valid recipient in the selected domain.".into(),
                    )
                })?;
            let recipient = config.recipient(address).ok_or_else(|| {
                Error(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "This recipient is not accepted by the draft routing policy.".into(),
                )
            })?;
            let (_, canonical_domain) = recipient.destination.rsplit_once('@').unwrap();
            let owner = config
                .domains
                .iter_mut()
                .find(|d| d.name.eq_ignore_ascii_case(canonical_domain))
                .ok_or_else(|| {
                    Error(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        "The canonical destination has no configured domain.".into(),
                    )
                })?;
            // A diagnostic must really probe even if ongoing verification is disabled.
            // This clone and cache are never installed in the SMTP runtime.
            owner.recipient_verification = Some(Verification {
                timeout_ms: 8000,
                positive_cache_seconds: 0,
                negative_cache_seconds: 0,
            });
            let verdict = Runtime::default().check(&config, &recipient, "").await;
            json!({"check":"recipient", "status":match verdict { Verdict::Accepted => "accepted", Verdict::Unknown => "unknown", Verdict::Unavailable => "unavailable" },
                "recipient":address, "destination":recipient.destination, "routes":recipient.hosts,
                "envelope_sender":"", "data_sent":false,
                "loopback_test_allowed":config.relay.allow_loopback_plaintext})
        }
    };
    // A concurrent configuration activation makes the result stale, even if a
    // network operation completed successfully. Never attach it to a newer draft.
    if control.snapshot().revision != body.revision {
        return Err(Error(
            StatusCode::CONFLICT,
            "Configuration changed during the check; reload and check again.".into(),
        ));
    }
    Ok(Json(
        json!({"revision":body.revision,"domain":body.domain,"hostname":config.hostname,
        "checked_at":now(),"draft":true,"result":result}),
    ))
}

fn mx_result(mut records: Vec<(u16, String)>, hostname: &str) -> Value {
    records.sort();
    records.dedup();
    let truncated = records.len() > 32;
    let null_mx = records.iter().any(|(_, h)| h == ".");
    let local_mx_present = records
        .iter()
        .any(|(_, h)| h.trim_end_matches('.').eq_ignore_ascii_case(hostname));
    let status = if null_mx {
        "null_mx"
    } else if records.is_empty() {
        "no_records"
    } else {
        "available"
    };
    json!({"check":"dns","status":status,"local_mx_present":local_mx_present,"truncated":truncated,
        "records":records.into_iter().take(32).map(|(priority,host)| json!({"priority":priority,"host":host})).collect::<Vec<_>>()})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dns_observations_preserve_priority_null_mx_and_bounded_output() {
        let result = mx_result(
            vec![
                (20, "backup.example.test.".into()),
                (10, "MX.EXAMPLE.TEST.".into()),
            ],
            "mx.example.test",
        );
        assert_eq!(result["records"][0]["priority"], 10);
        assert_eq!(result["local_mx_present"], true);
        assert_eq!(
            mx_result(vec![(0, ".".into())], "mx.example.test")["status"],
            "null_mx"
        );
        assert_eq!(mx_result(vec![], "mx.example.test")["status"], "no_records");
        let many = mx_result(
            (0..40).map(|n| (n, format!("mx{n}.test"))).collect(),
            "mx0.test",
        );
        assert_eq!(many["truncated"], true);
        assert_eq!(many["records"].as_array().unwrap().len(), 32);
    }
}
