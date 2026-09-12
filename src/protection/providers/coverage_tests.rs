use super::*;
use serde_json::json;

fn unknown(url: &str) -> serde_json::Value {
    json!({"url":url,"error":false,"in_database":false})
}
#[test]
fn batches_bind_every_response_once_and_reject_foreign_or_duplicate_targets() {
    let names = vec!["first.example.com".into(), "second.example.com".into()];
    let a = unknown("https://first.example.com/");
    let b = unknown("https://second.example.com/");
    assert_eq!(
        parse_crdf_batch(&json!({"error":false,"data":[b,a]}), &names).unwrap(),
        vec![Verdict::Unknown; 2]
    );
    for entries in [
        json!([a]),
        json!([a, a]),
        json!([a, unknown("https://foreign.example.org/")]),
        json!([a, b, unknown("https://extra.example.org/")]),
    ] {
        assert!(parse_crdf_batch(&json!({"error":false,"data":entries}), &names).is_err());
    }
}
#[test]
fn retry_after_is_bounded_and_accepts_http_dates_without_raw_headers() {
    use reqwest::header::{HeaderMap, HeaderValue, RETRY_AFTER};
    let mut headers = HeaderMap::new();
    headers.insert(RETRY_AFTER, HeaderValue::from_static("720"));
    assert_eq!(retry_after(&headers), Some(720));
    headers.insert(
        RETRY_AFTER,
        HeaderValue::from_static("18446744073709551615"),
    );
    assert_eq!(retry_after(&headers), Some(7 * 86400));
    let date = httpdate::fmt_http_date(std::time::SystemTime::now() + Duration::from_secs(100));
    headers.insert(RETRY_AFTER, HeaderValue::from_str(&date).unwrap());
    assert!((99..=101).contains(&retry_after(&headers).unwrap()));
    headers.append(RETRY_AFTER, HeaderValue::from_static("20"));
    assert_eq!(retry_after(&headers), None);
}
#[tokio::test]
async fn cached_detection_survives_quota_cooldown_and_busy_transport() {
    let root = tempfile::tempdir().unwrap();
    let config = Settings {
        max_parallel: 1,
        crdf_per_minute: 1,
        crdf_per_day: 1,
        ..Default::default()
    };
    let client = Client::new(&config, root.path()).unwrap();
    let key = "synthetic-key-for-coverage-1234";
    save_key(root.path(), Provider::Crdf, key).unwrap();
    let credential = credential_id(Provider::Crdf, key);
    client
        .reserve(
            Provider::Crdf,
            "previous".into(),
            credential.clone(),
            Quota { minute: 1, day: 1 },
        )
        .await
        .unwrap();
    client
        .remember(
            target_key(Provider::Crdf, &credential, "z.example.org", false),
            credential.clone(),
            Some(Verdict::Malicious),
            true,
        )
        .await
        .unwrap();
    let mut targets = Targets::default();
    targets
        .domains
        .extend(["a.example.org".into(), "z.example.org".into()]);
    let (report, hits) = client
        .inspect(Provider::Crdf, true, &targets, &Policy::default())
        .await;
    assert_eq!(report.status, Status::Quota);
    assert_eq!(report.checked, 1);
    assert_eq!(report.cache_hits, 1);
    assert_eq!(report.omitted, 1);
    assert_eq!(hits, vec![("z.example.org".into(), false)]);
    assert_eq!(report.request_count, 0);
    let _occupied = client.gate.acquire().await.unwrap();
    let (report, hits) = client
        .inspect(Provider::Crdf, true, &targets, &Policy::default())
        .await;
    assert_eq!(report.status, Status::Busy);
    assert_eq!(report.checked, 1);
    assert_eq!(hits.len(), 1);
}
#[tokio::test]
async fn queued_requests_do_not_consume_quota_when_cancelled() {
    let root = tempfile::tempdir().unwrap();
    let config = Settings {
        timeout_ms: 100,
        max_parallel: 1,
        ..Default::default()
    };
    let client = Client::new(&config, root.path()).unwrap();
    save_key(root.path(), Provider::Crdf, "synthetic-key-for-queue-1234").unwrap();
    let _occupied = client.requests.acquire().await.unwrap();
    let mut targets = Targets::default();
    targets.domains.insert("example.org".into());
    let (report, _) = client
        .inspect(Provider::Crdf, true, &targets, &Policy::default())
        .await;
    assert_eq!(report.failure, Some(Failure::Timeout));
    assert_eq!(report.request_count, 0);
    assert_eq!(
        quota_usage(root.path(), Provider::Crdf).unwrap().day_used,
        0
    );
}
#[tokio::test]
async fn a_transient_error_has_one_budgeted_retry_and_preserves_transport_diagnostics() {
    let requests = Arc::new(AtomicUsize::new(0));
    let calls = requests.clone();
    let app=axum::Router::new().fallback(axum::routing::post(move|axum::Json(input):axum::Json<serde_json::Value>|{
        let n=calls.fetch_add(1,Ordering::SeqCst);
        async move {if n==0 {(axum::http::StatusCode::SERVICE_UNAVAILABLE,axum::Json(json!({})))} else {
            (axum::http::StatusCode::OK,axum::Json(json!({"error":false,"data":input["urls"].as_array().unwrap().iter().map(|s|unknown(s.as_str().unwrap())).collect::<Vec<_>>()})))
        }}
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/lookup", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let root = tempfile::tempdir().unwrap();
    let config = Settings {
        timeout_ms: 2000,
        crdf_per_minute: 2,
        crdf_per_day: 2,
        ..Default::default()
    };
    let mut client = Client::new(&config, root.path()).unwrap();
    client.endpoint_override = Some(endpoint);
    save_key(root.path(), Provider::Crdf, "synthetic-key-for-retry-1234").unwrap();
    let mut targets = Targets::default();
    targets
        .domains
        .extend(["a.example.org".into(), "b.example.org".into()]);
    let (report, hits) = client
        .inspect(Provider::Crdf, true, &targets, &Policy::default())
        .await;
    assert_eq!(report.status, Status::Complete);
    assert_eq!(report.checked, 2);
    assert!(hits.is_empty());
    assert_eq!(report.request_count, 2);
    assert_eq!(report.http_status_counts.get(&503), Some(&1));
    assert_eq!(report.failure_counts.get("http"), Some(&1));
    assert_eq!(
        quota_usage(root.path(), Provider::Crdf).unwrap().day_used,
        2
    );
    let (cached, _) = client
        .inspect(Provider::Crdf, true, &targets, &Policy::default())
        .await;
    assert_eq!(cached.cache_hits, 2);
    assert_eq!(cached.request_count, 0);
    assert_eq!(requests.load(Ordering::SeqCst), 2);
    server.abort();
}
#[tokio::test]
async fn a_provider_retry_after_survives_restart_without_automatic_resubmission() {
    let app = axum::Router::new().fallback(axum::routing::any(|| async {
        (
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            [("retry-after", "720")],
            "{}",
        )
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/lookup", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let root = tempfile::tempdir().unwrap();
    let config = Settings::default();
    let mut client = Client::new(&config, root.path()).unwrap();
    client.endpoint_override = Some(endpoint);
    save_key(
        root.path(),
        Provider::Crdf,
        "synthetic-key-for-backoff-1234",
    )
    .unwrap();
    let mut targets = Targets::default();
    targets.domains.insert("example.org".into());
    let (report, _) = client
        .inspect(Provider::Crdf, true, &targets, &Policy::default())
        .await;
    assert_eq!(report.failure, Some(Failure::RateLimit));
    assert_eq!(report.retry_after_seconds, Some(720));
    assert_eq!(report.request_count, 1);
    drop(client);
    assert!(
        quota_usage(root.path(), Provider::Crdf)
            .unwrap()
            .cooldown_until
            .unwrap()
            >= crate::now() + 715
    );
    let client = Client::new(&config, root.path()).unwrap();
    let (report, _) = client
        .inspect(Provider::Crdf, true, &targets, &Policy::default())
        .await;
    assert_eq!(report.status, Status::Quota);
    assert_eq!(report.request_count, 0);
    server.abort();
}
