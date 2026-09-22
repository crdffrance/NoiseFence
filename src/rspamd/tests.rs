use super::*;
use axum::{Router, body::Bytes, http::HeaderMap, routing::post};
use serde_json::json;
use std::sync::Mutex;

const MAIL: &[u8] = b"From: sender@example.org\r\nTo: alice@example.test\r\nSubject: Original\r\n\r\nOriginal body.\r\n";
const ANSWER: &str = r#"{"score":7.25,"required_score":6,"action":"add header","symbols":{"TEST_RULE":{"score":8,"options":["hidden@example.test","https://private.invalid/"]},"GOOD":{"score":-0.75}},"emails":["hidden@example.test"],"subject":"rewritten","milter":{"remove_headers":{"Subject":0}}}"#;

fn settings() -> Settings {
    Settings {
        enabled: true,
        ..Default::default()
    }
}
fn recipients() -> Vec<crate::config::Recipient> {
    ["alice@example.test", "hidden@example.test"]
        .map(|a| crate::config::Recipient {
            address: a.into(),
            destination: a.into(),
            hosts: vec!["127.0.0.1".into()],
        })
        .to_vec()
}
fn begin(runtime: &Arc<Runtime>, store: &Store, id: &str) -> Ticket {
    runtime
        .begin(
            MAIL,
            Envelope {
                ip: "203.0.113.7".parse().unwrap(),
                helo: "sender.example.org",
                sender: "sender@example.org",
                recipients: &recipients(),
                id,
            },
            store.clone(),
        )
        .unwrap()
}
fn report() -> Report {
    Report {
        status: Status::Complete,
        job_id: "job".into(),
        started_at: crate::now(),
        expires_at: crate::now() + 600,
        raw_sha256: crate::message::digest(MAIL),
        profile: "test".into(),
        settings_sha256: "a".repeat(64),
        server: None,
        elapsed_ms: 2,
        score: Some(7.25),
        required_score: Some(6.),
        action: Some("add header".into()),
        symbols: vec![],
        noisefence_outcome: Some(Outcome::Legitimate),
        comparison: Comparison::Inconclusive,
    }
}
async fn stored(store: &Store, id: &str) -> serde_json::Value {
    let id = id.to_string();
    store
        .read(move |db| {
            let text: String =
                db.query_row("SELECT scan FROM messages WHERE id=?1", [id], |r| r.get(0))?;
            Ok(serde_json::from_str(&text)?)
        })
        .await
        .unwrap()
}
async fn until(mut f: impl AsyncFnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(3), async {
        while !f().await {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

#[test]
fn protocol_keeps_negative_points_and_never_exposes_options_or_rewrites() {
    let parsed = parse(ANSWER.as_bytes(), None).unwrap();
    assert_eq!(parsed.symbols[1].score, -0.75);
    assert_eq!(parsed.score, Some(7.25));
    let early=parse(br#"{"is_skipped":true,"score":15,"required_score":15,"action":"reject","symbols":{"GTUBE":{"score":15}}}"#,None).unwrap();
    assert!(early.skipped);
    assert_eq!(early.score, Some(15.));
    assert_eq!(early.symbols[0].name, "GTUBE");
    assert!(
        !serde_json::to_string(&parsed.symbols)
            .unwrap()
            .contains("hidden")
    );
    for body in [
        r#"{}"#,
        r#"{"score":0,"required_score":0,"action":"no action","symbols":{}}"#,
        r#"{"score":1e999,"required_score":6,"action":"reject","symbols":{}}"#,
        r#"{"score":1,"required_score":6,"action":"reject\r\ninjected","symbols":{}}"#,
        r#"{"score":1,"required_score":6,"action":"reject","symbols":{"user@example.test":{"score":1}}}"#,
    ] {
        assert!(parse(body.as_bytes(), None).is_err(), "{body}");
    }
    assert!(parse(br#"{"is_skipped":true}"#, None).unwrap().skipped);
    let clean = parse(
        br#"{"score":-3.2,"required_score":6,"action":"no action","symbols":{}}"#,
        None,
    )
    .unwrap();
    assert_eq!(clean.score, Some(-3.2));
}

#[test]
fn comparison_uses_decisions_not_threshold_guesses_and_missing_is_not_clean() {
    let mut r = report();
    assert_eq!(r.compare(), Comparison::Disagreement);
    r.noisefence_outcome = Some(Outcome::Unwanted);
    assert_eq!(r.compare(), Comparison::Agreement);
    for outcome in [None, Some(Outcome::Undetermined)] {
        r.noisefence_outcome = outcome;
        assert_eq!(r.compare(), Comparison::Inconclusive);
    }
    r.noisefence_outcome = Some(Outcome::Unwanted);
    for action in ["greylist", "soft reject", "custom_action"] {
        r.action = Some(action.into());
        assert_eq!(r.compare(), Comparison::Inconclusive);
    }
    r.action = Some("reject".into());
    r.status = Status::Timeout;
    assert_eq!(r.compare(), Comparison::Inconclusive);
    r.status = Status::Pending;
    r.expires_at = 0;
    assert_eq!(r.visible().status, Status::Interrupted);
}

#[test]
fn endpoint_memory_limits_and_web_privileges_are_validated() {
    let mut s = settings();
    s.endpoint = "192.0.2.1:11333".parse().unwrap();
    assert!(s.validate().is_err());
    s = settings();
    s.queue_capacity = 32;
    s.max_bytes = 8 * 1024 * 1024;
    assert!(s.validate().is_err());
    let mut cfg: crate::config::Config =
        toml::from_str(include_str!("../../config/development.toml")).unwrap();
    cfg.rspamd = Some(settings());
    let hash = crate::quality::policy_hash(&cfg);
    let mut without = cfg.clone();
    without.rspamd = None;
    assert_eq!(hash, crate::quality::policy_hash(&without));
    let before = crate::control::Settings::from_config(&without);
    let mut hydrated = before.clone();
    hydrated.hydrate(&cfg);
    assert!(
        hydrated
            .detection
            .as_ref()
            .unwrap()
            .modules
            .contains_key("rspamd")
    );
    let mut patch = crate::management::Detection::from_config(&cfg);
    assert!(
        !patch.modules["rspamd"]
            .as_object()
            .unwrap()
            .contains_key("endpoint")
    );
    patch.modules.get_mut("rspamd").unwrap()["endpoint"] = json!("127.0.0.1:22");
    assert!(patch.apply(&mut cfg).is_err());
    patch = crate::management::Detection::from_config(&cfg);
    patch.modules.get_mut("rspamd").unwrap()["sample_percent"] = json!(25);
    patch.apply(&mut cfg).unwrap();
    assert_eq!(cfg.rspamd.unwrap().sample_percent, 25);
}

#[tokio::test]
async fn asynchronous_scan_uses_original_envelope_and_only_updates_comparison_after_commit() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    let received = Arc::new(Mutex::new(None));
    let server_gate = gate.clone();
    let seen = received.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route(
                "/checkv2",
                post(move |headers: HeaderMap, raw: Bytes| {
                    let seen = seen.clone();
                    let gate = server_gate.clone();
                    async move {
                        *seen.lock().unwrap() = Some((headers, raw));
                        let _permit = gate.acquire().await.unwrap();
                        ([("Server", "rspamd/test")], ANSWER)
                    }
                }),
            ),
        )
        .await
        .unwrap();
    });
    let runtime = Arc::new(
        Runtime::new(
            Some(Settings {
                endpoint,
                ..settings()
            }),
            None,
        )
        .unwrap(),
    );
    let ticket = begin(&runtime, &store, "transaction");
    until(async || received.lock().unwrap().is_some()).await;
    {
        let seen = received.lock().unwrap();
        let (headers, raw) = seen.as_ref().unwrap();
        assert_eq!(&raw[..], MAIL);
        assert_eq!(headers["ip"], "203.0.113.7");
        assert_eq!(headers["helo"], "sender.example.org");
        assert_eq!(headers["from"], "sender@example.org");
        assert_eq!(headers.get_all("rcpt").iter().count(), 2);
        assert_eq!(headers["queue-id"], "transaction");
    }
    let mut scan = crate::engine::extract(MAIL, 10000);
    scan.score = 12.3;
    scan.complete = true;
    scan.decision = Some(crate::fusion::runtime::Decision::legacy(&scan, 95.));
    let mut initial = ticket.report.clone();
    initial.bind(&scan);
    scan.rspamd = Some(initial);
    let variants = ["one", "two"]
        .map(|id| crate::store::QueueVariant {
            id: id.into(),
            scan: scan.clone(),
            raw: MAIL.to_vec().into(),
            recipients: vec![(recipients()[0].clone(), None)],
        })
        .to_vec();
    // This completes while Rspamd has not returned a single response byte.
    tokio::time::timeout(
        Duration::from_secs(2),
        store.enqueue_variants("sender@example.org".into(), variants),
    )
    .await
    .unwrap()
    .unwrap();
    ticket.commit(vec!["one".into(), "two".into()]);
    let before = stored(&store, "one").await;
    assert_eq!(before["rspamd"]["status"], "pending");
    store.run(|db| { db.execute_batch("INSERT INTO cluster_state VALUES('role','worker'); INSERT INTO ha_local VALUES('one',1,1); UPDATE messages SET scan=json_set(scan,'$.future_field',123) WHERE id='one';")?; Ok(()) }).await.unwrap();
    gate.add_permits(1);
    until(async || stored(&store, "two").await["rspamd"]["status"] == "complete").await;
    let mut after = stored(&store, "one").await;
    let report = after.as_object_mut().unwrap().remove("rspamd").unwrap();
    assert_eq!(report["comparison"], "disagreement");
    assert_eq!(report["score"], 7.25);
    assert_eq!(report["server"], "rspamd/test");
    assert!(!report.to_string().contains("hidden"));
    assert!(!report.to_string().contains("milter"));
    assert_eq!(
        after.as_object_mut().unwrap().remove("future_field"),
        Some(json!(123))
    );
    let mut before = before;
    before.as_object_mut().unwrap().remove("rspamd");
    assert_eq!(after, before);
    store
        .read(|db| {
            assert_eq!(
                db.query_row(
                    "SELECT generation FROM ha_local WHERE message_id='one'",
                    [],
                    |r| r.get::<_, i64>(0)
                )?,
                3
            );
            assert!(
                db.query_row(
                    "SELECT count(*) FROM cluster_dirty WHERE message_id='one'",
                    [],
                    |r| r.get::<_, i64>(0)
                )? > 0
            );
            Ok(())
        })
        .await
        .unwrap();
    server.abort();
}

#[tokio::test]
async fn bounded_admission_survives_revisions_disable_and_cancel() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let runtime = Arc::new(
        Runtime::new(
            Some(Settings {
                max_parallel: 1,
                queue_capacity: 0,
                ..settings()
            }),
            None,
        )
        .unwrap(),
    );
    let held = begin(&runtime, &store, "held");
    assert_eq!(held.report.status, Status::Pending);
    let next = Arc::new(Runtime::new(Some(settings()), Some(&runtime)).unwrap());
    assert!(Arc::ptr_eq(&runtime.memory, &next.memory));
    assert_eq!(begin(&next, &store, "busy").report.status, Status::Busy);
    let off = Runtime::new(None, Some(&next)).unwrap();
    off.activate();
    assert_eq!(begin(&next, &store, "off").report.status, Status::Busy);
    drop(held);
    runtime.outstanding.set_limit(1);
    until(async || runtime.outstanding.available_permits() == 1).await;
    let sampling = Arc::new(
        Runtime::new(
            Some(Settings {
                sample_percent: 0,
                ..settings()
            }),
            None,
        )
        .unwrap(),
    );
    assert_eq!(
        begin(&sampling, &store, "sample").report.status,
        Status::NotSampled
    );
    let small = Arc::new(
        Runtime::new(
            Some(Settings {
                max_bytes: 1024,
                ..settings()
            }),
            None,
        )
        .unwrap(),
    );
    let big = small
        .begin(
            &vec![b'a'; 1025],
            Envelope {
                ip: "127.0.0.1".parse().unwrap(),
                helo: "localhost",
                sender: "",
                recipients: &[],
                id: "big",
            },
            store,
        )
        .unwrap();
    assert_eq!(big.report.status, Status::Oversize);
}

#[tokio::test]
async fn failures_remain_explicit_without_replacing_native_results() {
    for (kind, expected) in [
        ("timeout", Status::Timeout),
        ("invalid", Status::InvalidResponse),
        ("oversize", Status::InvalidResponse),
        ("redirect", Status::Unavailable),
    ] {
        let root = tempfile::tempdir().unwrap();
        let store = Store::open(root.path()).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let followed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let exported = followed.clone();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new()
                    .route(
                        "/checkv2",
                        post(move |headers: HeaderMap| async move {
                            assert_eq!(headers["from"], "<>");
                            match kind {
                                "timeout" => {
                                    tokio::time::sleep(Duration::from_millis(400)).await;
                                    (
                                        axum::http::StatusCode::OK,
                                        HeaderMap::new(),
                                        ANSWER.to_string(),
                                    )
                                }
                                "invalid" => (
                                    axum::http::StatusCode::OK,
                                    HeaderMap::new(),
                                    "invalid JSON".into(),
                                ),
                                "oversize" => (
                                    axum::http::StatusCode::OK,
                                    HeaderMap::new(),
                                    " ".repeat(MAX_RESPONSE + 1),
                                ),
                                _ => {
                                    let mut h = HeaderMap::new();
                                    h.insert("location", "/export".parse().unwrap());
                                    (axum::http::StatusCode::TEMPORARY_REDIRECT, h, String::new())
                                }
                            }
                        }),
                    )
                    .route(
                        "/export",
                        post(move || {
                            exported.store(true, std::sync::atomic::Ordering::SeqCst);
                            async { ANSWER }
                        }),
                    ),
            )
            .await
            .unwrap();
        });
        let runtime = Arc::new(
            Runtime::new(
                Some(Settings {
                    endpoint,
                    timeout_ms: 100,
                    ..settings()
                }),
                None,
            )
            .unwrap(),
        );
        let ticket = runtime
            .begin(
                MAIL,
                Envelope {
                    ip: "203.0.113.9".parse().unwrap(),
                    helo: "sender.example.org",
                    sender: "",
                    recipients: &recipients(),
                    id: "null-sender",
                },
                store.clone(),
            )
            .unwrap();
        let mut scan = crate::engine::extract(MAIL, 10000);
        scan.score = 12.5;
        scan.complete = true;
        scan.rspamd = Some(ticket.report.clone());
        store
            .enqueue(
                "null-sender".into(),
                String::new(),
                vec![recipients()[0].clone()],
                scan,
                MAIL.to_vec(),
            )
            .await
            .unwrap();
        ticket.commit(vec!["null-sender".into()]);
        until(async || stored(&store, "null-sender").await["rspamd"]["status"] != "pending").await;
        let after = stored(&store, "null-sender").await;
        assert_eq!(
            after["rspamd"]["status"],
            serde_json::to_value(expected).unwrap()
        );
        assert!(after["rspamd"]["score"].is_null());
        assert_eq!(after["score"], 12.5);
        assert_eq!(after["complete"], true);
        assert!(!followed.load(std::sync::atomic::Ordering::SeqCst));
        server.abort();
    }
}
