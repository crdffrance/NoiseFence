mod common;
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use noisefence::{
    api,
    delivery_log::{Attempt, Event},
    diagnostics::AnalysisPolicy,
    engine::extract,
    store::{Job, Store},
};
use tower::ServiceExt;

fn transcript(route: &str, code: u16) -> Attempt {
    Attempt {
        route: route.into(),
        peer: Some("192.0.2.25:25".into()),
        started: noisefence::now(),
        elapsed_ms: 120,
        outcome: if code == 250 {
            "delivered"
        } else {
            "temporary"
        }
        .into(),
        truncated: false,
        events: vec![Event {
            phase: "data_result".into(),
            elapsed_ms: 120,
            code: Some(code),
            enhanced_code: Some(if code == 250 { "2.0.0" } else { "4.7.1" }.into()),
            response: Some(format!("{code} queued by {route}")),
            detail: None,
        }],
    }
}
async fn queue(store: &Store, cfg: &noisefence::config::Config) -> (String, Job, Job) {
    let id = uuid::Uuid::new_v4().to_string();
    let mut scan = extract(common::MESSAGE, 10000);
    scan.analysis_policy = Some(AnalysisPolicy::capture(cfg));
    store
        .enqueue(
            id.clone(),
            "sender@example.org".into(),
            vec![
                cfg.recipient("alice@example.test").unwrap(),
                cfg.recipient("bob@example.test").unwrap(),
            ],
            scan,
            common::MESSAGE.to_vec(),
        )
        .await
        .unwrap();
    let a = store.claim().await.unwrap().unwrap();
    let b = store.claim().await.unwrap().unwrap();
    (id, a, b)
}

#[tokio::test]
async fn diagnostics_enforce_recipient_grants_and_authentication() {
    let root = tempfile::tempdir().unwrap();
    let cfg = common::config(root.path());
    let store = Store::open(root.path()).unwrap();
    for (user, addresses, admin) in [
        ("alice", vec!["alice@example.test".into()], false),
        ("domain", vec!["*@example.test".into()], false),
        ("other", vec!["nobody@example.test".into()], false),
        ("admin", vec![], true),
    ] {
        api::create_user(
            &store,
            user.into(),
            "a long password 123".into(),
            addresses,
            admin,
        )
        .await
        .unwrap();
    }
    let (id, a, b) = queue(&store, &cfg).await;
    store
        .finish_with_attempts(
            &a,
            "delivered",
            "",
            0,
            &[transcript("mx-alice.example.org", 250)],
        )
        .await
        .unwrap();
    store
        .finish_with_attempts(
            &b,
            "pending",
            "451 4.7.1 Retry later",
            noisefence::now() + 1800,
            &[transcript("mx-bob.example.org", 451)],
        )
        .await
        .unwrap();
    let alice = serde_json::to_value(
        store
            .diagnostics("alice".into(), id.clone())
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(alice["recipients"].as_array().unwrap().len(), 1);
    assert_eq!(alice["recipients"][0]["logs"][0]["events"][0]["code"], 250);
    assert!(!alice.to_string().contains("mx-bob"));
    assert!(!alice.to_string().contains("bob@example.test"));
    assert!(!alice.to_string().contains("\"features\":"));
    assert!(!alice.to_string().contains("rendez-vous est confirme"));
    for user in ["domain", "admin"] {
        let visible = store
            .diagnostics(user.into(), id.clone())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(visible.recipients.len(), 2);
        assert!(visible.recipients[1].next_attempt > noisefence::now());
        assert!(
            visible.recipients[1]
                .last_error
                .as_ref()
                .unwrap()
                .contains("451")
        );
    }
    assert!(
        store
            .diagnostics("other".into(), id.clone())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .diagnostics_for("alice".into(), id.clone(), Some(b.delivery_id))
            .await
            .unwrap()
            .is_none()
    );
    let app = api::router(cfg.clone(), store.clone()).unwrap();
    let path = format!("/api/v1/messages/{id}/diagnostics");
    let response = app
        .clone()
        .oneshot(Request::get(&path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    for (user, expected) in [("alice", StatusCode::OK), ("other", StatusCode::NOT_FOUND)] {
        let login = app
            .clone()
            .oneshot(
                Request::post("/api/v1/login")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::ORIGIN, &cfg.web.public_origin)
                    .body(Body::from(format!(
                        r#"{{"username":"{user}","password":"a long password 123"}}"#
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        let cookie = login.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_string();
        let response = app
            .clone()
            .oneshot(
                Request::get(&path)
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(!String::from_utf8_lossy(&body).contains("mx-bob"));
    }
    store
        .run(|db| {
            db.execute("UPDATE users SET disabled=1 WHERE username='alice'", [])?;
            Ok(())
        })
        .await
        .unwrap();
    assert!(
        store
            .diagnostics("alice".into(), id)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn restricted_api_redacts_other_bcc_and_aliases_in_new_and_historical_remote_text() {
    let root = tempfile::tempdir().unwrap();
    let cfg = common::config(root.path());
    let store = Store::open(root.path()).unwrap();
    api::create_user(
        &store,
        "alice".into(),
        "a long password 123".into(),
        vec!["alice@example.test".into()],
        false,
    )
    .await
    .unwrap();
    let (id, a, b) = queue(&store, &cfg).await;
    assert_eq!(a.destination, "alice@example.test");
    assert_eq!(b.destination, "bob@example.test");

    // Bob is a Bcc recipient of the same message. Neither the unknown mailbox
    // nor the alias below belongs to the current delivery's envelope. Stored
    // historical text must be protected even though it predates relay redaction.
    let raw = concat!(
        "451 4.7.1 upstream quota for bob@example.test; ",
        "unlisted-bcc@outside.test; archive+alias@outside.test; ",
        r#""hidden \"quoted\" name"@outside.test; "#,
        r#"\"hidden \\\"escaped\\\" name\"@outside.test; "#,
        "用户@例子.公司; “hidden name”＠例子。公司; ",
        r"hidden\u0040outside.test; hidden%40outside.test; retry later",
    );
    fn assert_private(text: &str) {
        for private in [
            "bob@example.test",
            "unlisted-bcc",
            "archive+alias",
            "hidden",
            "outside.test",
            "用户",
            "例子",
            "mx-bcc-only",
        ] {
            assert!(!text.contains(private), "leaked remote identity: {private}");
        }
        assert!(text.contains("[redacted]"));
        assert!(text.contains("451 4.7.1 upstream quota"));
        assert!(text.contains("retry later"));
    }
    let mut trace = transcript("mx.remote.test", 451);
    trace.events[0].response = Some(raw.into());
    trace.events[0].detail = Some(raw.into());
    let historical = serde_json::to_string(&trace).unwrap();
    store
        .finish_with_attempts(&a, "pending", raw, noisefence::now() + 1800, &[trace])
        .await
        .unwrap();
    store
        .finish_with_attempts(
            &b,
            "pending",
            "451 Bcc-only delivery error",
            noisefence::now() + 1800,
            &[transcript("mx-bcc-only.example.test", 451)],
        )
        .await
        .unwrap();
    let delivery_id = a.delivery_id;
    let persisted: (String, String) = store
        .read(move |db| {
            Ok(db.query_row(
                "SELECT d.error,a.trace FROM deliveries d JOIN delivery_attempts a ON a.delivery_id=d.id WHERE d.id=?1",
                [delivery_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?)
        })
        .await
        .unwrap();
    assert_private(&persisted.0);
    assert_private(&persisted.1);

    // Bypass the current write sanitizer to simulate an actual pre-hotfix row.
    let old_trace = historical.clone();
    store
        .run(move |db| {
            db.execute(
                "UPDATE deliveries SET error=?2 WHERE id=?1",
                rusqlite::params![delivery_id, raw],
            )?;
            db.execute(
                "UPDATE delivery_attempts SET trace=?2 WHERE delivery_id=?1",
                rusqlite::params![delivery_id, old_trace],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    drop(store);
    let store = Store::open(root.path()).unwrap();
    let app = api::router(cfg.clone(), store.clone()).unwrap();
    let login = app
        .clone()
        .oneshot(
            Request::post("/api/v1/login")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ORIGIN, &cfg.web.public_origin)
                .body(Body::from(
                    r#"{"username":"alice","password":"a long password 123"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::OK);
    let cookie = login.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    let path = format!("/api/v1/messages/{id}/diagnostics");
    for url in [path.clone(), format!("{path}?delivery_id={delivery_id}")] {
        let response = app
            .clone()
            .oneshot(
                Request::get(url)
                    .header(header::COOKIE, cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_private(std::str::from_utf8(&body).unwrap());
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let recipients = value["recipients"].as_array().unwrap();
        assert_eq!(recipients.len(), 1);
        assert_eq!(recipients[0]["address"], "alice@example.test");
        assert_private(recipients[0]["last_error"].as_str().unwrap());
        let event = &recipients[0]["logs"][0]["events"][0];
        assert_eq!(event["code"], 451);
        assert_eq!(event["enhanced_code"], "4.7.1");
        assert_private(event["response"].as_str().unwrap());
        assert_private(event["detail"].as_str().unwrap());
    }
    let forbidden = app
        .oneshot(
            Request::get(format!("{path}?delivery_id={}", b.delivery_id))
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(forbidden.status(), StatusCode::NOT_FOUND);
    // The fixture is still raw on disk: privacy came from the read boundary,
    // not a migration or a coincidental rewrite by the persistence sanitizer.
    let still_historical: (String, String) = store
        .read(move |db| {
            Ok(db.query_row(
                "SELECT d.error,a.trace FROM deliveries d JOIN delivery_attempts a ON a.delivery_id=d.id WHERE d.id=?1",
                [delivery_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?)
        })
        .await
        .unwrap();
    assert_eq!(still_historical, (raw.to_string(), historical));
}

#[tokio::test]
async fn traces_survive_restart_are_bounded_and_expire_with_metadata() {
    let root = tempfile::tempdir().unwrap();
    let cfg = common::config(root.path());
    let store = Store::open(root.path()).unwrap();
    api::create_user(
        &store,
        "admin".into(),
        "a long password 123".into(),
        vec![],
        true,
    )
    .await
    .unwrap();
    let (id, a, b) = queue(&store, &cfg).await;
    for i in 0..55 {
        store
            .finish_with_attempts(
                &a,
                "pending",
                "451 retry",
                0,
                &[transcript(&format!("mx-{i}.example.org"), 451)],
            )
            .await
            .unwrap();
    }
    store
        .finish_with_attempts(
            &a,
            "delivered",
            "",
            0,
            &[transcript("mx-final.example.org", 250)],
        )
        .await
        .unwrap();
    store.finish(&b, "delivered", "", 0).await.unwrap();
    store.cleanup().await.unwrap();
    assert!(!store.raw_path(&id).exists());
    drop(store);
    let store = Store::open(root.path()).unwrap();
    store.recover().await.unwrap();
    let visible = store
        .diagnostics("admin".into(), id.clone())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(visible.recipients[0].logs.len(), 50);
    assert_eq!(
        visible.recipients[0].logs[0].trace.route,
        "mx-final.example.org"
    );
    assert_eq!(
        visible.recipients[0].logs[0].trace.events[0].code,
        Some(250)
    );
    assert!(visible.recipients[1].logs.is_empty());
    assert_eq!(
        visible.analysis.policy.unwrap().threshold,
        cfg.filter.threshold
    );
    let key = id.clone();
    store
        .run(move |db| {
            db.execute(
                "UPDATE messages SET created=?2 WHERE id=?1",
                rusqlite::params![key, noisefence::now() - 31 * 86400],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    assert!(
        store
            .diagnostics("admin".into(), id)
            .await
            .unwrap()
            .is_none()
    );
    store.cleanup().await.unwrap();
    let count: i64 = store
        .read(|db| Ok(db.query_row("SELECT COUNT(*) FROM delivery_attempts", [], |r| r.get(0))?))
        .await
        .unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn transcript_failure_rolls_back_delivery_state() {
    let root = tempfile::tempdir().unwrap();
    let cfg = common::config(root.path());
    let store = Store::open(root.path()).unwrap();
    let (_, a, _) = queue(&store, &cfg).await;
    store.run(|db|{db.execute_batch("CREATE TRIGGER simulate_log_failure BEFORE INSERT ON delivery_attempts BEGIN SELECT RAISE(ABORT,'simulated disk failure'); END;")?;Ok(())}).await.unwrap();
    assert!(
        store
            .finish_with_attempts(&a, "delivered", "", 0, &[transcript("mx.example.org", 250)])
            .await
            .is_err()
    );
    let id = a.delivery_id;
    let state: String = store
        .read(move |db| {
            Ok(
                db.query_row("SELECT status FROM deliveries WHERE id=?1", [id], |r| {
                    r.get(0)
                })?,
            )
        })
        .await
        .unwrap();
    assert_eq!(state, "sending");
    assert!(store.raw_path(&a.message_id).exists());
}

#[test]
fn historical_policy_is_unknown_and_new_policy_is_a_snapshot() {
    let mut cfg =
        (*common::config(std::path::Path::new("/tmp/noisefence-diagnostics-test"))).clone();
    let scan = extract(common::MESSAGE, 10000);
    let old = noisefence::diagnostics::Analysis::from(scan);
    assert!(old.policy.is_none());
    let snapshot = AnalysisPolicy::capture(&cfg);
    cfg.filter.threshold = 12.0;
    assert_ne!(snapshot.threshold, cfg.filter.threshold);
    let encoded = serde_json::to_string(&snapshot).unwrap();
    assert!(!encoded.contains("key"));
}

#[tokio::test]
async fn many_recipient_history_is_bounded_and_can_be_loaded_separately() {
    let root = tempfile::tempdir().unwrap();
    let mut cfg = (*common::config(root.path())).clone();
    cfg.domains[0]
        .recipients
        .push("charlie@example.test".into());
    let store = Store::open(root.path()).unwrap();
    api::create_user(
        &store,
        "admin".into(),
        "a long password 123".into(),
        vec![],
        true,
    )
    .await
    .unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    let recipients = [
        "alice@example.test",
        "bob@example.test",
        "charlie@example.test",
    ]
    .iter()
    .map(|a| cfg.recipient(a).unwrap())
    .collect();
    store
        .enqueue(
            id.clone(),
            "sender@example.org".into(),
            recipients,
            extract(common::MESSAGE, 10000),
            common::MESSAGE.to_vec(),
        )
        .await
        .unwrap();
    for _ in 0..3 {
        let job = store.claim().await.unwrap().unwrap();
        store
            .finish_with_attempts(
                &job,
                "delivered",
                "",
                0,
                &vec![transcript("mx.example.org", 250); 50],
            )
            .await
            .unwrap();
    }
    let all = store
        .diagnostics("admin".into(), id.clone())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        all.recipients.iter().map(|r| r.logs.len()).sum::<usize>(),
        100
    );
    let omitted = &all.recipients[2];
    assert_eq!(omitted.logs_available, 50);
    assert!(omitted.logs_truncated);
    let scoped = store
        .diagnostics_for("admin".into(), id, Some(omitted.delivery_id))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(scoped.recipients.len(), 1);
    assert_eq!(scoped.recipients[0].logs.len(), 50);
    assert!(!scoped.recipients[0].logs_truncated);
}
