mod common;
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use noisefence::{api, engine::extract, store::Store};
use tower::ServiceExt;

#[tokio::test]
async fn api_lists_and_statistics_follow_stored_decisions_and_recipient_grants() {
    use noisefence::fusion::runtime::{Decision, DecisionSource, Outcome};
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
    let cases = [
        ("old-high", 99.0, true, None),
        ("old-incomplete", 99.0, false, None),
        (
            "fusion-unwanted",
            1.0,
            true,
            Some((Outcome::Unwanted, Some(0.1))),
        ),
        (
            "fusion-legitimate",
            99.0,
            true,
            Some((Outcome::Legitimate, Some(99.0))),
        ),
        (
            "fusion-undetermined",
            99.0,
            false,
            Some((Outcome::Undetermined, None)),
        ),
        (
            "hidden-recipient",
            99.0,
            true,
            Some((Outcome::Unwanted, Some(99.0))),
        ),
    ];
    for (subject, score, complete, decision) in cases {
        let mut scan = extract(common::MESSAGE, 10000);
        scan.subject = subject.into();
        scan.score = score;
        scan.complete = complete;
        scan.decision = decision.map(|(outcome, score)| Decision {
            source: DecisionSource::Fusion,
            outcome,
            score,
            model: "SOFTWARE-TEST-ONLY".into(),
        });
        store
            .enqueue(
                uuid::Uuid::new_v4().to_string(),
                "sender@example.org".into(),
                vec![
                    cfg.recipient(if subject == "hidden-recipient" {
                        "bob@example.test"
                    } else {
                        "alice@example.test"
                    })
                    .unwrap(),
                ],
                scan,
                common::MESSAGE.to_vec(),
            )
            .await
            .unwrap();
    }
    let app = api::router(cfg.clone(), store).unwrap();
    let response = app
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
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = response.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    for (path, count) in [
        ("/api/v1/messages", 5),
        ("/api/v1/messages?filter=spam", 2),
        ("/api/v1/messages?filter=incomplete", 2),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::get(path)
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(!String::from_utf8_lossy(&body).contains("bob@example.test"));
        let rows: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(rows.len(), count);
        for row in &rows {
            assert!(row["decision"].is_object());
            if path.ends_with("=spam") {
                assert_eq!(row["decision"]["outcome"], "unwanted");
            }
            if path.ends_with("=incomplete") {
                assert_eq!(row["decision"]["outcome"], "undetermined");
            }
        }
    }
    let response = app
        .oneshot(
            Request::get("/api/v1/stats")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let stats: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(stats["received"], 5);
    assert_eq!(stats["flagged"], 2);
    assert_eq!(stats["pending"], 5);
}

#[tokio::test]
async fn durable_queue_recovery_acl_feedback_and_retention() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = common::config(dir.path());
    let store = Store::open(dir.path()).unwrap();
    api::create_user(
        &store,
        "alice".into(),
        "a long password 123".into(),
        vec!["alice@example.test".into()],
        false,
    )
    .await
    .unwrap();
    api::create_user(
        &store,
        "bob".into(),
        "a long password 456".into(),
        vec!["bob@example.test".into()],
        true,
    )
    .await
    .unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    let mut scan = extract(common::MESSAGE, 10000);
    let mut evidence = noisefence::evidence::Evidence::new(
        &cfg,
        noisefence::evidence::Artifacts::new(&cfg, None, None, false),
        false,
    );
    evidence.source = noisefence::evidence::Source::SmtpSession;
    evidence.authentication.state = noisefence::evidence::State::Complete;
    evidence.authentication.spf = Some(noisefence::evidence::AuthResult::Pass);
    scan.evidence = Some(evidence);
    scan.smtp_policy = noisefence::smtp_policy::PolicyResult {
        status: noisefence::smtp_policy::PolicyStatus::Complete,
        version: noisefence::smtp_policy::VERSION.into(),
        candidate_weight: 0.5,
        checks: vec![noisefence::engine::Signal {
            id: "helo_literal_mismatch".into(),
            detail: "Identité de connexion différente".into(),
            weight: 0.5,
        }],
        ..Default::default()
    };
    store
        .enqueue(
            id.clone(),
            "sender@example.org".into(),
            vec![cfg.recipient("alice@example.test").unwrap()],
            scan,
            common::MESSAGE.to_vec(),
        )
        .await
        .unwrap();
    let job = store.claim().await.unwrap().unwrap();
    assert!(store.raw_path(&id).is_file());
    drop(store);
    let store = Store::open(dir.path()).unwrap();
    store.recover().await.unwrap();
    let retried = store.claim().await.unwrap().unwrap();
    assert_eq!(retried.delivery_id, job.delivery_id);
    assert_eq!(retried.attempts, 2);
    assert!(
        store
            .list("bob".into(), "".into(), "all".into(), 0, 95.0)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .feedback("bob".into(), id.clone(), true)
            .await
            .is_err()
    );
    let items = store
        .list("alice".into(), "rendez-vous".into(), "all".into(), 0, 95.0)
        .await
        .unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(
        items[0].evidence.as_ref().unwrap().authentication.spf,
        Some(noisefence::evidence::AuthResult::Pass)
    );
    assert_eq!(
        items[0].smtp_policy.version,
        noisefence::smtp_policy::VERSION
    );
    assert_eq!(items[0].smtp_policy.candidate_weight, 0.5);
    assert_eq!(items[0].smtp_policy.applied_weight, 0.0);
    assert_eq!(items[0].smtp_policy.checks[0].id, "helo_literal_mismatch");
    store
        .feedback("alice".into(), id.clone(), false)
        .await
        .unwrap();
    store.finish(&retried, "delivered", "", 0).await.unwrap();
    store.cleanup().await.unwrap();
    assert!(!store.raw_path(&id).exists());
    assert_eq!(
        store
            .list("alice".into(), "".into(), "all".into(), 0, 95.0)
            .await
            .unwrap()
            .len(),
        1
    );
    let key = id.clone();
    store
        .run(move |db| {
            db.execute("UPDATE messages SET created=0 WHERE id=?1", [key])?;
            Ok(())
        })
        .await
        .unwrap();
    store.cleanup().await.unwrap();
    assert!(
        store
            .list("alice".into(), "".into(), "all".into(), 0, 95.0)
            .await
            .unwrap()
            .is_empty()
    );
}
#[tokio::test]
async fn login_csrf_and_cross_user_isolation() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = common::config(dir.path());
    let store = Store::open(dir.path()).unwrap();
    api::create_user(
        &store,
        "alice".into(),
        "a long password 123".into(),
        vec!["alice@example.test".into()],
        false,
    )
    .await
    .unwrap();
    let app = api::router(cfg.clone(), store).unwrap();
    let request = |origin: &str| {
        Request::post("/api/v1/login")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ORIGIN, origin)
            .body(Body::from(
                r#"{"username":"alice","password":"a long password 123"}"#,
            ))
            .unwrap()
    };
    assert_eq!(
        app.clone()
            .oneshot(request("https://attacker.invalid"))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    let response = app
        .clone()
        .oneshot(request(&cfg.web.public_origin))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = response.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    assert!(
        response.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .contains("HttpOnly")
    );
    let body: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let csrf = body["csrf"].as_str().unwrap();
    let req = Request::post("/api/v1/logout")
        .header(header::COOKIE, &cookie)
        .header(header::ORIGIN, &cfg.web.public_origin)
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let req = Request::post("/api/v1/logout")
        .header(header::COOKIE, &cookie)
        .header(header::ORIGIN, &cfg.web.public_origin)
        .header("x-csrf-token", csrf)
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::OK
    );
    let req = Request::get("/api/v1/me")
        .header(header::COOKIE, &cookie)
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.oneshot(req).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
}
#[tokio::test]
async fn bcc_ownership_is_checked_on_envelope_not_headers() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = common::config(dir.path());
    let store = Store::open(dir.path()).unwrap();
    for user in ["alice", "bob"] {
        api::create_user(
            &store,
            user.into(),
            "a long password 123".into(),
            vec![format!("{user}@example.test")],
            false,
        )
        .await
        .unwrap();
    }
    let id = uuid::Uuid::new_v4().to_string();
    store
        .enqueue(
            id,
            "sender@example.org".into(),
            vec![
                cfg.recipient("alice@example.test").unwrap(),
                cfg.recipient("bob@example.test").unwrap(),
            ],
            extract(common::MESSAGE, 10000),
            common::MESSAGE.to_vec(),
        )
        .await
        .unwrap();
    let bob = store
        .list("bob".into(), "".into(), "all".into(), 0, 95.0)
        .await
        .unwrap();
    assert_eq!(bob.len(), 1);
    assert_eq!(bob[0].recipients.len(), 1);
    assert_eq!(bob[0].recipients[0].address, "bob@example.test");
}
#[tokio::test]
async fn missing_durable_body_is_a_startup_error() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = common::config(dir.path());
    let store = Store::open(dir.path()).unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    store
        .enqueue(
            id.clone(),
            "sender@example.org".into(),
            vec![cfg.recipient("alice@example.test").unwrap()],
            extract(common::MESSAGE, 10000),
            common::MESSAGE.to_vec(),
        )
        .await
        .unwrap();
    std::fs::remove_file(store.raw_path(&id)).unwrap();
    assert!(store.recover().await.is_err());
}

#[tokio::test]
async fn partial_delivery_retry_and_dsn_survive_restart_without_losing_other_recipients() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = common::config(dir.path());
    let store = Store::open(dir.path()).unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    store
        .enqueue(
            id.clone(),
            "sender@example.org".into(),
            vec![
                cfg.recipient("alice@example.test").unwrap(),
                cfg.recipient("bob@example.test").unwrap(),
            ],
            extract(common::MESSAGE, 10000),
            common::MESSAGE.to_vec(),
        )
        .await
        .unwrap();
    let alice = store.claim().await.unwrap().unwrap();
    store.finish(&alice, "delivered", "", 0).await.unwrap();
    let bob = store.claim().await.unwrap().unwrap();
    store
        .finish(&bob, "pending", "451 Try later", noisefence::now() + 3600)
        .await
        .unwrap();
    store.cleanup().await.unwrap();
    assert!(store.raw_path(&id).exists());
    assert!(store.claim().await.unwrap().is_none());
    let key = bob.delivery_id;
    store
        .run(move |db| {
            db.execute("UPDATE deliveries SET next_attempt=0 WHERE id=?1", [key])?;
            Ok(())
        })
        .await
        .unwrap();
    drop(store);
    let store = Store::open(dir.path()).unwrap();
    store.recover().await.unwrap();
    let retried = store.claim().await.unwrap().unwrap();
    assert_eq!(retried.destination, "bob@example.test");
    assert_eq!(retried.attempts, 2);
    store
        .finish(&retried, "failed", "550 Mailbox unavailable", 0)
        .await
        .unwrap();
    store.cleanup().await.unwrap();
    assert!(store.raw_path(&id).exists());
    let failed = store.failed().await.unwrap().pop().unwrap();
    store
        .enqueue_dsn(
            failed.clone(),
            common::MESSAGE.to_vec(),
            vec!["mx.example.org".into()],
        )
        .await
        .unwrap();
    // Replaying the same failure must never create a second notification delivery.
    store
        .enqueue_dsn(
            failed,
            common::MESSAGE.to_vec(),
            vec!["mx.example.org".into()],
        )
        .await
        .unwrap();
    store.cleanup().await.unwrap();
    assert!(!store.raw_path(&id).exists());
    drop(store);
    let store = Store::open(dir.path()).unwrap();
    store.recover().await.unwrap();
    let notification = store.claim().await.unwrap().unwrap();
    assert!(notification.is_dsn);
    assert!(notification.sender.is_empty());
    assert_eq!(notification.destination, "sender@example.org");
    assert!(store.raw_path(&notification.message_id).exists());
    assert!(store.claim().await.unwrap().is_none());
    assert!(store.failed().await.unwrap().is_empty());
}

#[tokio::test]
async fn failed_metadata_transaction_cannot_leave_an_accepted_message() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = common::config(dir.path());
    let store = Store::open(dir.path()).unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    let recipient = cfg.recipient("alice@example.test").unwrap();
    // A duplicate violates the unique recipient constraint after the message insert.
    let result = store
        .enqueue(
            id.clone(),
            "sender@example.org".into(),
            vec![recipient.clone(), recipient],
            extract(common::MESSAGE, 10000),
            common::MESSAGE.to_vec(),
        )
        .await;
    assert!(result.is_err());
    assert!(!store.raw_path(&id).exists());
    assert!(store.claim().await.unwrap().is_none());
    store.recover().await.unwrap();
}
