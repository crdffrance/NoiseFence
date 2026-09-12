use noisefence::{
    adaptive::{self, Class, Tenant},
    native_filter::{Runtime, Settings},
    store::Store,
};
use rusqlite::params;
use serde_json::json;
mod common;

#[tokio::test]
async fn annotation_api_requires_session_origin_csrf_and_message_access() {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    let (root, store) = fixture().await;
    let token = noisefence::api::random_token();
    let hash = noisefence::message::digest(token.as_bytes());
    store.run(move|db| {db.execute("INSERT INTO sessions(token_hash,username,csrf,expires) VALUES(?1,'alice','synthetic-csrf',?2)",params![hash,noisefence::now()+1000])?;Ok(())}).await.unwrap();
    let app = noisefence::api::router(common::config(root.path()), store).unwrap();
    for (session, origin, csrf, id, expected) in [
        (false, true, true, "one", StatusCode::UNAUTHORIZED),
        (true, false, true, "one", StatusCode::FORBIDDEN),
        (true, true, false, "one", StatusCode::FORBIDDEN),
        (true, true, true, "missing", StatusCode::NOT_FOUND),
        (true, true, true, "one", StatusCode::OK),
    ] {
        let mut req = Request::builder()
            .method("POST")
            .uri(format!("/api/v1/messages/{id}/adaptive-label"))
            .header("content-type", "application/json");
        if session {
            req = req.header("cookie", format!("noisefence_session={token}"));
        }
        req = req.header(
            "origin",
            if origin {
                "http://127.0.0.1:3000"
            } else {
                "https://untrusted.test"
            },
        );
        if csrf {
            req = req.header("x-csrf-token", "synthetic-csrf");
        }
        let response = app
            .clone()
            .oneshot(
                req.body(Body::from(
                    json!({"domain":"example.test","class":"phishing"}).to_string(),
                ))
                .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
}

async fn fixture() -> (tempfile::TempDir, Store) {
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path()).unwrap();
    let native = Runtime::new(Settings {
        adaptive: Some(adaptive::Settings {
            domains: [("example.test".into(), Tenant::default())].into(),
        }),
        ..Default::default()
    })
    .unwrap();
    let observation = native.offline(common::MESSAGE, &["example.test".into()]);
    let scan = noisefence::engine::Scan {
        complete: true,
        native_filter: Some(observation),
        ..Default::default()
    };
    store.run(move|db| {
        db.execute_batch("INSERT INTO users(username,password,admin) VALUES('admin','unused',1),('alice','unused',0),('bob','unused',0);
            INSERT INTO grants VALUES('alice','alice@example.test'),('bob','bob@other.test');")?;
        db.execute("INSERT INTO messages(id,created,sender,scan) VALUES('one',?1,'sender@example.org',?2)",params![noisefence::now()-100,serde_json::to_string(&scan)?])?;
        db.execute("INSERT INTO deliveries(message_id,address,destination,hosts,next_attempt) VALUES('one','alice@example.test','alice@example.test','[]',0)",[])?;
        Ok(())
    }).await.unwrap();
    (root, store)
}
#[tokio::test]
async fn labels_recheck_domain_acl_disabled_users_and_bcc_visibility() {
    let (_root, store) = fixture().await;
    assert!(
        adaptive::data::label(
            &store,
            "bob".into(),
            "one".into(),
            "example.test".into(),
            Some(Class::Phishing)
        )
        .await
        .is_err()
    );
    assert!(
        adaptive::data::label(
            &store,
            "alice".into(),
            "one".into(),
            "other.test".into(),
            Some(Class::Phishing)
        )
        .await
        .is_err()
    );
    adaptive::data::label(
        &store,
        "alice".into(),
        "one".into(),
        "example.test".into(),
        Some(Class::Phishing),
    )
    .await
    .unwrap();
    assert_eq!(
        adaptive::data::labels(&store, "alice".into(), "one".into())
            .await
            .unwrap()["domains"][0]["class"],
        "phishing"
    );
    store.run(|db| {db.execute("INSERT INTO deliveries(message_id,address,destination,hosts,next_attempt) VALUES('one','bob@other.test','bob@other.test','[]',0)",[])?;Ok(())}).await.unwrap();
    let view = adaptive::data::labels(&store, "bob".into(), "one".into())
        .await
        .unwrap();
    assert_eq!(
        view["domains"],
        json!([{"domain":"other.test","class":null}])
    );
    store
        .run(|db| {
            db.execute("UPDATE users SET disabled=1 WHERE username='alice'", [])?;
            Ok(())
        })
        .await
        .unwrap();
    assert!(
        adaptive::data::labels(&store, "alice".into(), "one".into())
            .await
            .is_err()
    );
}
#[tokio::test]
async fn detailed_truth_updates_binary_feedback_and_is_invalidated_by_later_corrections() {
    let (_root, store) = fixture().await;
    adaptive::data::label(
        &store,
        "alice".into(),
        "one".into(),
        "example.test".into(),
        Some(Class::Scam),
    )
    .await
    .unwrap();
    let spam: bool = store
        .read(|db| {
            Ok(db.query_row(
                "SELECT spam FROM feedback WHERE username='alice'",
                [],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap();
    assert!(spam);
    store
        .feedback("alice".into(), "one".into(), false)
        .await
        .unwrap();
    assert_eq!(
        adaptive::data::labels(&store, "alice".into(), "one".into())
            .await
            .unwrap()["domains"][0]["class"],
        json!(null)
    );
    adaptive::data::label(
        &store,
        "alice".into(),
        "one".into(),
        "example.test".into(),
        Some(Class::Publicity),
    )
    .await
    .unwrap();
    let spam: bool = store
        .read(|db| {
            Ok(db.query_row(
                "SELECT spam FROM feedback WHERE username='alice'",
                [],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap();
    assert!(!spam);
    adaptive::data::label(
        &store,
        "alice".into(),
        "one".into(),
        "example.test".into(),
        None,
    )
    .await
    .unwrap();
    let count: usize = store
        .read(|db| Ok(db.query_row("SELECT count(*) FROM feedback", [], |r| r.get(0))?))
        .await
        .unwrap();
    assert_eq!(count, 1);
}
#[tokio::test]
async fn export_excludes_conflicts_revoked_labels_and_cross_tenant_messages() {
    let (root, store) = fixture().await;
    adaptive::data::label(
        &store,
        "alice".into(),
        "one".into(),
        "example.test".into(),
        Some(Class::Phishing),
    )
    .await
    .unwrap();
    // Frozen export uses annotations strictly before its snapshot timestamp.
    store
        .run(|db| {
            db.execute("UPDATE adaptive_labels SET created=created-1", [])?;
            Ok(())
        })
        .await
        .unwrap();
    let result = adaptive::data::export(
        &store,
        "admin".into(),
        "example.test".into(),
        &root.path().join("first.jsonl"),
    )
    .await
    .unwrap();
    assert_eq!(result["exported"], 1);
    assert!(
        adaptive::data::export(
            &store,
            "alice".into(),
            "example.test".into(),
            &root.path().join("denied.jsonl")
        )
        .await
        .is_err()
    );
    adaptive::data::label(
        &store,
        "admin".into(),
        "one".into(),
        "example.test".into(),
        Some(Class::Legitimate),
    )
    .await
    .unwrap();
    store
        .run(|db| {
            db.execute("UPDATE adaptive_labels SET created=created-1", [])?;
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(
        adaptive::data::export(
            &store,
            "admin".into(),
            "example.test".into(),
            &root.path().join("conflict.jsonl")
        )
        .await
        .unwrap()["exported"],
        0
    );
    store
        .run(|db| {
            db.execute("DELETE FROM grants WHERE username='alice'", [])?;
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(
        adaptive::data::export(
            &store,
            "admin".into(),
            "example.test".into(),
            &root.path().join("revoked.jsonl")
        )
        .await
        .unwrap()["exported"],
        1
    );
    store.run(|db| {db.execute("INSERT INTO deliveries(message_id,address,destination,hosts,next_attempt) VALUES('one','bob@other.test','bob@other.test','[]',0)",[])?;Ok(())}).await.unwrap();
    assert_eq!(
        adaptive::data::export(
            &store,
            "admin".into(),
            "example.test".into(),
            &root.path().join("mixed.jsonl")
        )
        .await
        .unwrap()["exported"],
        0
    );
}
#[test]
fn native_old_rows_remain_readable_and_resource_limits_are_enforced() {
    let runtime = Runtime::new(Settings::default()).unwrap();
    let observation = runtime.offline(b"Subject: Test\r\n\r\nBonjour.", &[]);
    let mut value = serde_json::to_value(observation).unwrap();
    value.as_object_mut().unwrap().remove("adaptive_vector");
    value["report"].as_object_mut().unwrap().remove("adaptive");
    assert!(serde_json::from_value::<noisefence::native_filter::Observation>(value).is_ok());
    let settings = adaptive::Settings {
        domains: (0..17)
            .map(|i| (format!("d{i}.test"), Tenant::default()))
            .collect(),
    };
    assert!(settings.validate().is_err());
}
