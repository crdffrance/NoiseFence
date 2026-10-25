#[allow(dead_code)]
mod common;
#[path = "common/scim_http.rs"]
mod http;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use noisefence::{api, control::Controller, store::Store};
use serde_json::json;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tower::ServiceExt;
async fn setup() -> (tempfile::TempDir, Store, Router, Arc<Controller>) {
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path()).unwrap();
    store
        .run(|db| {
            for (name, token, admin) in [
                ("admin", http::ADMIN, true),
                ("reader", http::READER, false),
            ] {
                db.execute(
                    "INSERT INTO users VALUES(?1,'unused',?2,0)",
                    rusqlite::params![name, admin],
                )?;
                db.execute(
                    "INSERT INTO sessions VALUES(?1,?2,'csrf-http',?3)",
                    rusqlite::params![
                        noisefence::message::digest(token.as_bytes()),
                        name,
                        noisefence::now() + 3600
                    ],
                )?;
            }
            Ok(())
        })
        .await
        .unwrap();
    let (router, control) = http::router(common::config(root.path()), store.clone()).await;
    (root, store, router, control)
}
#[tokio::test]
async fn scim_http_enrollment_crud_discovery_and_revocation() {
    let (_root, _store, router, control) = setup().await;
    http::exercise(&router, &control).await;
}
#[tokio::test]
async fn scim_authentication_precedes_body_read_and_cookies_never_authorize() {
    let (_root, _store, router, _control) = setup().await;
    let polled = Arc::new(AtomicBool::new(false));
    let body = Body::from_stream(tokio_util::io::ReaderStream::new(Probe {
        polled: polled.clone(),
        started: None,
        release: None,
        bytes: b"private input".to_vec(),
        offset: 0,
    }));
    let req = Request::builder()
        .method("POST")
        .uri("/scim/a/v2/Users")
        .header("cookie", format!("noisefence_session={}", http::ADMIN))
        .body(body)
        .unwrap();
    let (s, h, _) = http::call(&router, req).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert!(h.contains_key("www-authenticate"));
    assert!(!polled.load(Ordering::SeqCst));
    let e = http::enroll(&router, "source", None).await;
    let req = http::provisioning(
        e["bearer"].as_str().unwrap(),
        "POST",
        "/scim/source/v2/Users",
        Body::from(vec![b'x'; 1024 * 1024 + 1]),
    );
    assert_eq!(
        http::call(&router, req).await.0,
        StatusCode::PAYLOAD_TOO_LARGE
    );
}
#[tokio::test]
async fn scim_revocation_while_body_arrives_prevents_mutation() {
    let (_root, store, router, _control) = setup().await;
    let e = http::enroll(&router, "source", None).await;
    let (started, ready) = tokio::sync::oneshot::channel();
    let (send, receive) = tokio::sync::oneshot::channel();
    let stream = tokio_util::io::ReaderStream::new(Probe {
        polled: Arc::new(AtomicBool::new(false)),
        started: Some(started),
        release: Some(receive),
        bytes: json!({"schemas":[noisefence::identity::scim::USER_SCHEMA],"userName":"late"})
            .to_string()
            .into_bytes(),
        offset: 0,
    });
    let task = tokio::spawn(router.clone().oneshot(http::provisioning(
        e["bearer"].as_str().unwrap(),
        "POST",
        "/scim/source/v2/Users",
        Body::from_stream(stream),
    )));
    tokio::time::timeout(std::time::Duration::from_secs(3), ready)
        .await
        .unwrap()
        .unwrap();
    http::call(
        &router,
        http::admin_request(
            http::ADMIN,
            "/admin/identity/connections/revoke",
            Some(json!({"source_id":"source","generation":e["generation"]})),
            true,
        ),
    )
    .await;
    send.send(()).unwrap();
    assert_eq!(
        task.await.unwrap().unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        store
            .read(|db| Ok(db.query_row(
                "SELECT count(*) FROM sqlite_master WHERE name='identity_scim_resources'",
                [],
                |r| r.get::<_, i64>(0)
            )?))
            .await
            .unwrap(),
        0
    );
}
#[tokio::test]
async fn scim_enrollment_rejects_scope_lifetime_origin_and_client_generated_secrets() {
    let (root, store, router, _control) = setup().await;
    for (key, value) in [
        ("expires", json!(noisefence::now() + 91 * 86400)),
        (
            "source",
            json!({"id":"bad/id","label":"Bad","provider":"scim","authority":"tenant","scopes":["example.test"],"stale_after_seconds":3600}),
        ),
        (
            "source",
            json!({"id":"bad","label":"Bad","provider":"scim","authority":"tenant","scopes":["other.test"],"stale_after_seconds":3600}),
        ),
    ] {
        let mut input = http::enroll_input("source", None);
        input[key] = value;
        assert_eq!(
            http::call(
                &router,
                http::admin_request(
                    http::ADMIN,
                    "/admin/identity/scim/enroll",
                    Some(input),
                    true
                )
            )
            .await
            .0,
            StatusCode::CONFLICT
        );
    }
    assert!(!root.path().join("directory-vault/key").exists());
    let mut base = (*common::config(root.path())).clone();
    base.web.public_origin = "https://attacker.invalid/path".into();
    base.web.secure_cookies = true;
    let control = Controller::load(Arc::new(base.clone()), store.clone())
        .await
        .unwrap();
    let router = api::router_controlled(Arc::new(base), store, Some(control)).unwrap();
    let mut req = http::admin_request(
        http::ADMIN,
        "/admin/identity/scim/enroll",
        Some(http::enroll_input("source", None)),
        true,
    );
    req.headers_mut()
        .insert("origin", "https://attacker.invalid/path".parse().unwrap());
    assert_eq!(http::call(&router, req).await.0, StatusCode::CONFLICT);
}
#[tokio::test]
async fn scim_endpoint_uses_origin_configuration_and_never_weakens_other_routes() {
    use noisefence::identity::scim::endpoint::base;
    for origin in [
        "https://example.test/path",
        "https://user@example.test",
        "https://example.test?x=1",
        "https://example.test#x",
        "http://example.test",
        "https://example.test/",
    ] {
        assert!(base(origin, "source", true).is_err());
    }
    assert!(base("http://127.0.0.1:3000", "source", false).is_err());
    assert!(base("http://127.0.0.1:3000", "source", true).is_ok());
    let (_root, _store, router, _control) = setup().await;
    let (s, _, _) = http::call(
        &router,
        Request::builder()
            .uri("/scim/unknown")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

struct Probe {
    polled: Arc<AtomicBool>,
    started: Option<tokio::sync::oneshot::Sender<()>>,
    release: Option<tokio::sync::oneshot::Receiver<()>>,
    bytes: Vec<u8>,
    offset: usize,
}
impl tokio::io::AsyncRead for Probe {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.polled.store(true, Ordering::SeqCst);
        if let Some(started) = self.started.take() {
            let _ = started.send(());
        }
        if let Some(release) = self.release.as_mut() {
            if std::future::Future::poll(std::pin::Pin::new(release), cx).is_pending() {
                return std::task::Poll::Pending;
            }
            self.release = None;
        }
        let size = buf.remaining().min(self.bytes.len() - self.offset);
        buf.put_slice(&self.bytes[self.offset..self.offset + size]);
        self.offset += size;
        std::task::Poll::Ready(Ok(()))
    }
}
#[tokio::test]
async fn scim_disconnected_requests_keep_capacity_until_their_work_stops() {
    let (_root, _store, router, _control) = setup().await;
    let e = http::enroll(&router, "source", None).await;
    let token = e["bearer"].as_str().unwrap();
    let mut releases = vec![];
    for i in 0..4 {
        let (started, ready) = tokio::sync::oneshot::channel();
        let (send, receive) = tokio::sync::oneshot::channel();
        let stream=tokio_util::io::ReaderStream::new(Probe{polled:Arc::new(AtomicBool::new(false)),started:Some(started),release:Some(receive),bytes:json!({"schemas":[noisefence::identity::scim::USER_SCHEMA],"userName":format!("detached-{i}")}).to_string().into_bytes(),offset:0});
        let task = tokio::spawn(router.clone().oneshot(http::provisioning(
            token,
            "POST",
            "/scim/source/v2/Users",
            Body::from_stream(stream),
        )));
        tokio::time::timeout(std::time::Duration::from_secs(3), ready)
            .await
            .unwrap()
            .unwrap();
        task.abort();
        let _ = task.await;
        releases.push(send);
    }
    assert_eq!(
        http::call(
            &router,
            http::provisioning(token, "GET", "/scim/source/v2/Users", Body::empty())
        )
        .await
        .0,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        http::call(
            &router,
            http::admin_request(http::ADMIN, "/admin/identity/connections", None, false)
        )
        .await
        .0,
        StatusCode::OK
    );
    for release in releases {
        release.send(()).unwrap();
    }
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let (s, _, v) = http::call(
                &router,
                http::provisioning(token, "GET", "/scim/source/v2/Users", Body::empty()),
            )
            .await;
            if s == StatusCode::OK && v["totalResults"] == 4 {
                break;
            }
            assert!(s == StatusCode::OK || s == StatusCode::TOO_MANY_REQUESTS);
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn scim_slow_body_has_a_deadline_and_never_creates_a_resource() {
    let (_root, _store, router, _control) = setup().await;
    let e = http::enroll(&router, "source", None).await;
    let token = e["bearer"].as_str().unwrap();
    let (_send, receive) = tokio::sync::oneshot::channel();
    let stream = tokio_util::io::ReaderStream::new(Probe {
        polled: Arc::new(AtomicBool::new(false)),
        started: None,
        release: Some(receive),
        bytes: vec![],
        offset: 0,
    });
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(12),
        http::call(
            &router,
            http::provisioning(
                token,
                "POST",
                "/scim/source/v2/Users",
                Body::from_stream(stream),
            ),
        ),
    )
    .await
    .unwrap();
    assert_eq!(response.0, StatusCode::REQUEST_TIMEOUT);
    assert_eq!(
        http::call(
            &router,
            http::provisioning(token, "GET", "/scim/source/v2/Users", Body::empty())
        )
        .await
        .2["totalResults"],
        0
    );
}
