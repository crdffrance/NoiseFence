#[allow(dead_code)]
mod common;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use noisefence::{api, store::Store};
use rusqlite::params;
use serde_json::{Value, json};
use tower::ServiceExt;

async fn account(store: &Store, name: &str, admin: bool, grants: Vec<&str>) -> String {
    let name = name.to_owned();
    let grants: Vec<String> = grants.into_iter().map(str::to_owned).collect();
    let token = api::random_token();
    let hash = noisefence::message::digest(token.as_bytes());
    store.run(move|db| {
        db.execute("INSERT INTO users(username,password,admin) VALUES(?1,'unused-in-test',?2)",params![name,admin])?;
        for g in grants {db.execute("INSERT INTO grants(username,address) VALUES(?1,?2)",params![name,g])?;}
        db.execute("INSERT INTO sessions(token_hash,username,csrf,expires) VALUES(?1,?2,'test-csrf',?3)",params![hash,name,noisefence::now()+3600])?;Ok(())
    }).await.unwrap();
    token
}
async fn request(
    app: &Router,
    token: &str,
    path: &str,
    data: Option<Value>,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .uri(format!("/api/v1{path}"))
        .header("cookie", format!("noisefence_session={token}"));
    let body = if let Some(data) = data {
        req = req
            .method("POST")
            .header("content-type", "application/json")
            .header("origin", "http://127.0.0.1:3000")
            .header("x-csrf-token", "test-csrf");
        Body::from(data.to_string())
    } else {
        Body::empty()
    };
    let response = app.clone().oneshot(req.body(body).unwrap()).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| json!({"body":String::from_utf8_lossy(&bytes)})),
    )
}
async fn fixture() -> (tempfile::TempDir, Store, Router, String) {
    let dir = tempfile::tempdir().unwrap();
    let cfg = common::config(dir.path());
    let store = Store::open(dir.path()).unwrap();
    let token = account(&store, "admin", true, vec![]).await;
    let app = api::router(cfg, store.clone()).unwrap();
    (dir, store, app, token)
}
fn invite(username: &str) -> Value {
    json!({"username":username,"admin":false,"addresses":["alice@example.test"],"days":3})
}
async fn create(app: &Router, admin: &str, username: &str) -> String {
    let (status, data) = request(app, admin, "/admin/invitations", Some(invite(username))).await;
    assert_eq!(status, StatusCode::OK, "{data}");
    data["url"]
        .as_str()
        .unwrap()
        .split("#invite=")
        .nth(1)
        .unwrap()
        .to_owned()
}
#[tokio::test]
async fn invitation_consumed_once_and_normal_login_works() {
    let (_dir, store, app, admin) = fixture().await;
    let token = create(&app, &admin, "newuser").await;
    let (_, list) = request(&app, &admin, "/admin/invitations", None).await;
    assert!(!list.to_string().contains(&token));
    assert!(!list.to_string().contains("token_hash"));
    let data = json!({"token":token,"password":"my long new password","confirmation":"my long new password"});
    let (a, b) = tokio::join!(
        request(&app, "", "/onboarding/accept", Some(data.clone())),
        request(&app, "", "/onboarding/accept", Some(data))
    );
    assert!(
        (a.0 == StatusCode::OK && b.0 == StatusCode::BAD_REQUEST)
            || (b.0 == StatusCode::OK && a.0 == StatusCode::BAD_REQUEST)
    );
    assert_eq!(
        request(&app, "", "/onboarding/check", Some(json!({"token":token})))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        request(
            &app,
            "",
            "/login",
            Some(json!({"username":"newuser","password":"my long new password"}))
        )
        .await
        .0,
        StatusCode::OK
    );
    let grants = store
        .run(|db| {
            Ok(db.query_row(
                "SELECT address FROM grants WHERE username='newuser'",
                [],
                |r| r.get::<_, String>(0),
            )?)
        })
        .await
        .unwrap();
    assert_eq!(grants, "alice@example.test");
}
#[tokio::test]
async fn rotation_revocation_expiry_and_creator_revocation() {
    let (_dir, store, app, admin) = fixture().await;
    let old = create(&app, &admin, "one").await;
    let new = create(&app, &admin, "one").await;
    assert_ne!(old, new);
    assert_eq!(
        request(&app, "", "/onboarding/check", Some(json!({"token":old})))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    let (_, list) = request(&app, &admin, "/admin/invitations", None).await;
    let item = list
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["status"] == "pending")
        .unwrap();
    assert_eq!(
        request(
            &app,
            &admin,
            "/admin/invitations/revoke",
            Some(json!({"id":item["id"],"version":item["version"]}))
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        request(&app, "", "/onboarding/check", Some(json!({"token":new})))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    let expired = create(&app, &admin, "expired").await;
    store
        .run(|db| {
            db.execute(
                "UPDATE console_invitations SET expires=0 WHERE username='expired'",
                [],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(
        request(
            &app,
            "",
            "/onboarding/check",
            Some(json!({"token":expired}))
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let token = create(&app, &admin, "last").await;
    store
        .run(|db| {
            db.execute("UPDATE users SET disabled=1 WHERE username='admin'", [])?;
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(
        request(&app, "", "/onboarding/check", Some(json!({"token":token})))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
}
#[tokio::test]
async fn acl_csrf_grants_and_conflicts_are_enforced() {
    let (_dir, store, app, admin) = fixture().await;
    let user = account(&store, "user", false, vec!["alice@example.test"]).await;
    assert_eq!(
        request(&app, &user, "/admin/invitations", Some(invite("intruder")))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let mut body = invite("outsider");
    body["addresses"] = json!(["*@external.example"]);
    assert_eq!(
        request(&app, &admin, "/admin/invitations", Some(body))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        request(&app, &admin, "/admin/invitations", Some(invite("admin")))
            .await
            .0,
        StatusCode::CONFLICT
    );
    let token = create(&app, &admin, "pending").await;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/onboarding/check")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(json!({"token":token}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let _ = account(&store, "pending", false, vec![]).await;
    assert_eq!(request(&app,"","/onboarding/accept",Some(json!({"token":token,"password":"new-password-1234","confirmation":"new-password-1234"}))).await.0,StatusCode::BAD_REQUEST);
}
