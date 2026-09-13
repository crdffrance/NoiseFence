#[allow(dead_code)]
mod common;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use noisefence::{api, mfa, store::Store};
use rusqlite::params;
use serde_json::{Value, json};
use tower::ServiceExt;
const PASSWORD: &str = "synthetic-long-password-123";
async fn call(
    app: &Router,
    origin: &str,
    path: &str,
    cookie: &str,
    csrf: &str,
    body: Option<Value>,
) -> (StatusCode, Value, String) {
    let mut req = Request::builder()
        .uri(format!("/api/v1{path}"))
        .header("origin", origin)
        .header("cookie", cookie)
        .header("x-csrf-token", csrf);
    let b = if let Some(value) = body {
        req = req
            .method("POST")
            .header("content-type", "application/json");
        Body::from(value.to_string())
    } else {
        Body::empty()
    };
    let r = app.clone().oneshot(req.body(b).unwrap()).await.unwrap();
    let status = r.status();
    let cookie = r
        .headers()
        .get("set-cookie")
        .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_owned())
        .unwrap_or_default();
    let bytes = r.into_body().collect().await.unwrap().to_bytes();
    let v = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v, cookie)
}
fn current_code(encoded: &str) -> String {
    // Test client decodes the provisioning key and independently produces its OTP.
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut raw = Vec::new();
    let mut n = 0u32;
    let mut bits = 0;
    for b in encoded.bytes() {
        n = (n << 5) | alphabet.iter().position(|v| *v == b).unwrap() as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            raw.push((n >> bits) as u8);
        }
    }
    let mac = ring::hmac::sign(
        &ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &raw),
        &((noisefence::now() / 30) as u64).to_be_bytes(),
    );
    let b = mac.as_ref();
    let i = (b[19] & 15) as usize;
    let n = u32::from_be_bytes(b[i..i + 4].try_into().unwrap()) & 0x7fffffff;
    format!("{:06}", n % 1_000_000)
}
#[tokio::test]
async fn enrollment_revokes_cookies_requires_factor_and_consumes_recovery_once() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = common::config(dir.path());
    let store = Store::open(dir.path()).unwrap();
    api::create_user(&store, "admin".into(), PASSWORD.into(), vec![], true)
        .await
        .unwrap();
    let app = api::router(cfg.clone(), store.clone()).unwrap();
    let origin = &cfg.web.public_origin;
    let (status, user, cookie) = call(
        &app,
        origin,
        "/login",
        "",
        "",
        Some(json!({"username":"admin","password":PASSWORD})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let csrf = user["csrf"].as_str().unwrap();
    assert_eq!(
        call(
            &app,
            origin,
            "/mfa/enroll",
            &cookie,
            "",
            Some(json!({"password":PASSWORD}))
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let (status, pending, _) = call(
        &app,
        origin,
        "/mfa/enroll",
        &cookie,
        csrf,
        Some(json!({"password":PASSWORD})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{pending}");
    let secret = pending["secret"].as_str().unwrap();
    let code = current_code(secret);
    assert_eq!(
        call(
            &app,
            origin,
            "/mfa/confirm",
            &cookie,
            csrf,
            Some(json!({"code":"abcdef"}))
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let (status, confirmed, _) = call(
        &app,
        origin,
        "/mfa/confirm",
        &cookie,
        csrf,
        Some(json!({"code":code})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{confirmed}");
    let recovery = confirmed["recovery_codes"][0].as_str().unwrap();
    assert_eq!(
        call(&app, origin, "/metrics", &cookie, "", None).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(
            &app,
            origin,
            "/login",
            "",
            "",
            Some(json!({"username":"admin","password":PASSWORD}))
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(
            &app,
            origin,
            "/login",
            "",
            "",
            Some(json!({"username":"admin","password":PASSWORD,"code":code}))
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    // Reopen both the store and router: factor/replay enforcement survives a process restart.
    let resumed = api::router(cfg.clone(), Store::open(dir.path()).unwrap()).unwrap();
    let (status, _, fresh) = call(
        &resumed,
        origin,
        "/login",
        "",
        "",
        Some(json!({"username":"admin","password":PASSWORD,"code":recovery})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        call(&resumed, origin, "/metrics", &fresh, "", None).await.0,
        StatusCode::OK
    );
    assert_eq!(
        call(
            &resumed,
            origin,
            "/login",
            "",
            "",
            Some(json!({"username":"admin","password":PASSWORD,"code":recovery}))
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    let raw = store
        .run(|db| {
            assert_eq!(
                db.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))?,
                4
            );
            Ok(db.query_row(
                "SELECT secret FROM mfa_credentials WHERE username='admin'",
                [],
                |r| r.get::<_, Vec<u8>>(0),
            )?)
        })
        .await
        .unwrap();
    assert!(!raw.windows(secret.len()).any(|s| s == secret.as_bytes()));
    std::fs::rename(dir.path().join("mfa.key"), dir.path().join("saved-key")).unwrap();
    assert!(api::router(cfg, store).is_err());
    assert!(!dir.path().join("mfa.key").exists());
}
#[tokio::test]
async fn forged_session_without_factor_cannot_access_any_authenticated_route() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = common::config(dir.path());
    let store = Store::open(dir.path()).unwrap();
    api::create_user(&store, "admin".into(), PASSWORD.into(), vec![], true)
        .await
        .unwrap();
    let app = api::router(cfg.clone(), store.clone()).unwrap();
    let secret = mfa::Key::open(dir.path())
        .unwrap()
        .seal("admin", &mfa::secret())
        .unwrap();
    let raw = "a".repeat(64);
    let digest = noisefence::message::digest(raw.as_bytes());
    store
        .run(move |db| {
            db.execute(
                "INSERT INTO mfa_credentials VALUES('admin',?1,1,0,-1)",
                [secret],
            )?;
            db.execute(
                "INSERT INTO sessions VALUES(?1,'admin','csrf',?2)",
                params![digest, noisefence::now() + 3600],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    for route in [
        "/me",
        "/messages",
        "/stats",
        "/metrics",
        "/mfa",
        "/admin/config",
    ] {
        assert_eq!(
            call(
                &app,
                &cfg.web.public_origin,
                route,
                &format!("noisefence_session={raw}"),
                "csrf",
                None
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED,
            "{route}"
        );
    }
}
#[tokio::test]
async fn challenge_rate_is_persistent_and_expires() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    api::create_user(&store, "alice".into(), PASSWORD.into(), vec![], false)
        .await
        .unwrap();
    store
        .run(|db| {
            for _ in 0..10 {
                assert!(mfa::attempt(db, "alice", 1000)?);
            }
            assert!(!mfa::attempt(db, "alice", 1000)?);
            Ok(())
        })
        .await
        .unwrap();
    Store::open(dir.path())
        .unwrap()
        .run(|db| {
            assert!(!mfa::attempt(db, "alice", 1599)?);
            assert!(mfa::attempt(db, "alice", 1600)?);
            Ok(())
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn removal_needs_password_and_a_fresh_factor_and_keeps_schema_guard() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = common::config(dir.path());
    let store = Store::open(dir.path()).unwrap();
    api::create_user(&store, "alice".into(), PASSWORD.into(), vec![], false)
        .await
        .unwrap();
    let app = api::router(cfg.clone(), store.clone()).unwrap();
    let sealed = mfa::Key::open(dir.path())
        .unwrap()
        .seal("alice", &mfa::secret())
        .unwrap();
    let recovery = mfa::recovery();
    let saved = recovery.clone();
    store
        .run(move |db| {
            db.execute(
                "INSERT INTO mfa_credentials VALUES('alice',?1,1,0,-1)",
                [sealed],
            )?;
            for value in saved {
                db.execute(
                    "INSERT INTO mfa_recovery VALUES('alice',?1)",
                    [noisefence::message::digest(value.as_bytes())],
                )?;
            }
            db.execute_batch("PRAGMA user_version=4")?;
            Ok(())
        })
        .await
        .unwrap();
    let origin = &cfg.web.public_origin;
    let (status, user, cookie) = call(
        &app,
        origin,
        "/login",
        "",
        "",
        Some(json!({"username":"alice","password":PASSWORD,"code":recovery[0]})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let csrf = user["csrf"].as_str().unwrap();
    assert_eq!(
        call(
            &app,
            origin,
            "/mfa/disable",
            &cookie,
            csrf,
            Some(json!({"password":"wrong","code":recovery[1]}))
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        call(&app, origin, "/me", &cookie, "", None).await.0,
        StatusCode::OK
    );
    assert_eq!(
        call(
            &app,
            origin,
            "/mfa/disable",
            &cookie,
            csrf,
            Some(json!({"password":PASSWORD,"code":"abcdef"}))
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        call(
            &app,
            origin,
            "/mfa/disable",
            &cookie,
            csrf,
            Some(json!({"password":PASSWORD,"code":recovery[1]}))
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        call(&app, origin, "/me", &cookie, "", None).await.0,
        StatusCode::UNAUTHORIZED
    );
    store
        .run(|db| {
            assert_eq!(
                db.query_row("SELECT COUNT(*) FROM mfa_credentials", [], |r| r
                    .get::<_, i64>(0))?,
                0
            );
            assert_eq!(
                db.query_row("SELECT COUNT(*) FROM mfa_recovery", [], |r| r
                    .get::<_, i64>(0))?,
                0
            );
            assert_eq!(
                db.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))?,
                4
            );
            Ok(())
        })
        .await
        .unwrap();
}
