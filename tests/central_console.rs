#[allow(dead_code)]
mod common;
#[path = "common/postgres.rs"]
mod postgres;
#[path = "common/web_auth.rs"]
mod web_auth;
use axum::http::StatusCode;
use noisefence::{api, store::Store};
use serde_json::json;
use web_auth::{call, current_code};
const PASSWORD: &str = "synthetic-long-password-123";

#[tokio::test]
#[ignore = "requires disposable PostgreSQL on 127.0.0.1:15432 and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn central_console_accounts_invitations_and_mfa_use_the_authoritative_backend() {
    let fixture = postgres::Fixture::new().await;
    let db = fixture.connect().await;
    let hash = api::hash_password(PASSWORD).unwrap();
    db.execute(
        "INSERT INTO noisefence.users(username,password,admin) VALUES('admin',$1,true)",
        &[&hash],
    )
    .await
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let cfg = common::config(dir.path());
    let store = Store::open(dir.path()).unwrap();
    // An old local account must not authenticate in central mode.
    store
        .run(move |db| {
            db.execute(
                "INSERT INTO users(username,password,admin) VALUES('old-local-admin',?1,1)",
                [&hash],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    let store = store
        .with_management(fixture.central.clone())
        .await
        .unwrap();
    let app = api::router(cfg.clone(), store.clone()).unwrap();
    let origin = &cfg.web.public_origin;
    let (status, _, _) = call(
        &app,
        origin,
        "/login",
        "",
        "",
        Some(json!({"username":"old-local-admin","password":PASSWORD})),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
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
    let (status, users, _) = call(&app, origin, "/admin/users", &cookie, csrf, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(users.as_array().unwrap().len(), 1);
    let (status,_,_)=call(&app,origin,"/admin/users",&cookie,csrf,Some(json!({"username":"alice","admin":false,"disabled":false,"addresses":["alice@example.test"],"password":PASSWORD,"version":-1}))).await;
    assert_eq!(status, StatusCode::OK);
    let (status,_,_)=call(&app,origin,"/admin/users",&cookie,csrf,Some(json!({"username":"alice","admin":false,"disabled":false,"addresses":["alice@example.test"],"password":PASSWORD,"version":-1}))).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, invite, _) = call(
        &app,
        origin,
        "/admin/invitations",
        &cookie,
        csrf,
        Some(
            json!({"username":"invited","admin":false,"addresses":["alice@example.test"],"days":1}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let token = invite["url"]
        .as_str()
        .unwrap()
        .split("#invite=")
        .nth(1)
        .unwrap();
    let (status, claim, _) = call(
        &app,
        origin,
        "/onboarding/check",
        "",
        "",
        Some(json!({"token":token})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(claim["username"], "invited");
    let acceptance = json!({"token":token,"password":PASSWORD,"confirmation":PASSWORD});
    let (status, _, _) = call(
        &app,
        origin,
        "/onboarding/accept",
        "",
        "",
        Some(acceptance.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, _) = call(&app, origin, "/onboarding/accept", "", "", Some(acceptance)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, invited, invited_cookie) = call(
        &app,
        origin,
        "/login",
        "",
        "",
        Some(json!({"username":"invited","password":PASSWORD})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(invited["addresses"], json!(["alice@example.test"]));
    let (status, _, _) = call(
        &app,
        origin,
        "/admin/users",
        &invited_cookie,
        invited["csrf"].as_str().unwrap(),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status,_,_)=call(&app,origin,"/admin/users",&cookie,csrf,Some(json!({"username":"invited","admin":false,"disabled":true,"addresses":["alice@example.test"],"password":null,"version":1}))).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, _) = call(&app, origin, "/me", &invited_cookie, "", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, setup, _) = call(
        &app,
        origin,
        "/mfa/enroll",
        &cookie,
        csrf,
        Some(json!({"password":PASSWORD})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let code = current_code(setup["secret"].as_str().unwrap());
    let (status, confirmation, _) = call(
        &app,
        origin,
        "/mfa/confirm",
        &cookie,
        csrf,
        Some(json!({"code":code})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let recovery = confirmation["recovery_codes"].as_array().unwrap();
    assert_eq!(recovery.len(), 10);
    let (status, _, _) = call(&app, origin, "/me", &cookie, "", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let missing = tempfile::tempdir().unwrap();
    assert!(
        Store::open(missing.path())
            .unwrap()
            .with_management(fixture.central.clone())
            .await
            .is_err()
    );
    assert!(!missing.path().join("mfa.key").exists());
    let (status, mfa_user, mfa_cookie) = call(
        &app,
        origin,
        "/login",
        "",
        "",
        Some(json!({"username":"admin","password":PASSWORD,"code":recovery[0]})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let mfa_csrf = mfa_user["csrf"].as_str().unwrap();
    let (status, _, _) = call(
        &app,
        origin,
        "/login",
        "",
        "",
        Some(json!({"username":"admin","password":PASSWORD,"code":recovery[0]})),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, factors, _) = call(&app, origin, "/mfa", &mfa_cookie, mfa_csrf, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(factors["recovery_remaining"], 9);
    let (status, _, _) = call(
        &app,
        origin,
        "/mfa/disable",
        &mfa_cookie,
        mfa_csrf,
        Some(json!({"password":PASSWORD,"code":recovery[1]})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
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
    let replacement = "replacement-long-synthetic-password";
    let (status, _, _) = call(
        &app,
        origin,
        "/password",
        &cookie,
        csrf,
        Some(json!({"current_password":PASSWORD,"new_password":replacement})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, _) = call(&app, origin, "/me", &cookie, "", None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _, renewed_cookie) = call(
        &app,
        origin,
        "/login",
        "",
        "",
        Some(json!({"username":"admin","password":replacement})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    store
        .run(|db| {
            let count: i64 = db.query_row("SELECT count(*) FROM users", [], |r| r.get(0))?;
            assert_eq!(
                count, 1,
                "central account writes must not modify old local users"
            );
            let count: i64 = db.query_row("SELECT count(*) FROM sessions", [], |r| r.get(0))?;
            assert_eq!(
                count, 0,
                "central sessions must not be duplicated into SQLite"
            );
            Ok(())
        })
        .await
        .unwrap();
    fixture.suspend().await;
    let (status, _, _) = call(&app, origin, "/me", &renewed_cookie, "", None).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    let (status, _, _) = call(
        &app,
        origin,
        "/login",
        "",
        "",
        Some(json!({"username":"old-local-admin","password":PASSWORD})),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "an unavailable authority must never fall back to old SQLite credentials"
    );
    fixture.resume().await;
    let (status, _, _) = call(&app, origin, "/me", &renewed_cookie, "", None).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "central sessions survive a database outage"
    );
    drop(app);
    drop(store);
    drop(db);
    fixture.finish().await;
}
