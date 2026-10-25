#[allow(dead_code)]
mod common;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use noisefence::{
    api,
    control::Controller,
    identity::{directory, management},
    store::Store,
};
use serde_json::{Value, json};
use tower::ServiceExt;

fn draft() -> management::Draft {
    let s: directory::Snapshot =
        serde_json::from_str(include_str!("fixtures/identity/directory.json")).unwrap();
    s.into()
}
async fn account(store: &Store, name: &str, admin: bool) -> String {
    let token = api::random_token();
    let hash = noisefence::message::digest(token.as_bytes());
    let name = name.to_owned();
    store
        .run(move |db| {
            db.execute(
                "INSERT INTO users VALUES(?1,'unused',?2,0)",
                rusqlite::params![name, admin],
            )?;
            db.execute(
                "INSERT INTO sessions VALUES(?1,?2,'csrf-test',?3)",
                rusqlite::params![hash, name, noisefence::now() + 3600],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    token
}
async fn request(
    router: &Router,
    token: &str,
    path: &str,
    body: Option<Value>,
    csrf: bool,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .uri(format!("/api/v1{path}"))
        .header("cookie", format!("noisefence_session={token}"));
    let body = if let Some(body) = body {
        req = req
            .method("POST")
            .header("content-type", "application/json")
            .header("origin", "http://127.0.0.1:3000");
        if csrf {
            req = req.header("x-csrf-token", "csrf-test");
        }
        Body::from(body.to_string())
    } else {
        Body::empty()
    };
    let response = router
        .clone()
        .oneshot(req.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 32 * 1024 * 1024)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| json!({"raw":String::from_utf8_lossy(&bytes)})),
    )
}
#[tokio::test]
async fn manual_source_requires_authorization_review_and_distinct_activation() {
    let root = tempfile::tempdir().unwrap();
    let base = common::config(root.path());
    let store = Store::open(root.path()).unwrap();
    let admin = account(&store, "admin", true).await;
    let user = account(&store, "user", false).await;
    let control = Controller::load(base.clone(), store.clone()).await.unwrap();
    let router = api::router_controlled(base, store.clone(), Some(control.clone())).unwrap();
    let data = json!({"revision":0,"catalog_sha256":null,"edit":{"operation":"upsert_manual","draft":draft()}});
    assert_eq!(
        request(&router, &user, "/admin/identity", None, false)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(
            &router,
            &user,
            "/admin/identity/prepare",
            Some(data.clone()),
            true
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(
            &router,
            &admin,
            "/admin/identity/prepare",
            Some(data.clone()),
            false
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert!(!root.path().join("identity").exists());
    let (status, prepared) =
        request(&router, &admin, "/admin/identity/prepare", Some(data), true).await;
    assert_eq!(status, StatusCode::OK, "{prepared}");
    assert_eq!(prepared["active"], false);
    assert_eq!(prepared["review"]["people"]["added"], 1);
    assert_eq!(prepared["review"]["groups"]["added"], 1);
    assert!(control.snapshot().config.identity.is_none());
    let audit = store
        .read(|db| {
            Ok(db
                .prepare("SELECT action FROM audit WHERE action LIKE 'identity_%' ORDER BY id")?
                .query_map([], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .await
        .unwrap();
    assert_eq!(
        audit,
        vec!["identity_prepare_started", "identity_prepare_completed"]
    );
    let mut settings = serde_json::to_value(&control.snapshot().settings).unwrap();
    settings["identity_directory"] = prepared["selection"].clone();
    let (status, applied) = request(
        &router,
        &admin,
        "/admin/config",
        Some(json!({"revision":0,"settings":settings})),
        true,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{applied}");
    let (status, view) = request(
        &router,
        &admin,
        "/admin/identity?source=example-directory",
        None,
        false,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(view["sources"][0]["people"], 1);
    assert_eq!(view["draft"]["people"][0]["display_name"], "Alice Finance");
    let forbidden = request(
        &router,
        &user,
        "/admin/identity?source=example-directory",
        None,
        false,
    )
    .await;
    assert_eq!(forbidden.0, StatusCode::FORBIDDEN);
    assert!(!forbidden.1.to_string().contains("Alice"));
    let removal = json!({"revision":view["revision"],"catalog_sha256":view["catalog_sha256"],"edit":{"operation":"remove","source_id":"example-directory"}});
    let (status, preview) = request(
        &router,
        &admin,
        "/admin/identity/prepare",
        Some(removal),
        true,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{preview}");
    assert_eq!(preview["review"]["requires_attention"], true);
    assert_eq!(preview["review"]["removed_or_disabled"], 2);
    assert_eq!(
        preview["selection"]["reviewed_from"],
        view["catalog_sha256"]
    );
    assert_eq!(
        control.snapshot().config.identity.as_ref().unwrap().sha256,
        view["catalog_sha256"].as_str().unwrap()
    );
    // An administrator's later revocation cannot be bypassed with a prepared digest.
    store
        .run(|db| {
            db.execute("UPDATE users SET admin=0 WHERE username='admin'", [])?;
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(
        request(&router, &admin, "/admin/identity", None, false)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(
            &router,
            &admin,
            "/admin/identity/prepare",
            Some(json!({})),
            true
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
}
#[tokio::test]
async fn malformed_scope_provider_or_stale_revision_cannot_create_a_candidate() {
    let root = tempfile::tempdir().unwrap();
    let base = common::config(root.path());
    let store = Store::open(root.path()).unwrap();
    let admin = account(&store, "admin", true).await;
    let control = Controller::load(base.clone(), store.clone()).await.unwrap();
    let router = api::router_controlled(base, store, Some(control)).unwrap();
    let mut changed = draft();
    changed.source.scopes.insert("unmanaged.example".into());
    let data = json!({"revision":0,"catalog_sha256":null,"edit":{"operation":"upsert_manual","draft":changed}});
    assert_eq!(
        request(&router, &admin, "/admin/identity/prepare", Some(data), true)
            .await
            .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    changed = draft();
    changed.source.provider = directory::Provider::Entra;
    let data = json!({"revision":0,"catalog_sha256":null,"edit":{"operation":"upsert_manual","draft":changed}});
    assert_eq!(
        request(&router, &admin, "/admin/identity/prepare", Some(data), true)
            .await
            .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let data = json!({"revision":9,"catalog_sha256":null,"edit":{"operation":"upsert_manual","draft":draft()}});
    assert_eq!(
        request(&router, &admin, "/admin/identity/prepare", Some(data), true)
            .await
            .0,
        StatusCode::CONFLICT
    );
    assert!(!root.path().join("identity").exists());
}
#[test]
fn review_preserves_other_sources_and_flags_protected_and_mass_changes() {
    use std::collections::BTreeSet;
    let first: directory::Snapshot =
        serde_json::from_str(include_str!("fixtures/identity/directory.json")).unwrap();
    let mut other = first.clone();
    other.source.id = "another".into();
    let document = noisefence::identity::runtime::Document {
        schema: noisefence::identity::runtime::SCHEMA.into(),
        sources: vec![first.clone(), other.clone()],
    };
    let mut changed = draft();
    changed.people[0].activity = directory::Activity::Inactive;
    let candidate = management::preview(
        &document,
        management::Edit::UpsertManual {
            draft: Box::new(changed),
        },
        &BTreeSet::from(["example.test".into()]),
        1_800_000_010,
    )
    .unwrap();
    assert!(candidate.review.requires_attention);
    assert_eq!(candidate.review.removed_or_disabled, 1);
    assert!(candidate.review.protected_identity_changes > 0);
    assert_eq!(
        candidate
            .document
            .sources
            .iter()
            .find(|s| s.source.id == "another")
            .unwrap(),
        &other
    );
    let changed = candidate
        .document
        .sources
        .iter()
        .find(|s| s.source.id == "example-directory")
        .unwrap();
    assert_eq!(changed.generation, 2);
    assert_eq!(changed.completed_at, 1_800_000_010);
}

#[tokio::test]
async fn large_authorized_import_and_revoked_mfa_are_bounded_before_activation() {
    let root = tempfile::tempdir().unwrap();
    let base = common::config(root.path());
    let store = Store::open(root.path()).unwrap();
    let token = account(&store, "admin", true).await;
    let control = Controller::load(base.clone(), store.clone()).await.unwrap();
    let router = api::router_controlled(base, store.clone(), Some(control.clone())).unwrap();
    let mut source = draft();
    let original = source.people[0].clone();
    source.people.extend((0..1500).map(|n| {
        let mut p = original.clone();
        p.id = format!("extra-{n}");
        p.addresses = Default::default();
        p
    }));
    let data = json!({"revision":0,"catalog_sha256":null,"edit":{"operation":"upsert_manual","draft":source}});
    assert!(serde_json::to_vec(&data).unwrap().len() > 128 * 1024);
    let result = request(
        &router,
        &token,
        "/admin/identity/prepare",
        Some(data.clone()),
        true,
    )
    .await;
    assert_eq!(result.0, StatusCode::OK, "{}", result.1);
    assert!(control.snapshot().config.identity.is_none());
    store
        .run(|db| {
            db.execute(
                "INSERT INTO mfa_credentials VALUES('admin',?1,1,0,-1)",
                [vec![0u8; 32]],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    let denied = request(&router, &token, "/admin/identity/prepare", Some(data), true).await;
    assert_eq!(denied.0, StatusCode::UNAUTHORIZED);
    assert_eq!(
        request(&router, &token, "/admin/identity", None, false)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let completed: i64 = store
        .run(|db| {
            Ok(db.query_row(
                "SELECT count(*) FROM audit WHERE action='identity_prepare_completed'",
                [],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap();
    assert_eq!(completed, 1);
}

#[tokio::test]
async fn automatic_memory_is_admin_reviewed_validated_and_durable() {
    let root = tempfile::tempdir().unwrap();
    let base = common::config(root.path());
    let store = Store::open(root.path()).unwrap();
    let admin = account(&store, "admin", true).await;
    let user = account(&store, "user", false).await;
    let control = Controller::load(base.clone(), store.clone()).await.unwrap();
    let router =
        api::router_controlled(base.clone(), store.clone(), Some(control.clone())).unwrap();
    let mut settings = serde_json::to_value(&control.snapshot().settings).unwrap();
    settings["contact_learning"] =
        serde_json::to_value(noisefence::identity::learning::Settings::default()).unwrap();
    let proposal = json!({"revision":0,"settings":settings});
    assert_eq!(
        request(
            &router,
            &user,
            "/admin/config",
            Some(proposal.clone()),
            true
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(
            &router,
            &admin,
            "/admin/config",
            Some(proposal.clone()),
            false
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let mut invalid = proposal.clone();
    invalid["settings"]["contact_learning"]["minimum_campaigns"] = json!(1);
    assert!(
        !request(&router, &admin, "/admin/config", Some(invalid), true)
            .await
            .0
            .is_success()
    );
    assert!(control.snapshot().config.contact_learning.is_none());
    let applied = request(&router, &admin, "/admin/config", Some(proposal), true).await;
    assert_eq!(applied.0, StatusCode::OK, "{:?}", applied.1);
    assert!(
        control
            .snapshot()
            .config
            .contact_learning
            .as_ref()
            .unwrap()
            .enabled
    );
    let revision = control.snapshot().revision;
    let mut stale = serde_json::to_value(&control.snapshot().settings).unwrap();
    stale.as_object_mut().unwrap().remove("contact_learning");
    assert!(
        !request(
            &router,
            &admin,
            "/admin/config",
            Some(json!({"revision":revision,"settings":stale})),
            true
        )
        .await
        .0
        .is_success()
    );
    drop(router);
    drop(control);
    let reloaded = Controller::load(base, store).await.unwrap();
    assert!(
        reloaded
            .snapshot()
            .config
            .contact_learning
            .as_ref()
            .unwrap()
            .enabled
    );
}

#[tokio::test]
async fn entra_sync_is_authenticated_csrf_protected_bounded_and_not_an_import_endpoint() {
    provider_sync_authorization("entra").await;
}
#[tokio::test]
async fn okta_sync_is_authenticated_csrf_protected_bounded_and_not_an_import_endpoint() {
    provider_sync_authorization("okta").await;
}
#[tokio::test]
async fn google_sync_is_authenticated_csrf_protected_bounded_and_not_an_import_endpoint() {
    provider_sync_authorization("google").await;
}
async fn provider_sync_authorization(provider: &str) {
    let root = tempfile::tempdir().unwrap();
    let base = common::config(root.path());
    let store = Store::open(root.path()).unwrap();
    let admin = account(&store, "admin", true).await;
    let user = account(&store, "user", false).await;
    let control = Controller::load(base.clone(), store.clone()).await.unwrap();
    let router = api::router_controlled(base, store.clone(), Some(control)).unwrap();
    let path = format!("/admin/identity/sync/{provider}");
    let mut data = json!({"revision":0,"catalog_sha256":null,"source":draft().source,"client_id":"invalid","client_secret":"dummy","operation":uuid::Uuid::new_v4().to_string()});
    if provider != "entra" {
        let object = data.as_object_mut().unwrap();
        object.remove("client_id");
        object.remove("client_secret");
        object.insert("access_token".into(), json!("dummy"));
    }
    assert_eq!(
        request(&router, &user, &path, Some(data.clone()), true)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(&router, &admin, &path, Some(data.clone()), false)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(&router, &admin, &path, Some(data), true).await.0,
        StatusCode::CONFLICT
    );
    let oversized = json!({"client_secret":"x".repeat(17000)});
    assert_eq!(
        request(&router, &admin, &path, Some(oversized), true)
            .await
            .0,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert_eq!(
        request(
            &router,
            &user,
            "/admin/identity/sync/00000000-0000-4000-8000-000000000001",
            None,
            false
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let count = store
        .read(|db| {
            Ok(db.query_row(
                "SELECT count(*) FROM audit WHERE action='identity_sync'",
                [],
                |r| r.get::<_, i64>(0),
            )?)
        })
        .await
        .unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn saved_directory_access_api_is_private_explicit_bounded_and_recoverable() {
    let root = tempfile::tempdir().unwrap();
    let base = common::config(root.path());
    let store = Store::open(root.path()).unwrap();
    let admin = account(&store, "admin", true).await;
    let user = account(&store, "user", false).await;
    let control = Controller::load(base.clone(), store.clone()).await.unwrap();
    let router = api::router_controlled(base, store.clone(), Some(control.clone())).unwrap();
    let mut source = draft().source;
    source.provider = directory::Provider::Entra;
    source.authority = "11111111-1111-4111-8111-111111111111".into();
    let operation = uuid::Uuid::new_v4().to_string();
    let secret = "SYNTHETIC-API-DIRECTORY-SECRET";
    let body = json!({"operation":operation,"revision":0,"catalog_sha256":null,"expected_generation":null,"source":source,"expires":noisefence::now()+3600,"credential":{"kind":"entra_application","client_id":"22222222-2222-4222-8222-222222222222","client_secret":secret}});
    let endpoint = "/admin/identity/connections";
    assert_eq!(
        request(&router, &user, endpoint, None, false).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(&router, &user, endpoint, Some(body.clone()), true)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(&router, &admin, endpoint, Some(body.clone()), false)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert!(!root.path().join("directory-vault").exists());
    for bad in [
        json!({"revision":99}),
        json!({"expires":noisefence::now()-1}),
        json!({"source":{ "scopes":["outside.test"] }}),
    ] {
        let mut invalid = body.clone();
        for (key, value) in bad.as_object().unwrap() {
            if key == "source" {
                invalid["source"]["scopes"] = value["scopes"].clone();
            } else {
                invalid[key] = value.clone();
            }
        }
        let (status, reply) = request(&router, &admin, endpoint, Some(invalid), true).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(!reply.to_string().contains(secret));
    }
    let mut huge = body.clone();
    huge["credential"]["client_secret"] = "x".repeat(65536).into();
    assert_eq!(
        request(&router, &admin, endpoint, Some(huge), true).await.0,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    let (status, reply) = request(&router, &admin, endpoint, Some(body.clone()), true).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["connections"][0]["generation"], operation);
    assert_eq!(reply["connections"][0]["status"], "configured");
    assert!(
        !reply.to_string().contains(secret)
            && !reply.to_string().contains("sealed")
            && !reply.to_string().contains("key_id")
    );
    // Simulate a lost POST response: the chosen generation is recoverable by GET
    // after controller reconstruction, without resending the plaintext secret.
    let reloaded = Controller::load(control.snapshot().config.clone(), store.clone())
        .await
        .unwrap();
    let view = reloaded
        .directory_connections(
            "admin".into(),
            noisefence::message::digest(admin.as_bytes()),
        )
        .await
        .unwrap();
    assert_eq!(view.connections[0].generation, operation);
    assert_eq!(
        request(&router, &admin, endpoint, Some(body.clone()), true)
            .await
            .0,
        StatusCode::CONFLICT
    );
    let next = uuid::Uuid::new_v4().to_string();
    let mut rotated = body;
    rotated["operation"] = next.clone().into();
    rotated["expected_generation"] = operation.clone().into();
    assert_eq!(
        request(&router, &admin, endpoint, Some(rotated), true)
            .await
            .0,
        StatusCode::OK
    );
    let revoked = "/admin/identity/connections/revoke";
    assert_eq!(
        request(
            &router,
            &admin,
            revoked,
            Some(json!({"source_id":source.id,"generation":operation})),
            true
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let reference = json!({"source_id":source.id,"generation":next});
    let vault = root.path().join("directory-vault");
    std::fs::rename(vault.join("key"), vault.join("key.offline")).unwrap();
    let (status, view) = request(&router, &admin, endpoint, None, false).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(view["vault"], "unavailable");
    assert_eq!(view["connections"][0]["status"], "key_unavailable");
    let attempt = json!({"operation":uuid::Uuid::new_v4().to_string(),"revision":0,"catalog_sha256":null,"connection":reference});
    assert_eq!(
        request(
            &router,
            &admin,
            "/admin/identity/sync/stored",
            Some(attempt),
            true
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    assert!(!vault.join("key").exists());
    std::fs::rename(vault.join("key.offline"), vault.join("key")).unwrap();
    let (_, view) = request(&router, &admin, endpoint, None, false).await;
    assert_eq!(view["connections"][0]["status"], "configured");
    let (status, reply) = request(&router, &admin, revoked, Some(reference.clone()), true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(reply["connections"][0]["status"], "revoked");
    // Refused before any network work; no tenant is contacted by this test.
    let (status,_)=request(&router,&admin,"/admin/identity/sync/stored",Some(json!({"operation":uuid::Uuid::new_v4().to_string(),"revision":0,"catalog_sha256":null,"connection":reference})),true).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(control.snapshot().revision, 0);
    assert!(control.snapshot().config.identity.is_none());
}
