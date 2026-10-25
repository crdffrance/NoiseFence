use super::*;
use crate::{identity::directory, store::Store};
async fn setup() -> (tempfile::TempDir, Arc<Controller>, String) {
    let root = tempfile::tempdir().unwrap();
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut config: crate::config::Config =
        toml::from_str(include_str!("../../../config/development.toml")).unwrap();
    config.data_dir = root.path().into();
    config.smtp.minimum_free_bytes = 0;
    let store = Store::open(root.path()).unwrap();
    store
        .run(|db| {
            db.execute("INSERT INTO users VALUES('admin','unused',1,0)", [])?;
            db.execute(
                "INSERT INTO sessions VALUES('session','admin','csrf',?1)",
                [crate::now() + 3600],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    let control = Controller::load(Arc::new(config), store).await.unwrap();
    (root, control, "session".into())
}
fn snapshot() -> directory::Snapshot {
    let mut snapshot: directory::Snapshot = serde_json::from_str(include_str!(
        "../../../tests/fixtures/identity/directory.json"
    ))
    .unwrap();
    snapshot.source.provider = directory::Provider::Entra;
    snapshot.source.authority = "11111111-1111-4111-8111-111111111111".into();
    snapshot.completed_at = crate::now();
    snapshot.generation = 1;
    snapshot
}
fn request(source: &str) -> Request {
    let now = crate::now();
    Request {
        id: uuid::Uuid::new_v4().to_string(),
        source_id: source.into(),
        runner: uuid::Uuid::new_v4().to_string(),
        revision: 0,
        catalog_sha256: None,
        created: now,
        deadline: now + 360,
    }
}
fn empty() -> runtime::Document {
    runtime::Document {
        schema: runtime::SCHEMA.into(),
        sources: vec![],
    }
}
#[tokio::test]
async fn entra_candidate_survives_restart_without_implicit_activation() {
    candidate_survives_restart(directory::Provider::Entra).await;
}
#[tokio::test]
async fn okta_candidate_survives_restart_without_implicit_activation() {
    candidate_survives_restart(directory::Provider::Okta).await;
}
async fn candidate_survives_restart(provider: directory::Provider) {
    let (_root, c, session) = setup().await;
    let mut s = snapshot();
    if provider == directory::Provider::Okta {
        s.source.authority = "example.okta.com".into();
    }
    s.source.provider = provider;
    let mut req = request(&s.source.id);
    req.runner = c.identity_sync_runner.clone();
    c.identity_sync_begin(&req, "admin".into(), session.clone())
        .await
        .unwrap();
    assert_eq!(
        c.identity_sync_status(req.id.clone(), "admin".into(), session.clone())
            .await
            .unwrap()
            .state,
        "running"
    );
    let other_instance = Controller::load(c.base.clone(), c.store.clone())
        .await
        .unwrap();
    let unknown = other_instance
        .identity_sync_status(req.id.clone(), "admin".into(), session.clone())
        .await
        .unwrap();
    assert_eq!(unknown.state, "outcome_unknown");
    assert!(
        other_instance
            .identity_sync_begin(&req, "admin".into(), session.clone())
            .await
            .is_err()
    );
    let prepared = c
        .prepare_collected_directory(
            &req,
            empty(),
            s,
            BTreeSet::from(["example.test".into()]),
            "admin".into(),
            session.clone(),
        )
        .await
        .unwrap();
    assert!(!prepared.active && c.snapshot().config.identity.is_none());
    c.identity_sync_finish(
        Event {
            request: req.clone(),
            outcome: Outcome::Ready {
                prepared: Box::new(prepared.clone()),
            },
        },
        "admin".into(),
    )
    .await
    .unwrap();
    let restarted = Controller::load(c.base.clone(), c.store.clone())
        .await
        .unwrap();
    let view = restarted
        .identity_sync_status(req.id.clone(), "admin".into(), session.clone())
        .await
        .unwrap();
    assert_eq!(view.state, "ready");
    assert!(!view.stale);
    assert_eq!(view.prepared.unwrap().selection, prepared.selection);
    assert!(restarted.snapshot().config.identity.is_none());
    let next = prepared
        .selection
        .apply(&c.base.data_dir, None)
        .unwrap()
        .unwrap();
    let doc = runtime::read_document(&next, crate::now()).unwrap();
    assert!(
        doc.sources[0]
            .people
            .iter()
            .all(|p| p.protected_roles.is_empty())
    );
    assert!(doc.sources[0].groups.iter().all(|g| !g.protected));
    assert!(
        c.identity_sync_finish(
            Event {
                request: req,
                outcome: Outcome::Failed {
                    reason: Failure::Collection
                }
            },
            "admin".into()
        )
        .await
        .is_err()
    );
}
#[tokio::test]
async fn synchronization_refuses_revoked_authorization_stale_policy_and_ambiguous_receipts() {
    let (_root, c, session) = setup().await;
    let s = snapshot();
    let mut req = request(&s.source.id);
    req.revision = 1;
    assert!(matches!(
        c.prepare_collected_directory(
            &req,
            empty(),
            s.clone(),
            BTreeSet::from(["example.test".into()]),
            "admin".into(),
            session.clone()
        )
        .await,
        Err(Failure::Stale)
    ));
    req.revision = 0;
    c.identity_sync_begin(&req, "admin".into(), session.clone())
        .await
        .unwrap();
    c.store
        .run(|db| {
            db.execute("UPDATE users SET disabled=1 WHERE username='admin'", [])?;
            Ok(())
        })
        .await
        .unwrap();
    assert!(
        c.identity_sync_status(req.id.clone(), "admin".into(), session.clone())
            .await
            .is_err()
    );
    assert!(matches!(
        c.prepare_collected_directory(
            &req,
            empty(),
            s,
            BTreeSet::from(["example.test".into()]),
            "admin".into(),
            session.clone()
        )
        .await,
        Err(Failure::Authorization)
    ));
    // Outcome recording is permitted for the already-authorized operation but
    // grants no new read, preparation or activation after revocation.
    c.identity_sync_finish(
        Event {
            request: req.clone(),
            outcome: Outcome::Failed {
                reason: Failure::Authorization,
            },
        },
        "admin".into(),
    )
    .await
    .unwrap();
    assert!(c.snapshot().config.identity.is_none());
    assert!(!c.base.data_dir.join("identity").exists());
}
#[test]
fn provider_refresh_preserves_protection_and_refuses_missing_protected_identity() {
    let old = snapshot();
    let previous = runtime::Document {
        schema: runtime::SCHEMA.into(),
        sources: vec![old.clone()],
    };
    let mut new = old.clone();
    new.generation += 1;
    new.completed_at += 1;
    new.people[0].protected_roles.clear();
    new.groups[0].protected = false;
    let candidate = management::preview_collected(
        &previous,
        new.clone(),
        &BTreeSet::from(["example.test".into()]),
        new.completed_at,
    )
    .unwrap();
    assert_eq!(
        candidate.document.sources[0].people[0].protected_roles,
        old.people[0].protected_roles
    );
    assert!(candidate.document.sources[0].groups[0].protected);
    new.people.clear();
    new.memberships.clear();
    new.delegations.clear();
    assert!(
        management::preview_collected(
            &previous,
            new,
            &BTreeSet::from(["example.test".into()]),
            crate::now() + 1
        )
        .is_err()
    );
}
