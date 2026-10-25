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
        scheduled: None,
        connection: None,
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
#[tokio::test]
async fn google_candidate_survives_restart_without_implicit_activation() {
    candidate_survives_restart(directory::Provider::Google).await;
}
fn collected(snapshot: directory::Snapshot) -> entra::Collected {
    entra::Collected {
        snapshot,
        requests: 5,
        pages: 4,
        bytes: 1200,
        excluded_members: std::collections::BTreeMap::from([("external_membership".into(), 2)]),
    }
}
async fn candidate_survives_restart(provider: directory::Provider) {
    let (_root, c, session) = setup().await;
    let mut s = snapshot();
    if provider == directory::Provider::Okta {
        s.source.authority = "example.okta.com".into();
    }
    if provider == directory::Provider::Google {
        s.source.authority = "C01234567".into();
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
            collected(s),
            BTreeSet::from(["example.test".into()]),
            "admin".into(),
            Some(session.clone()),
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
    let restored = view.prepared.unwrap();
    assert_eq!(restored.selection, prepared.selection);
    assert_eq!(restored.collection, prepared.collection);
    assert!(restored.review.requires_attention);
    assert_eq!(
        restored.collection.unwrap().excluded_members["external_membership"],
        2
    );
    // Old terminal receipts omitted collection accounting. They remain readable.
    let mut legacy = prepared.clone();
    legacy.collection = None;
    let old = Event {
        request: req.clone(),
        outcome: Outcome::Ready {
            prepared: Box::new(legacy),
        },
    }
    .encode()
    .unwrap();
    assert!(!old.contains("collection"));
    assert_eq!(Event::decode(&old).unwrap().encode().unwrap(), old);
    let mut invalid = prepared.clone();
    invalid
        .collection
        .as_mut()
        .unwrap()
        .excluded_members
        .insert("raw provider text".into(), 1);
    assert!(
        Event {
            request: req.clone(),
            outcome: Outcome::Ready {
                prepared: Box::new(invalid)
            }
        }
        .encode()
        .is_err()
    );
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
            collected(s.clone()),
            BTreeSet::from(["example.test".into()]),
            "admin".into(),
            Some(session.clone())
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
            collected(s),
            BTreeSet::from(["example.test".into()]),
            "admin".into(),
            Some(session.clone())
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

async fn saved_access(
    c: &Controller,
    session: &str,
    source: Source,
) -> crate::identity::connections::Reference {
    use crate::identity::connections::{Credential, Metadata, PROTOCOL, Reference};
    let (key, version) = c
        .store
        .identity_connection_prepare("admin".into(), session.into())
        .await
        .unwrap();
    let generation = uuid::Uuid::new_v4().to_string();
    let reference = Reference {
        source_id: source.id.clone(),
        generation: generation.clone(),
    };
    let record = key
        .seal(
            Metadata {
                protocol: PROTOCOL.into(),
                source,
                generation,
                supersedes: None,
                authority: c.store.directory_connection_authority(),
                key_id: key.id(),
                owner: "admin".into(),
                owner_version: version,
                created: crate::now(),
                expires: crate::now() + 3600,
            },
            &Credential::EntraApplication {
                client_id: "22222222-2222-4222-8222-222222222222".into(),
                client_secret: "SYNTHETIC-SECRET-NEVER-LOG".into(),
            },
        )
        .unwrap();
    c.store
        .identity_connection_save(None, record, "admin".into(), session.into())
        .await
        .unwrap();
    reference
}
#[tokio::test]
async fn stored_collection_cancellation_never_publishes_revoked_material() {
    let (_root, c, session) = setup().await;
    let snapshot = snapshot();
    let reference = saved_access(&c, &session, snapshot.source.clone()).await;
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let req = c
        .start_directory_sync(
            uuid::Uuid::new_v4().to_string(),
            0,
            None,
            snapshot.source.clone(),
            Collector::Synthetic(receiver),
            "admin".into(),
            session.clone(),
            Some(reference.clone()),
        )
        .await
        .unwrap();
    // No provider request runs: the synthetic transport stays pending until the
    // authorization watcher observes the persisted revocation and drops it.
    c.store
        .identity_connection_revoke(
            reference.source_id.clone(),
            reference.generation.clone(),
            "admin".into(),
            session.clone(),
        )
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let view = c
                .identity_sync_status(req.id.clone(), "admin".into(), session.clone())
                .await
                .unwrap();
            if view.state == "failed" {
                assert!(matches!(view.reason, Some(Failure::Authorization)));
                assert!(view.prepared.is_none());
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(sender.send(collected(snapshot)).is_err());
    assert_eq!(c.snapshot().revision, 0);
    assert!(c.snapshot().config.identity.is_none());
}
#[tokio::test]
async fn stored_ready_receipt_rechecks_revocation_in_its_commit_transaction() {
    let (_root, c, session) = setup().await;
    let s = snapshot();
    let reference = saved_access(&c, &session, s.source.clone()).await;
    let mut req = request(&s.source.id);
    req.runner = c.identity_sync_runner.clone();
    req.connection = Some(reference.clone());
    c.identity_sync_begin(&req, "admin".into(), session.clone())
        .await
        .unwrap();
    let prepared = c
        .prepare_collected_directory(
            &req,
            empty(),
            collected(s.clone()),
            s.source.scopes.clone(),
            "admin".into(),
            Some(session.clone()),
        )
        .await
        .unwrap();
    c.store
        .identity_connection_revoke(
            reference.source_id.clone(),
            reference.generation,
            "admin".into(),
            session.clone(),
        )
        .await
        .unwrap();
    c.identity_sync_finish_authorized(
        Event {
            request: req.clone(),
            outcome: Outcome::Ready {
                prepared: Box::new(prepared),
            },
        },
        "admin".into(),
        Some(session.clone()),
    )
    .await
    .unwrap();
    let view = c
        .identity_sync_status(req.id, "admin".into(), session.clone())
        .await
        .unwrap();
    assert_eq!(view.state, "failed");
    assert!(matches!(view.reason, Some(Failure::Authorization)));
    assert!(view.prepared.is_none());
    let mut next = request(&s.source.id);
    next.connection = req.connection;
    assert!(
        c.identity_sync_begin(&next, "admin".into(), session)
            .await
            .is_err()
    );
    c.store
        .read(|db| {
            let mut rows = db.prepare("SELECT object_id FROM audit")?;
            for row in rows.query_map([], |r| r.get::<_, String>(0))? {
                assert!(!row?.contains("SYNTHETIC-SECRET-NEVER-LOG"));
            }
            Ok(())
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn scheduled_collection_survives_logout_but_requires_review_and_live_grant() {
    use crate::identity::{
        connections::vault::Key,
        schedule::{Grant, PROTOCOL},
    };
    let (root, c, session) = setup().await;
    let snapshot = snapshot();
    let reference = saved_access(&c, &session, snapshot.source.clone()).await;
    let grant = Grant {
        protocol: PROTOCOL.into(),
        id: uuid::Uuid::new_v4().to_string(),
        connection: reference.clone(),
        created: crate::now(),
        expires: crate::now() + 1800,
        interval_seconds: 900,
    };
    c.store
        .identity_schedule_save(
            reference.clone(),
            None,
            grant.clone(),
            Key::load(root.path()).unwrap(),
            "admin".into(),
            session.clone(),
        )
        .await
        .unwrap();
    let record = c.store.identity_schedule_due(0).await.unwrap().remove(0);
    let mut req = request(&snapshot.source.id);
    req.runner = c.identity_sync_runner.clone();
    req.connection = Some(reference.clone());
    req.scheduled = Some(
        record
            .schedule
            .as_ref()
            .unwrap()
            .binding(&record.metadata)
            .unwrap(),
    );
    assert!(
        c.identity_sync_begin(&req, "admin".into(), session.clone())
            .await
            .is_err()
    );
    c.store
        .identity_schedule_claim(req.clone(), Key::load(root.path()).unwrap())
        .await
        .unwrap();
    c.store
        .run(|db| {
            db.execute("DELETE FROM sessions", [])?;
            Ok(())
        })
        .await
        .unwrap();
    let prepared = c
        .prepare_collected_directory(
            &req,
            empty(),
            collected(snapshot.clone()),
            snapshot.source.scopes.clone(),
            "admin".into(),
            None,
        )
        .await
        .unwrap();
    assert!(!prepared.active && c.snapshot().config.identity.is_none());
    // Grant revocation between preparation and terminal commit forbids Ready.
    c.store
        .run(|db| {
            db.execute(
                "INSERT INTO sessions VALUES('again','admin','csrf',?1)",
                [crate::now() + 3600],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    c.store
        .identity_schedule_stop(reference, grant.id, "admin".into(), "again".into())
        .await
        .unwrap();
    c.identity_sync_finish_authorized(
        Event {
            request: req.clone(),
            outcome: Outcome::Ready {
                prepared: Box::new(prepared),
            },
        },
        "admin".into(),
        None,
    )
    .await
    .unwrap();
    let view = c
        .identity_sync_status(req.id, "admin".into(), "again".into())
        .await
        .unwrap();
    assert_eq!(view.state, "failed");
    assert!(matches!(view.reason, Some(Failure::Authorization)));
    assert!(view.prepared.is_none());
    assert_eq!(c.snapshot().revision, 0);
}

#[tokio::test]
async fn scheduled_worker_shares_one_shot_admission_and_cancels_on_stop() {
    use crate::identity::{
        connections::vault::Key,
        schedule::{Grant, PROTOCOL},
    };
    let (root, c, session) = setup().await;
    let snapshot = snapshot();
    let reference = saved_access(&c, &session, snapshot.source.clone()).await;
    let grant = Grant {
        protocol: PROTOCOL.into(),
        id: uuid::Uuid::new_v4().to_string(),
        connection: reference.clone(),
        created: crate::now(),
        expires: crate::now() + 1800,
        interval_seconds: 900,
    };
    c.store
        .identity_schedule_save(
            reference.clone(),
            None,
            grant.clone(),
            Key::load(root.path()).unwrap(),
            "admin".into(),
            session.clone(),
        )
        .await
        .unwrap();
    let record = c.store.identity_schedule_due(0).await.unwrap().remove(0);
    let mut req = request(&snapshot.source.id);
    req.runner = c.identity_sync_runner.clone();
    req.connection = Some(reference.clone());
    req.scheduled = Some(
        record
            .schedule
            .as_ref()
            .unwrap()
            .binding(&record.metadata)
            .unwrap(),
    );
    let mut manual = req.clone();
    manual.id = uuid::Uuid::new_v4().to_string();
    manual.scheduled = None;
    c.identity_sync_begin(&manual, "admin".into(), session.clone())
        .await
        .unwrap();
    assert!(
        c.store
            .identity_schedule_claim(req.clone(), Key::load(root.path()).unwrap())
            .await
            .is_err()
    );
    c.identity_sync_finish_authorized(
        Event {
            request: manual,
            outcome: Outcome::Failed {
                reason: Failure::Collection,
            },
        },
        "admin".into(),
        Some(session.clone()),
    )
    .await
    .unwrap();
    c.store
        .identity_schedule_claim(req.clone(), Key::load(root.path()).unwrap())
        .await
        .unwrap();
    let (send, receive) = tokio::sync::oneshot::channel();
    let task = c.launch_directory_collection(
        req.clone(),
        empty(),
        snapshot.source.clone(),
        snapshot.source.scopes.clone(),
        1,
        Collector::Synthetic(receive),
        "admin".into(),
        None,
    );
    c.store
        .identity_schedule_stop(reference, grant.id, "admin".into(), session.clone())
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
    assert!(send.send(collected(snapshot)).is_err());
    let view = c
        .identity_sync_status(req.id, "admin".into(), session)
        .await
        .unwrap();
    assert_eq!(view.state, "failed");
    assert!(matches!(view.reason, Some(Failure::Authorization)));
    assert!(view.prepared.is_none());
    assert_eq!(c.snapshot().revision, 0);
}
#[tokio::test]
async fn stopped_schedule_daemon_does_not_initialize_a_vault() {
    let (root, c, _) = setup().await;
    let (_stop, rx) = tokio::sync::watch::channel(true);
    c.run_directory_schedules(rx).await.unwrap();
    assert!(!root.path().join("directory-vault").exists());
}
