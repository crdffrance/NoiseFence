#[path = "common/directory_connection.rs"]
mod common;
#[path = "common/postgres.rs"]
mod postgres;
use noisefence::{
    central::Central,
    identity::connections::{Record, vault::Key},
    store::Store,
};
async fn setup(f: &postgres::Fixture) -> String {
    let db = f.connect().await;
    let session = "a".repeat(64);
    db.execute("INSERT INTO noisefence.users(username,password,admin) VALUES('admin','unused',true),('reader','unused',false)",&[]).await.unwrap();
    db.execute("INSERT INTO noisefence.sessions(token_hash,username,csrf,expires) VALUES($1,'admin','csrf',$2)",&[&session,&(noisefence::now()+3600)]).await.unwrap();
    session
}
#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn central_connections_are_encrypted_durable_authorized_and_cas_protected() {
    let f = postgres::Fixture::new().await;
    let session = setup(&f).await;
    let db = f.connect().await;
    let root = tempfile::tempdir().unwrap();
    assert!(
        f.central
            .identity_connection_prepare(root.path().into(), "reader", &session)
            .await
            .is_err()
    );
    assert!(!root.path().join("directory-vault").exists());
    let (key, version) = f
        .central
        .identity_connection_prepare(root.path().into(), "admin", &session)
        .await
        .unwrap();
    let first = common::record(
        &key,
        &f.central.directory_connection_authority(),
        version,
        None,
    );
    f.central
        .identity_connection_save(None, &first, "admin", &session)
        .await
        .unwrap();
    f.central
        .identity_connection_save(None, &first, "admin", &session)
        .await
        .unwrap();
    let reopened = Central::new(&f.settings).unwrap();
    let recovered = reopened
        .identity_connection_get("synthetic", &first.metadata.generation, "admin", &session)
        .await
        .unwrap();
    assert!(
        Key::load(root.path())
            .unwrap()
            .open(&recovered, noisefence::now())
            .is_ok()
    );
    assert!(
        reopened
            .identity_connection_list("reader", &session)
            .await
            .is_err()
    );
    let a = common::record(
        &key,
        &f.central.directory_connection_authority(),
        version,
        Some(&first),
    );
    let b = common::record(
        &key,
        &f.central.directory_connection_authority(),
        version,
        Some(&first),
    );
    let (one, two) = tokio::join!(
        f.central
            .identity_connection_save(Some(&first.metadata.generation), &a, "admin", &session),
        reopened.identity_connection_save(Some(&first.metadata.generation), &b, "admin", &session)
    );
    assert_ne!(one.is_ok(), two.is_ok());
    let winner = if one.is_ok() { a } else { b };
    f.central
        .identity_connection_save(Some(&first.metadata.generation), &winner, "admin", &session)
        .await
        .unwrap();
    assert!(
        f.central
            .identity_connection_get("synthetic", &first.metadata.generation, "admin", &session)
            .await
            .is_err()
    );
    assert!(
        f.central
            .identity_connection_revoke("synthetic", &first.metadata.generation, "admin", &session)
            .await
            .is_err()
    );
    let raw: String = db
        .query_one(
            "SELECT record::text FROM noisefence.identity_connections",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(!raw.contains("SYNTHETIC-NO-LIVE-PROVIDER-SECRET"));
    assert!(
        Record::decode(
            &raw,
            "synthetic",
            &f.central.directory_connection_authority()
        )
        .is_ok()
    );
    let public = serde_json::to_string(
        &f.central
            .identity_connection_list("admin", &session)
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(!public.contains("sealed") && !public.contains("SECRET"));
    f.central
        .identity_connection_revoke("synthetic", &winner.metadata.generation, "admin", &session)
        .await
        .unwrap();
    f.central
        .identity_connection_revoke("synthetic", &winner.metadata.generation, "admin", &session)
        .await
        .unwrap();
    assert!(
        f.central
            .identity_connection_get("synthetic", &winner.metadata.generation, "admin", &session)
            .await
            .is_err()
    );
    assert!(
        f.central
            .identity_connection_save(Some(&first.metadata.generation), &winner, "admin", &session)
            .await
            .is_err()
    );
    let raw: String = db
        .query_one(
            "SELECT record::text FROM noisefence.identity_connections",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let record: Record = serde_json::from_str(&raw).unwrap();
    assert!(record.sealed.is_none());
    let audits:i64=db.query_one("SELECT count(*) FROM noisefence.audit WHERE action IN ('identity_connection_saved','identity_connection_revoked')",&[]).await.unwrap().get(0);
    assert_eq!(audits, 3);
    assert_eq!(
        db.query_one(
            "SELECT sha256 FROM noisefence.schema_migrations WHERE version=1",
            &[]
        )
        .await
        .unwrap()
        .get::<_, String>(0),
        noisefence::message::digest(include_bytes!("../src/central/schema.sql"))
    );
    drop(reopened);
    f.finish().await;
}
#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn selected_authority_refuses_local_shadow_and_revoked_owner_rights() {
    let f = postgres::Fixture::new().await;
    let session = setup(&f).await;
    let db = f.connect().await;
    let root = tempfile::tempdir().unwrap();
    let local = Store::open(root.path()).unwrap();
    let hash = session.clone();
    local
        .run(move |db| {
            db.execute("INSERT INTO users VALUES('admin','unused',1,0)", [])?;
            db.execute(
                "INSERT INTO sessions VALUES(?1,'admin','csrf',?2)",
                rusqlite::params![hash, noisefence::now() + 3600],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    let (key, version) = local
        .identity_connection_prepare("admin".into(), session.clone())
        .await
        .unwrap();
    let shadow = common::record(&key, "sqlite", version, None);
    local
        .identity_connection_save(None, shadow.clone(), "admin".into(), session.clone())
        .await
        .unwrap();
    let selected = local.with_management(f.central.clone()).await.unwrap();
    assert!(
        selected
            .identity_connection_list("admin".into(), session.clone())
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        selected
            .identity_connection_get(
                "synthetic".into(),
                shadow.metadata.generation.clone(),
                "admin".into(),
                session.clone()
            )
            .await
            .is_err()
    );
    let (_, version) = selected
        .identity_connection_prepare("admin".into(), session.clone())
        .await
        .unwrap();
    let record = common::record(
        &key,
        &selected.directory_connection_authority(),
        version,
        None,
    );
    selected
        .identity_connection_save(None, record.clone(), "admin".into(), session.clone())
        .await
        .unwrap();
    db.execute(
        "UPDATE noisefence.users SET version=version+1 WHERE username='admin'",
        &[],
    )
    .await
    .unwrap();
    assert!(
        selected
            .identity_connection_get(
                "synthetic".into(),
                record.metadata.generation.clone(),
                "admin".into(),
                session.clone()
            )
            .await
            .is_err()
    );
    assert_eq!(
        selected
            .identity_connection_list("admin".into(), session.clone())
            .await
            .unwrap()[0]
            .status,
        "authorization_changed"
    );
    let (_, version) = selected
        .identity_connection_prepare("admin".into(), session.clone())
        .await
        .unwrap();
    let next = common::record(
        &key,
        &selected.directory_connection_authority(),
        version,
        Some(&record),
    );
    selected
        .identity_connection_save(
            Some(record.metadata.generation),
            next.clone(),
            "admin".into(),
            session.clone(),
        )
        .await
        .unwrap();
    db.execute(
        "UPDATE noisefence.users SET admin=false WHERE username='admin'",
        &[],
    )
    .await
    .unwrap();
    assert!(
        selected
            .identity_connection_list("admin".into(), session.clone())
            .await
            .is_err()
    );
    db.execute(
        "UPDATE noisefence.users SET admin=true WHERE username='admin'",
        &[],
    )
    .await
    .unwrap();
    f.suspend().await;
    assert!(
        selected
            .identity_connection_list("admin".into(), session.clone())
            .await
            .is_err()
    );
    assert!(
        selected
            .identity_connection_get(
                "synthetic".into(),
                shadow.metadata.generation,
                "admin".into(),
                session.clone()
            )
            .await
            .is_err()
    );
    f.resume().await;
    drop(selected);
    f.finish().await;
}
#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn component_migration_is_additive_and_never_replaces_missing_key() {
    let f = postgres::Fixture::new().await;
    let session = setup(&f).await;
    let db = f.connect().await;
    f.central.migrate().await.unwrap();
    let root = tempfile::tempdir().unwrap();
    let (key, version) = f
        .central
        .identity_connection_prepare(root.path().into(), "admin", &session)
        .await
        .unwrap();
    let record = common::record(
        &key,
        &f.central.directory_connection_authority(),
        version,
        None,
    );
    f.central
        .identity_connection_save(None, &record, "admin", &session)
        .await
        .unwrap();
    std::fs::remove_file(root.path().join("directory-vault/key")).unwrap();
    assert!(
        f.central
            .identity_connection_prepare(root.path().into(), "admin", &session)
            .await
            .is_err()
    );
    assert!(!root.path().join("directory-vault/key").exists());
    db.execute(
        "UPDATE noisefence.identity_connection_schema SET version=2",
        &[],
    )
    .await
    .unwrap();
    assert!(f.central.migrate().await.is_err());
    assert!(
        f.central
            .identity_connection_list("admin", &session)
            .await
            .is_err()
    );
    assert!(
        f.central
            .identity_connection_save(None, &record, "admin", &session)
            .await
            .is_err()
    );
    let core: i64 = db
        .query_one("SELECT count(*) FROM noisefence.schema_migrations", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(core, 1);
    let rows: i64 = db
        .query_one("SELECT count(*) FROM noisefence.identity_connections", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(rows, 1);
    f.finish().await;
}

#[path = "common/directory_schedule.rs"]
mod schedule_contract;
#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn selected_postgres_schedules_share_durable_leases_and_use_owner_authorization() {
    let f = postgres::Fixture::new().await;
    let session = setup(&f).await;
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path())
        .unwrap()
        .with_management(f.central.clone())
        .await
        .unwrap();
    let (key, version) = store
        .identity_connection_prepare("admin".into(), session.clone())
        .await
        .unwrap();
    let record = common::record(&key, &store.directory_connection_authority(), version, None);
    store
        .identity_connection_save(None, record.clone(), "admin".into(), session.clone())
        .await
        .unwrap();
    schedule_contract::exercise(&store, root.path(), &session, &record).await;
    let old = store
        .identity_connection_get(
            "synthetic".into(),
            record.metadata.generation.clone(),
            "admin".into(),
            session.clone(),
        )
        .await
        .unwrap()
        .schedule
        .unwrap()
        .grant
        .id;
    schedule_contract::enable(&store, root.path(), &session, &record, Some(old)).await;
    let db = f.connect().await;
    db.execute("DELETE FROM noisefence.sessions", &[])
        .await
        .unwrap();
    let reopened = Store::open(root.path())
        .unwrap()
        .with_management(Central::new(&f.settings).unwrap())
        .await
        .unwrap();
    let row = reopened.identity_schedule_due(0).await.unwrap().remove(0);
    let request = schedule_contract::request(&row);
    reopened
        .identity_schedule_claim(request.clone(), Key::load(root.path()).unwrap())
        .await
        .unwrap();
    reopened
        .identity_schedule_authorized(request.clone())
        .await
        .unwrap();
    db.execute(
        "UPDATE noisefence.users SET version=version+1 WHERE username='admin'",
        &[],
    )
    .await
    .unwrap();
    assert!(
        reopened
            .identity_schedule_authorized(request)
            .await
            .is_err()
    );
    assert!(reopened.identity_schedule_due(0).await.unwrap().is_empty());
    drop(reopened);
    drop(store);
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn scheduled_catalog_preparation_requires_a_live_grant_and_never_activates_policy() {
    for invalidation in ["none", "stopped", "rotated"] {
        scheduled_candidate(invalidation).await;
    }
}
async fn scheduled_candidate(invalidation: &str) {
    use noisefence::identity::{
        directory, management, runtime,
        sync::{self, Event, Outcome},
    };
    let f = postgres::Fixture::new().await;
    let session = setup(&f).await;
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path())
        .unwrap()
        .with_management(f.central.clone())
        .await
        .unwrap();
    let (key, version) = store
        .identity_connection_prepare("admin".into(), session.clone())
        .await
        .unwrap();
    let record = common::record(&key, &store.directory_connection_authority(), version, None);
    store
        .identity_connection_save(None, record.clone(), "admin".into(), session.clone())
        .await
        .unwrap();
    let grant = schedule_contract::enable(&store, root.path(), &session, &record, None).await;
    let row = store.identity_schedule_due(0).await.unwrap().remove(0);
    let req = schedule_contract::request(&row);
    // The ordinary administrator path cannot manufacture a scheduled lease.
    assert!(
        f.central
            .identity_sync_begin(&req, "admin", &session)
            .await
            .is_err()
    );
    store
        .identity_schedule_claim(req.clone(), Key::load(root.path()).unwrap())
        .await
        .unwrap();
    let snapshot = directory::Snapshot {
        schema: directory::SCHEMA.into(),
        source: record.metadata.source.clone(),
        generation: 1,
        completed_at: noisefence::now(),
        people: vec![],
        groups: vec![],
        memberships: Default::default(),
        delegations: Default::default(),
    };
    let empty = runtime::Document {
        schema: runtime::SCHEMA.into(),
        sources: vec![],
    };
    let candidate = management::preview_collected(
        &empty,
        snapshot,
        &record.metadata.source.scopes,
        noisefence::now(),
    )
    .unwrap();
    let bytes = serde_json::to_vec(&candidate.document).unwrap();
    let mut invented = req.clone();
    invented.id = uuid::Uuid::new_v4().to_string();
    assert!(
        f.central
            .prepare_scheduled_identity_directory(root.path().into(), bytes.clone(), 0, &invented)
            .await
            .is_err()
    );
    let selection = f
        .central
        .prepare_scheduled_identity_directory(root.path().into(), bytes.clone(), 0, &req)
        .await
        .unwrap();
    let outcome:Outcome=serde_json::from_value(serde_json::json!({"state":"ready","prepared":{"revision":0,"selection":selection,"review":candidate.review,"active":false}})).unwrap();
    match invalidation {
        "stopped" => store
            .identity_schedule_stop(
                schedule_contract::reference(&record),
                grant.id,
                "admin".into(),
                session.clone(),
            )
            .await
            .unwrap(),
        "rotated" => {
            let next = common::record(
                &key,
                &store.directory_connection_authority(),
                version,
                Some(&record),
            );
            store
                .identity_connection_save(
                    Some(record.metadata.generation.clone()),
                    next,
                    "admin".into(),
                    session.clone(),
                )
                .await
                .unwrap();
        }
        "none" => (),
        _ => unreachable!(),
    }
    if invalidation != "none" {
        assert!(
            f.central
                .prepare_scheduled_identity_directory(root.path().into(), bytes, 0, &req)
                .await
                .is_err()
        );
    }
    store
        .identity_schedule_finish(
            Event {
                request: req.clone(),
                outcome,
            },
            "admin".into(),
        )
        .await
        .unwrap();
    let raw = f
        .central
        .identity_sync_read(&req.id, "admin", &session)
        .await
        .unwrap();
    let event = sync::latest(&raw).unwrap().remove(&req.id).unwrap();
    assert_eq!(
        matches!(event.outcome, Outcome::Ready { .. }),
        invalidation == "none"
    );
    if let Outcome::Ready { prepared } = &event.outcome {
        assert!(!prepared.active);
    }
    if invalidation == "none" {
        let current = store
            .identity_connection_get(
                "synthetic".into(),
                record.metadata.generation.clone(),
                "admin".into(),
                session.clone(),
            )
            .await
            .unwrap();
        let schedule = current.schedule.unwrap();
        assert!(!schedule.due(noisefence::now() + 901, 0));
    }
    assert!(store.identity_schedule_due(0).await.unwrap().is_empty());
    drop(store);
    f.finish().await;
}
