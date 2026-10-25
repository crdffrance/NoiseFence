#[path = "common/directory_connection.rs"]
mod common;
use noisefence::{
    identity::connections::{Record, vault::Key},
    store::Store,
};
async fn setup() -> (tempfile::TempDir, Store) {
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path()).unwrap();
    store.run(|db| { db.execute_batch("INSERT INTO users VALUES('admin','unused',1,0),('other','unused',1,0),('user','unused',0,0)")?;
        for (session,user) in [("a","admin"),("o","other"),("u","user")] {
            db.execute("INSERT INTO sessions VALUES(?1,?2,'csrf',?3)",rusqlite::params![session,user,noisefence::now()+3600])?;
        } Ok(()) }).await.unwrap();
    (root, store)
}
async fn save(store: &Store, record: &Record, previous: Option<&Record>) -> anyhow::Result<()> {
    store
        .identity_connection_save(
            previous.map(|p| p.metadata.generation.clone()),
            record.clone(),
            "admin".into(),
            "a".into(),
        )
        .await
}
async fn get(store: &Store, record: &Record) -> anyhow::Result<Record> {
    store
        .identity_connection_get(
            record.metadata.source.id.clone(),
            record.metadata.generation.clone(),
            "admin".into(),
            "a".into(),
        )
        .await
}
#[tokio::test]
async fn sqlite_encrypted_connections_survive_restart_and_revoke_with_cas() {
    let (root, store) = setup().await;
    let (key, version) = store
        .identity_connection_prepare("admin".into(), "a".into())
        .await
        .unwrap();
    let first = common::record(&key, &store.directory_connection_authority(), version, None);
    save(&store, &first, None).await.unwrap();
    save(&store, &first, None).await.unwrap();
    let reopened = Store::open(root.path()).unwrap();
    let value = get(&reopened, &first).await.unwrap();
    assert!(
        Key::load(root.path())
            .unwrap()
            .open(&value, noisefence::now())
            .is_ok()
    );
    let second = common::record(&key, "sqlite", version, Some(&first));
    save(&store, &second, Some(&first)).await.unwrap();
    save(&store, &second, Some(&first)).await.unwrap();
    assert!(get(&store, &first).await.is_err());
    assert!(save(&store, &first, None).await.is_err());
    assert!(
        store
            .identity_connection_revoke(
                "synthetic".into(),
                first.metadata.generation.clone(),
                "admin".into(),
                "a".into()
            )
            .await
            .is_err()
    );
    store
        .identity_connection_revoke(
            "synthetic".into(),
            second.metadata.generation.clone(),
            "other".into(),
            "o".into(),
        )
        .await
        .unwrap();
    store
        .identity_connection_revoke(
            "synthetic".into(),
            second.metadata.generation.clone(),
            "other".into(),
            "o".into(),
        )
        .await
        .unwrap();
    assert!(get(&store, &second).await.is_err());
    assert!(save(&store, &second, Some(&first)).await.is_err());
    let list = store
        .identity_connection_list("admin".into(), "a".into())
        .await
        .unwrap();
    assert_eq!(list[0].status, "revoked");
    let public = serde_json::to_string(&list).unwrap();
    assert!(!public.contains("sealed") && !public.contains("SECRET"));
    store.run(|db| {
        let raw:String=db.query_row("SELECT record FROM identity_connections",[],|r|r.get(0))?;
        assert!(!raw.contains("SECRET")); let record:Record=serde_json::from_str(&raw)?; assert!(record.sealed.is_none());
        let count:i64=db.query_row("SELECT count(*) FROM audit WHERE action IN ('identity_connection_saved','identity_connection_revoked')",[],|r|r.get(0))?;
        assert_eq!(count,3); Ok(())
    }).await.unwrap();
}
#[tokio::test]
async fn sqlite_privilege_mfa_and_owner_version_are_checked_before_use() {
    let (root, store) = setup().await;
    assert!(
        store
            .identity_connection_prepare("user".into(), "u".into())
            .await
            .is_err()
    );
    assert!(!root.path().join("directory-vault").exists());
    let (key, version) = store
        .identity_connection_prepare("admin".into(), "a".into())
        .await
        .unwrap();
    let record = common::record(&key, "sqlite", version, None);
    save(&store, &record, None).await.unwrap();
    assert!(
        store
            .identity_connection_list("user".into(), "u".into())
            .await
            .is_err()
    );
    assert!(
        store
            .identity_connection_get(
                "synthetic".into(),
                record.metadata.generation.clone(),
                "admin".into(),
                "u".into()
            )
            .await
            .is_err()
    );
    store
        .run(|db| {
            db.execute("INSERT INTO console_user_versions VALUES('admin',1)", [])?;
            Ok(())
        })
        .await
        .unwrap();
    assert!(get(&store, &record).await.is_err());
    let list = store
        .identity_connection_list("other".into(), "o".into())
        .await
        .unwrap();
    assert_eq!(list[0].status, "authorization_changed");
    let next = common::record(&key, "sqlite", 1, Some(&record));
    save(&store, &next, Some(&record)).await.unwrap();
    store
        .run(|db| {
            db.execute(
                "INSERT INTO mfa_credentials VALUES('admin',?1,1,0,-1)",
                [vec![0u8; 48]],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    assert!(get(&store, &next).await.is_err());
    assert!(
        store
            .identity_connection_prepare("admin".into(), "a".into())
            .await
            .is_err()
    );
    store
        .run(|db| {
            db.execute("UPDATE users SET disabled=1 WHERE username='admin'", [])?;
            Ok(())
        })
        .await
        .unwrap();
    assert!(
        store
            .identity_connection_get(
                "synthetic".into(),
                next.metadata.generation,
                "other".into(),
                "o".into()
            )
            .await
            .is_err()
    );
}
#[tokio::test]
async fn sqlite_schema_mismatch_and_missing_key_refuse_without_replacement() {
    let (root, store) = setup().await;
    let (key, version) = store
        .identity_connection_prepare("admin".into(), "a".into())
        .await
        .unwrap();
    let record = common::record(&key, "sqlite", version, None);
    save(&store, &record, None).await.unwrap();
    let path = root.path().join("directory-vault/key");
    std::fs::remove_file(&path).unwrap();
    assert!(
        store
            .identity_connection_prepare("admin".into(), "a".into())
            .await
            .is_err()
    );
    assert!(!path.exists());
    store
        .run(|db| {
            db.execute("UPDATE identity_connection_schema SET version=2", [])?;
            Ok(())
        })
        .await
        .unwrap();
    assert!(
        store
            .identity_connection_list("admin".into(), "a".into())
            .await
            .is_err()
    );
    assert!(save(&store, &record, None).await.is_err());
}
#[tokio::test]
async fn sqlite_separate_connections_serialize_rotation_and_preserve_source() {
    let (root, store) = setup().await;
    let other = Store::open(root.path()).unwrap();
    let (key, version) = store
        .identity_connection_prepare("admin".into(), "a".into())
        .await
        .unwrap();
    let first = common::record(&key, "sqlite", version, None);
    save(&store, &first, None).await.unwrap();
    let second = common::record(&key, "sqlite", version, Some(&first));
    let competing = common::record(&key, "sqlite", version, Some(&first));
    let (a, b) = tokio::join!(
        save(&store, &second, Some(&first)),
        save(&other, &competing, Some(&first))
    );
    assert_ne!(a.is_ok(), b.is_ok());
    let winner = if a.is_ok() { second } else { competing };
    let mut changed = common::record(&key, "sqlite", version, Some(&winner));
    changed.metadata.source.authority = "33333333-3333-4333-8333-333333333333".into();
    assert!(save(&store, &changed, Some(&winner)).await.is_err());
    let mut wrong = common::record(&key, "postgres:other", version, Some(&winner));
    assert!(save(&store, &wrong, Some(&winner)).await.is_err());
    wrong.metadata.authority = "sqlite".into();
    wrong.metadata.expires = noisefence::now();
    assert!(save(&store, &wrong, Some(&winner)).await.is_err());
}

#[tokio::test]
async fn sqlite_import_refuses_to_silently_discard_authority_bound_connections() {
    let (_root, store) = setup().await;
    let (key, version) = store
        .identity_connection_prepare("admin".into(), "a".into())
        .await
        .unwrap();
    let record = common::record(&key, "sqlite", version, None);
    save(&store, &record, None).await.unwrap();
    store
        .run(|db| {
            let tx = db.transaction()?;
            let error = noisefence::central::import::AccountsSnapshot::capture(&tx, None)
                .err()
                .unwrap();
            assert!(error.to_string().contains("explicit credential migration"));
            assert_eq!(
                tx.query_row("SELECT count(*) FROM identity_connections", [], |r| r
                    .get::<_, i64>(0))?,
                1
            );
            Ok(())
        })
        .await
        .unwrap();
}

#[path = "common/directory_schedule.rs"]
mod schedule_contract;
#[tokio::test]
async fn sqlite_schedules_share_durable_leases_and_revoke_without_browser_sessions() {
    let (root, store) = setup().await;
    let (key, version) = store
        .identity_connection_prepare("admin".into(), "a".into())
        .await
        .unwrap();
    let record = common::record(&key, "sqlite", version, None);
    save(&store, &record, None).await.unwrap();
    schedule_contract::exercise(&store, root.path(), "a", &record).await;
    let old = get(&store, &record)
        .await
        .unwrap()
        .schedule
        .unwrap()
        .grant
        .id;
    schedule_contract::enable(&store, root.path(), "a", &record, Some(old)).await;
    // Logging out is not revocation of the explicit finite grant.
    store
        .run(|db| {
            db.execute("DELETE FROM sessions WHERE username='admin'", [])?;
            Ok(())
        })
        .await
        .unwrap();
    let restarted = Store::open(root.path()).unwrap();
    let row = restarted.identity_schedule_due(0).await.unwrap().remove(0);
    let request = schedule_contract::request(&row);
    restarted
        .identity_schedule_claim(request.clone(), Key::load(root.path()).unwrap())
        .await
        .unwrap();
    restarted
        .identity_schedule_authorized(request.clone())
        .await
        .unwrap();
    store
        .run(|db| {
            db.execute("INSERT INTO console_user_versions VALUES('admin',1)", [])?;
            Ok(())
        })
        .await
        .unwrap();
    assert!(
        restarted
            .identity_schedule_authorized(request)
            .await
            .is_err()
    );
    assert!(restarted.identity_schedule_due(0).await.unwrap().is_empty());
}
#[tokio::test]
async fn sqlite_schedule_tampering_fails_closed_before_admission() {
    let (root, store) = setup().await;
    let (key, version) = store
        .identity_connection_prepare("admin".into(), "a".into())
        .await
        .unwrap();
    let record = common::record(&key, "sqlite", version, None);
    save(&store, &record, None).await.unwrap();
    schedule_contract::enable(&store, root.path(), "a", &record, None).await;
    store
        .run(|db| {
            let raw: String =
                db.query_row("SELECT record FROM identity_connections", [], |r| r.get(0))?;
            let mut value: Record = serde_json::from_str(&raw)?;
            value.schedule.as_mut().unwrap().grant.interval_seconds = 1800;
            db.execute(
                "UPDATE identity_connections SET record=?1",
                [value.encode()?],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    let row = store.identity_schedule_due(0).await.unwrap().remove(0);
    assert!(
        store
            .identity_schedule_claim(
                schedule_contract::request(&row),
                Key::load(root.path()).unwrap()
            )
            .await
            .is_err()
    );
    store
        .run(|db| {
            let count: i64 = db.query_row(
                "SELECT count(*) FROM audit WHERE action='identity_sync'",
                [],
                |r| r.get(0),
            )?;
            assert_eq!(count, 0);
            Ok(())
        })
        .await
        .unwrap();
}
