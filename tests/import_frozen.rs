#[allow(dead_code)]
mod common;
use noisefence::{
    central::{
        import::{SourceLocks, frozen::with_source},
        outbox,
    },
    store::Store,
};
use rusqlite::{Connection, OpenFlags};
use std::os::unix::fs::PermissionsExt;

#[tokio::test]
async fn frozen_export_preserves_original_generations_excludes_writers_and_cleans_up() {
    let root = tempfile::tempdir().unwrap();
    let parent = tempfile::tempdir().unwrap();
    let parent = parent.path().canonicalize().unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut config = (*common::config(&root.path().canonicalize().unwrap())).clone();
    config.cluster = Some(toml::from_str("role='coordinator'\nnode_id='mx1'").unwrap());
    let store = Store::open(&config.data_dir).unwrap();
    store.run(|db| {
        db.execute_batch("INSERT INTO cluster_state VALUES('role','coordinator'),('node_id','mx1'); PRAGMA user_version=6;")?;
        let scan=serde_json::to_string(&noisefence::engine::Scan::default())?;
        let id=uuid::Uuid::new_v4().to_string();
        db.execute("INSERT INTO messages(id,created,sender,scan) VALUES(?1,1,'sender@example.test',?2)",rusqlite::params![id,scan])?;
        db.execute("INSERT INTO deliveries(message_id,address,destination,hosts,next_attempt) VALUES(?1,'alice@example.test','alice@example.test','[]',0)",[&id])?;
        Ok(())
    }).await.unwrap();
    let guard = store.daemon_lock().unwrap();
    assert!(with_source(&config, &parent, |_| Ok(())).is_err());
    drop(guard);
    let mut exported = None;
    let mut epoch = None;
    let result: anyhow::Result<()> = with_source(&config, &parent, |source| {
        exported = Some(source.export_path().to_owned());
        epoch = Some(source.receipt.journal.identity.clone());
        assert!(SourceLocks::acquire(&config.data_dir).is_err());
        assert_eq!(
            std::fs::metadata(source.export_path())?
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let mut writer = Connection::open(config.data_dir.join("state.sqlite3"))?;
        writer.busy_timeout(std::time::Duration::ZERO)?;
        assert!(
            writer
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .is_err()
        );
        let copy =
            Connection::open_with_flags(source.export_path(), OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let original = outbox::status(&writer)?;
        let cloned = outbox::status(&copy)?;
        assert_eq!(original.identity, cloned.identity);
        assert_eq!(original.sequence, cloned.sequence);
        assert_eq!(cloned.sequence, source.receipt.journal.sequence);
        assert_eq!(outbox::pending(&writer, 100)?, outbox::pending(&copy, 100)?);
        assert_eq!(
            copy.query_row("PRAGMA quick_check", [], |r| r.get::<_, String>(0))?,
            "ok"
        );
        assert!(source.receipt.bytes > 0);
        assert_eq!(
            source.receipt.sha256,
            noisefence::message::digest(&std::fs::read(source.export_path())?)
        );
        anyhow::bail!("synthetic protocol interruption")
    });
    assert!(
        exported.is_some(),
        "export failed before callback: {result:?}"
    );
    assert!(result.is_err());
    assert!(!exported.unwrap().exists());
    assert_eq!(std::fs::read_dir(&parent).unwrap().count(), 0);
    let guard = SourceLocks::acquire(&config.data_dir).unwrap();
    drop(guard);
    let mut db = Connection::open(config.data_dir.join("state.sqlite3")).unwrap();
    let tx = db
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .unwrap();
    assert_eq!(outbox::identity(&tx).unwrap(), epoch.unwrap());
    assert_eq!(
        tx.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        6
    );
    tx.rollback().unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(with_source(&config, &parent, |_| Ok(())).is_err());
    assert_eq!(std::fs::read_dir(&parent).unwrap().count(), 0);
}

#[tokio::test]
async fn durable_selection_keeps_process_locks_and_never_downgrades_after_interruption() {
    use noisefence::{
        central::{
            binding::Binding,
            selection::{Selection, key_digest},
        },
        cluster::{
            Role,
            activation::{Acknowledgement, Journal, Progress},
            artifacts,
        },
        control::Settings,
    };
    let root = tempfile::tempdir().unwrap();
    let parent = tempfile::tempdir().unwrap();
    let parent = parent.path().canonicalize().unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut config = (*common::config(&root.path().canonicalize().unwrap())).clone();
    config.cluster = Some(toml::from_str("role='coordinator'\nnode_id='mx1'").unwrap());
    let store = Store::open(&config.data_dir).unwrap();
    noisefence::mfa::Key::open(&config.data_dir).unwrap();
    let base = artifacts::capture(&config, Settings::from_config(&config), 0).unwrap();
    let publication = artifacts::bind_credentials(
        artifacts::capture(&config, Settings::from_config(&config), 1).unwrap(),
    )
    .unwrap();
    artifacts::freeze(&config.data_dir, &publication, 0).unwrap();
    let authority = store.run(move |db| {
        db.execute_batch("INSERT INTO cluster_state VALUES('role','coordinator'),('node_id','mx1'); PRAGMA user_version=6;")?;
        let tx=db.transaction()?;
        Journal::initialize(&tx,"mx1",base.bundle)?;
        let journal=Journal::begin(&tx,publication.bundle,vec!["mx1".into()],1)?;
        let epoch=journal.rollout().unwrap().epoch().clone();
        Journal::acknowledge(&tx,"mx1",&Acknowledgement{epoch:epoch.clone(),progress:Progress::Prepared},2)?;
        Journal::commit(&tx,&epoch,3)?;
        Journal::acknowledge(&tx,"mx1",&Acknowledgement{epoch:epoch.clone(),progress:Progress::Applied},4)?;
        let released=Journal::release(&tx,&epoch,5)?;
        let local=serde_json::json!({"version":1,"node":"mx1","authority":released,"installed":released.current(),"installed_epoch":epoch,"prepared":epoch});
        tx.execute("INSERT INTO cluster_state VALUES('activation_participant',?1)",[local.to_string()])?;
        tx.commit()?;
        Ok(released)
    }).await.unwrap();
    let mut installed = None;
    let result: anyhow::Result<()> = with_source(&config, &parent, |source| {
        let selection = Selection::new(
            Binding {
                instance: uuid::Uuid::new_v4().to_string(),
                source_digest: "a".repeat(64),
            },
            source.receipt.journal.identity.clone(),
            Role::Coordinator,
            authority.current_epoch(),
            Some(key_digest(&config.data_dir)?),
        )?;
        let mut wrong = selection.clone();
        wrong.mfa_key_sha256 = Some("b".repeat(64));
        assert!(source.select(&authority, &wrong).is_err());
        let db = Connection::open(config.data_dir.join("state.sqlite3"))?;
        assert_eq!(
            db.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))?,
            6
        );
        let actual = source.select(&authority, &selection)?;
        assert_eq!(actual, selection);
        assert_eq!(Selection::read(&db)?, Some(selection.clone()));
        assert!(
            SourceLocks::acquire(&config.data_dir).is_err(),
            "hold daemon locks after durable local commit"
        );
        assert!(source.select(&authority, &selection).is_err());
        installed = Some(selection);
        anyhow::bail!("synthetic loss of coordinator acknowledgement")
    });
    assert!(
        installed.is_some(),
        "selection failed before intended interruption: {result:?}"
    );
    assert!(result.is_err());
    let db = Connection::open(config.data_dir.join("state.sqlite3")).unwrap();
    assert_eq!(Selection::read(&db).unwrap(), installed);
    assert!(
        Store::open(&config.data_dir).is_err(),
        "legacy startup must stay fenced"
    );
    assert!(SourceLocks::acquire(&config.data_dir).is_ok());
    assert_eq!(std::fs::read_dir(&parent).unwrap().count(), 0);
}
