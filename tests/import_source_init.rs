#[allow(dead_code)]
mod common;
use noisefence::{
    central::{import::offline::initialize_source, outbox},
    store::Store,
};

#[tokio::test]
async fn original_spool_epoch_is_durable_idempotent_and_requires_stopped_writers() {
    let root = tempfile::tempdir().unwrap();
    let mut config = (*common::config(&root.path().canonicalize().unwrap())).clone();
    config.cluster = Some(toml::from_str("role='coordinator'\nnode_id='mx2'").unwrap());
    let store = Store::open(&config.data_dir).unwrap();
    store.run(|db|{db.execute_batch("INSERT INTO cluster_state VALUES('role','coordinator'),('node_id','mx2'); PRAGMA user_version=6;")?;Ok(())}).await.unwrap();
    let guard = store.daemon_lock().unwrap();
    assert!(initialize_source(&config).is_err());
    store
        .read(|db| {
            assert_eq!(
                db.query_row(
                    "SELECT count(*) FROM sqlite_master WHERE name='management_journal'",
                    [],
                    |r| r.get::<_, i64>(0)
                )?,
                0
            );
            Ok(())
        })
        .await
        .unwrap();
    drop(guard);
    let first = initialize_source(&config).unwrap();
    assert_eq!(first.node, "mx2");
    assert_eq!(initialize_source(&config).unwrap(), first);
    let saved = store.read(|db| outbox::identity(db)).await.unwrap();
    assert_eq!(saved, first);
    config.cluster.as_mut().unwrap().node_id = "another".into();
    assert!(initialize_source(&config).is_err());
    store
        .read(|db| {
            assert_eq!(
                db.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))?,
                6
            );
            Ok(())
        })
        .await
        .unwrap();
}
