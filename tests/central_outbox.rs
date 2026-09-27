use noisefence::{central::outbox, store::Store};
use rusqlite::params;

fn insert(db: &rusqlite::Connection, id: &str) {
    db.execute(
        "INSERT INTO messages(id,created,sender,scan) VALUES(?1,0,'sender@example.test','{}')",
        [id],
    )
    .unwrap();
    db.execute("INSERT INTO deliveries(message_id,address,destination,hosts,next_attempt) VALUES(?1,'alice@example.test','alice@example.test','[]',0)", [id]).unwrap();
}

#[tokio::test]
async fn local_commit_rollback_and_lost_ack_preserve_new_generations() {
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path()).unwrap();
    store
        .run(|db| {
            let identity = outbox::initialize(db, "mx1")?;
            let tx = db.transaction()?;
            insert(&tx, "rolled-back");
            tx.rollback()?;
            assert!(outbox::pending(db, 12)?.is_empty());
            insert(db, "accepted");
            let first = outbox::pending(db, 12)?;
            assert_eq!(first.len(), 1);
            db.execute(
                "UPDATE deliveries SET status='delivered' WHERE message_id='accepted'",
                [],
            )?;
            assert_eq!(outbox::acknowledge(db, &identity, &first)?, 0);
            let newer = outbox::pending(db, 12)?;
            assert!(newer[0].generation > first[0].generation);
            assert_eq!(outbox::acknowledge(db, &identity, &newer)?, 1);
            assert_eq!(outbox::acknowledge(db, &identity, &newer)?, 0);
            assert_eq!(outbox::status(db)?.pending, 0);
            Ok(())
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn retention_leaves_tombstone_and_restart_preserves_epoch() {
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path()).unwrap();
    let identity = store
        .run(|db| {
            let identity = outbox::initialize(db, "mx1")?;
            insert(db, "expired");
            db.execute("DELETE FROM messages WHERE id='expired'", [])?;
            let entries = outbox::pending(db, 12)?;
            assert_eq!(entries.len(), 1);
            assert!(entries[0].deleted);
            Ok(identity)
        })
        .await
        .unwrap();
    drop(store);
    let reopened = Store::open(root.path()).unwrap();
    reopened
        .run(move |db| {
            assert_eq!(outbox::initialize(db, "mx1")?, identity);
            assert_eq!(outbox::status(db)?.tombstones, 1);
            assert!(outbox::initialize(db, "mx2").is_err());
            let mut wrong = identity.clone();
            wrong.epoch = uuid::Uuid::new_v4().to_string();
            let entries = outbox::pending(db, 12)?;
            assert!(outbox::acknowledge(db, &wrong, &entries).is_err());
            assert_eq!(outbox::status(db)?.pending, 1);
            Ok(())
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn imported_remote_history_is_not_claimed_as_local() {
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path()).unwrap();
    store
        .run(|db| {
            outbox::initialize(db, "mx1")?;
            let tx = db.transaction()?;
            insert(&tx, "remote");
            tx.execute(
                "INSERT INTO cluster_origin VALUES('remote','mx2','remote',0,0,1)",
                [],
            )?;
            tx.commit()?;
            assert!(outbox::pending(db, 12)?.is_empty());
            db.execute("UPDATE messages SET scan='{}' WHERE id='remote'", [])?;
            db.execute("DELETE FROM messages WHERE id='remote'", [])?;
            assert!(outbox::pending(db, 12)?.is_empty());
            Ok(())
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn metadata_variants_and_transcripts_are_journaled() {
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path()).unwrap();
    store
        .run(|db| {
            insert(db, "existing");
            let identity = outbox::initialize(db, "mx1")?;
            let entries = outbox::pending(db, 12)?;
            assert_eq!(entries.len(), 1);
            outbox::acknowledge(db, &identity, &entries)?;
            let id: i64 = db.query_row("SELECT id FROM deliveries", [], |r| r.get(0))?;
            for sql in [
                "INSERT INTO delivery_policy(delivery_id,action) VALUES(?1,'quarantine')",
                "INSERT INTO delivery_filtering(delivery_id,assessment) VALUES(?1,'{}')",
                "INSERT INTO delivery_attempts(delivery_id,attempt,trace) VALUES(?1,1,'{}')",
            ] {
                db.execute(sql, params![id])?;
                let entries = outbox::pending(db, 12)?;
                assert_eq!(entries.len(), 1);
                assert!(!entries[0].deleted);
                outbox::acknowledge(db, &identity, &entries)?;
            }
            Ok(())
        })
        .await
        .unwrap();
}
