//! Constant-time validation of a short-lived history snapshot at durable enqueue.
//! Human corrections, grants and edits invalidate the snapshot. Ordinary incoming
//! mail does not: it has no human feedback and cannot create correspondent trust.
use anyhow::{Result, ensure};
use rusqlite::Connection;

pub fn install(db: &Connection) -> Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS sender_history_epoch(id INTEGER PRIMARY KEY CHECK(id=1),revision INTEGER NOT NULL DEFAULT 0);
        INSERT OR IGNORE INTO sender_history_epoch(id) VALUES(1);")?;
    for table in ["feedback", "feedback_categories", "grants", "users"] {
        for operation in ["INSERT", "UPDATE", "DELETE"] {
            db.execute_batch(&format!("CREATE TRIGGER IF NOT EXISTS history_epoch_{table}_{operation} AFTER {operation} ON {table}
                BEGIN UPDATE sender_history_epoch SET revision=revision+1 WHERE id=1; END;"))?;
        }
    }
    for (table, fields) in [
        ("deliveries", "address,destination,message_id"),
        ("messages", "created,is_dsn,scan"),
        (
            "sender_history_receipts",
            "recipient,destination,sender,domain,received,raw_hash,campaign,simhash,eligible",
        ),
    ] {
        // A just-enqueued message can receive its sandbox report inside this
        // transaction. It has no feedback and could not have influenced trust.
        let condition = if table == "messages" {
            "WHEN EXISTS(SELECT 1 FROM feedback WHERE message_id=OLD.id) OR EXISTS(SELECT 1 FROM feedback_categories WHERE message_id=OLD.id)"
        } else {
            ""
        };
        db.execute_batch(&format!("CREATE TRIGGER IF NOT EXISTS history_epoch_{table}_routing AFTER UPDATE OF {fields} ON {table} {condition}
            BEGIN UPDATE sender_history_epoch SET revision=revision+1 WHERE id=1; END;"))?;
    }
    // Cascades for deleting a message/delivery reach its history receipts. Expired
    // rows were excluded from the snapshot and periodic pruning must not force
    // unrelated SMTP retries. The snapshot deadline also covers time-only expiry.
    db.execute_batch(&format!("CREATE TRIGGER IF NOT EXISTS history_epoch_receipt_delete AFTER DELETE ON sender_history_receipts
        WHEN OLD.received>CAST(strftime('%s','now') AS INTEGER)-{}
        BEGIN UPDATE sender_history_epoch SET revision=revision+1 WHERE id=1; END;",super::TTL_SECONDS))?;
    Ok(())
}

/// Opaque and non-serializable: only a live history read transaction creates it.
#[derive(Clone)]
pub struct Epoch {
    revision: i64,
    as_of: i64,
    expires: i64,
}
impl std::fmt::Debug for Epoch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HistoryEpoch { private snapshot }")
    }
}
impl Epoch {
    pub(super) fn capture(db: &Connection, now: i64) -> Result<Self> {
        ensure!(
            !db.is_autocommit(),
            "history epoch requires a read snapshot"
        );
        let revision = db.query_row(
            "SELECT revision FROM sender_history_epoch WHERE id=1",
            [],
            |r| r.get(0),
        )?;
        Ok(Self {
            revision,
            as_of: now,
            expires: now + 5,
        })
    }
    pub(super) fn expire_before(&mut self, deadline: i64) {
        self.expires = self.expires.min(deadline);
    }
    pub(crate) fn validate(&self, db: &Connection, now: i64) -> Result<()> {
        ensure!(
            !db.is_autocommit(),
            "history epoch requires the enqueue transaction"
        );
        ensure!(
            now >= self.as_of && now < self.expires,
            "sender history snapshot expired; retry analysis"
        );
        let current: i64 = db.query_row(
            "SELECT revision FROM sender_history_epoch WHERE id=1",
            [],
            |r| r.get(0),
        )?;
        ensure!(
            current == self.revision,
            "sender history changed; retry analysis"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn expired_and_future_snapshots_are_rejected_without_sleeping() {
        let root = tempfile::tempdir().unwrap();
        let store = crate::store::Store::open(root.path()).unwrap();
        store
            .run(|db| {
                let tx = db.transaction()?;
                let now = crate::now();
                let current = Epoch::capture(&tx, now)?;
                current.validate(&tx, now)?;
                assert!(current.validate(&tx, now + 5).is_err());
                assert!(current.validate(&tx, now - 1).is_err());
                assert!(Epoch::capture(&tx, now - 6)?.validate(&tx, now).is_err());
                Ok(())
            })
            .await
            .unwrap();
    }
    #[tokio::test]
    async fn later_feedback_change_invalidates_snapshot_across_store_instances() {
        let root = tempfile::tempdir().unwrap();
        let store = crate::store::Store::open(root.path()).unwrap();
        let epoch = store
            .run(|db| {
                let tx = db.transaction()?;
                Epoch::capture(&tx, crate::now())
            })
            .await
            .unwrap();
        let other = crate::store::Store::open(root.path()).unwrap();
        other
            .run(|db| {
                db.execute(
                    "INSERT INTO users(username,password,admin) VALUES('new','unused',0)",
                    [],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        store
            .run(move |db| {
                let tx = db.transaction()?;
                assert!(epoch.validate(&tx, crate::now()).is_err());
                Ok(())
            })
            .await
            .unwrap();
    }
}
