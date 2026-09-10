//! Keep revision triggers understood by 0.5.0-dev.4 on a binary rollback.
use anyhow::Result;
use rusqlite::Connection;
pub(super) fn install(db: &Connection) -> Result<()> {
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
        BEGIN UPDATE sender_history_epoch SET revision=revision+1 WHERE id=1; END;",super::super::TTL_SECONDS))?;
    Ok(())
}
