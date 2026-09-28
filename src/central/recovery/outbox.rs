//! Offline replay preparation. Never changes SMTP delivery or replication state.
use crate::central::{outbox, selection::Selection};
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};

/// The supervisor must hold this source's daemon/calibration locks and freeze
/// central writers. `high_water` comes from that exact restored source authority.
/// Keep the recorded floor on retries, rather than recomputing it during replay.
pub fn requeue(
    db: &mut Connection,
    expected: &Selection,
    operation: &str,
    high_water: i64,
    log_id_floor: i64,
) -> Result<Value> {
    ensure!(
        high_water >= 0
            && (0..i64::MAX).contains(&log_id_floor)
            && uuid::Uuid::parse_str(operation).is_ok_and(|id| id.to_string() == operation),
        "Invalid recovery replay inputs"
    );
    let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    ensure!(
        Selection::read(&tx)?.as_ref() == Some(expected) && outbox::identity(&tx)? == expected.node,
        "Recovery replay authority mismatch"
    );
    let pending: String = tx
        .query_row(
            "SELECT value FROM cluster_state WHERE key='management_recovery_required'",
            [],
            |r| r.get(0),
        )
        .context("Recovery replay requires a stopped, fenced source")?;
    let pending: Value = serde_json::from_str(&pending)?;
    ensure!(
        pending["protocol"] == "noisefence-management-recovery-1"
            && pending["operation"] == operation,
        "Recovery replay operation differs from the source fence"
    );
    let previous: Option<String> = tx
        .query_row(
            "SELECT value FROM cluster_state WHERE key='management_recovery_outbox'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    if let Some(previous) = previous {
        let previous: Value = serde_json::from_str(&previous)?;
        ensure!(
            previous["protocol"] == "noisefence-management-replay-1"
                && previous["operation"] == operation
                && previous["selection"] == serde_json::to_value(expected)?
                && previous["central_high_water"] == high_water
                && previous["central_log_id_floor"] == log_id_floor,
            "Another recovery replay is already recorded"
        );
        reserve_log_ids(&tx, log_id_floor)?;
        tx.commit()?;
        return Ok(previous);
    }
    let log_sequence = reserve_log_ids(&tx, log_id_floor)?;
    let orphan: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM management_outbox o WHERE NOT deleted AND NOT EXISTS(SELECT 1 FROM messages m WHERE m.id=o.message_id)) OR EXISTS(SELECT 1 FROM management_log_outbox o WHERE NOT deleted AND NOT EXISTS(SELECT 1 FROM delivery_attempts a WHERE a.id=o.log_id))", [], |r| r.get(0))?;
    ensure!(
        !orphan,
        "Incomplete local history cannot be silently discarded during recovery"
    );
    let base: i64 = tx.query_row("SELECT MAX(sequence,?1,COALESCE((SELECT MAX(generation) FROM management_outbox),0),COALESCE((SELECT MAX(generation) FROM management_log_outbox),0)) FROM management_journal WHERE id=1", [high_water], |r| r.get(0))?;
    tx.execute_batch("CREATE TEMP TABLE recovery_messages AS
        SELECT id AS message_id,0 AS deleted FROM messages m
          WHERE NOT EXISTS(SELECT 1 FROM cluster_origin c WHERE c.message_id=m.id)
        UNION ALL SELECT message_id,1 FROM management_outbox o WHERE deleted=1
          AND NOT EXISTS(SELECT 1 FROM messages m WHERE m.id=o.message_id);
        CREATE TEMP TABLE recovery_logs AS
        SELECT a.id AS log_id,d.message_id,d.address AS recipient,0 AS deleted
          FROM delivery_attempts a JOIN deliveries d ON d.id=a.delivery_id JOIN messages m ON m.id=d.message_id
          WHERE NOT EXISTS(SELECT 1 FROM cluster_origin c WHERE c.message_id=m.id)
        UNION ALL SELECT log_id,message_id,recipient,1 FROM management_log_outbox o WHERE deleted=1
          AND NOT EXISTS(SELECT 1 FROM delivery_attempts a WHERE a.id=o.log_id)
          AND NOT EXISTS(SELECT 1 FROM cluster_origin c WHERE c.message_id=o.message_id)
          AND NOT EXISTS(SELECT 1 FROM recovery_messages m WHERE m.message_id=o.message_id AND m.deleted=1);")?;
    let messages: i64 = tx.query_row("SELECT count(*) FROM recovery_messages", [], |r| r.get(0))?;
    let logs: i64 = tx.query_row("SELECT count(*) FROM recovery_logs", [], |r| r.get(0))?;
    let count = messages
        .checked_add(logs)
        .context("Recovery replay count overflow")?;
    ensure!(count <= 1_000_000, "Recovery replay exceeds source limit");
    let end = base
        .checked_add(count)
        .context("Recovery replay generation overflow")?;
    tx.execute("DELETE FROM management_outbox", [])?;
    tx.execute("INSERT INTO management_outbox(message_id,generation,deleted) SELECT message_id,?1+row_number() OVER(ORDER BY message_id),deleted FROM recovery_messages", [base])?;
    tx.execute("DELETE FROM management_log_outbox", [])?;
    tx.execute("INSERT INTO management_log_outbox(log_id,generation,message_id,recipient,deleted) SELECT log_id,?1+row_number() OVER(ORDER BY log_id),message_id,recipient,deleted FROM recovery_logs", [base + messages])?;
    tx.execute(
        "UPDATE management_journal SET sequence=?1 WHERE id=1",
        [end],
    )?;
    let result = json!({"protocol":"noisefence-management-replay-1","operation":operation,
        "selection":expected,"central_high_water":high_water,"central_log_id_floor":log_id_floor,"log_sequence":log_sequence,"first_generation":if count>0 {Some(base+1)} else {None},
        "sequence":end,"scheduled_messages":messages,"scheduled_logs":logs});
    tx.execute(
        "INSERT INTO cluster_state(key,value) VALUES('management_recovery_outbox',?1)",
        params![serde_json::to_string(&result)?],
    )?;
    tx.execute_batch("DROP TABLE recovery_logs; DROP TABLE recovery_messages;")?;
    tx.commit()?;
    Ok(result)
}

/// Reserve every previously observed ID before any future SMTP attempt can insert.
/// Called inside the same transaction as the replay receipt and outbox generation.
fn reserve_log_ids(tx: &rusqlite::Transaction<'_>, floor: i64) -> Result<i64> {
    let mut q = tx.prepare("SELECT seq FROM sqlite_sequence WHERE name='delivery_attempts'")?;
    let existing = q
        .query_map([], |r| r.get::<_, i64>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    ensure!(
        existing.len() <= 1 && existing.iter().all(|v| *v >= 0),
        "Invalid local transcript allocator"
    );
    let maximum:i64=tx.query_row("SELECT MAX(COALESCE((SELECT MAX(id) FROM delivery_attempts),0),COALESCE((SELECT MAX(log_id) FROM management_log_outbox),0))",[],|r|r.get(0))?;
    let sequence = floor
        .max(maximum)
        .max(existing.first().copied().unwrap_or(0));
    ensure!(
        (0..i64::MAX).contains(&sequence),
        "Local transcript ID space exhausted"
    );
    if existing.is_empty() {
        tx.execute(
            "INSERT INTO sqlite_sequence(name,seq) VALUES('delivery_attempts',?1)",
            [sequence],
        )?;
    } else {
        tx.execute(
            "UPDATE sqlite_sequence SET seq=?1 WHERE name='delivery_attempts'",
            [sequence],
        )?;
    }
    Ok(sequence)
}
