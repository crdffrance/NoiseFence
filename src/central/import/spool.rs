//! Complete offline metadata capture, including already acknowledged history.
use crate::central::{history, logs, outbox};
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, Transaction};

const MAX_ROWS: usize = 100_000;
const MAX_BYTES: usize = 256 * 1024 * 1024;

/// Coordinator copies need reconciliation against the owning spool. Their
/// numeric delivery/log IDs and legacy generations are not the owner's IDs.
pub struct Mirror {
    pub owner: String,
    pub updated: i64,
    pub record: crate::cluster::history::Record,
}
pub struct MirrorLog {
    pub owner: String,
    pub local_id: i64,
    pub message_id: String,
    pub recipient: String,
    pub log: logs::Log,
}
/// Sensitive metadata: deliberately neither Debug nor serializable as a whole.
/// Capture under the offline installer's daemon/worker locks, then commit the
/// caller transaction before copying to PostgreSQL. No bodies are read here.
pub struct SpoolSnapshot {
    pub identity: outbox::Identity,
    pub metadata: Vec<history::Event>,
    pub logs: Vec<logs::Event>,
    pub mirrors: Vec<Mirror>,
    pub mirror_logs: Vec<MirrorLog>,
}
impl SpoolSnapshot {
    /// Reseed retained owner rows, preserving existing deletion tombstones.
    /// A savepoint rolls back reseeding on any validation/size error even if the
    /// caller catches it and commits its outer transaction. New generations are
    /// durable in the same journal used by future runtime updates/receipts.
    pub fn capture(tx: &mut Transaction<'_>) -> Result<Self> {
        let save = tx.savepoint()?;
        let result = capture(&save, true, None)?;
        save.commit()?;
        Ok(result)
    }
    /// Re-read the exact frozen import generation without reseeding journals.
    /// All retained owner rows must still have pending journal entries.
    pub fn read_seeded(tx: &Transaction<'_>) -> Result<Self> {
        capture(tx, false, None)
    }
    /// Verify the same journal after a partial local format-seven commit.
    pub fn read_selected(
        tx: &Transaction<'_>,
        selected: &crate::central::selection::Selection,
    ) -> Result<Self> {
        capture(tx, false, Some(selected))
    }
}
fn bounded_total(bytes: &mut usize, rows: &mut usize, size: usize) -> Result<()> {
    *bytes = bytes.checked_add(size).context("Snapshot size overflow")?;
    *rows += 1;
    ensure!(
        *bytes <= MAX_BYTES && *rows <= MAX_ROWS,
        "Spool snapshot exceeds bounds"
    );
    Ok(())
}
fn capture(
    db: &Connection,
    reseed: bool,
    selected: Option<&crate::central::selection::Selection>,
) -> Result<SpoolSnapshot> {
    let version: i64 = db.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    ensure!(
        version == if selected.is_some() { 7 } else { 6 },
        "Spool format differs from the requested capture mode"
    );
    ensure!(
        crate::central::selection::Selection::read(db)?.as_ref() == selected
            && !(reseed && selected.is_some()),
        "Spool selection differs from the requested capture authority"
    );
    let identity = outbox::identity(db)?;
    ensure!(
        crate::cluster::valid_id(&identity.node)
            && uuid::Uuid::parse_str(&identity.epoch)
                .is_ok_and(|u| u.to_string() == identity.epoch),
        "Invalid spool identity"
    );
    ensure!(
        db.prepare("PRAGMA foreign_key_check")?
            .query([])?
            .next()?
            .is_none(),
        "Spool has inconsistent foreign keys"
    );
    let (count, size): (i64, i64) = db.query_row(
        "SELECT (SELECT count(*) FROM messages)+(SELECT count(*) FROM delivery_attempts)+(SELECT count(*) FROM management_outbox)+(SELECT count(*) FROM management_log_outbox),
        coalesce((SELECT sum(length(CAST(scan AS BLOB))) FROM messages),0)+coalesce((SELECT sum(length(CAST(trace AS BLOB))) FROM delivery_attempts),0)", [], |r| Ok((r.get(0)?,r.get(1)?)))?;
    ensure!(
        count <= 2 * MAX_ROWS as i64 && size <= MAX_BYTES as i64,
        "Spool snapshot exceeds bounds"
    );
    // Bounds are checked in SQLite before any potentially large field is copied
    // into Rust. Detailed event validation follows on the projected records.
    let invalid: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM messages m WHERE length(m.id)>36 OR length(m.sender)>254 OR length(CAST(m.scan AS BLOB))>2097152 OR m.is_dsn NOT IN(0,1) OR m.raw_present NOT IN(0,1) OR (SELECT count(*) FROM deliveries d WHERE d.message_id=m.id) NOT BETWEEN 1 AND 100 OR length(CAST(m.scan AS BLOB))+coalesce((SELECT sum(length(CAST(coalesce(f.assessment,'') AS BLOB))+length(CAST(coalesce(d.error,'') AS BLOB))+length(d.address)+length(d.destination)+256) FROM deliveries d LEFT JOIN delivery_filtering f ON f.delivery_id=d.id WHERE d.message_id=m.id),0)>3000000)
        OR EXISTS(SELECT 1 FROM delivery_attempts WHERE length(CAST(trace AS BLOB))>524288)
        OR EXISTS(SELECT 1 FROM cluster_origin WHERE length(node_id)>100 OR node_id=?1 OR remote_id<>message_id OR raw_present NOT IN(0,1))", [&identity.node], |r| r.get(0))?;
    ensure!(!invalid, "Invalid or oversized retained metadata");
    let sequence: i64 = db.query_row(
        "SELECT sequence FROM management_journal WHERE id=1",
        [],
        |r| r.get(0),
    )?;
    let highest: i64 = db.query_row("SELECT max(coalesce((SELECT max(generation) FROM management_outbox),0),coalesce((SELECT max(generation) FROM management_log_outbox),0))",[],|r|r.get(0))?;
    ensure!(
        sequence >= highest && sequence >= 0 && sequence < i64::MAX - 2 * MAX_ROWS as i64,
        "Invalid management sequence"
    );
    let contradictory: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM management_outbox o JOIN messages m ON m.id=o.message_id WHERE o.deleted<>0) OR EXISTS(SELECT 1 FROM management_log_outbox o JOIN delivery_attempts a ON a.id=o.log_id WHERE o.deleted<>0)",[],|r|r.get(0))?;
    ensure!(
        !contradictory,
        "Retained rows conflict with deletion tombstones"
    );
    if reseed {
        db.execute("INSERT INTO management_outbox(message_id,generation,deleted) SELECT m.id,j.sequence+row_number() OVER(ORDER BY m.id),0 FROM messages m JOIN management_journal j ON j.id=1 WHERE NOT EXISTS(SELECT 1 FROM cluster_origin c WHERE c.message_id=m.id) ON CONFLICT(message_id) DO UPDATE SET generation=excluded.generation,deleted=0",[])?;
        db.execute("UPDATE management_journal SET sequence=max(sequence,coalesce((SELECT max(generation) FROM management_outbox),0)) WHERE id=1",[])?;
        db.execute("INSERT INTO management_log_outbox(log_id,generation,message_id,recipient,deleted) SELECT a.id,j.sequence+row_number() OVER(ORDER BY a.id),d.message_id,d.address,0 FROM delivery_attempts a JOIN deliveries d ON d.id=a.delivery_id JOIN management_journal j ON j.id=1 WHERE NOT EXISTS(SELECT 1 FROM cluster_origin c WHERE c.message_id=d.message_id) ON CONFLICT(log_id) DO UPDATE SET generation=excluded.generation,message_id=excluded.message_id,recipient=excluded.recipient,deleted=0",[])?;
        db.execute("UPDATE management_journal SET sequence=max(sequence,coalesce((SELECT max(generation) FROM management_log_outbox),0)) WHERE id=1",[])?;
    } else {
        let missing: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM messages m WHERE NOT EXISTS(SELECT 1 FROM cluster_origin c WHERE c.message_id=m.id) AND NOT EXISTS(SELECT 1 FROM management_outbox o WHERE o.message_id=m.id AND o.deleted=0)) OR EXISTS(SELECT 1 FROM delivery_attempts a JOIN deliveries d ON d.id=a.delivery_id WHERE NOT EXISTS(SELECT 1 FROM cluster_origin c WHERE c.message_id=d.message_id) AND NOT EXISTS(SELECT 1 FROM management_log_outbox o WHERE o.log_id=a.id AND o.deleted=0 AND o.message_id=d.message_id AND o.recipient=d.address))", [], |r| r.get(0))?;
        ensure!(
            !missing,
            "Frozen import journal is incomplete; source capture is no longer valid"
        );
    }
    let mut result = SpoolSnapshot {
        identity,
        metadata: Vec::new(),
        logs: Vec::new(),
        mirrors: Vec::new(),
        mirror_logs: Vec::new(),
    };
    let mut bytes = 0;
    let mut total = 0;
    let mut query=db.prepare("SELECT o.message_id,o.generation,o.deleted,c.node_id FROM management_outbox o LEFT JOIN cluster_origin c ON c.message_id=o.message_id ORDER BY o.generation LIMIT 100001")?;
    let mut rows = query.query([])?;
    while let Some(row) = rows.next()? {
        ensure!(
            row.get::<_, Option<String>>(3)?.is_none(),
            "Owner journal contains a mirrored message"
        );
        let receipt = outbox::Entry {
            id: row.get(0)?,
            generation: row.get(1)?,
            deleted: row.get(2)?,
        };
        let record = if receipt.deleted {
            None
        } else {
            Some(crate::cluster::history::snapshot(
                db,
                receipt.id.clone(),
                receipt.generation,
                false,
            )?)
        };
        let event = history::Event { receipt, record };
        event.validate()?;
        bounded_total(&mut bytes, &mut total, serde_json::to_vec(&event)?.len())?;
        result.metadata.push(event);
    }
    let mut query=db.prepare("SELECT c.node_id,c.message_id,c.remote_version,c.raw_present,c.updated FROM cluster_origin c ORDER BY c.message_id LIMIT 100001")?;
    let mut rows = query.query([])?;
    while let Some(row) = rows.next()? {
        let owner: String = row.get(0)?;
        ensure!(crate::cluster::valid_id(&owner), "Invalid mirror owner");
        let id: String = row.get(1)?;
        let generation: i64 = row.get(2)?;
        let mut record = crate::cluster::history::snapshot(db, id.clone(), generation, false)?;
        record.raw_present = row.get(3)?;
        let event = history::Event {
            receipt: outbox::Entry {
                id,
                generation,
                deleted: false,
            },
            record: Some(record),
        };
        event.validate()?;
        bounded_total(&mut bytes, &mut total, serde_json::to_vec(&event)?.len())?;
        result.mirrors.push(Mirror {
            owner,
            updated: row.get(4)?,
            record: event.record.unwrap(),
        });
    }
    let mut query=db.prepare("SELECT o.log_id,o.generation,o.message_id,o.recipient,o.deleted,a.attempt,a.trace,c.node_id FROM management_log_outbox o LEFT JOIN delivery_attempts a ON a.id=o.log_id LEFT JOIN cluster_origin c ON c.message_id=o.message_id ORDER BY o.generation LIMIT 100001")?;
    let mut rows = query.query([])?;
    while let Some(row) = rows.next()? {
        ensure!(
            row.get::<_, Option<String>>(7)?.is_none(),
            "Owner journal contains a mirrored transcript"
        );
        let receipt = logs::Receipt {
            local_id: row.get(0)?,
            generation: row.get(1)?,
            deleted: row.get(4)?,
        };
        let log = if receipt.deleted {
            None
        } else {
            Some(logs::Log {
                attempt: row.get(5)?,
                trace: serde_json::from_str(&row.get::<_, String>(6)?)?,
            })
        };
        let mut event = logs::Event {
            receipt,
            message_id: row.get(2)?,
            recipient: row.get(3)?,
            log,
        };
        event.validate()?;
        bounded_total(&mut bytes, &mut total, serde_json::to_vec(&event)?.len())?;
        result.logs.push(event);
    }
    let mut query=db.prepare("SELECT c.node_id,a.id,d.message_id,d.address,a.attempt,a.trace FROM delivery_attempts a JOIN deliveries d ON d.id=a.delivery_id JOIN cluster_origin c ON c.message_id=d.message_id ORDER BY a.id LIMIT 100001")?;
    let mut rows = query.query([])?;
    while let Some(row) = rows.next()? {
        let mut event = logs::Event {
            receipt: logs::Receipt {
                local_id: row.get(1)?,
                generation: 1,
                deleted: false,
            },
            message_id: row.get(2)?,
            recipient: row.get(3)?,
            log: Some(logs::Log {
                attempt: row.get(4)?,
                trace: serde_json::from_str(&row.get::<_, String>(5)?)?,
            }),
        };
        event.validate()?;
        bounded_total(&mut bytes, &mut total, serde_json::to_vec(&event)?.len())?;
        result.mirror_logs.push(MirrorLog {
            owner: row.get(0)?,
            local_id: event.receipt.local_id,
            message_id: event.message_id,
            recipient: event.recipient,
            log: event.log.unwrap(),
        });
    }
    Ok(result)
}
