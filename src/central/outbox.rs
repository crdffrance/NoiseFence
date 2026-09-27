//! Local metadata journal. Recording an event never opens a PostgreSQL connection.
//!
//! Changes coalesce per message, while acknowledgements compare generations. A
//! lost acknowledgement can replay a committed projection but cannot erase a
//! newer local change. Tombstones survive metadata retention until acknowledged.
use anyhow::{Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub node: String,
    pub epoch: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub id: String,
    pub generation: i64,
    pub deleted: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct Status {
    pub identity: Identity,
    pub sequence: i64,
    pub pending: u64,
    pub tombstones: u64,
    pub pending_logs: u64,
    pub log_tombstones: u64,
}

pub fn initialize(db: &mut Connection, node: &str) -> Result<Identity> {
    ensure!(
        crate::cluster::valid_id(node),
        "Invalid management journal node"
    );
    let tx = db.transaction()?;
    tx.execute_batch(include_str!("outbox.sql"))?;
    tx.execute_batch(include_str!("log-outbox.sql"))?;
    let created = tx.execute(
        "INSERT OR IGNORE INTO management_journal(id,node,epoch,sequence) VALUES(1,?1,?2,0)",
        params![node, uuid::Uuid::new_v4().to_string()],
    )? == 1;
    let identity = identity(&tx)?;
    ensure!(
        identity.node == node,
        "Management journal belongs to another node"
    );
    if created {
        let ids = tx.prepare("SELECT id FROM messages WHERE NOT EXISTS(SELECT 1 FROM cluster_origin o WHERE o.message_id=messages.id) ORDER BY id")?
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for id in ids {
            tx.execute(
                "UPDATE management_journal SET sequence=sequence+1 WHERE id=1",
                [],
            )?;
            tx.execute("INSERT INTO management_outbox SELECT ?1,sequence,0 FROM management_journal WHERE id=1", [&id])?;
        }
        tx.execute("INSERT INTO management_log_outbox(log_id,generation,message_id,recipient,deleted) SELECT a.id,j.sequence+row_number() OVER(ORDER BY a.id),d.message_id,d.address,0 FROM delivery_attempts a JOIN deliveries d ON d.id=a.delivery_id JOIN management_journal j ON j.id=1 WHERE NOT EXISTS(SELECT 1 FROM cluster_origin o WHERE o.message_id=d.message_id)", [])?;
        tx.execute("UPDATE management_journal SET sequence=MAX(sequence,COALESCE((SELECT MAX(generation) FROM management_log_outbox),0)) WHERE id=1", [])?;
    }
    tx.commit()?;
    Ok(identity)
}

pub fn identity(db: &Connection) -> Result<Identity> {
    Ok(db.query_row(
        "SELECT node,epoch FROM management_journal WHERE id=1",
        [],
        |r| {
            Ok(Identity {
                node: r.get(0)?,
                epoch: r.get(1)?,
            })
        },
    )?)
}

pub fn status(db: &Connection) -> Result<Status> {
    let identity = identity(db)?;
    let sequence = db.query_row(
        "SELECT sequence FROM management_journal WHERE id=1",
        [],
        |r| r.get(0),
    )?;
    let (pending, tombstones) = db.query_row(
        "SELECT COUNT(*),COALESCE(SUM(deleted),0) FROM management_outbox",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let (pending_logs, log_tombstones) = db.query_row(
        "SELECT COUNT(*),COALESCE(SUM(deleted),0) FROM management_log_outbox",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    Ok(Status {
        identity,
        sequence,
        pending,
        tombstones,
        pending_logs,
        log_tombstones,
    })
}

pub fn pending(db: &Connection, limit: usize) -> Result<Vec<Entry>> {
    ensure!(
        (1..=12).contains(&limit),
        "Management journal batch exceeds limit"
    );
    Ok(db.prepare("SELECT message_id,generation,deleted FROM management_outbox ORDER BY generation LIMIT ?1")?
        .query_map([limit as i64], |r| Ok(Entry { id: r.get(0)?, generation: r.get(1)?, deleted: r.get(2)? }))?
        .collect::<rusqlite::Result<Vec<_>>>()?)
}

/// Called only after the PostgreSQL transaction has committed. The epoch binds
/// receipts to this spool; a restored/replaced node cannot acknowledge another.
pub fn acknowledge(db: &mut Connection, source: &Identity, entries: &[Entry]) -> Result<u64> {
    ensure!(entries.len() <= 12, "Too many management receipts");
    let tx = db.transaction()?;
    ensure!(
        identity(&tx)? == *source,
        "Management receipt identity mismatch"
    );
    let mut removed = 0;
    for entry in entries {
        ensure!(
            entry.generation > 0,
            "Invalid management receipt generation"
        );
        let current: Option<i64> = tx
            .query_row(
                "SELECT generation FROM management_outbox WHERE message_id=?1",
                [&entry.id],
                |r| r.get(0),
            )
            .optional()?;
        if current == Some(entry.generation) {
            removed += tx.execute("DELETE FROM management_outbox WHERE message_id=?1 AND generation=?2 AND deleted=?3", params![entry.id,entry.generation,entry.deleted])? as u64;
        }
    }
    tx.commit()?;
    Ok(removed)
}
