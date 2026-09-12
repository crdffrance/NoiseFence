//! Idempotent metadata replication. Bodies and queue ownership stay on the SMTP node.
use crate::{engine::Scan, store::Store};
use anyhow::{Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub id: String,
    pub generation: i64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub id: String,
    pub generation: i64,
    pub created: i64,
    pub sender: String,
    pub scan: Scan,
    pub is_dsn: bool,
    pub raw_present: bool,
    pub deliveries: Vec<Delivery>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Delivery {
    pub address: String,
    pub destination: String,
    pub status: String,
    pub attempts: u32,
    pub next_attempt: i64,
    pub error: Option<String>,
    pub action: Option<String>,
    pub held_until: Option<i64>,
    pub released_at: Option<i64>,
    pub filtering: Option<crate::custom_filtering::Assessment>,
    pub logs: Vec<Log>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Log {
    pub attempt: u32,
    pub trace: crate::delivery_log::Attempt,
}

pub async fn export(store: &Store) -> Result<Vec<Record>> {
    store.read(|db| {
        let ids=db.prepare("SELECT c.message_id,c.generation FROM cluster_dirty c JOIN messages m ON m.id=c.message_id WHERE NOT EXISTS(SELECT 1 FROM cluster_origin o WHERE o.message_id=m.id) ORDER BY c.generation LIMIT 12")?.query_map([],|r|Ok((r.get::<_,String>(0)?,r.get::<_,i64>(1)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
        let mut records=Vec::new();let mut size=0;
        for (id,generation) in ids {
            let (created,sender,scan,is_dsn,raw_present)=db.query_row("SELECT created,sender,scan,is_dsn,raw_present FROM messages WHERE id=?1",[&id],|r|Ok((r.get(0)?,r.get(1)?,r.get::<_,String>(2)?,r.get(3)?,r.get(4)?)))?;
            let mut deliveries=Vec::new();
            let mut query=db.prepare("SELECT d.id,d.address,d.destination,d.status,d.attempts,d.next_attempt,d.error,p.action,p.held_until,p.released_at,f.assessment FROM deliveries d LEFT JOIN delivery_policy p ON p.delivery_id=d.id LEFT JOIN delivery_filtering f ON f.delivery_id=d.id WHERE d.message_id=?1 ORDER BY d.id")?;
            let mut rows=query.query([&id])?;
            while let Some(r)=rows.next()? {
                let delivery_id:i64=r.get(0)?;
                let logs=db.prepare("SELECT attempt,trace FROM delivery_attempts WHERE delivery_id=?1 ORDER BY id DESC LIMIT 5")?.query_map([delivery_id],|r|Ok((r.get::<_,u32>(0)?,r.get::<_,String>(1)?)))?.map(|r| {let (attempt,raw)=r?;Ok(Log{attempt,trace:serde_json::from_str(&raw)?})}).collect::<Result<Vec<_>>>()?;
                deliveries.push(Delivery{address:r.get(1)?,destination:r.get(2)?,status:r.get(3)?,attempts:r.get(4)?,next_attempt:r.get(5)?,error:r.get(6)?,action:r.get(7)?,held_until:r.get(8)?,released_at:r.get(9)?,filtering:r.get::<_,Option<String>>(10)?.map(|s|serde_json::from_str(&s)).transpose()?,logs});
            }
            let record=Record{id,generation,created,sender,scan:serde_json::from_str(&scan)?,is_dsn,raw_present,deliveries};
            let bytes=serde_json::to_vec(&record)?.len();
            ensure!(bytes<=3*1024*1024,"Une analyse dépasse la limite de synchronisation de 3 Mio.");
            if size+bytes>3*1024*1024 {break;}
            size+=bytes;records.push(record);
        }
        Ok(records)
    }).await
}
pub async fn acknowledge(store: &Store, receipts: Vec<Receipt>) -> Result<()> {
    store
        .run(move |db| {
            let tx = db.transaction()?;
            for r in receipts {
                tx.execute(
                    "DELETE FROM cluster_dirty WHERE message_id=?1 AND generation=?2",
                    params![r.id, r.generation],
                )?;
            }
            tx.commit()?;
            Ok(())
        })
        .await
}
pub fn ingest(
    db: &mut Connection,
    node: &str,
    records: Vec<Record>,
    now: i64,
) -> Result<Vec<Receipt>> {
    ensure!(records.len() <= 12, "Too many messages per batch");
    let tx = db.transaction()?;
    ensure!(
        tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM cluster_nodes WHERE id=?1 AND enabled=1)",
            [node],
            |r| r.get::<_, bool>(0)
        )?,
        "Node revoked"
    );
    let mut receipts = Vec::new();
    for mut record in records {
        ensure!(
            uuid::Uuid::parse_str(&record.id).is_ok_and(|id| id.to_string() == record.id)
                && record.generation > 0
                && record.created <= now + 300
                && record.created >= 0,
            "Invalid replicated identity"
        );
        ensure!(
            (record.sender.is_empty() || crate::config::valid_address(&record.sender))
                && !record.deliveries.is_empty()
                && record.deliveries.len() <= 100,
            "Invalid replicated envelope"
        );
        let old: Option<(String, i64)> = tx
            .query_row(
                "SELECT node_id,remote_version FROM cluster_origin WHERE message_id=?1",
                [&record.id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        ensure!(
            old.as_ref().is_none_or(|(owner, _)| owner == node),
            "Message belongs to another node"
        );
        if old.is_some() {
            let (created, sender): (i64, String) = tx.query_row(
                "SELECT created,sender FROM messages WHERE id=?1",
                [&record.id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            ensure!(
                created == record.created && sender == record.sender,
                "Accepted envelope changed"
            );
            let old_recipients = tx
                .prepare("SELECT address,destination FROM deliveries WHERE message_id=?1")?
                .query_map([&record.id], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
                })?
                .collect::<rusqlite::Result<std::collections::BTreeSet<_>>>()?;
            let new_recipients = record
                .deliveries
                .iter()
                .map(|d| (d.address.clone(), d.destination.clone()))
                .collect::<std::collections::BTreeSet<_>>();
            ensure!(
                old_recipients == new_recipients,
                "Accepted recipient set changed"
            );
        }
        if old.is_none() {
            ensure!(
                !tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM messages WHERE id=?1)",
                    [&record.id],
                    |r| r.get::<_, bool>(0)
                )?,
                "Local message collision"
            );
        }
        if old
            .as_ref()
            .is_some_and(|(_, version)| *version >= record.generation)
        {
            receipts.push(Receipt {
                id: record.id,
                generation: record.generation,
            });
            continue;
        }
        // Aged, resolved metadata follows the same retention as the local console.
        if record.created < now - 30 * 86400 && !record.raw_present {
            receipts.push(Receipt {
                id: record.id,
                generation: record.generation,
            });
            continue;
        }
        ensure!(
            record.scan.score.is_finite() && (0.0..=100.0).contains(&record.scan.score),
            "Invalid decision score"
        );
        let scan = serde_json::to_string(&record.scan)?;
        ensure!(scan.len() <= 2 * 1024 * 1024, "Scan too large");
        tx.execute("INSERT INTO messages(id,created,sender,scan,is_dsn,raw_present) VALUES(?1,?2,?3,?4,?5,0) ON CONFLICT(id) DO UPDATE SET scan=excluded.scan",params![record.id,record.created,record.sender,scan,record.is_dsn])?;
        tx.execute("INSERT INTO cluster_origin(message_id,node_id,remote_id,updated,raw_present,remote_version) VALUES(?1,?2,?1,?3,?4,?5) ON CONFLICT(message_id) DO UPDATE SET updated=excluded.updated,raw_present=excluded.raw_present,remote_version=excluded.remote_version",params![record.id,node,now,record.raw_present,record.generation])?;
        let mut addresses = std::collections::HashSet::new();
        for d in &mut record.deliveries {
            ensure!(
                crate::config::valid_address(&d.address)
                    && crate::config::valid_address(&d.destination)
                    && addresses.insert(d.address.clone()),
                "Invalid or duplicate recipient"
            );
            ensure!(
                [
                    "pending",
                    "sending",
                    "delivered",
                    "failed",
                    "notified",
                    "quarantined",
                    "discarded",
                    "expired"
                ]
                .contains(&d.status.as_str()),
                "Invalid remote delivery status"
            );
            ensure!(
                d.action
                    .as_ref()
                    .is_none_or(|a| ["deliver", "tag", "quarantine"].contains(&a.as_str()))
                    && d.logs.len() <= 5,
                "Invalid remote policy"
            );
            let error = d
                .error
                .as_ref()
                .map(|e| crate::delivery_log::sanitize(e, 2048).0);
            tx.execute("INSERT INTO deliveries(message_id,address,destination,hosts,status,attempts,next_attempt,error) VALUES(?1,?2,?3,'[]',?4,?5,?6,?7) ON CONFLICT(message_id,address) DO UPDATE SET status=excluded.status,attempts=excluded.attempts,next_attempt=excluded.next_attempt,error=excluded.error",params![record.id,d.address,d.destination,d.status,d.attempts,d.next_attempt,error])?;
            let id: i64 = tx.query_row(
                "SELECT id FROM deliveries WHERE message_id=?1 AND address=?2",
                params![record.id, d.address],
                |r| r.get(0),
            )?;
            if let Some(action) = &d.action {
                tx.execute(
                    "INSERT OR REPLACE INTO delivery_policy VALUES(?1,?2,?3,?4)",
                    params![id, action, d.held_until, d.released_at],
                )?;
            }
            if let Some(filtering) = &d.filtering {
                tx.execute(
                    "INSERT OR REPLACE INTO delivery_filtering VALUES(?1,?2)",
                    params![id, serde_json::to_string(filtering)?],
                )?;
            }
            tx.execute("DELETE FROM delivery_attempts WHERE delivery_id=?1", [id])?;
            for log in d.logs.iter_mut().rev() {
                log.trace.sanitize();
                tx.execute(
                    "INSERT INTO delivery_attempts(delivery_id,attempt,trace) VALUES(?1,?2,?3)",
                    params![id, log.attempt, serde_json::to_string(&log.trace)?],
                )?;
            }
        }
        // Recipients are immutable after SMTP acceptance; a node may not hide a prior recipient.
        let count: i64 = tx.query_row(
            "SELECT COUNT(*) FROM deliveries WHERE message_id=?1",
            [&record.id],
            |r| r.get(0),
        )?;
        ensure!(
            count == record.deliveries.len() as i64,
            "Recipient set changed"
        );
        receipts.push(Receipt {
            id: record.id,
            generation: record.generation,
        });
    }
    tx.commit()?;
    Ok(receipts)
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Release,
    Delete,
    Retry,
}
impl From<crate::quarantine::Command> for Operation {
    fn from(c: crate::quarantine::Command) -> Self {
        match c {
            crate::quarantine::Command::Release => Self::Release,
            crate::quarantine::Command::Delete => Self::Delete,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Command {
    pub id: String,
    pub message_id: String,
    pub recipient: String,
    pub command: Operation,
    pub username: String,
    pub expires: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandResult {
    pub id: String,
    pub result: String,
}
pub async fn execute(store: &Store, commands: Vec<Command>) -> Result<Vec<CommandResult>> {
    ensure!(commands.len() <= 32, "Too many commands");
    let results=store.run(move|db| {
        let tx=db.transaction()?;let mut results=Vec::new();
        for c in commands {
            ensure!(uuid::Uuid::parse_str(&c.id).is_ok() && uuid::Uuid::parse_str(&c.message_id).is_ok() && crate::config::valid_address(&c.recipient) && c.username.len()<=100,"Invalid command");
            if let Some(result)=tx.query_row("SELECT result FROM cluster_command_receipts WHERE id=?1",[&c.id],|r|r.get::<_,String>(0)).optional()? {results.push(CommandResult{id:c.id,result});continue;}
            let now=crate::now();
            let item:Option<i64>=tx.query_row("SELECT d.id FROM deliveries d JOIN messages m ON m.id=d.message_id LEFT JOIN delivery_policy p ON p.delivery_id=d.id WHERE m.id=?1 AND d.address=?2 AND ((?4=1 AND d.status='pending') OR (?4=0 AND d.status='quarantined' AND p.held_until>?3)) AND m.raw_present=1 AND NOT EXISTS(SELECT 1 FROM cluster_origin WHERE message_id=m.id)",params![c.message_id,c.recipient,now,matches!(c.command,Operation::Retry)],|r|r.get(0)).optional()?;
            let result=if c.expires<now {"expired"} else if let Some(id)=item {
                ensure!(c.expires<=now+600,"Command validity too long");
                let status=match c.command {Operation::Release|Operation::Retry=>"pending",Operation::Delete=>"discarded"};
                tx.execute("UPDATE deliveries SET status=?2,next_attempt=?3,error=NULL WHERE id=?1",params![id,status,now])?;
                if matches!(c.command,Operation::Release) {tx.execute("UPDATE delivery_policy SET released_at=?2 WHERE delivery_id=?1",params![id,now])?;}
                tx.execute("INSERT INTO audit(created,username,action,object_id) VALUES(?1,?2,?3,?4)",params![now,c.username,format!("cluster_{:?}",c.command).to_lowercase(),c.id])?;
                "done"
            } else {"conflict"};
            tx.execute("INSERT INTO cluster_command_receipts VALUES(?1,?2,?3)",params![c.id,result,now])?;
            results.push(CommandResult{id:c.id,result:result.into()});
        }
        tx.execute("DELETE FROM cluster_command_receipts WHERE created<?1",[crate::now()-30*86400])?;
        tx.commit()?;Ok(results)
    }).await?;
    store.notify_delivery();
    Ok(results)
}
