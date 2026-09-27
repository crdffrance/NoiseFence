//! Idempotent PostgreSQL projections of queue metadata; no queue lease is moved.
use super::{
    Central, database_error,
    outbox::{Entry, Identity},
};
use crate::cluster::history::Record;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashSet};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub receipt: Entry,
    pub record: Option<Record>,
}

impl Event {
    pub fn validate(&self) -> Result<()> {
        let r = &self.receipt;
        ensure!(
            uuid::Uuid::parse_str(&r.id).is_ok_and(|id| id.to_string() == r.id) && r.generation > 0,
            "Invalid management event identity"
        );
        ensure!(
            r.deleted == self.record.is_none(),
            "Incoherent management tombstone"
        );
        if let Some(record) = &self.record {
            ensure!(
                record.id == r.id && record.generation == r.generation,
                "Management event generation mismatch"
            );
            ensure!(
                (0..=crate::now() + 300).contains(&record.created)
                    && (record.sender.is_empty() || crate::config::valid_address(&record.sender))
                    && (1..=100).contains(&record.deliveries.len()),
                "Invalid management envelope"
            );
            crate::scoring::validate_transport(&record.scan)?;
            ensure!(
                serde_json::to_vec(&record.scan)?.len() <= 2 * 1024 * 1024,
                "Management scan exceeds limit"
            );
            let mut seen = HashSet::new();
            for d in &record.deliveries {
                ensure!(
                    crate::config::valid_address(&d.address)
                        && crate::config::valid_address(&d.destination)
                        && seen.insert(&d.address),
                    "Invalid management recipient"
                );
                ensure!(
                    [
                        "pending",
                        "sending",
                        "delivered",
                        "failed",
                        "notified",
                        "dsn_suppressed",
                        "quarantined",
                        "discarded",
                        "expired"
                    ]
                    .contains(&d.status.as_str()),
                    "Invalid management delivery status"
                );
                ensure!(
                    d.logs.len() <= 5
                        && d.action
                            .as_ref()
                            .is_none_or(|a| ["deliver", "tag", "quarantine"].contains(&a.as_str())),
                    "Invalid management delivery policy"
                );
            }
        }
        ensure!(
            serde_json::to_vec(self)?.len() <= 3 * 1024 * 1024,
            "Management event exceeds limit"
        );
        Ok(())
    }
}

pub async fn export(store: &crate::store::Store) -> Result<(Identity, Vec<Event>)> {
    store
        .read(|db| {
            let identity = super::outbox::identity(db)?;
            let mut events = Vec::new();
            // Reserve the array delimiters and a comma per entry in the bound.
            let mut bytes = 2usize;
            for receipt in super::outbox::pending(db, 12)? {
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
                let event = Event { receipt, record };
                event.validate()?;
                let size = serde_json::to_vec(&event)?.len() + 1;
                ensure!(
                    size + 2 <= 3 * 1024 * 1024,
                    "Management event exceeds batch limit"
                );
                if bytes + size > 3 * 1024 * 1024 {
                    break;
                }
                bytes += size;
                events.push(event);
            }
            Ok((identity, events))
        })
        .await
}

impl Central {
    /// One bounded background batch. Never call from SMTP acceptance or hold a
    /// SQLite writer while waiting for PostgreSQL. Cancellation is safe at each
    /// await: unacknowledged entries remain durable and can be replayed.
    pub async fn synchronize_once(&self, store: &crate::store::Store) -> Result<usize> {
        let metadata = self.synchronize_metadata_once(store).await?;
        Ok(metadata + self.synchronize_logs_once(store).await?)
    }

    pub async fn synchronize_metadata_once(&self, store: &crate::store::Store) -> Result<usize> {
        let (identity, mut events) = export(store).await?;
        if events.is_empty() {
            return Ok(0);
        }
        let receipts = self.ingest(&identity, &mut events).await?;
        let count = receipts.len();
        store
            .run(move |db| super::outbox::acknowledge(db, &identity, &receipts))
            .await?;
        Ok(count)
    }

    /// Explicit node registration during migration; never silently changes epochs
    /// or re-enables a revoked node. Replacement requires fenced reconciliation.
    pub async fn register_source(&self, identity: &Identity) -> Result<()> {
        ensure!(
            crate::cluster::valid_id(&identity.node)
                && uuid::Uuid::parse_str(&identity.epoch).is_ok(),
            "Invalid management source"
        );
        let db = self
            .ingestion
            .get()
            .await
            .map_err(|_| anyhow::anyhow!("Central ingestion capacity unavailable"))?;
        db.execute("INSERT INTO noisefence.sources(node,epoch,created) VALUES($1,$2,$3) ON CONFLICT(node) DO NOTHING", &[&identity.node,&identity.epoch,&crate::now()]).await.map_err(database_error)?;
        let row = db
            .query_one(
                "SELECT epoch,enabled FROM noisefence.sources WHERE node=$1",
                &[&identity.node],
            )
            .await
            .map_err(database_error)?;
        ensure!(
            row.get::<_, String>(0) == identity.epoch && row.get::<_, bool>(1),
            "Management source requires reconciliation or is revoked"
        );
        Ok(())
    }

    pub async fn ingest(&self, identity: &Identity, events: &mut [Event]) -> Result<Vec<Entry>> {
        tokio::time::timeout(
            std::time::Duration::from_secs(15),
            self.ingest_batch(identity, events, None),
        )
        .await
        .map_err(|_| anyhow::anyhow!("Central ingestion deadline exceeded"))?
    }

    pub async fn ingest_from_node(
        &self,
        node: &super::nodes::Authenticated,
        events: &mut [Event],
    ) -> Result<Vec<Entry>> {
        tokio::time::timeout(
            std::time::Duration::from_secs(15),
            self.ingest_batch(node.identity(), events, Some(node)),
        )
        .await
        .map_err(|_| anyhow::anyhow!("Central ingestion deadline exceeded"))?
    }
    async fn ingest_batch(
        &self,
        identity: &Identity,
        events: &mut [Event],
        credential: Option<&super::nodes::Authenticated>,
    ) -> Result<Vec<Entry>> {
        ensure!(events.len() <= 12, "Management batch exceeds limit");
        let mut ids = HashSet::new();
        for event in events.iter() {
            event.validate()?;
            ensure!(
                ids.insert(&event.receipt.id),
                "Duplicate management event in batch"
            );
        }
        ensure!(
            serde_json::to_vec(events)?.len() <= 3 * 1024 * 1024,
            "Management batch exceeds byte limit"
        );
        let mut db = self
            .ingestion
            .get()
            .await
            .map_err(|_| anyhow::anyhow!("Central ingestion capacity unavailable"))?;
        let tx = db.transaction().await.map_err(database_error)?;
        let node = tx
            .query_opt(
                "SELECT epoch,enabled FROM noisefence.sources WHERE node=$1 FOR UPDATE",
                &[&identity.node],
            )
            .await
            .map_err(database_error)?
            .ok_or_else(|| anyhow::anyhow!("Unregistered management source"))?;
        ensure!(
            node.get::<_, String>(0) == identity.epoch && node.get::<_, bool>(1),
            "Management source revoked or epoch mismatch"
        );
        if let Some(credential) = credential {
            credential.check(&tx).await?;
        }
        let mut receipts = Vec::new();
        let mut high_water = 0i64;
        for event in events {
            let receipt = &event.receipt;
            let old=tx.query_opt("SELECT node,epoch,generation,deleted FROM noisefence.message_versions WHERE id=$1 FOR UPDATE", &[&receipt.id]).await.map_err(database_error)?;
            if let Some(old) = &old {
                ensure!(
                    old.get::<_, String>(0) == identity.node
                        && old.get::<_, String>(1) == identity.epoch,
                    "Message belongs to another management source"
                );
                if old.get::<_, i64>(2) >= receipt.generation {
                    receipts.push(receipt.clone());
                    continue;
                }
                ensure!(
                    !old.get::<_, bool>(3) || receipt.deleted,
                    "Deleted message cannot be resurrected"
                );
            }
            if old.is_some() {
                tx.execute(
                    "UPDATE noisefence.message_versions SET generation=$2,deleted=$3 WHERE id=$1",
                    &[&receipt.id, &receipt.generation, &receipt.deleted],
                )
                .await
                .map_err(database_error)?;
            } else {
                tx.execute(
                    "INSERT INTO noisefence.message_versions VALUES($1,$2,$3,$4,$5)",
                    &[
                        &receipt.id,
                        &identity.node,
                        &identity.epoch,
                        &receipt.generation,
                        &receipt.deleted,
                    ],
                )
                .await
                .map_err(database_error)?;
            }
            if let Some(record) = &mut event.record {
                if old.is_some() {
                    let original = tx
                        .query_one(
                            "SELECT created,sender,is_dsn FROM noisefence.messages WHERE id=$1",
                            &[&record.id],
                        )
                        .await
                        .map_err(database_error)?;
                    ensure!(
                        original.get::<_, i64>(0) == record.created
                            && original.get::<_, String>(1) == record.sender
                            && original.get::<_, bool>(2) == record.is_dsn,
                        "Accepted message envelope changed"
                    );
                    let existing=tx.query("SELECT address,destination FROM noisefence.deliveries WHERE message_id=$1", &[&record.id]).await.map_err(database_error)?
                        .iter().map(|r|(r.get::<_,String>(0),r.get::<_,String>(1))).collect::<BTreeSet<_>>();
                    let incoming = record
                        .deliveries
                        .iter()
                        .map(|d| (d.address.clone(), d.destination.clone()))
                        .collect::<BTreeSet<_>>();
                    ensure!(existing == incoming, "Accepted recipient set changed");
                }
                let scan = serde_json::to_value(&record.scan)?;
                let assessment = crate::assessment::historical(&record.scan);
                let mut rules = record
                    .scan
                    .reasons
                    .iter()
                    .map(|r| r.id.as_str())
                    .collect::<Vec<_>>()
                    .join(" ");
                let mut limit = 16384.min(rules.len());
                while !rules.is_char_boundary(limit) {
                    limit -= 1;
                }
                rules.truncate(limit);

                tx.execute("INSERT INTO noisefence.messages(id,created,sender,scan,is_dsn,raw_present,category,score,rules) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(id) DO UPDATE SET scan=excluded.scan,raw_present=excluded.raw_present,category=excluded.category,score=excluded.score,rules=excluded.rules,updated_at=EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)::bigint", &[&record.id,&record.created,&record.sender,&scan,&record.is_dsn,&record.raw_present,&assessment.category.as_str(),&assessment.score.value,&rules]).await.map_err(database_error)?;
                for d in &mut record.deliveries {
                    let error = d
                        .error
                        .as_ref()
                        .map(|v| crate::delivery_log::sanitize(v, 2048).0);
                    for log in &mut d.logs {
                        log.trace.sanitize();
                    }
                    let filtering = d.filtering.as_ref().map(serde_json::to_value).transpose()?;
                    let logs = serde_json::to_value(&d.logs)?;
                    tx.execute("INSERT INTO noisefence.deliveries(message_id,address,destination,status,attempts,next_attempt,error,action,held_until,released_at,filtering,logs) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT(message_id,address) DO UPDATE SET status=excluded.status,attempts=excluded.attempts,next_attempt=excluded.next_attempt,error=excluded.error,action=excluded.action,held_until=excluded.held_until,released_at=excluded.released_at,filtering=excluded.filtering,logs=excluded.logs", &[&record.id,&d.address,&d.destination,&d.status,&i64::from(d.attempts),&d.next_attempt,&error,&d.action,&d.held_until,&d.released_at,&filtering,&logs]).await.map_err(database_error)?;
                }
            } else {
                tx.execute(
                    "DELETE FROM noisefence.messages WHERE id=$1",
                    &[&receipt.id],
                )
                .await
                .map_err(database_error)?;
            }
            high_water = high_water.max(receipt.generation);
            receipts.push(receipt.clone());
        }
        tx.execute("UPDATE noisefence.sources SET last_seen=$2,last_sequence=GREATEST(last_sequence,$3) WHERE node=$1", &[&identity.node,&crate::now(),&high_water]).await.map_err(database_error)?;
        tx.commit().await.map_err(database_error)?;
        Ok(receipts)
    }
}
