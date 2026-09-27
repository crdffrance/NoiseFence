//! Complete retained SMTP histories, transferred independently in bounded batches.
use super::{Central, database_error, outbox::Identity};
use anyhow::{Result, ensure};
use rusqlite::params;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub local_id: i64,
    pub generation: i64,
    pub deleted: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub receipt: Receipt,
    pub message_id: String,
    pub recipient: String,
    pub log: Option<Log>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Log {
    pub attempt: u32,
    pub trace: crate::delivery_log::Attempt,
}

impl Event {
    fn validate(&mut self) -> Result<()> {
        ensure!(
            self.receipt.local_id > 0
                && self.receipt.generation > 0
                && self.receipt.deleted == self.log.is_none(),
            "Invalid central transcript identity"
        );
        ensure!(
            uuid::Uuid::parse_str(&self.message_id)
                .is_ok_and(|id| id.to_string() == self.message_id)
                && crate::config::valid_address(&self.recipient),
            "Invalid central transcript recipient"
        );
        if let Some(log) = &mut self.log {
            log.trace.sanitize();
        }
        ensure!(
            serde_json::to_vec(self)?.len() <= 512 * 1024,
            "Central transcript exceeds limit"
        );
        Ok(())
    }
}

pub async fn export(store: &crate::store::Store) -> Result<(Identity, Vec<Event>)> {
    store.read(|db| {
        let identity=super::outbox::identity(db)?;
        let mut q=db.prepare("SELECT o.log_id,o.generation,o.message_id,o.recipient,o.deleted,a.attempt,a.trace FROM management_log_outbox o LEFT JOIN delivery_attempts a ON a.id=o.log_id WHERE NOT EXISTS(SELECT 1 FROM management_outbox m WHERE m.message_id=o.message_id) ORDER BY o.generation LIMIT 12")?;
        let mut rows=q.query([])?;
        let mut events=Vec::new();let mut bytes=2;
        while let Some(r)=rows.next()? {
            let deleted:bool=r.get(4)?;
            let mut event=Event {receipt:Receipt{local_id:r.get(0)?,generation:r.get(1)?,deleted},message_id:r.get(2)?,recipient:r.get(3)?,log:if deleted {None}else{Some(Log{attempt:r.get(5)?,trace:serde_json::from_str(&r.get::<_,String>(6)?)?})}};
            event.validate()?;
            let size=serde_json::to_vec(&event)?.len()+1;
            if bytes+size>3*1024*1024 {break;}
            bytes+=size;events.push(event);
        }
        Ok((identity,events))
    }).await
}

pub async fn acknowledge(
    store: &crate::store::Store,
    identity: Identity,
    receipts: Vec<Receipt>,
) -> Result<usize> {
    ensure!(receipts.len() <= 12, "Too many transcript receipts");
    store.run(move |db| {
        let tx=db.transaction()?;
        ensure!(super::outbox::identity(&tx)?==identity,"Transcript receipt epoch mismatch");
        let mut count=0;
        for receipt in receipts {
            ensure!(receipt.local_id>0 && receipt.generation>0,"Invalid transcript receipt");
            count+=tx.execute("DELETE FROM management_log_outbox WHERE log_id=?1 AND generation=?2 AND deleted=?3",params![receipt.local_id,receipt.generation,receipt.deleted])?;
        }
        tx.commit()?;Ok(count)
    }).await
}

impl Central {
    pub async fn synchronize_logs_once(&self, store: &crate::store::Store) -> Result<usize> {
        let (identity, mut events) = export(store).await?;
        if events.is_empty() {
            return Ok(0);
        }
        let receipts = self.ingest_logs(&identity, &mut events).await?;
        let count = receipts.len();
        acknowledge(store, identity, receipts).await?;
        Ok(count)
    }
    pub async fn ingest_logs(
        &self,
        identity: &Identity,
        events: &mut [Event],
    ) -> Result<Vec<Receipt>> {
        tokio::time::timeout(
            std::time::Duration::from_secs(15),
            self.ingest_log_batch(identity, events, None),
        )
        .await
        .map_err(|_| anyhow::anyhow!("Central transcript deadline exceeded"))?
    }
    pub async fn ingest_logs_from_node(
        &self,
        node: &super::nodes::Authenticated,
        events: &mut [Event],
    ) -> Result<Vec<Receipt>> {
        tokio::time::timeout(
            std::time::Duration::from_secs(15),
            self.ingest_log_batch(node.identity(), events, Some(node)),
        )
        .await
        .map_err(|_| anyhow::anyhow!("Central transcript deadline exceeded"))?
    }
    async fn ingest_log_batch(
        &self,
        identity: &Identity,
        events: &mut [Event],
        credential: Option<&super::nodes::Authenticated>,
    ) -> Result<Vec<Receipt>> {
        ensure!(events.len() <= 12, "Too many transcripts per batch");
        let mut ids = std::collections::HashSet::new();
        for event in events.iter_mut() {
            event.validate()?;
            ensure!(
                ids.insert(event.receipt.local_id),
                "Duplicate transcript in batch"
            );
        }
        ensure!(
            serde_json::to_vec(events)?.len() <= 3 * 1024 * 1024,
            "Transcript batch exceeds limit"
        );
        let mut db = self
            .ingestion
            .get()
            .await
            .map_err(|_| anyhow::anyhow!("Central transcript capacity unavailable"))?;
        let tx = db.transaction().await.map_err(database_error)?;
        let source = tx
            .query_opt(
                "SELECT epoch,enabled FROM noisefence.sources WHERE node=$1 FOR UPDATE",
                &[&identity.node],
            )
            .await
            .map_err(database_error)?
            .ok_or_else(|| anyhow::anyhow!("Unknown transcript source"))?;
        ensure!(
            source.get::<_, String>(0) == identity.epoch && source.get::<_, bool>(1),
            "Transcript source revoked or epoch mismatch"
        );
        if let Some(credential) = credential {
            credential.check(&tx).await?;
        }
        let mut receipts = Vec::new();
        for event in events {
            let r = &event.receipt;
            let message = tx
                .query_opt(
                    "SELECT node,epoch,deleted FROM noisefence.message_versions WHERE id=$1",
                    &[&event.message_id],
                )
                .await
                .map_err(database_error)?
                .ok_or_else(|| anyhow::anyhow!("Transcript message has not been synchronized"))?;
            ensure!(
                message.get::<_, String>(0) == identity.node
                    && message.get::<_, String>(1) == identity.epoch,
                "Transcript belongs to another source"
            );
            if message.get::<_, bool>(2) {
                receipts.push(r.clone());
                continue;
            }
            let delivery: i64 = tx
                .query_one(
                    "SELECT id FROM noisefence.deliveries WHERE message_id=$1 AND address=$2",
                    &[&event.message_id, &event.recipient],
                )
                .await
                .map_err(database_error)?
                .get(0);
            let old=tx.query_opt("SELECT message_id,delivery_id,generation,deleted FROM noisefence.delivery_log_versions WHERE node=$1 AND epoch=$2 AND local_id=$3 FOR UPDATE", &[&identity.node,&identity.epoch,&r.local_id]).await.map_err(database_error)?;
            if let Some(old) = old {
                ensure!(
                    old.get::<_, String>(0) == event.message_id
                        && old.get::<_, Option<i64>>(1) == Some(delivery),
                    "Transcript recipient identity changed"
                );
                if old.get::<_, i64>(2) >= r.generation {
                    receipts.push(r.clone());
                    continue;
                }
                ensure!(
                    !old.get::<_, bool>(3) || r.deleted,
                    "Removed transcript cannot be resurrected"
                );
            }
            tx.execute("INSERT INTO noisefence.delivery_log_versions(node,epoch,local_id,message_id,delivery_id,generation,deleted) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(node,epoch,local_id) DO UPDATE SET generation=excluded.generation,deleted=excluded.deleted", &[&identity.node,&identity.epoch,&r.local_id,&event.message_id,&delivery,&r.generation,&r.deleted]).await.map_err(database_error)?;
            if let Some(log) = &event.log {
                tx.execute("INSERT INTO noisefence.delivery_logs(node,epoch,local_id,message_id,attempt,trace) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(node,epoch,local_id) DO UPDATE SET attempt=excluded.attempt,trace=excluded.trace", &[&identity.node,&identity.epoch,&r.local_id,&event.message_id,&i64::from(log.attempt),&serde_json::to_value(&log.trace)?]).await.map_err(database_error)?;
            } else {
                tx.execute("DELETE FROM noisefence.delivery_logs WHERE node=$1 AND epoch=$2 AND local_id=$3", &[&identity.node,&identity.epoch,&r.local_id]).await.map_err(database_error)?;
            }
            receipts.push(r.clone());
        }
        tx.commit().await.map_err(database_error)?;
        Ok(receipts)
    }
}
