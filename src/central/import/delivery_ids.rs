//! Restore the coordinator's public recipient IDs before importing transcripts.
use crate::central::{Central, database_error};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};

pub struct DeliveryIdentities {
    pub(super) rows: Vec<Value>,
}
impl DeliveryIdentities {
    /// Capture the coordinator's complete recipient projection, including worker
    /// messages. Worker-local numeric IDs are not public console identities.
    pub fn capture(tx: &rusqlite::Transaction<'_>) -> Result<Self> {
        let mut query = tx.prepare(
            "SELECT d.id,CASE WHEN length(d.message_id)<=36 THEN d.message_id END,CASE WHEN length(d.address)<=254 THEN d.address END,CASE WHEN length(d.destination)<=254 THEN d.destination END,m.is_dsn,m.sender='' FROM deliveries d LEFT JOIN messages m ON m.id=d.message_id ORDER BY d.id LIMIT 100001",
        )?;
        let mut rows = query.query([])?;
        let mut values = Vec::new();
        let mut bytes = 0;
        while let Some(row) = rows.next()? {
            let id: i64 = row.get(0)?;
            let message: String = row.get(1)?;
            let address: String = row.get(2)?;
            let destination: String = row.get(3)?;
            ensure!(
                id > 0
                    && id < i64::MAX - 200_000
                    && crate::ha::replica::valid_id(&message)
                    && (!message.starts_with("dsn-")
                        || (row.get::<_, bool>(4)? && row.get::<_, bool>(5)?))
                    && crate::config::valid_address(&address)
                    && crate::config::valid_address(&destination),
                "Invalid public delivery identity"
            );
            let value =
                json!({"id":id,"message_id":message,"address":address,"destination":destination});
            bytes += serde_json::to_vec(&value)?.len();
            ensure!(
                values.len() < 100_000 && bytes <= 64 * 1024 * 1024,
                "Delivery identity snapshot exceeds bounds"
            );
            values.push(value);
        }
        Ok(Self { rows: values })
    }
}
impl Central {
    /// Offline-only: metadata from every MX must already exist, while central
    /// policy activation and SMTP transcript ingestion must not have started.
    /// A failure rolls back recipient IDs; a sequence gap is harmless.
    pub async fn import_delivery_identities(&self, snapshot: &DeliveryIdentities) -> Result<()> {
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            let mut db=self.ingestion.get().await.map_err(|_|anyhow::anyhow!("Migration database unavailable"))?;
            let tx=db.transaction().await.map_err(database_error)?;
            crate::central::admin::management_lock(&tx).await?;
            tx.batch_execute("LOCK TABLE noisefence.sources,noisefence.deliveries,noisefence.delivery_log_versions,noisefence.policy_authority,noisefence.migration_state IN ACCESS EXCLUSIVE MODE").await.map_err(database_error)?;
            let used:bool=tx.query_one("SELECT EXISTS(SELECT 1 FROM noisefence.policy_authority) OR EXISTS(SELECT 1 FROM noisefence.migration_state WHERE activated_at IS NOT NULL) OR EXISTS(SELECT 1 FROM noisefence.delivery_log_versions)",&[]).await.map_err(database_error)?.get(0);
            ensure!(!used,"Restore public recipient IDs before policy activation or transcript import");
            let (count,ceiling):(i64,i64)={let r=tx.query_one("SELECT count(*),coalesce(max(id),0) FROM noisefence.deliveries",&[]).await.map_err(database_error)?;(r.get(0),r.get(1))};
            ensure!(count<=100_000 && ceiling<i64::MAX-200_000,"Central delivery identity range exceeds limits");
            let negative:bool=tx.query_one("SELECT EXISTS(SELECT 1 FROM noisefence.deliveries WHERE id<=0)",&[]).await.map_err(database_error)?.get(0);
            ensure!(!negative,"Invalid central delivery identity");
            tx.batch_execute("CREATE TEMP TABLE nf_delivery_id_import(id bigint PRIMARY KEY,message_id text NOT NULL,address text NOT NULL,destination text NOT NULL,UNIQUE(message_id,address)) ON COMMIT DROP").await.map_err(database_error)?;
            for rows in snapshot.rows.chunks(250) {
                tx.execute("INSERT INTO nf_delivery_id_import SELECT * FROM jsonb_to_recordset($1) AS r(id bigint,message_id text,address text,destination text)",&[&Value::Array(rows.to_vec())]).await.map_err(database_error)?;
            }
            let missing:bool=tx.query_one("SELECT EXISTS(SELECT 1 FROM nf_delivery_id_import i WHERE NOT EXISTS(SELECT 1 FROM noisefence.deliveries d WHERE d.message_id=i.message_id AND d.address=i.address AND d.destination=i.destination))",&[]).await.map_err(database_error)?.get(0);
            ensure!(!missing,"A public recipient is missing or differs from imported MX metadata");
            // Additional worker deliveries may not yet have reached the old
            // console. Keep their IDs when outside the reserved legacy range;
            // otherwise allocate above both ranges. Repeating this is stable.
            tx.batch_execute("CREATE TEMP TABLE nf_delivery_id_rewrite ON COMMIT DROP AS
                WITH limits AS (SELECT coalesce(max(id),0) AS legacy_max FROM nf_delivery_id_import),
                base AS (SELECT GREATEST(l.legacy_max,coalesce((SELECT max(id) FROM noisefence.deliveries),0)) AS ceiling,l.legacy_max FROM limits l)
                SELECT d.id AS old_id,coalesce(i.id,CASE WHEN d.id>b.legacy_max THEN d.id ELSE b.ceiling+row_number() OVER(ORDER BY d.id) END) AS new_id
                FROM noisefence.deliveries d CROSS JOIN base b LEFT JOIN nf_delivery_id_import i ON i.message_id=d.message_id AND i.address=d.address;
                CREATE UNIQUE INDEX ON nf_delivery_id_rewrite(new_id);
                UPDATE noisefence.deliveries SET id=-id;
                UPDATE noisefence.deliveries d SET id=r.new_id FROM nf_delivery_id_rewrite r WHERE d.id=-r.old_id;").await.map_err(database_error)?;
            let mismatch:bool=tx.query_one("SELECT EXISTS(SELECT 1 FROM nf_delivery_id_import i LEFT JOIN noisefence.deliveries d ON d.id=i.id WHERE d.message_id IS DISTINCT FROM i.message_id OR d.address IS DISTINCT FROM i.address OR d.destination IS DISTINCT FROM i.destination)",&[]).await.map_err(database_error)?.get(0);
            ensure!(!mismatch,"Public recipient identity verification failed");
            let actual:i64=tx.query_one("SELECT count(*) FROM noisefence.deliveries",&[]).await.map_err(database_error)?.get(0);
            ensure!(actual==count,"Recipient count changed during identity import");
            // Never rewind the sequence, including after a failed earlier import.
            // Sequence advancement itself is nontransactional and can leave gaps.
            if count>0 {
                tx.query_one("SELECT setval('noisefence.deliveries_id_seq',GREATEST((SELECT last_value FROM noisefence.deliveries_id_seq),(SELECT max(id) FROM noisefence.deliveries)),true)",&[]).await.map_err(database_error)?;
            }
            tx.commit().await.map_err(database_error)?;
            Ok(())
        }).await.context("Delivery identity migration deadline exceeded")?
    }
}
