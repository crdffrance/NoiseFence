use super::{Central, database_error};
use crate::diagnostics::{AttemptLog, MessageDiagnostics, RecipientDiagnostics};
use anyhow::Result;

impl Central {
    pub async fn diagnostics(
        &self,
        username: &str,
        id: &str,
        delivery_id: Option<i64>,
    ) -> Result<Option<MessageDiagnostics>> {
        let mut db = self
            .interactive
            .get()
            .await
            .map_err(|_| anyhow::anyhow!("Central diagnostics capacity unavailable"))?;
        let tx = db
            .build_transaction()
            .read_only(true)
            .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
            .start()
            .await
            .map_err(database_error)?;
        let row=tx.query_opt("SELECT m.scan FROM noisefence.messages m WHERE m.id=$1 AND (m.created>=$3 OR m.raw_present) AND EXISTS(SELECT 1 FROM noisefence.deliveries d JOIN noisefence.console_access g ON g.delivery_id=d.id WHERE d.message_id=m.id AND g.username=$2 AND ($4::bigint IS NULL OR d.id=$4))", &[&id,&username,&(crate::now()-30*86400),&delivery_id]).await.map_err(database_error)?;
        let Some(row) = row else {
            return Ok(None);
        };
        let scan: crate::engine::Scan = serde_json::from_value(row.get(0))?;
        let rows=tx.query("SELECT d.id,d.address,d.destination,d.status,d.attempts,d.next_attempt,NULLIF(d.error,''),(SELECT count(*) FROM noisefence.delivery_log_versions v JOIN noisefence.delivery_logs l USING(node,epoch,local_id) WHERE v.delivery_id=d.id AND NOT v.deleted) FROM noisefence.deliveries d JOIN noisefence.console_access g ON g.delivery_id=d.id WHERE d.message_id=$1 AND g.username=$2 AND ($3::bigint IS NULL OR d.id=$3) ORDER BY d.id", &[&id,&username,&delivery_id]).await.map_err(database_error)?;
        let mut remaining = 100usize;
        let mut recipients = Vec::new();
        for row in rows {
            let delivery_id: i64 = row.get(0);
            let logs_available = row.get::<_, i64>(7) as usize;
            let mut logs = Vec::new();
            if remaining > 0 {
                for r in tx.query("SELECT l.local_id,l.attempt,l.trace FROM noisefence.delivery_log_versions v JOIN noisefence.delivery_logs l USING(node,epoch,local_id) WHERE v.delivery_id=$1 AND NOT v.deleted ORDER BY l.local_id DESC LIMIT $2", &[&delivery_id,&(remaining.min(50) as i64)]).await.map_err(database_error)? {
                    let mut trace:crate::delivery_log::Attempt=serde_json::from_value(r.get(2))?;
                    trace.sanitize();
                    logs.push(AttemptLog {id:r.get(0),attempt:r.get::<_,i64>(1).try_into()?,trace});
                }
            }
            remaining -= logs.len();
            recipients.push(RecipientDiagnostics {
                delivery_id,
                address: row.get(1),
                destination: row.get(2),
                status: row.get(3),
                attempts: row.get::<_, i64>(4).try_into()?,
                next_attempt: row.get(5),
                last_error: row
                    .get::<_, Option<String>>(6)
                    .as_deref()
                    .map(crate::delivery_log::sanitize_text),
                logs_available,
                logs_truncated: logs_available > logs.len(),
                logs,
            });
        }
        tx.commit().await.map_err(database_error)?;
        Ok(Some(MessageDiagnostics {
            message_id: id.to_owned(),
            analysis: scan.into(),
            recipients,
        }))
    }
}
