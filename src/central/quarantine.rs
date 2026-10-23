//! Read-only command receipts and current recipient state from central management.
use super::{Central, database_error};
use crate::quarantine::history::{History, Request, execution, result};
use anyhow::Result;
impl Central {
    pub async fn quarantine_history(
        &self,
        user: &str,
        session: &str,
        message: &str,
        recipient: &str,
    ) -> Result<Option<History>> {
        let mut db = self
            .interactive
            .get()
            .await
            .map_err(|_| anyhow::anyhow!("Central history capacity unavailable"))?;
        let tx = db
            .build_transaction()
            .read_only(true)
            .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
            .start()
            .await
            .map_err(database_error)?;
        let at = crate::now();
        let row = tx
            .query_opt(
                "SELECT d.status,m.raw_present,d.held_until,d.released_at,v.node,m.updated_at
             FROM noisefence.deliveries d JOIN noisefence.messages m ON m.id=d.message_id
             JOIN noisefence.console_access g ON g.delivery_id=d.id
             JOIN noisefence.message_versions v ON v.id=m.id
             WHERE d.message_id=$1 AND d.address=$2 AND g.username=$3
               AND (m.created>=$5::bigint-30*86400 OR m.raw_present)
               AND EXISTS(SELECT 1 FROM noisefence.sessions s
                 WHERE s.username=$3 AND s.token_hash=$4 AND s.expires>$5
                   AND (s.mfa_verified OR NOT EXISTS(SELECT 1 FROM noisefence.mfa_credentials k
                     WHERE k.username=s.username AND k.enabled)))",
                &[&message, &recipient, &user, &session, &at],
            )
            .await
            .map_err(database_error)?;
        let Some(row) = row else { return Ok(None) };
        let rows = tx.query(
            "SELECT id,node,username,command,created,expires,result,finished,execution_result,executed_at
             FROM noisefence.queue_commands
             WHERE message_id=$1 AND recipient=$2 AND created>=$3 AND command IN ('release','delete')
             ORDER BY created DESC,id DESC LIMIT 51",
            &[&message, &recipient, &(at-30*86400)],
        ).await.map_err(database_error)?;
        let requests: Vec<_> = rows
            .iter()
            .map(|r| Request {
                id: r.get(0),
                node: r.get(1),
                actor: r.get(2),
                action: r.get(3),
                requested_at: r.get(4),
                expires_at: r.get(5),
                result: result(r.get::<_, Option<String>>(6).as_deref(), r.get(5), at),
                finished_at: r.get(7),
                execution_result: execution(r.get::<_, Option<String>>(8).as_deref()),
                acknowledged_at: r.get(9),
            })
            .collect();
        let pending_command = requests
            .iter()
            .find(|c| c.result == "pending")
            .map(|c| c.id.clone());
        let mut view = History {
            schema: "quarantine-history-1",
            message_id: message.into(),
            recipient: recipient.into(),
            checked_at: at,
            snapshot_at: Some(row.get(5)),
            source: "central",
            node: Some(row.get(4)),
            status: row.get(0),
            raw_available: row.get(1),
            held_until: row.get(2),
            released_at: row.get(3),
            pending_command,
            events: vec![],
            requests,
            events_truncated: false,
            requests_truncated: false,
        };
        view.bound();
        tx.commit().await.map_err(database_error)?;
        Ok(Some(view))
    }
}
