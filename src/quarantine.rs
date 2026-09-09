//! Quarantine is a durable per-recipient delivery state, never a second mail queue.
use crate::{now, store::Store};
use anyhow::Result;
use rusqlite::{OptionalExtension, params};
use serde::Deserialize;

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Command {
    Release,
    Delete,
}

pub enum Change {
    Done,
    NotFound,
    Conflict,
}

impl Store {
    /// ACL and session checks share the write transaction with the state change.
    /// Each call names one envelope recipient; hidden recipients cannot be released.
    pub async fn quarantine_action(
        &self,
        username: String,
        token_hash: String,
        message: String,
        recipient: String,
        command: Command,
    ) -> Result<Change> {
        let result = self.run(move |db| {
            let tx = db.transaction()?;
            let item: Option<(i64, String, bool, Option<i64>)> = tx.query_row(
                "SELECT d.id,d.status,m.raw_present,p.held_until FROM deliveries d JOIN messages m ON m.id=d.message_id JOIN console_access g ON g.delivery_id=d.id LEFT JOIN delivery_policy p ON p.delivery_id=d.id WHERE d.message_id=?1 AND d.address=?2 AND g.username=?3 AND EXISTS(SELECT 1 FROM sessions s WHERE s.username=?3 AND s.token_hash=?4 AND s.expires>?5)",
                params![message,recipient,username,token_hash,now()],
                |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)),
            ).optional()?;
            let Some((id,status,raw_present,until)) = item else { return Ok(Change::NotFound); };
            if status != "quarantined" || !raw_present || until.is_none_or(|t| t <= now()) {
                return Ok(Change::Conflict);
            }
            let (status, action) = match command {
                Command::Release => ("pending", "quarantine_release"),
                Command::Delete => ("discarded", "quarantine_delete"),
            };
            tx.execute("UPDATE deliveries SET status=?2,next_attempt=?3,error=NULL WHERE id=?1", params![id,status,now()])?;
            if matches!(command, Command::Release) {
                // Give released mail its full SMTP retry period from release time.
                tx.execute("UPDATE delivery_policy SET released_at=?2 WHERE delivery_id=?1",params![id,now()])?;
            }
            tx.execute("INSERT INTO audit(created,username,action,object_id) VALUES(?1,?2,?3,?4)",params![now(),username,action,id.to_string()])?;
            tx.commit()?;
            Ok(Change::Done)
        }).await?;
        if matches!(result, Change::Done) {
            self.notify_delivery();
        }
        Ok(result)
    }
}
