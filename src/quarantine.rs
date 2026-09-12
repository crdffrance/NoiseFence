//! Quarantine is a durable per-recipient delivery state, never a second mail queue.
use crate::{now, store::Store};
use anyhow::Result;
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Command {
    Release,
    Delete,
}

type HeldDelivery = (i64, String, bool, Option<i64>, Option<String>);

pub enum Change {
    Done,
    Queued(String),
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
            let item: Option<HeldDelivery> = tx.query_row(
                "SELECT d.id,d.status,(m.raw_present=1 OR COALESCE(o.raw_present=1,0)),p.held_until,o.node_id FROM deliveries d JOIN messages m ON m.id=d.message_id JOIN console_access g ON g.delivery_id=d.id LEFT JOIN delivery_policy p ON p.delivery_id=d.id LEFT JOIN cluster_origin o ON o.message_id=m.id WHERE d.message_id=?1 AND d.address=?2 AND g.username=?3 AND EXISTS(SELECT 1 FROM sessions s WHERE s.username=?3 AND s.token_hash=?4 AND s.expires>?5)",
                params![message,recipient,username,token_hash,now()],
                |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)),
            ).optional()?;
            let Some((id,status,raw_present,until,remote)) = item else { return Ok(Change::NotFound); };
            if status != "quarantined" || !raw_present || until.is_none_or(|t| t <= now()) {
                return Ok(Change::Conflict);
            }
            if let Some(node)=remote {
                if !tx.query_row("SELECT EXISTS(SELECT 1 FROM cluster_nodes WHERE id=?1 AND enabled=1)",[&node],|r|r.get::<_,bool>(0))? {return Ok(Change::Conflict);}
                tx.execute("UPDATE cluster_commands SET result='expired',finished=?1 WHERE finished IS NULL AND expires<?1",[now()])?;
                if tx.query_row("SELECT EXISTS(SELECT 1 FROM cluster_commands WHERE node_id=?1 AND message_id=?2 AND recipient=?3 AND finished IS NULL)",params![node,message,recipient],|r|r.get::<_,bool>(0))? {return Ok(Change::Conflict);}
                let command_id=uuid::Uuid::new_v4().to_string();
                tx.execute("INSERT INTO cluster_commands(id,node_id,message_id,recipient,command,username,created,expires) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",params![command_id,node,message,recipient,serde_json::to_string(&command)?,username,now(),now()+300])?;
                tx.execute("INSERT INTO audit(created,username,action,object_id) VALUES(?1,?2,'cluster_quarantine_request',?3)",params![now(),username,command_id])?;
                tx.commit()?;return Ok(Change::Queued(command_id));
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
