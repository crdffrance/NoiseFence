//! Central authorization, durable commands, and local atomic queue execution.
//! PostgreSQL never owns a delivery lease or changes SMTP queue rows directly.
use super::{Central, database_error, outbox::Identity};
use crate::{
    cluster::history::{Command, CommandResult, Operation},
    quarantine::Change,
};
use anyhow::{Result, ensure};
use rusqlite::{OptionalExtension, params};
use serde_json::{Value, json};

fn name(operation: Operation) -> &'static str {
    match operation {
        Operation::Release => "release",
        Operation::Delete => "delete",
        Operation::Retry => "retry",
    }
}
fn parse(operation: &str) -> Result<Operation> {
    match operation {
        "release" => Ok(Operation::Release),
        "delete" => Ok(Operation::Delete),
        "retry" => Ok(Operation::Retry),
        _ => anyhow::bail!("Invalid central queue operation"),
    }
}
pub async fn pending_receipts(
    store: &crate::store::Store,
    identity: &Identity,
) -> Result<Vec<CommandResult>> {
    let identity = identity.clone();
    store.read(move |db| {
        ensure!(super::outbox::identity(db)?==identity,"Command receipt spool epoch mismatch");
        Ok(db.prepare("SELECT b.id,r.result FROM management_command_bindings b JOIN cluster_command_receipts r ON r.id=b.id WHERE b.epoch=?1 AND b.acknowledged=0 ORDER BY b.created,b.id LIMIT 12")?.query_map([identity.epoch],|r|Ok(CommandResult{id:r.get(0)?,result:r.get(1)?}))?.collect::<rusqlite::Result<Vec<_>>>()?)
    }).await
}
pub async fn acknowledge_receipts(
    store: &crate::store::Store,
    identity: Identity,
    receipts: Vec<CommandResult>,
) -> Result<()> {
    ensure!(receipts.len() <= 12, "Too many command acknowledgements");
    store.run(move |db| {
        let tx=db.transaction()?;
        ensure!(super::outbox::identity(&tx)?==identity,"Command receipt spool epoch mismatch");
        for r in receipts {
            tx.execute("UPDATE management_command_bindings SET acknowledged=1 WHERE id=?1 AND epoch=?2 AND EXISTS(SELECT 1 FROM cluster_command_receipts c WHERE c.id=?1 AND c.result=?3)",params![r.id,identity.epoch,r.result])?;
        }
        tx.commit()?;Ok(())
    }).await
}
pub async fn execute(
    store: &crate::store::Store,
    identity: Identity,
    commands: Vec<Command>,
) -> Result<Vec<CommandResult>> {
    ensure!(commands.len() <= 12, "Too many central commands");
    let results = store
        .run(move |db| {
            let tx = db.transaction()?;
            ensure!(
                super::outbox::identity(&tx)? == identity,
                "Command spool epoch mismatch"
            );
            let mut seen = std::collections::HashSet::new();
            for command in &commands {
                ensure!(seen.insert(&command.id), "Duplicate central command");
                ensure!(
                    command.expires <= crate::now() + 600,
                    "Command validity too long"
                );
                let digest = crate::message::digest(&serde_json::to_vec(command)?);
                let binding: Option<(String, String)> = tx
                    .query_row(
                        "SELECT epoch,digest FROM management_command_bindings WHERE id=?1",
                        [&command.id],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .optional()?;
                if let Some((epoch, original)) = binding {
                    ensure!(
                        epoch == identity.epoch && original == digest,
                        "Command identity or payload changed"
                    );
                } else {
                    ensure!(
                        !tx.query_row(
                            "SELECT EXISTS(SELECT 1 FROM cluster_command_receipts WHERE id=?1)",
                            [&command.id],
                            |r| r.get::<_, bool>(0)
                        )?,
                        "Command ID already belongs to another authority"
                    );
                    tx.execute(
                        "INSERT INTO management_command_bindings(id,epoch,digest,created) VALUES(?1,?2,?3,?4)",
                        params![command.id, identity.epoch, digest, crate::now()],
                    )?;
                }
            }
            let results = crate::cluster::history::execute_transaction(&tx, commands)?;
            tx.execute(
                "DELETE FROM management_command_bindings WHERE acknowledged=1 AND created<?1",
                [crate::now() - 30 * 86400],
            )?;
            tx.commit()?;
            Ok(results)
        })
        .await?;
    store.notify_delivery();
    Ok(results)
}

impl Central {
    pub async fn queue_quarantine(
        &self,
        username: &str,
        session: &str,
        message: &str,
        recipient: &str,
        operation: crate::quarantine::Command,
    ) -> Result<Change> {
        self.request_command(
            username,
            session,
            None,
            Some((message, recipient)),
            operation.into(),
        )
        .await
    }
    pub async fn queue_retry(
        &self,
        username: &str,
        session: &str,
        delivery: i64,
    ) -> Result<String> {
        match self
            .request_command(username, session, Some(delivery), None, Operation::Retry)
            .await?
        {
            Change::Queued(id) => Ok(id),
            _ => anyhow::bail!("Only a pending, authorized delivery can be tried again"),
        }
    }
    async fn request_command(
        &self,
        username: &str,
        session: &str,
        delivery: Option<i64>,
        target: Option<(&str, &str)>,
        operation: Operation,
    ) -> Result<Change> {
        let mut db = self
            .interactive
            .get()
            .await
            .map_err(|_| anyhow::anyhow!("Central queue capacity unavailable"))?;
        let tx = db.transaction().await.map_err(database_error)?;
        super::admin::management_lock(&tx).await?;
        if !super::mfa::allowed(&tx, username, session, None).await? {
            return Ok(Change::NotFound);
        }
        let actor = tx
            .query_one(
                "SELECT admin,version FROM noisefence.users WHERE username=$1",
                &[&username],
            )
            .await
            .map_err(database_error)?;
        if matches!(operation, Operation::Retry) && !actor.get::<_, bool>(0) {
            return Ok(Change::NotFound);
        }
        let (message, recipient) = target.unzip();
        let row=tx.query_opt("SELECT d.message_id,d.address,d.status,m.raw_present,d.held_until,v.node,v.epoch FROM noisefence.deliveries d JOIN noisefence.messages m ON m.id=d.message_id JOIN noisefence.message_versions v ON v.id=m.id JOIN noisefence.console_access a ON a.delivery_id=d.id WHERE a.username=$1 AND (($2::bigint IS NOT NULL AND d.id=$2) OR ($2 IS NULL AND d.message_id=$3 AND d.address=$4)) FOR UPDATE OF d", &[&username,&delivery,&message,&recipient]).await.map_err(database_error)?;
        let Some(row) = row else {
            return Ok(Change::NotFound);
        };
        let status: String = row.get(2);
        let valid = if matches!(operation, Operation::Retry) {
            status == "pending"
        } else {
            status == "quarantined"
                && row
                    .get::<_, Option<i64>>(4)
                    .is_some_and(|t| t > crate::now())
        };
        if !valid || !row.get::<_, bool>(3) {
            return Ok(Change::Conflict);
        }
        let message: String = row.get(0);
        let recipient: String = row.get(1);
        let node: String = row.get(5);
        let epoch: String = row.get(6);
        if tx.query_opt("SELECT node FROM noisefence.sources WHERE node=$1 AND epoch=$2 AND enabled FOR SHARE", &[&node,&epoch]).await.map_err(database_error)?.is_none() {return Ok(Change::Conflict);}
        tx.execute("UPDATE noisefence.queue_commands SET result='expired',finished=$4 WHERE node=$1 AND message_id=$2 AND recipient=$3 AND finished IS NULL AND expires<=$4", &[&node,&message,&recipient,&crate::now()]).await.map_err(database_error)?;
        if tx.query_opt("SELECT id FROM noisefence.queue_commands WHERE node=$1 AND message_id=$2 AND recipient=$3 AND finished IS NULL", &[&node,&message,&recipient]).await.map_err(database_error)?.is_some() {return Ok(Change::Conflict);}
        let id = uuid::Uuid::new_v4().to_string();
        tx.execute("INSERT INTO noisefence.queue_commands(id,node,node_epoch,message_id,recipient,command,username,session_hash,actor_version,created,expires) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)", &[&id,&node,&epoch,&message,&recipient,&name(operation),&username,&session,&actor.get::<_,i64>(1),&crate::now(),&(crate::now()+300)]).await.map_err(database_error)?;
        tx.execute("INSERT INTO noisefence.audit(created,username,action,object_id) VALUES($1,$2,'queue_request',$3)", &[&crate::now(),&username,&id]).await.map_err(database_error)?;
        tx.commit().await.map_err(database_error)?;
        Ok(Change::Queued(id))
    }

    /// Called only for an authenticated node identity. Re-check the human
    /// session, version and exact recipient grant before each dispatch.
    pub async fn pending_commands(&self, identity: &Identity) -> Result<Vec<Command>> {
        self.pending_commands_authenticated(identity, None).await
    }
    pub async fn pending_commands_for_node(
        &self,
        node: &super::nodes::Authenticated,
    ) -> Result<Vec<Command>> {
        self.pending_commands_authenticated(node.identity(), Some(node))
            .await
    }
    async fn pending_commands_authenticated(
        &self,
        identity: &Identity,
        credential: Option<&super::nodes::Authenticated>,
    ) -> Result<Vec<Command>> {
        let mut db = self
            .ingestion
            .get()
            .await
            .map_err(|_| anyhow::anyhow!("Central command capacity unavailable"))?;
        let tx = db.transaction().await.map_err(database_error)?;
        super::admin::management_lock(&tx).await?;
        ensure!(tx.query_opt("SELECT node FROM noisefence.sources WHERE node=$1 AND epoch=$2 AND enabled FOR SHARE", &[&identity.node,&identity.epoch]).await.map_err(database_error)?.is_some(),"Command source revoked or epoch mismatch");
        if let Some(credential) = credential {
            credential.check(&tx).await?;
        }
        tx.execute("UPDATE noisefence.queue_commands SET result='expired',finished=$2 WHERE node=$1 AND finished IS NULL AND expires<=$2", &[&identity.node,&crate::now()]).await.map_err(database_error)?;
        let rows=tx.query("SELECT id,message_id,recipient,command,username,expires,session_hash,actor_version FROM noisefence.queue_commands WHERE node=$1 AND node_epoch=$2 AND finished IS NULL ORDER BY created,id LIMIT 12 FOR UPDATE", &[&identity.node,&identity.epoch]).await.map_err(database_error)?;
        let mut commands = Vec::new();
        for row in rows {
            let username: String = row.get(4);
            let session: String = row.get(6);
            let version: i64 = row.get(7);
            let id: String = row.get(0);
            let message_id: String = row.get(1);
            let recipient: String = row.get(2);
            let operation: String = row.get(3);
            let authorized=super::mfa::allowed(&tx,&username,&session,None).await? && tx.query_opt("SELECT u.username FROM noisefence.users u JOIN noisefence.console_access a ON a.username=u.username JOIN noisefence.deliveries d ON d.id=a.delivery_id WHERE u.username=$1 AND u.version=$2 AND d.message_id=$3 AND d.address=$4 AND ($5!='retry' OR u.admin)", &[&username,&version,&message_id,&recipient,&operation]).await.map_err(database_error)?.is_some();
            if !authorized {
                tx.execute(
                    "UPDATE noisefence.queue_commands SET result='revoked',finished=$2 WHERE id=$1",
                    &[&id, &crate::now()],
                )
                .await
                .map_err(database_error)?;
                continue;
            }
            commands.push(Command {
                id,
                message_id,
                recipient,
                command: parse(&operation)?,
                username,
                expires: row.get(5),
            });
        }
        tx.execute("INSERT INTO noisefence.command_tombstones(id,node,epoch,execution_result,executed_at) SELECT id,node,node_epoch,execution_result,executed_at FROM noisefence.queue_commands WHERE finished<$1 ON CONFLICT(id) DO NOTHING", &[&(crate::now()-30*86400)]).await.map_err(database_error)?;
        tx.execute(
            "DELETE FROM noisefence.queue_commands WHERE finished<$1",
            &[&(crate::now() - 30 * 86400)],
        )
        .await
        .map_err(database_error)?;
        tx.commit().await.map_err(database_error)?;
        Ok(commands)
    }

    pub async fn acknowledge_commands(
        &self,
        identity: &Identity,
        receipts: &[CommandResult],
    ) -> Result<()> {
        self.acknowledge_commands_authenticated(identity, receipts, None)
            .await
    }
    pub async fn acknowledge_commands_for_node(
        &self,
        node: &super::nodes::Authenticated,
        receipts: &[CommandResult],
    ) -> Result<()> {
        self.acknowledge_commands_authenticated(node.identity(), receipts, Some(node))
            .await
    }
    async fn acknowledge_commands_authenticated(
        &self,
        identity: &Identity,
        receipts: &[CommandResult],
        credential: Option<&super::nodes::Authenticated>,
    ) -> Result<()> {
        ensure!(receipts.len() <= 12, "Too many command receipts");
        let mut db = self
            .ingestion
            .get()
            .await
            .map_err(|_| anyhow::anyhow!("Central command capacity unavailable"))?;
        let tx = db.transaction().await.map_err(database_error)?;
        ensure!(tx.query_opt("SELECT node FROM noisefence.sources WHERE node=$1 AND epoch=$2 AND enabled FOR SHARE", &[&identity.node,&identity.epoch]).await.map_err(database_error)?.is_some(),"Command source revoked or epoch mismatch");
        if let Some(credential) = credential {
            credential.check(&tx).await?;
        }
        for r in receipts {
            ensure!(
                ["done", "expired", "conflict"].contains(&r.result.as_str()),
                "Invalid command receipt"
            );
            let previous=tx.query_opt("SELECT result,execution_result FROM noisefence.queue_commands WHERE id=$1 AND node=$2 AND node_epoch=$3 FOR UPDATE", &[&r.id,&identity.node,&identity.epoch]).await.map_err(database_error)?;
            let Some(previous) = previous else {
                let archived=tx.query_opt("SELECT execution_result FROM noisefence.command_tombstones WHERE id=$1 AND node=$2 AND epoch=$3 FOR UPDATE", &[&r.id,&identity.node,&identity.epoch]).await.map_err(database_error)?.ok_or_else(||anyhow::anyhow!("Command does not belong to this source"))?;
                ensure!(
                    archived
                        .get::<_, Option<String>>(0)
                        .is_none_or(|result| result == r.result),
                    "Conflicting archived command receipt"
                );
                tx.execute("UPDATE noisefence.command_tombstones SET execution_result=$2,executed_at=COALESCE(executed_at,$3) WHERE id=$1", &[&r.id,&r.result,&crate::now()]).await.map_err(database_error)?;
                continue;
            };
            if let Some(executed) = previous.get::<_, Option<String>>(1) {
                ensure!(executed == r.result, "Conflicting execution receipt");
            }
            if let Some(previous) = previous.get::<_, Option<String>>(0) {
                // Expiry/revocation may win while a previously authorized worker
                // is already finishing. Preserve that outcome and its audit.
                ensure!(
                    previous == r.result || ["expired", "revoked"].contains(&previous.as_str()),
                    "Conflicting command receipt"
                );
                tx.execute("UPDATE noisefence.queue_commands SET execution_result=$2,executed_at=COALESCE(executed_at,$3) WHERE id=$1", &[&r.id,&r.result,&crate::now()]).await.map_err(database_error)?;
                continue;
            }
            tx.execute(
                "UPDATE noisefence.queue_commands SET result=$2,finished=$3,execution_result=$2,executed_at=$3 WHERE id=$1",
                &[&r.id, &r.result, &crate::now()],
            )
            .await
            .map_err(database_error)?;
        }
        tx.commit().await.map_err(database_error)?;
        Ok(())
    }

    pub async fn synchronize_commands_once(&self, store: &crate::store::Store) -> Result<usize> {
        let identity = store.read(|db| super::outbox::identity(db)).await?;
        let pending = pending_receipts(store, &identity).await?;
        if !pending.is_empty() {
            self.acknowledge_commands(&identity, &pending).await?;
            acknowledge_receipts(store, identity.clone(), pending.clone()).await?;
        }
        let commands = self.pending_commands(&identity).await?;
        if commands.is_empty() {
            return Ok(pending.len());
        }
        let receipts = execute(store, identity.clone(), commands).await?;
        self.acknowledge_commands(&identity, &receipts).await?;
        acknowledge_receipts(store, identity, receipts.clone()).await?;
        Ok(pending.len() + receipts.len())
    }

    pub async fn queue(&self, username: &str, local_node: &str) -> Result<Vec<Value>> {
        let db = self
            .interactive
            .get()
            .await
            .map_err(|_| anyhow::anyhow!("Central queue capacity unavailable"))?;
        let rows=db.query("SELECT d.id,d.message_id,d.address,d.status,d.attempts,d.next_attempt,d.error,m.created,v.node,EXISTS(SELECT 1 FROM noisefence.queue_commands c WHERE c.message_id=m.id AND c.recipient=d.address AND c.finished IS NULL) FROM noisefence.deliveries d JOIN noisefence.messages m ON m.id=d.message_id JOIN noisefence.message_versions v ON v.id=m.id WHERE d.status IN ('pending','sending','failed') AND EXISTS(SELECT 1 FROM noisefence.users u WHERE u.username=$1 AND u.admin AND NOT u.disabled) ORDER BY m.created,d.id LIMIT 200", &[&username]).await.map_err(database_error)?;
        Ok(rows.iter().map(|r|json!({"id":r.get::<_,i64>(0),"message_id":r.get::<_,String>(1),"address":r.get::<_,String>(2),"status":r.get::<_,String>(3),"attempts":r.get::<_,i64>(4),"next_attempt":r.get::<_,i64>(5),"error":r.get::<_,Option<String>>(6),"created":r.get::<_,i64>(7),"node_id":if r.get::<_,String>(8)==local_node {None}else{Some(r.get::<_,String>(8))},"pending_command":r.get::<_,bool>(9)})).collect())
    }
}
