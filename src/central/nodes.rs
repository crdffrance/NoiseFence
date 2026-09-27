//! Management node identities are separate from browser users and sessions.
use super::{Central, admin::management_lock, database_error, outbox::Identity};
use anyhow::{Context, Result, ensure};
use deadpool_postgres::Transaction;

/// Created only after authentication. Transports cannot construct a receipt
/// authority from a node name supplied in a JSON body.
#[derive(Clone)]
pub struct Authenticated {
    pub(crate) identity: Identity,
    pub(crate) hash: String,
}
impl Authenticated {
    pub fn identity(&self) -> &Identity {
        &self.identity
    }
    /// Recheck inside the transaction that accepts a payload. Rotation waits
    /// for this read lock or wins first and causes the transaction to fail.
    pub(super) async fn check(&self, tx: &Transaction<'_>) -> Result<()> {
        ensure!(tx.query_opt("SELECT node FROM noisefence.cluster_nodes WHERE node=$1 AND epoch=$2 AND token_hash=$3 AND enabled FOR SHARE", &[&self.identity.node,&self.identity.epoch,&self.hash]).await.map_err(database_error)?.is_some(),"Node credential revoked");
        Ok(())
    }
}
impl Central {
    /// Explicit installer/import step; never enroll an unknown spool from an
    /// incoming payload. Existing identities cannot silently rotate or rebind.
    pub async fn enroll_node(
        &self,
        identity: &Identity,
        name: &str,
        token_hash: &str,
    ) -> Result<()> {
        ensure!(
            !name.is_empty()
                && name.len() <= 100
                && !name.chars().any(char::is_control)
                && crate::compatibility::valid_hash(token_hash),
            "Invalid node enrollment"
        );
        let mut db = self
            .interactive
            .get()
            .await
            .context("Central node capacity unavailable")?;
        let tx = db.transaction().await.map_err(database_error)?;
        management_lock(&tx).await?;
        ensure!(tx.query_opt("SELECT node FROM noisefence.sources WHERE node=$1 AND epoch=$2 AND enabled FOR UPDATE", &[&identity.node,&identity.epoch]).await.map_err(database_error)?.is_some(),"Node spool must be registered first");
        let existing=tx.query_opt("SELECT epoch,token_hash,enabled FROM noisefence.cluster_nodes WHERE node=$1 FOR UPDATE", &[&identity.node]).await.map_err(database_error)?;
        if let Some(existing) = existing {
            ensure!(
                existing.get::<_, String>(0) == identity.epoch
                    && existing.get::<_, String>(1) == token_hash
                    && existing.get::<_, bool>(2),
                "Existing node requires explicit reconciliation"
            );
        } else {
            ensure!(
                tx.query_one("SELECT count(*) FROM noisefence.cluster_nodes", &[])
                    .await
                    .map_err(database_error)?
                    .get::<_, i64>(0)
                    < 63,
                "Maximum node count reached"
            );
            tx.execute("INSERT INTO noisefence.cluster_nodes(node,epoch,name,token_hash,created) VALUES($1,$2,$3,$4,$5)", &[&identity.node,&identity.epoch,&name,&token_hash,&crate::now()]).await.map_err(database_error)?;
        }
        tx.commit().await.map_err(database_error)?;
        Ok(())
    }
    pub async fn authenticate_node(&self, node: &str, hash: &str) -> Result<Option<Authenticated>> {
        if !crate::cluster::valid_id(node) || !crate::compatibility::valid_hash(hash) {
            return Ok(None);
        }
        let db = self
            .interactive
            .get()
            .await
            .context("Central node capacity unavailable")?;
        let row=db.query_opt("SELECT n.epoch,n.token_hash FROM noisefence.cluster_nodes n JOIN noisefence.sources s ON s.node=n.node AND s.epoch=n.epoch WHERE n.node=$1 AND n.enabled AND s.enabled", &[&node]).await.map_err(database_error)?;
        let Some(row) = row else { return Ok(None) };
        let expected: String = row.get(1);
        if expected.len() != hash.len()
            || expected
                .bytes()
                .zip(hash.bytes())
                .fold(0, |v, (a, b)| v | (a ^ b))
                != 0
        {
            return Ok(None);
        }
        Ok(Some(Authenticated {
            identity: Identity {
                node: node.to_owned(),
                epoch: row.get(0),
            },
            hash: hash.to_owned(),
        }))
    }
    pub async fn node_overview(
        &self,
        actor: &str,
    ) -> Result<(Vec<serde_json::Value>, Vec<serde_json::Value>)> {
        let mut db = self
            .interactive
            .get()
            .await
            .context("Central node capacity unavailable")?;
        let tx = db
            .build_transaction()
            .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
            .start()
            .await
            .map_err(database_error)?;
        super::admin::administrator(&tx, actor).await?;
        let nodes=tx.query("SELECT node,name,enabled,created,last_seen,applied_revision,applied_digest,status,version FROM noisefence.cluster_nodes ORDER BY node LIMIT 64", &[]).await.map_err(database_error)?.iter().map(|r|serde_json::json!({"id":r.get::<_,String>(0),"name":r.get::<_,String>(1),"enabled":r.get::<_,bool>(2),"created":r.get::<_,i64>(3),"last_seen":r.get::<_,Option<i64>>(4),"applied_revision":r.get::<_,Option<i64>>(5),"applied_digest":r.get::<_,Option<String>>(6),"status":r.get::<_,serde_json::Value>(7),"version":r.get::<_,i64>(8)})).collect();
        let commands=tx.query("SELECT id,node,recipient,command,created,result,finished FROM noisefence.queue_commands ORDER BY created DESC,id LIMIT 50", &[]).await.map_err(database_error)?.iter().map(|r|serde_json::json!({"id":r.get::<_,String>(0),"node_id":r.get::<_,String>(1),"recipient":r.get::<_,String>(2),"command":serde_json::to_string(&r.get::<_,String>(3)).unwrap(),"created":r.get::<_,i64>(4),"result":r.get::<_,Option<String>>(5),"finished":r.get::<_,Option<i64>>(6)})).collect();
        tx.commit().await.map_err(database_error)?;
        Ok((nodes, commands))
    }
}

pub struct Edit<'a> {
    pub id: &'a str,
    pub name: &'a str,
    pub enabled: bool,
    pub version: i64,
    pub token_hash: Option<&'a str>,
}
impl Central {
    /// Updates an explicitly enrolled spool. Creating/replacing a spool still
    /// requires the import/enrollment workflow, never a guessed remote epoch.
    pub async fn edit_node(&self, actor: &str, session: &str, edit: Edit<'_>) -> Result<i64> {
        ensure!(
            crate::cluster::valid_id(edit.id)
                && !edit.name.is_empty()
                && edit.name.len() <= 100
                && !edit.name.chars().any(char::is_control)
                && edit.token_hash.is_none_or(crate::compatibility::valid_hash),
            "Invalid node settings"
        );
        let mut db = self
            .interactive
            .get()
            .await
            .context("Central node capacity unavailable")?;
        let tx = db.transaction().await.map_err(database_error)?;
        management_lock(&tx).await?;
        ensure!(
            super::mfa::allowed(&tx, actor, session, None).await?,
            "Administrator session expired or revoked"
        );
        super::admin::administrator(&tx, actor).await?;
        let source = tx
            .query_opt(
                "SELECT epoch FROM noisefence.sources WHERE node=$1 FOR UPDATE",
                &[&edit.id],
            )
            .await
            .map_err(database_error)?
            .context("Enroll the node spool before editing its settings")?;
        let r = tx
            .query_opt(
                "SELECT epoch,version FROM noisefence.cluster_nodes WHERE node=$1 FOR UPDATE",
                &[&edit.id],
            )
            .await
            .map_err(database_error)?
            .context("Enroll the node spool before editing its settings")?;
        ensure!(
            r.get::<_, String>(0) == source.get::<_, String>(0)
                && r.get::<_, i64>(1) == edit.version,
            "Node identity or version changed; reload"
        );
        ensure!(
            tx.query_opt(
                "SELECT id FROM noisefence.policy_authority WHERE node=$1",
                &[&edit.id]
            )
            .await
            .map_err(database_error)?
            .is_none(),
            "The policy authority cannot be edited as a worker"
        );
        let version:i64=tx.query_one("UPDATE noisefence.cluster_nodes SET name=$2,enabled=$3,token_hash=COALESCE($4,token_hash),version=version+1 WHERE node=$1 RETURNING version", &[&edit.id,&edit.name,&edit.enabled,&edit.token_hash]).await.map_err(database_error)?.get(0);
        tx.execute(
            "UPDATE noisefence.sources SET enabled=$2 WHERE node=$1",
            &[&edit.id, &edit.enabled],
        )
        .await
        .map_err(database_error)?;
        if !edit.enabled {
            tx.execute("UPDATE noisefence.queue_commands SET result='revoked',finished=$2 WHERE node=$1 AND finished IS NULL", &[&edit.id,&crate::now()]).await.map_err(database_error)?;
        }
        if edit.token_hash.is_some() || !edit.enabled {
            // A fresh authenticated report is required after rotation/revocation.
            tx.execute(
                "DELETE FROM noisefence.policy_peers WHERE node=$1",
                &[&edit.id],
            )
            .await
            .map_err(database_error)?;
        }
        tx.execute("INSERT INTO noisefence.audit(created,username,action,object_id) VALUES($1,$2,'cluster_node',$3)", &[&crate::now(),&actor,&edit.id]).await.map_err(database_error)?;
        tx.commit().await.map_err(database_error)?;
        Ok(version)
    }
}
