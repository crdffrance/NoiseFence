//! Revoke snapshot-era node tokens without granting access to additional nodes.
use crate::central::{Central, admin::management_lock, database_error};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::Path};

impl Central {
    /// Called only while all selected source copies remain locked and original
    /// writers are fenced. Publishing tokens to the actual workers is separate.
    pub(super) async fn recover_worker_access(
        &self,
        operation: &str,
        path: &Path,
        workers: &BTreeMap<String, String>,
    ) -> Result<Value> {
        let binding = self
            .binding()
            .context("Selected recovery database required")?;
        let keys = super::node_credentials::prepare(path, binding, operation, workers)?;
        let hashes = keys.hashes();
        let fingerprint = crate::message::digest(&serde_json::to_vec(
            &json!({"workers":workers,"hashes":hashes}),
        )?);
        let mut db = self
            .interactive
            .get()
            .await
            .context("Worker recovery capacity unavailable")?;
        let tx = db.transaction().await.map_err(database_error)?;
        management_lock(&tx).await?;
        let mut report:Value=tx.query_one("SELECT report FROM noisefence.migration_state WHERE id=1 AND source_digest=$1 AND report->>'instance'=$2 AND activated_at IS NOT NULL FOR UPDATE",&[&binding.source_digest,&binding.instance]).await.map_err(database_error)?.get(0);
        let actor = report["access_recoveries"][operation]["username"]
            .as_str()
            .context("Recover browser access before worker credentials")?
            .to_owned();
        ensure!(
            !report["policy_recoveries"][operation].is_null(),
            "Reconcile policy before worker credentials"
        );
        let owner: String = tx
            .query_one(
                "SELECT node FROM noisefence.policy_authority WHERE id=1 FOR SHARE",
                &[],
            )
            .await
            .map_err(database_error)?
            .get(0);
        let expected:BTreeMap<String,String>=tx.query("SELECT node,epoch FROM noisefence.sources WHERE enabled AND node<>$1 ORDER BY node FOR SHARE",&[&owner]).await.map_err(database_error)?.into_iter().map(|r|(r.get(0),r.get(1))).collect();
        ensure!(&expected == workers, "Recovery worker source set changed");
        let rows=tx.query("SELECT node,epoch,token_hash FROM noisefence.cluster_nodes WHERE enabled ORDER BY node FOR UPDATE",&[]).await.map_err(database_error)?;
        let enrolled: BTreeMap<String, String> =
            rows.iter().map(|r| (r.get(0), r.get(1))).collect();
        ensure!(
            enrolled == *workers,
            "Recovery worker enrollment differs; never re-enable or enroll snapshot identities implicitly"
        );
        let old_hashes: BTreeMap<String, String> =
            rows.iter().map(|r| (r.get(0), r.get(2))).collect();
        let existing = &report["worker_access_recoveries"][operation];
        if !existing.is_null() {
            ensure!(
                existing["fingerprint"] == fingerprint
                    && existing["credentials_file"] == json!(path)
                    && old_hashes == hashes,
                "Recovery worker credential receipt no longer matches installed authority"
            );
            return Ok(existing.clone());
        }
        ensure!(
            hashes
                .values()
                .all(|hash| !old_hashes.values().any(|old| old == hash)),
            "Recovery must replace all previous worker credentials"
        );
        for (node, hash) in &hashes {
            tx.execute("UPDATE noisefence.cluster_nodes SET token_hash=$2,version=version+1,last_seen=NULL,applied_revision=NULL,applied_digest=NULL,status='{}' WHERE node=$1",&[node,hash]).await.map_err(database_error)?;
        }
        let receipt = json!({"operation":operation,"fingerprint":fingerprint,"workers":workers.len(),
            "credentials_file":path,"worker_installation_required":true,"central_management_recovery_required":true});
        let records = report
            .as_object_mut()
            .context("Invalid migration receipt")?
            .entry("worker_access_recoveries")
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .context("Invalid worker recovery receipts")?;
        ensure!(records.len() < 256, "Worker recovery receipt limit reached");
        records.insert(operation.into(), receipt.clone());
        tx.execute(
            "UPDATE noisefence.migration_state SET report=$1 WHERE id=1",
            &[&report],
        )
        .await
        .map_err(database_error)?;
        tx.execute("INSERT INTO noisefence.audit(created,username,action,object_id) VALUES($1,$2,'recover_worker_credentials',$3)",&[&crate::now(),&actor,&operation]).await.map_err(database_error)?;
        tx.commit().await.map_err(database_error)?;
        Ok(receipt)
    }
}
