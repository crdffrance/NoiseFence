//! Verify installed worker keys while all original writers remain fenced.
use crate::{
    central::{Central, admin::management_lock, database_error},
    cluster::Role,
    config::Config,
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

pub(super) fn installed_hash(path: &Path) -> Result<String> {
    ensure!(
        path.is_absolute(),
        "Worker credential path must be absolute"
    );
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    // SAFETY: geteuid only reads the process identity.
    ensure!(
        meta.is_file()
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.permissions().mode() & 0o077 == 0
            && meta.len() <= 66,
        "Installed worker credentials must be owner-private bounded regular files"
    );
    let mut token = String::new();
    file.take(67).read_to_string(&mut token)?;
    let token = token.trim();
    ensure!(
        token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit()),
        "Invalid installed worker credential"
    );
    Ok(crate::message::digest(token.as_bytes()))
}

impl Central {
    /// The caller holds every selected source's daemon/calibration locks and has
    /// already checked remote fencing, access, history and policy for this operation.
    /// This never writes worker files or clears a source's startup marker.
    pub(super) async fn verify_recovered_worker_installation(
        &self,
        configs: &[Config],
        operation: &str,
        credentials: &Path,
        workers: &BTreeMap<String, String>,
    ) -> Result<Value> {
        let binding = self
            .binding()
            .context("Selected recovery database required")?;
        let keys = super::node_credentials::read(credentials, binding, operation, workers)?
            .context("Prepared worker credentials missing")?;
        let hashes = keys.hashes();
        let mut paths = BTreeMap::new();
        for config in configs {
            let cluster = config.cluster.as_ref().context("Worker identity missing")?;
            if cluster.role != Role::Worker {
                continue;
            }
            let path = cluster
                .credential_file
                .as_ref()
                .context("Configured worker credential path missing")?;
            ensure!(
                hashes.get(&cluster.node_id) == Some(&installed_hash(path)?),
                "Worker credential installation does not match the recovery operation"
            );
            ensure!(
                paths
                    .insert(cluster.node_id.clone(), path.clone())
                    .is_none(),
                "Duplicate worker installation"
            );
        }
        ensure!(
            paths.keys().eq(workers.keys()),
            "Incomplete worker credential installation set"
        );
        let access_fingerprint = crate::message::digest(&serde_json::to_vec(
            &json!({"workers":workers,"hashes":hashes}),
        )?);
        let fingerprint = crate::message::digest(&serde_json::to_vec(
            &json!({"authority":access_fingerprint,"paths":paths}),
        )?);
        let mut db = self
            .interactive
            .get()
            .await
            .context("Worker installation capacity unavailable")?;
        let tx = db.transaction().await.map_err(database_error)?;
        management_lock(&tx).await?;
        let mut report:Value=tx.query_one("SELECT report FROM noisefence.migration_state WHERE id=1 AND source_digest=$1 AND report->>'instance'=$2 AND activated_at IS NOT NULL FOR UPDATE",&[&binding.source_digest,&binding.instance]).await.map_err(database_error)?.get(0);
        let actor = report["access_recoveries"][operation]["username"]
            .as_str()
            .context("Recovery access receipt missing")?
            .to_owned();
        let issued = &report["worker_access_recoveries"][operation];
        ensure!(
            issued["fingerprint"] == access_fingerprint
                && issued["credentials_file"] == json!(credentials),
            "Installed worker keys differ from the issued recovery authority"
        );
        let rows=tx.query("SELECT n.node,n.epoch,n.token_hash FROM noisefence.cluster_nodes n JOIN noisefence.sources s ON s.node=n.node AND s.epoch=n.epoch WHERE n.enabled AND s.enabled ORDER BY n.node FOR SHARE OF n,s",&[]).await.map_err(database_error)?;
        let current: BTreeMap<String, (String, String)> = rows
            .iter()
            .map(|r| (r.get(0), (r.get(1), r.get(2))))
            .collect();
        ensure!(
            current.len() == workers.len()
                && current
                    .iter()
                    .all(|(node, (epoch, hash))| workers.get(node) == Some(epoch)
                        && hashes.get(node) == Some(hash)),
            "Installed worker credential authority changed"
        );
        // Re-read under the central authority lock: an old verification receipt
        // cannot hide a subsequently replaced or removed local key file.
        for (node, path) in &paths {
            ensure!(
                hashes.get(node) == Some(&installed_hash(path)?),
                "Worker credential file changed during verification"
            );
        }
        let existing = &report["worker_installation_recoveries"][operation];
        if !existing.is_null() {
            ensure!(
                existing["fingerprint"] == fingerprint,
                "Worker installation receipt mismatch"
            );
            return Ok(existing.clone());
        }
        let receipt = json!({"operation":operation,"fingerprint":fingerprint,"workers":workers.len(),
            "worker_credentials_verified":true,"verification_scope":"configured_local_files","central_management_recovery_required":true});
        let records = report
            .as_object_mut()
            .context("Invalid migration receipt")?
            .entry("worker_installation_recoveries")
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .context("Invalid worker installation receipts")?;
        ensure!(
            records.len() < 256,
            "Worker installation receipt limit reached"
        );
        records.insert(operation.into(), receipt.clone());
        tx.execute(
            "UPDATE noisefence.migration_state SET report=$1 WHERE id=1",
            &[&report],
        )
        .await
        .map_err(database_error)?;
        tx.execute("INSERT INTO noisefence.audit(created,username,action,object_id) VALUES($1,$2,'verify_recovery_worker_installation',$3)",&[&crate::now(),&actor,&operation]).await.map_err(database_error)?;
        tx.commit().await.map_err(database_error)?;
        Ok(receipt)
    }
}
