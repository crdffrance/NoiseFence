//! Restore a unanimous installed policy without manufacturing rollout acknowledgements.
use crate::{
    central::{
        Central, admin::management_lock, database_error, import::SourceLocks, selection::Selection,
    },
    cluster::{
        Role,
        activation::{Journal, participant::Local},
        artifacts,
    },
    config::Config,
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::collections::BTreeMap;

/// Stable recovery identity for a completed policy. A final acknowledgement may
/// refresh rollout.updated independently on each cache. It carries no revision or
/// liveness authority here; all other fields, including acknowledgements, remain bound.
pub(super) fn identity(journal: &Journal) -> Result<Value> {
    journal.validate()?;
    ensure!(
        journal.released(),
        "Recovery identity requires a completed policy"
    );
    let mut value = serde_json::to_value(journal)?;
    if let Some(updated) = value.pointer_mut("/rollout/updated") {
        *updated = json!(0);
    }
    Ok(value)
}

impl Central {
    /// All original writers must already be fenced. These local locks protect
    /// stopped recovery copies; they cannot establish a remote authority fence.
    /// Does not clear startup markers or install a policy on a divergent node.
    pub async fn reconcile_recovered_policy(
        &self,
        configs: &[Config],
        operation: &str,
    ) -> Result<Value> {
        ensure!(
            (1..=64).contains(&configs.len()),
            "Invalid recovery source count"
        );
        let locks = configs
            .iter()
            .map(|c| SourceLocks::acquire(&c.data_dir))
            .collect::<Result<Vec<_>>>()?;
        self.reconcile_recovered_policy_held(configs, operation, &locks)
            .await
    }

    pub(super) async fn reconcile_recovered_policy_held(
        &self,
        configs: &[Config],
        operation: &str,
        locks: &[SourceLocks],
    ) -> Result<Value> {
        ensure!(
            (1..=64).contains(&configs.len()),
            "Invalid recovery source count"
        );
        ensure!(
            uuid::Uuid::parse_str(operation).is_ok_and(|v| v.to_string() == operation),
            "Invalid recovery operation"
        );
        let binding = self
            .binding()
            .context("Recovery requires a selected database")?;
        ensure!(
            configs.len() == locks.len(),
            "Recovery source locks missing"
        );
        let mut identities = BTreeMap::new();
        let mut agreed: Option<Journal> = None;
        let mut coordinator = None;
        for (config, guard) in configs.iter().zip(locks) {
            guard.verify_for(&config.data_dir)?;
            let mut db = rusqlite::Connection::open_with_flags(
                config.data_dir.join("state.sqlite3"),
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )?;
            let tx = db.transaction()?;
            let selection = Selection::read(&tx)?.context("Recovery source is not selected")?;
            ensure!(
                &selection.database == binding,
                "Recovery source database mismatch"
            );
            let cluster = config
                .cluster
                .as_ref()
                .context("Recovery source cluster identity missing")?;
            ensure!(
                cluster.node_id == selection.node.node && cluster.role == selection.role,
                "Recovery configuration identity mismatch"
            );
            selection.verify_key(&config.data_dir)?;
            let pending: String = tx.query_row(
                "SELECT value FROM cluster_state WHERE key='management_recovery_required'",
                [],
                |r| r.get(0),
            )?;
            let pending: Value = serde_json::from_str(&pending)?;
            ensure!(
                pending["protocol"] == "noisefence-management-recovery-1"
                    && pending["operation"] == operation,
                "Recovery source operation mismatch"
            );
            let local = Local::read(&tx)?.context("Recovery policy cache missing")?;
            let journal = local.authority();
            ensure!(
                journal.released() && local.installed_epoch() == &journal.current_epoch(),
                "Finish coordinated policy recovery before reconciling installed caches"
            );
            ensure!(
                local.installed_epoch().sequence > selection.baseline.sequence
                    || local.installed_epoch() == &selection.baseline,
                "Recovery policy predates cutover"
            );
            artifacts::materialize(config, local.installed(), true)?;
            if let Some(previous) = &agreed {
                ensure!(
                    identity(previous)? == identity(journal)?,
                    "Recovery participants disagree on policy authority"
                );
            } else {
                agreed = Some(journal.clone());
            }
            ensure!(
                identities
                    .insert(selection.node.node.clone(), selection.node.epoch.clone())
                    .is_none(),
                "Duplicate recovery source"
            );
            if selection.role == Role::Coordinator {
                ensure!(
                    coordinator.replace(selection.node.node).is_none(),
                    "Multiple recovery coordinators"
                );
            }
        }
        let journal = agreed.context("Recovery policy missing")?;
        ensure!(
            coordinator.as_deref() == Some(journal.owner()),
            "Recovery coordinator differs from policy owner"
        );
        let rollout = journal
            .rollout()
            .context("Recovery requires an enrolled policy")?;
        ensure!(
            rollout.participants().keys().eq(identities.keys()),
            "Recovery policy participant set mismatch"
        );
        for guard in locks {
            guard.verify()?;
        }
        tokio::time::timeout(
            std::time::Duration::from_secs(60),
            self.reconcile_policy_locked(operation, &journal, &identities),
        )
        .await
        .context("Recovery policy deadline exceeded")?
    }

    async fn reconcile_policy_locked(
        &self,
        operation: &str,
        journal: &Journal,
        identities: &BTreeMap<String, String>,
    ) -> Result<Value> {
        let binding = self
            .binding()
            .context("Recovery requires a selected database")?;
        let mut db = self
            .interactive
            .get()
            .await
            .context("Recovery policy capacity unavailable")?;
        let tx = db.transaction().await.map_err(database_error)?;
        management_lock(&tx).await?;
        let mut report:Value=tx.query_one("SELECT report FROM noisefence.migration_state WHERE id=1 AND source_digest=$1 AND report->>'instance'=$2 AND activated_at IS NOT NULL FOR UPDATE",&[&binding.source_digest,&binding.instance]).await.map_err(database_error)?.get(0);
        let access = report["access_recoveries"][operation]
            .as_object()
            .context("Recover access before policy reconciliation")?;
        let actor = access
            .get("username")
            .and_then(Value::as_str)
            .context("Recovery actor missing")?
            .to_owned();
        let saved_sources = access
            .get("replay_sources")
            .and_then(Value::as_array)
            .context("Recovery source receipt missing")?;
        let mut saved = BTreeMap::new();
        for source in saved_sources.iter().filter(|s| s["enabled"] == true) {
            let node = source["identity"]["node"]
                .as_str()
                .context("Invalid recorded source")?;
            let epoch = source["identity"]["epoch"]
                .as_str()
                .context("Invalid recorded epoch")?;
            ensure!(
                saved.insert(node.to_owned(), epoch.to_owned()).is_none(),
                "Duplicate recorded source"
            );
        }
        ensure!(
            &saved == identities,
            "Recovery policy sources differ from access recovery"
        );
        let current: BTreeMap<String, String> = tx
            .query(
                "SELECT node,epoch FROM noisefence.sources WHERE enabled ORDER BY node FOR SHARE",
                &[],
            )
            .await
            .map_err(database_error)?
            .into_iter()
            .map(|r| (r.get(0), r.get(1)))
            .collect();
        ensure!(&current == identities, "Recovery policy membership changed");
        let row=tx.query_one("SELECT node,epoch,journal,membership FROM noisefence.policy_authority WHERE id=1 FOR UPDATE",&[]).await.map_err(database_error)?;
        ensure!(
            row.get::<_, String>(0) == journal.owner()
                && row.get::<_, String>(1) == identities[journal.owner()]
                && row.get::<_, Value>(3) == serde_json::to_value(identities)?,
            "Recovery policy authority identity mismatch"
        );
        let previous: Journal = serde_json::from_value(row.get(2))?;
        previous.validate()?;
        let head=tx.query_one("SELECT revision,activation_epoch,activated_at IS NOT NULL FROM noisefence.policy_head WHERE id=1 FOR UPDATE",&[]).await.map_err(database_error)?;
        ensure!(
            head.get::<_, i64>(0) == previous.current().revision
                && head.get::<_, Value>(1) == serde_json::to_value(previous.current_epoch())?
                && head.get::<_, bool>(2),
            "Recovered policy head changed"
        );
        let incoming = serde_json::to_value(journal)?;
        let before = serde_json::to_value(&previous)?;
        let rank = |j: &Journal| {
            j.rollout()
                .map_or(j.current_epoch().sequence, |r| r.epoch().sequence)
        };
        ensure!(
            previous.owner() == journal.owner() && previous.released(),
            "Resolve unfinished restored policy before reconciliation"
        );
        ensure!(
            rank(&previous) < rank(journal) || identity(&previous)? == identity(journal)?,
            "Recovery would overwrite a newer or conflicting policy"
        );
        ensure!(
            previous.current().revision <= journal.current().revision
                && (previous.current_epoch().sequence < journal.current_epoch().sequence
                    || previous.current_epoch() == journal.current_epoch()),
            "Recovery would roll back the active policy"
        );
        let settings = serde_json::to_value(&journal.current().settings)?;
        let hash = crate::message::digest(&serde_json::to_vec(&journal.current().settings)?);
        let revision = journal.current().revision;
        ensure!(
            !tx.query_one(
                "SELECT EXISTS(SELECT 1 FROM noisefence.policy_revisions WHERE id>$1)",
                &[&revision]
            )
            .await
            .map_err(database_error)?
            .get::<_, bool>(0),
            "Recovery would discard newer policy history"
        );
        if let Some(row) = tx
            .query_opt(
                "SELECT settings,sha256 FROM noisefence.policy_revisions WHERE id=$1",
                &[&revision],
            )
            .await
            .map_err(database_error)?
        {
            ensure!(
                row.get::<_, Value>(0) == settings && row.get::<_, String>(1) == hash,
                "Recovery revision conflicts with existing history"
            );
        } else {
            tx.execute("INSERT INTO noisefence.policy_revisions(id,created,username,settings,sha256) VALUES($1,$2,$3,$4,$5)",&[&revision,&crate::now(),&actor,&settings,&hash]).await.map_err(database_error)?;
        }
        let fingerprint = crate::message::digest(&serde_json::to_vec(
            &json!({"journal":identity(journal)?,"sources":identities}),
        )?);
        let existing = &report["policy_recoveries"][operation];
        if !existing.is_null() {
            ensure!(
                existing["fingerprint"] == fingerprint
                    && identity(&previous)? == identity(journal)?,
                "Recovery policy receipt mismatch"
            );
            let head=tx.query_one("SELECT revision,activation_epoch,activated_at IS NOT NULL FROM noisefence.policy_head WHERE id=1",&[]).await.map_err(database_error)?;
            ensure!(
                head.get::<_, i64>(0) == revision
                    && head.get::<_, Value>(1) == serde_json::to_value(journal.current_epoch())?
                    && head.get::<_, bool>(2),
                "Recovered policy head changed"
            );
            return Ok(existing.clone());
        }
        let receipt = json!({"operation":operation,"fingerprint":fingerprint,"epoch":journal.current_epoch(),"sources":identities.len(),"central_management_recovery_required":true,
            "restored_rollout_updated":before.pointer("/rollout/updated"),
            "installed_rollout_updated":incoming.pointer("/rollout/updated")});
        let records = report
            .as_object_mut()
            .context("Invalid migration receipt")?
            .entry("policy_recoveries")
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .context("Invalid policy recovery receipts")?;
        ensure!(records.len() < 256, "Policy recovery receipt limit reached");
        records.insert(operation.into(), receipt.clone());
        tx.execute("UPDATE noisefence.policy_authority SET journal=$1,actor=NULL,actor_version=NULL,session_hash=NULL,scope=NULL,incident=NULL WHERE id=1",&[&incoming]).await.map_err(database_error)?;
        // Zero means recovered installation evidence, never a fresh heartbeat.
        tx.execute("UPDATE noisefence.policy_head SET revision=$1,activated_at=0,activation_epoch=$2 WHERE id=1",&[&revision,&serde_json::to_value(journal.current_epoch())?]).await.map_err(database_error)?;
        tx.execute("DELETE FROM noisefence.policy_peers", &[])
            .await
            .map_err(database_error)?;
        tx.execute(
            "UPDATE noisefence.migration_state SET report=$1 WHERE id=1",
            &[&report],
        )
        .await
        .map_err(database_error)?;
        tx.execute("INSERT INTO noisefence.audit(created,username,action,object_id) VALUES($1,$2,'recover_installed_policy',$3)",&[&crate::now(),&actor,&operation]).await.map_err(database_error)?;
        tx.query_one("SELECT setval('noisefence.policy_revisions_id_seq',GREATEST((SELECT last_value FROM noisefence.policy_revisions_id_seq),$1),true)",&[&revision.max(1)]).await.map_err(database_error)?;
        tx.commit().await.map_err(database_error)?;
        Ok(receipt)
    }
}
