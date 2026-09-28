//! Final destination commit, after durable local selection on every source.
use super::PreparedImport;
use crate::{
    central::{Central, binding::Binding, database_error, selection::Selection},
    cluster::Role,
};
use anyhow::{Context, Result, ensure};
use std::collections::BTreeSet;

impl Central {
    /// Final offline cutover primitive, not a remote orchestration API.
    ///
    /// The caller MUST hold every source's process locks and SQLite write
    /// reservations from capture through `commit_sources`. The callback verifies
    /// installed artifacts and original MFA key, installs the supplied selections
    /// in those source transactions, durably commits ALL of them and reads the
    /// selections back. Return only after every source has completed this step.
    /// No configuration or service is changed here.
    ///
    /// PostgreSQL stays inactive if source commits fail, including a partial
    /// commit. In that case keep the services stopped and resume the same binding;
    /// never start a legacy binary or silently unselect a committed source.
    /// A lost reply after the destination commit requires inspecting its receipt,
    /// not creating another authority. Already active receipts are refused here.
    pub async fn activate_import<F>(
        &self,
        binding: &Binding,
        prepared: &PreparedImport,
        selections: &[Selection],
        commit_sources: F,
    ) -> Result<()>
    where
        F: FnOnce() -> Result<Vec<Selection>>,
    {
        binding.validate()?;
        ensure!(
            self.binding().is_none(),
            "Runtime cannot activate an import"
        );
        ensure!(
            prepared.digest == binding.source_digest,
            "Management sources changed after import"
        );
        let mut nodes = BTreeSet::new();
        for selection in selections {
            selection.validate()?;
            ensure!(
                selection.database == *binding
                    && nodes.insert(selection.node.node.clone())
                    && prepared
                        .sources
                        .iter()
                        .any(|s| s.identity == selection.node)
                    && selection.baseline == prepared.policy.journal.current_epoch()
                    && (selection.role == Role::Coordinator)
                        == (selection.node.node == prepared.policy.journal.owner()),
                "Activation selection differs from frozen source authority"
            );
        }
        ensure!(
            nodes.len() == prepared.sources.len(),
            "Activation requires every captured source, including disabled nodes"
        );
        tokio::time::timeout(std::time::Duration::from_secs(120), async {
            let mut db = self.ingestion.get().await.context("Import database unavailable")?;
            let tx = db.transaction().await.map_err(database_error)?;
            // Serialize activators before taking SHARE locks (otherwise two
            // sessions could deadlock while upgrading migration_state to write).
            tx.batch_execute("LOCK TABLE noisefence.migration_state IN EXCLUSIVE MODE")
                .await.map_err(database_error)?;
            super::parity::lock(&tx).await?;
            let valid: bool = tx.query_one("SELECT EXISTS(SELECT 1 FROM noisefence.migration_state WHERE id=1 AND source_digest=$1 AND report->>'instance'=$2 AND report->>'phase'='copied_not_activated' AND activated_at IS NULL) AND (SELECT count(*)=1 FROM noisefence.schema_migrations) AND EXISTS(SELECT 1 FROM noisefence.schema_migrations WHERE version=1 AND sha256=$3)", &[&binding.source_digest,&binding.instance,&crate::message::digest(include_bytes!("../schema.sql"))]).await.map_err(database_error)?.get(0);
            ensure!(valid, "Activation requires the matching completed inactive import");
            super::parity::verify(&tx, prepared).await?;

            let installed = commit_sources().context(
                "Local selection did not complete; keep all services stopped and recover the same authority",
            )?;
            // Order is not significant; identity was checked for uniqueness.
            ensure!(
                installed.len() == selections.len()
                    && selections.iter().all(|s| installed.iter().filter(|i| *i == s).count() == 1),
                "Durable selection receipts do not cover every source"
            );
            let receipts = serde_json::to_value(&installed)?;
            let count = tx.execute("UPDATE noisefence.migration_state SET activated_at=$3,report=jsonb_set(jsonb_set(report,'{phase}','\"active\"'::jsonb),'{selections}',$4) WHERE id=1 AND source_digest=$1 AND report->>'instance'=$2 AND activated_at IS NULL", &[&binding.source_digest,&binding.instance,&crate::now(),&receipts]).await.map_err(database_error)?;
            ensure!(count == 1, "Activation receipt changed unexpectedly");
            tx.commit().await.map_err(database_error)?;
            Ok(())
        }).await.context("Activation deadline exceeded; inspect the existing receipt before recovery")?
    }
}
