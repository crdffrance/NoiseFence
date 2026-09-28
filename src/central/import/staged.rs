//! Ordered offline import into a fresh destination. Never activates a backend.
use super::{
    AccountsSnapshot, DeliveryIdentities, PolicySnapshot, QualitySnapshot, ReconciledSpools,
    ReconciliationReport, SpoolSnapshot,
};
use crate::central::{Central, binding::Binding, database_error};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub struct PreparedImport {
    pub(super) accounts: AccountsSnapshot,
    pub(super) deliveries: DeliveryIdentities,
    pub(super) quality: QualitySnapshot,
    pub(super) policy: PolicySnapshot,
    pub(super) sources: Vec<SpoolSnapshot>,
    reconciliation: ReconciliationReport,
    pub(super) digest: String,
}
/// A copy receipt is not an activation authorization. Backups, source/artifact
/// checks and local selection transactions still need to pass before cutover.
#[derive(Debug, Serialize)]
pub struct StagedImport {
    pub database: Binding,
    pub reconciliation: ReconciliationReport,
}
impl PreparedImport {
    pub fn new(
        accounts: AccountsSnapshot,
        deliveries: DeliveryIdentities,
        quality: QualitySnapshot,
        policy: PolicySnapshot,
        spools: ReconciledSpools,
    ) -> Result<Self> {
        let (mut sources, reconciliation) = spools.into_sources();
        sources.sort_by(|a, b| a.identity.node.cmp(&b.identity.node));
        let epochs: BTreeMap<String, String> = sources
            .iter()
            .map(|s| (s.identity.node.clone(), s.identity.epoch.clone()))
            .collect();
        ensure!(
            epochs == policy.epochs,
            "Prepared policy and spool epochs differ"
        );
        let mut digest = Sha256::new();
        part(&mut digest, &"noisefence-offline-import-1")?;
        part(
            &mut digest,
            &crate::message::digest(include_bytes!("../schema.sql")),
        )?;
        part(&mut digest, &accounts.tables)?;
        part(&mut digest, &deliveries.rows)?;
        part(&mut digest, &quality.tables)?;
        part(
            &mut digest,
            &(
                &policy.tables,
                &policy.journal,
                &policy.epochs,
                &policy.membership,
            ),
        )?;
        part(&mut digest, &reconciliation)?;
        for source in &sources {
            part(&mut digest, &source.identity)?;
            for event in &source.metadata {
                part(&mut digest, event)?;
            }
            for event in &source.logs {
                part(&mut digest, event)?;
            }
        }
        let digest = hex::encode(digest.finalize());
        Ok(Self {
            accounts,
            deliveries,
            quality,
            policy,
            sources,
            reconciliation,
            digest,
        })
    }
}
fn part<T: Serialize>(digest: &mut Sha256, value: &T) -> Result<()> {
    // Canonical object ordering, independent of map iteration order. Each part
    // is bounded by its capture primitive; no entire-spool JSON allocation.
    let canonical = serde_json::to_value(value)?;
    struct Writer<'a>(&'a mut Sha256);
    impl std::io::Write for Writer<'_> {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    serde_json::to_writer(Writer(digest), &canonical)?;
    digest.update(b"\n");
    Ok(())
}
impl Central {
    async fn verify_import_destination(&self, prepared: &PreparedImport) -> Result<()> {
        tokio::time::timeout(std::time::Duration::from_secs(120), async {
            let mut db = self
                .ingestion
                .get()
                .await
                .context("Import database unavailable")?;
            let tx = db.transaction().await.map_err(database_error)?;
            super::parity::lock(&tx).await?;
            super::parity::verify(&tx, prepared).await?;
            tx.commit().await.map_err(database_error)?;
            Ok(())
        })
        .await
        .context("Import destination verification deadline exceeded")?
    }
    /// Validate source freshness against a completed but inactive copy. The
    /// caller must retain its source locks; this is not an activation receipt.
    pub async fn verify_import_sources(
        &self,
        binding: &Binding,
        prepared: &PreparedImport,
    ) -> Result<()> {
        binding.validate()?;
        ensure!(
            self.binding().is_none(),
            "Runtime-bound databases cannot verify offline imports"
        );
        ensure!(
            prepared.digest == binding.source_digest,
            "Management sources changed after import; do not activate this copy"
        );
        tokio::time::timeout(std::time::Duration::from_secs(120), async {
            let mut db = self.ingestion.get().await.context("Import database unavailable")?;
            let tx = db.transaction().await.map_err(database_error)?;
            super::parity::lock(&tx).await?;
            let valid: bool = tx.query_one("SELECT EXISTS(SELECT 1 FROM noisefence.migration_state WHERE id=1 AND source_digest=$1 AND report->>'instance'=$2 AND report->>'phase'='copied_not_activated' AND activated_at IS NULL) AND (SELECT count(*)=1 FROM noisefence.schema_migrations) AND EXISTS(SELECT 1 FROM noisefence.schema_migrations WHERE version=1 AND sha256=$3)", &[&binding.source_digest, &binding.instance, &crate::message::digest(include_bytes!("../schema.sql"))]).await.map_err(database_error)?.get(0);
            ensure!(valid, "Import receipt is missing, changed, incomplete or already active");
            super::parity::verify(&tx, prepared).await?;
            tx.commit().await.map_err(database_error)?;
            Ok(())
        }).await.context("Import verification deadline exceeded")?
    }
    /// Caller holds every source daemon/learning lock for capture through final
    /// activation. Each copy phase is durable; failures leave an INACTIVE target
    /// and the original SQLite sources intact. Never erases/reuses a failed or
    /// previously populated destination. Use a fresh destination after failure.
    pub async fn stage_import(&self, mut prepared: PreparedImport) -> Result<StagedImport> {
        ensure!(
            self.binding().is_none(),
            "Runtime-bound databases cannot run offline imports"
        );
        let binding = Binding {
            instance: uuid::Uuid::new_v4().to_string(),
            source_digest: prepared.digest.clone(),
        };
        self.claim_import(&binding, &prepared.reconciliation)
            .await?;
        let copied: Result<()> = async {
            self.import_accounts(&prepared.accounts).await?;
            self.import_phase(&binding, "accounts").await?;
            for source in &mut prepared.sources {
                self.register_source(&source.identity).await?;
                // One bounded event per commit avoids packing several near-3MiB
                // scans into an oversized batch. No SMTP connection waits here.
                for event in &mut source.metadata {
                    self.ingest(&source.identity, std::slice::from_mut(event))
                        .await?;
                }
            }
            self.import_phase(&binding, "metadata").await?;
            self.import_delivery_identities(&prepared.deliveries)
                .await?;
            self.import_phase(&binding, "recipient_ids").await?;
            for source in &mut prepared.sources {
                for event in &mut source.logs {
                    self.ingest_logs(&source.identity, std::slice::from_mut(event))
                        .await?;
                }
            }
            self.import_phase(&binding, "smtp_logs").await?;
            self.import_quality(&prepared.quality).await?;
            self.import_phase(&binding, "quality").await?;
            self.import_policy(&prepared.policy).await?;
            self.verify_import_destination(&prepared).await?;
            self.import_phase(&binding, "copied_not_activated").await?;
            Ok(())
        }
        .await;
        if let Err(error) = copied {
            // If the connection was lost, the last completed phase remains;
            // activation is still NULL and runtime binding cannot connect.
            let _ = self.import_phase(&binding, "failed").await;
            return Err(error.context("Offline import failed; source databases remain authoritative and destination is inactive"));
        }
        Ok(StagedImport {
            database: binding,
            reconciliation: prepared.reconciliation,
        })
    }
    async fn claim_import(
        &self,
        binding: &Binding,
        reconciliation: &ReconciliationReport,
    ) -> Result<()> {
        tokio::time::timeout(std::time::Duration::from_secs(30),async {
            let mut db=self.ingestion.get().await.context("Import database unavailable")?;
            let tx=db.transaction().await.map_err(database_error)?;
            super::super::admin::management_lock(&tx).await?;
            tx.batch_execute("LOCK TABLE noisefence.migration_state IN ACCESS EXCLUSIVE MODE").await.map_err(database_error)?;
            // Inspect ALL application tables, including future additions, rather
            // than infer emptiness merely from the account/source counts.
            let tables=tx.query("SELECT quote_ident(n.nspname)||'.'||quote_ident(c.relname) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='noisefence' AND c.relkind IN ('r','p') AND c.relname NOT IN ('schema_migrations','quality_exposure_state') ORDER BY c.relname",&[]).await.map_err(database_error)?;
            for table in tables {
                let table:String=table.get(0);
                let populated:bool=tx.query_one(&format!("SELECT EXISTS(SELECT 1 FROM {table})"),&[]).await.map_err(database_error)?.get(0);
                ensure!(!populated,"Offline import requires a fresh empty destination; existing data or receipts will not be overwritten");
            }
            let valid:bool=tx.query_one("SELECT (SELECT count(*)=1 FROM noisefence.schema_migrations) AND EXISTS(SELECT 1 FROM noisefence.schema_migrations WHERE version=1 AND sha256=$1) AND (SELECT count(*)=1 AND bool_and(id=1 AND generation=0) FROM noisefence.quality_exposure_state)",&[&crate::message::digest(include_bytes!("../schema.sql"))]).await.map_err(database_error)?.get(0);
            ensure!(valid,"Import destination schema or exposure state differs");
            let report=json!({"protocol":"noisefence-offline-import-1","instance":binding.instance,"phase":"claimed","reconciliation":reconciliation});
            tx.execute("INSERT INTO noisefence.migration_state(id,source_digest,imported_at,activated_at,report) VALUES(1,$1,$2,NULL,$3)",&[&binding.source_digest,&crate::now(),&report]).await.map_err(database_error)?;
            tx.commit().await.map_err(database_error)?;Ok(())
        }).await.context("Import claim deadline exceeded")?
    }
    async fn import_phase(&self, binding: &Binding, phase: &str) -> Result<()> {
        tokio::time::timeout(std::time::Duration::from_secs(10),async {
            let db=self.ingestion.get().await.context("Import database unavailable")?;
            let count=db.execute("UPDATE noisefence.migration_state SET report=jsonb_set(report,'{phase}',$3::jsonb) WHERE id=1 AND source_digest=$1 AND report->>'instance'=$2 AND activated_at IS NULL",&[&binding.source_digest,&binding.instance,&Value::String(phase.into())]).await.map_err(database_error)?;
            ensure!(count==1,"Import receipt changed or was activated unexpectedly");Ok(())
        }).await.context("Import receipt deadline exceeded")?
    }
}
