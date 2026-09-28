//! Coordinated offline preparation; retains every startup fence.
use crate::{
    central::{Central, database_error, import::SourceLocks, selection::Selection},
    cluster::{Role, activation::participant::Local, artifacts, protocol::private_write},
    config::Config,
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::Path};

impl Central {
    /// Prepare a restored management database using all stopped source copies.
    /// The supervisor must fence every original writer before calling this method
    /// and must target the restored database, never the live original database.
    /// Local locks do not prove remote fencing. No startup marker is cleared.
    pub async fn prepare_recovered_management(
        &self,
        configs: &[Config],
        operation: &str,
        credentials: &Path,
    ) -> Result<Value> {
        self.prepare_recovered_management_inner(configs, operation, credentials, None, false, false)
            .await
    }

    pub(super) async fn prepare_recovered_management_inner(
        &self,
        configs: &[Config],
        operation: &str,
        credentials: &Path,
        attestation: Option<&super::operator::Plan>,
        verify_worker_installation: bool,
        activate_console: bool,
    ) -> Result<Value> {
        ensure!(
            (1..=64).contains(&configs.len()),
            "Invalid recovery source count"
        );
        ensure!(
            uuid::Uuid::parse_str(operation).is_ok_and(|id| id.to_string() == operation),
            "Invalid recovery operation"
        );
        let binding = self
            .binding()
            .context("Recovery requires a selected database")?;
        // Nonblocking locks are retained across every await, including access
        // revocation and retries. A busy or duplicate source aborts before writes.
        let locks = configs
            .iter()
            .map(|c| SourceLocks::acquire(&c.data_dir))
            .collect::<Result<Vec<_>>>()?;
        let mut identities = BTreeMap::new();
        let mut workers = BTreeMap::new();
        let mut coordinator = None;
        let mut authority = None;
        for (config, guard) in configs.iter().zip(&locks) {
            guard.verify_for(&config.data_dir)?;
            config.validate()?;
            let mut connection = rusqlite::Connection::open_with_flags(
                config.data_dir.join("state.sqlite3"),
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )?;
            connection.busy_timeout(std::time::Duration::from_secs(2))?;
            let db = connection.transaction()?;
            let selected = Selection::read(&db)?.context("Recovery source is not selected")?;
            let cluster = config
                .cluster
                .as_ref()
                .context("Recovery cluster identity missing")?;
            ensure!(
                matches!(
                    (&config.management, selected.role),
                    (
                        Some(crate::central::bootstrap::Management::PostgreSql { .. }),
                        Role::Coordinator
                    ) | (
                        Some(crate::central::bootstrap::Management::Coordinator {}),
                        Role::Worker
                    )
                ),
                "Recovery configuration must retain its selected management backend"
            );
            ensure!(
                &selected.database == binding
                    && cluster.node_id == selected.node.node
                    && cluster.role == selected.role,
                "Recovery source authority mismatch"
            );
            selected.verify_key(&config.data_dir)?;
            let raw: String = db.query_row("SELECT CASE WHEN length(value)<=8192 THEN value END FROM cluster_state WHERE key='management_recovery_required'", [], |r|r.get(0))?;
            let pending: Value = serde_json::from_str(&raw)?;
            ensure!(
                pending["protocol"] == "noisefence-management-recovery-1"
                    && pending["operation"] == operation,
                "Recovery source operation mismatch"
            );
            let local = Local::read(&db)?.context("Recovery policy cache missing")?;
            ensure!(
                local.authority().released()
                    && local.installed_epoch() == &local.authority().current_epoch()
                    && (local.installed_epoch().sequence > selected.baseline.sequence
                        || local.installed_epoch() == &selected.baseline),
                "Recovery requires a completed installed policy"
            );
            let journal = super::policy::identity(local.authority())?;
            if let Some(previous) = &authority {
                ensure!(
                    previous == &journal,
                    "Recovery participants disagree on policy authority"
                );
            } else {
                authority = Some(journal);
            }
            ensure!(
                local.installed().credential_generation.is_some(),
                "Recovery requires immutable provider credentials"
            );
            let effective = artifacts::materialize(config, local.installed(), true)?;
            let snapshot = crate::credentials::Snapshot::capture(&effective)?;
            ensure!(
                Some(snapshot.fingerprint()).as_ref()
                    == local.installed().credential_generation.as_ref(),
                "Recovery credentials differ from installed policy"
            );
            if selected.role == Role::Worker {
                workers.insert(selected.node.node.clone(), selected.node.epoch.clone());
            }
            ensure!(
                identities
                    .insert(selected.node.node, selected.node.epoch)
                    .is_none(),
                "Duplicate recovery identity"
            );
            if selected.role == Role::Coordinator {
                ensure!(
                    coordinator.replace(config).is_none(),
                    "Multiple recovery coordinators"
                );
            }
        }
        let coordinator = coordinator.context("Recovery coordinator missing")?;
        if activate_console {
            ensure!(
                verify_worker_installation && attestation.is_some(),
                "Console activation requires explicit fencing and installed worker verification"
            );
            super::console::validate_console_stage(coordinator)?;
        }
        if let Some(plan) = attestation {
            plan.check_sources(binding, operation, &identities)?;
        }
        // The source set is checked before creating credentials or revoking access.
        let db = self
            .interactive
            .get()
            .await
            .context("Recovery preflight capacity unavailable")?;
        let current: BTreeMap<String, String> = db
            .query(
                "SELECT node,epoch FROM noisefence.sources WHERE enabled ORDER BY node",
                &[],
            )
            .await
            .map_err(database_error)?
            .into_iter()
            .map(|r| (r.get(0), r.get(1)))
            .collect();
        ensure!(
            current == identities,
            "Recovery requires every enabled source"
        );
        drop(db);
        self.validate_mfa_key(&coordinator.data_dir).await?;
        if let Some(plan) = attestation {
            plan.check_sources(binding, operation, &identities)?;
        }
        // Restored budget allocations cannot authorize fresh spending. This hold
        // survives later failures and is never automatically removed on retry.
        private_write(
            &coordinator.data_dir.join("ha-recovery-budget-hold"),
            b"Review restored provider allocations before issuing new credits.\n",
        )?;
        let access = self.recover_access_saved(operation, credentials).await?;
        let mut history = Vec::new();
        for (config, guard) in configs.iter().zip(&locks) {
            history.push(
                self.replay_recovered_source_held(&config.data_dir, operation, guard)
                    .await?,
            );
        }
        let policy = self
            .reconcile_recovered_policy_held(configs, operation, &locks)
            .await?;
        let mut worker_filename = credentials
            .file_name()
            .context("Recovery credential filename missing")?
            .to_os_string();
        worker_filename.push(".workers.json");
        let worker_credentials = credentials.with_file_name(worker_filename);
        let mut worker_access = self
            .recover_worker_access(operation, &worker_credentials, &workers)
            .await?;
        let worker_installation = if verify_worker_installation {
            let verified = self
                .verify_recovered_worker_installation(
                    configs,
                    operation,
                    &worker_credentials,
                    &workers,
                )
                .await?;
            worker_access["worker_installation_required"] = json!(false);
            Some(verified)
        } else {
            None
        };
        self.validate_mfa_key(&coordinator.data_dir).await?;
        for (config, guard) in configs.iter().zip(&locks) {
            guard.verify_for(&config.data_dir)?;
        }
        let console_activation = if activate_console {
            Some(
                self.activate_recovered_console(
                    coordinator,
                    operation,
                    &history,
                    &policy,
                    worker_installation
                        .as_ref()
                        .context("Worker installation verification missing")?,
                )
                .await?,
            )
        } else {
            None
        };
        Ok(
            json!({"operation":operation,"database":binding,"access":access,"history":history,
            "policy":policy,"worker_access":worker_access,"worker_installation":worker_installation,"console_activation":console_activation,"provider_budgets_held":true,"mfa_verified":true,
            "central_management_recovery_required":true,"smtp_started":false,"console_started":false}),
        )
    }
}
