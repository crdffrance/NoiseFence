//! Installation-only backend choice. No credentials enter shared policy bundles.
use crate::{config::Config, store::Store};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "backend", deny_unknown_fields)]
pub enum Management {
    #[serde(rename = "postgresql")]
    PostgreSql { connection: super::Settings },
    #[serde(rename = "coordinator")]
    Coordinator {},
}
impl Management {
    pub fn validate(&self, cluster: Option<&crate::cluster::Settings>) -> Result<()> {
        let cluster =
            cluster.context("Central management requires an explicit cluster identity")?;
        match self {
            Self::PostgreSql { connection } => {
                ensure!(
                    cluster.role == crate::cluster::Role::Coordinator,
                    "Only the coordinator connects directly to PostgreSQL"
                );
                connection.validate()?;
            }
            Self::Coordinator {} => ensure!(
                cluster.role == crate::cluster::Role::Worker,
                "Coordinator transport is for MX workers"
            ),
        }
        Ok(())
    }
}
#[derive(Clone, Copy)]
pub enum Purpose {
    Runtime,
    Console,
    Operator,
    Queue,
}

fn selected(config: &Config) -> Result<super::selection::Selection> {
    config
        .management
        .as_ref()
        .context("Management backend is not configured")?
        .validate(config.cluster.as_ref())?;
    let db = rusqlite::Connection::open_with_flags(
        config.data_dir.join("state.sqlite3"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    db.busy_timeout(std::time::Duration::from_secs(2))?;
    let selection = super::selection::Selection::read(&db)?
        .context("Complete the verified management migration before selecting this backend")?;
    let cluster = config.cluster.as_ref().unwrap();
    ensure!(
        selection.node.node == cluster.node_id && selection.role == cluster.role,
        "Configured node differs from selected storage"
    );
    Ok(selection)
}
pub fn open(config: &Config, purpose: Purpose) -> Result<Store> {
    let Some(management) = &config.management else {
        return Store::open(&config.data_dir);
    };
    let selection = selected(config)?;
    ensure!(
        !matches!(purpose, Purpose::Operator)
            || selection.role == crate::cluster::Role::Coordinator,
        "Use the coordinator for management operations"
    );
    if matches!(purpose, Purpose::Runtime) {
        selection.verify_key(&config.data_dir)?;
        require_complete_recovery(config)?;
    }
    if matches!(purpose, Purpose::Console) {
        super::recovery::activation::local_receipt(config)?;
    }
    let central = match management {
        Management::PostgreSql { connection } => {
            Some(super::Central::new_bound(connection, &selection.database)?)
        }
        Management::Coordinator {} => None,
    };
    Store::open_bound(&config.data_dir, &selection, central)
}
/// Check again under the daemon lock immediately before starting any service.
/// A queue-only restore cannot authorize a rollback of central access records.
pub fn require_complete_recovery(config: &Config) -> Result<()> {
    if config.management.is_none() {
        return Ok(());
    }
    let db = rusqlite::Connection::open_with_flags(
        config.data_dir.join("state.sqlite3"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let pending: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM cluster_state WHERE key IN ('management_recovery_required','management_console_activation'))",
        [],
        |r| r.get(0),
    )?;
    ensure!(
        !pending,
        "Complete coordinated management recovery before starting this restored queue"
    );
    super::recovery::worker_release::require_local_route(config, &db)?;
    Ok(())
}

/// Selected CLI tools read the verified installed participant bundle, never the
/// obsolete SQLite console revisions and never a database during cold startup.
pub fn effective_config(base: Arc<Config>) -> Result<Arc<Config>> {
    if base.management.is_none() {
        return crate::control::effective_from_disk(base);
    }
    let selection = selected(&base)?;
    let mut db = rusqlite::Connection::open_with_flags(
        base.data_dir.join("state.sqlite3"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    db.busy_timeout(std::time::Duration::from_secs(2))?;
    let tx = db.transaction()?;
    let local = crate::cluster::activation::participant::Local::read(&tx)?
        .context("Selected storage has no installed policy cache")?;
    let epoch = local.installed_epoch();
    ensure!(
        epoch.sequence > selection.baseline.sequence || epoch == &selection.baseline,
        "Cached policy predates the management cutover"
    );
    Ok(Arc::new(crate::cluster::artifacts::materialize(
        &base,
        local.installed(),
        true,
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn installation_backend_survives_local_roundtrips_but_never_enters_policy_bundles() {
        let root = tempfile::tempdir().unwrap();
        let mut config: Config =
            toml::from_str(include_str!("../../config/development.toml")).unwrap();
        config.data_dir = root.path().into();
        config.cluster = Some(toml::from_str("role='coordinator'\nnode_id='mx1'").unwrap());
        let management:Management=toml::from_str("backend='postgresql'\n[connection]\nhost='/run/postgresql'\ndatabase='noisefence'\nusername='noisefence'").unwrap();
        config.management = Some(management);
        config.validate().unwrap();
        let raw = toml::to_string(&config).unwrap();
        let reread: Config = toml::from_str(&raw).unwrap();
        assert!(reread.management.is_some());
        let settings = crate::control::Settings::from_config(&config);
        assert!(
            !serde_json::to_value(&settings)
                .unwrap()
                .to_string()
                .contains("/run/postgresql")
        );
        let publication = crate::cluster::artifacts::capture(&config, settings, 0).unwrap();
        assert!(publication.bundle.shared.get("management").is_none());
        let restored =
            crate::cluster::artifacts::materialize(&config, &publication.bundle, true).unwrap();
        assert!(restored.management.is_some());
        let models = crate::cluster::artifacts::model_base(&config, &publication.bundle).unwrap();
        assert!(models.management.is_some());
        assert!(open(&config, Purpose::Runtime).is_err());
        assert!(!root.path().join("state.sqlite3").exists());
        config.management = Some(Management::Coordinator {});
        assert!(config.validate().is_err());
        assert!(toml::from_str::<Management>("backend='sqlite'").is_err());
        assert!(
            toml::from_str::<Management>("backend='coordinator'\npassword='not-allowed'").is_err()
        );
    }
}
