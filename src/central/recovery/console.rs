//! Offline preparation of a selected console installation. Never authorizes startup.
use crate::{
    central::selection::Selection,
    cluster::{Role, activation::participant::Local},
    config::Config,
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    io::Read,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
};

/// Caller holds the source daemon/calibration locks throughout validation and
/// configuration publication. No PostgreSQL connection or stale SQLite account
/// lookup is used. Central MFA records must still be checked during final recovery.
pub fn validate_console_stage(config: &Config) -> Result<Value> {
    config.validate()?;
    ensure!(
        matches!(
            config.management,
            Some(crate::central::bootstrap::Management::PostgreSql { .. })
        ) && config
            .cluster
            .as_ref()
            .is_some_and(|c| c.role == Role::Coordinator)
            && config.web.listen.ip().is_loopback()
            && config.smtp.listen.ip().is_loopback()
            && config.smtp.listen.port() == 0
            && config.replication.is_none(),
        "Selected recovery requires a private coordinator console configuration"
    );
    let mut db = rusqlite::Connection::open_with_flags(
        config.data_dir.join("state.sqlite3"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    db.busy_timeout(std::time::Duration::from_secs(2))?;
    let tx = db.transaction()?;
    let selection = Selection::read(&tx)?.context("Selected console storage is missing")?;
    ensure!(
        selection.role == Role::Coordinator
            && config.cluster.as_ref().unwrap().node_id == selection.node.node,
        "Recovery console identity differs from selected storage"
    );
    selection.verify_key(&config.data_dir)?;
    let raw:String=tx.query_row("SELECT CASE WHEN length(value)<=8192 THEN value END FROM cluster_state WHERE key='management_recovery_required'",[],|r|r.get(0)).context("Selected console has no pending recovery fence")?;
    let pending: Value = serde_json::from_str(&raw)?;
    let operation = pending["operation"]
        .as_str()
        .context("Recovery operation missing")?;
    ensure!(
        pending["protocol"] == "noisefence-management-recovery-1"
            && uuid::Uuid::parse_str(operation).is_ok_and(|id| id.to_string() == operation),
        "Invalid recovery operation fence"
    );
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(config.data_dir.join("ha-recovery.json"))?;
    let info = file.metadata()?;
    ensure!(
        info.is_file() && info.len() <= 16384 && info.permissions().mode() & 0o077 == 0,
        "Private bounded queue recovery receipt required"
    );
    let mut bytes = Vec::new();
    file.take(16385).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 16384, "Queue recovery receipt exceeds limit");
    let recovery: Value = serde_json::from_slice(&bytes)?;
    ensure!(
        recovery["operation"] == operation
            && recovery["owner"] == selection.node.node
            && recovery["central_management_recovery_required"] == true
            && recovery["smtp_started"] == false,
        "Queue recovery receipt differs from selected console fence"
    );
    let local = Local::read(&tx)?.context("Selected console has no installed policy")?;
    ensure!(
        local.installed_epoch().sequence > selection.baseline.sequence
            || local.installed_epoch() == &selection.baseline,
        "Installed console policy predates cutover"
    );
    ensure!(
        local.installed().credential_generation.is_some(),
        "Selected console requires immutable provider credentials"
    );
    let effective = crate::cluster::artifacts::materialize(config, local.installed(), true)?;
    let credentials = crate::credentials::Snapshot::capture(&effective)?;
    ensure!(
        Some(credentials.fingerprint()).as_ref()
            == local.installed().credential_generation.as_ref(),
        "Installed console credentials differ from policy binding"
    );
    Ok(
        json!({"operation":operation,"database":selection.database,"node":selection.node.node,
        "central_management_recovery_required":true,"network_used":false,"smtp_enabled":false}),
    )
}

/// Begin queue recovery inside the caller's durable transaction while source locks
/// are held. Archive only a previously authorized console; unfinished operations
/// must be resumed rather than overwritten. SMTP remains fenced in every state.
pub fn begin_queue_recovery(tx: &rusqlite::Transaction<'_>, operation: &str) -> Result<()> {
    use super::worker_release::value;
    ensure!(
        uuid::Uuid::parse_str(operation).is_ok_and(|id| id.to_string() == operation),
        "Invalid console recovery operation"
    );
    let selected = Selection::read(tx)?.context("Console recovery selection missing")?;
    ensure!(
        selected.role == Role::Coordinator,
        "Queue recovery requires coordinator storage"
    );
    ensure!(
        value(tx, "management_worker_recovery")?.is_none()
            && value(tx, "management_worker_release")?.is_none()
            && value(tx, "management_worker_key_renewal")?.is_none(),
        "Worker recovery cannot become console recovery"
    );
    ensure!(
        !tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM cluster_state WHERE key=?1)",
            [format!("management_console_history_{operation}")],
            |r| r.get::<_, bool>(0)
        )?,
        "An archived console recovery operation cannot be reused"
    );
    let pending = value(tx, "management_recovery_required")?;
    let activation = value(tx, "management_console_activation")?;
    let replay = value(tx, "management_recovery_outbox")?;
    if let Some(pending) = &pending {
        let old = pending["operation"]
            .as_str()
            .context("Console recovery operation missing")?;
        ensure!(
            pending["protocol"] == "noisefence-management-recovery-1"
                && uuid::Uuid::parse_str(old).is_ok_and(|id| id.to_string() == old),
            "Invalid console recovery fence"
        );
        if let Some(replay) = &replay {
            ensure!(
                replay["protocol"] == "noisefence-management-replay-1"
                    && replay["operation"] == old
                    && replay["selection"] == serde_json::to_value(&selected)?,
                "Console replay authority mismatch"
            );
        }
        if let Some(activation) = &activation {
            ensure!(
                activation["protocol"] == "noisefence-management-console-1"
                    && activation["operation"] == old
                    && activation["database"] == serde_json::to_value(&selected.database)?
                    && activation["node"] == serde_json::to_value(&selected.node)?
                    && activation["console_only"] == true
                    && replay.is_some(),
                "Console activation authority mismatch"
            );
        }
        if old == operation {
            return Ok(());
        }
        ensure!(
            activation.is_some() && replay.is_some(),
            "Resume unfinished console recovery before starting another operation"
        );
        let count:i64 = tx.query_row("SELECT count(*) FROM cluster_state WHERE substr(key,1,27)='management_console_history_'", [], |r|r.get(0))?;
        let archive_key = format!("management_console_history_{old}");
        ensure!(
            count < 256
                && !tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM cluster_state WHERE key=?1)",
                    [&archive_key],
                    |r| r.get::<_, bool>(0)
                )?,
            "Console recovery archive is full or conflicting"
        );
        let archive = json!({"protocol":"noisefence-console-recovery-history-1","pending":pending,
            "activation":activation,"replay":replay,"next_operation":operation});
        tx.execute(
            "INSERT INTO cluster_state VALUES(?1,?2)",
            rusqlite::params![archive_key, serde_json::to_string(&archive)?],
        )?;
        tx.execute("DELETE FROM cluster_state WHERE key IN ('management_console_activation','management_recovery_outbox','management_recovery_required')", [])?;
    } else {
        ensure!(
            activation.is_none() && replay.is_none(),
            "Orphaned console recovery evidence"
        );
    }
    let pending = json!({"protocol":"noisefence-management-recovery-1","operation":operation,"created":crate::now()});
    tx.execute(
        "INSERT INTO cluster_state VALUES('management_recovery_required',?1)",
        [serde_json::to_string(&pending)?],
    )?;
    Ok(())
}
