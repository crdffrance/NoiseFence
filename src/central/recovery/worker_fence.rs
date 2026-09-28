//! Attach stopped worker queues to recovery without replacing any local state.
use crate::{
    central::{bootstrap::Management, import::SourceLocks, selection::Selection},
    cluster::{Role, activation::participant::Local, artifacts},
    config::Config,
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::Path};

/// The supervisor must persistently fence all original services/jobs first and
/// supply each actual worker's installed configuration. Locks on a copy do not
/// fence an original host. This command does not contact PostgreSQL or start services.
pub fn attach(path: &Path) -> Result<Value> {
    let plan = super::operator::Plan::read(path)?;
    let configs = plan
        .source_configs
        .iter()
        .map(|p| Config::load(p))
        .collect::<Result<Vec<_>>>()?;
    let locks = configs
        .iter()
        .map(|c| SourceLocks::acquire(&c.data_dir))
        .collect::<Result<Vec<_>>>()?;
    let mut identities = BTreeMap::new();
    let mut selections = Vec::new();
    let mut authority = None;
    let mut coordinator = None;
    // Validate every source, including existing markers, before changing any one.
    for (config, guard) in configs.iter().zip(&locks) {
        guard.verify_for(&config.data_dir)?;
        let mut db = rusqlite::Connection::open_with_flags(
            config.data_dir.join("state.sqlite3"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        db.busy_timeout(std::time::Duration::from_secs(2))?;
        let tx = db.transaction()?;
        let selected = Selection::read(&tx)?.context("Recovery worker source is not selected")?;
        let cluster = config
            .cluster
            .as_ref()
            .context("Recovery cluster identity missing")?;
        ensure!(
            selected.database == plan.database
                && selected.node.node == cluster.node_id
                && selected.role == cluster.role,
            "Recovery configuration differs from selected source"
        );
        ensure!(
            matches!(
                (&config.management, selected.role),
                (Some(Management::PostgreSql { .. }), Role::Coordinator)
                    | (Some(Management::Coordinator {}), Role::Worker)
            ),
            "Recovery source must retain its selected backend"
        );
        ensure!(
            identities
                .insert(selected.node.node.clone(), selected.node.epoch.clone())
                .is_none(),
            "Duplicate recovery source"
        );
        let local = Local::read(&tx)?.context("Recovery source policy cache missing")?;
        let journal = local.authority();
        ensure!(
            journal.released()
                && local.installed_epoch() == &journal.current_epoch()
                && (local.installed_epoch().sequence > selected.baseline.sequence
                    || local.installed_epoch() == &selected.baseline),
            "Finish the source policy rollout before attaching recovery"
        );
        artifacts::materialize(config, local.installed(), true)?;
        let value = journal.clone();
        if let Some(previous) = &authority {
            ensure!(
                super::policy::identity(previous)? == super::policy::identity(&value)?,
                "Recovery sources disagree on installed policy"
            );
        } else {
            authority = Some(value);
        }
        if selected.role == Role::Coordinator {
            ensure!(
                coordinator.replace(selected.node.node.clone()).is_none()
                    && journal.owner() == selected.node.node,
                "Recovery requires one matching coordinator"
            );
            let stage = super::console::validate_console_stage(config)?;
            ensure!(
                stage["operation"] == plan.operation,
                "Coordinator belongs to another recovery"
            );
        } else {
            check_markers(&tx, &selected, &plan.operation)?;
        }
        selections.push(selected);
    }
    ensure!(coordinator.is_some(), "Recovery coordinator missing");
    let authority = authority.context("Recovery policy missing")?;
    ensure!(
        authority
            .rollout()
            .context("Recovery source policy is not enrolled")?
            .participants()
            .keys()
            .eq(identities.keys()),
        "Recovery source set differs from installed policy participants"
    );
    plan.check_sources(&plan.database, &plan.operation, &identities)?;
    let mut workers = Vec::new();
    for ((config, guard), selected) in configs.iter().zip(&locks).zip(&selections) {
        if selected.role != Role::Worker {
            continue;
        }
        guard.verify_for(&config.data_dir)?;
        let mut db = rusqlite::Connection::open_with_flags(
            config.data_dir.join("state.sqlite3"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
        )?;
        db.busy_timeout(std::time::Duration::from_secs(2))?;
        db.execute_batch("PRAGMA synchronous=FULL")?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        ensure!(
            Selection::read(&tx)?.as_ref() == Some(selected),
            "Recovery source selection changed"
        );
        let previous = check_markers(&tx, selected, &plan.operation)?;
        let receipt = if let Markers::Pending(previous) = previous {
            previous
        } else {
            if let Markers::Completed(archive) = previous {
                let operation = archive["attachment"]["operation"].as_str().unwrap();
                tx.execute(
                    "INSERT INTO cluster_state VALUES(?1,?2)",
                    rusqlite::params![
                        format!("management_worker_history_{operation}"),
                        serde_json::to_string(&archive)?
                    ],
                )?;
                tx.execute("DELETE FROM cluster_state WHERE key IN ('management_worker_recovery','management_worker_release','management_worker_key_renewal','management_recovery_outbox')", [])?;
            }
            let receipt = json!({"protocol":"noisefence-worker-recovery-1","operation":plan.operation,
                "selection":selected,"created":crate::now(),"queue_replaced":false});
            let pending = json!({"protocol":"noisefence-management-recovery-1","operation":plan.operation,"created":crate::now()});
            tx.execute(
                "INSERT INTO cluster_state VALUES('management_recovery_required',?1)",
                [serde_json::to_string(&pending)?],
            )?;
            tx.execute(
                "INSERT INTO cluster_state VALUES('management_worker_recovery',?1)",
                [serde_json::to_string(&receipt)?],
            )?;
            receipt
        };
        tx.commit()?;
        workers.push(receipt);
    }
    for (config, guard) in configs.iter().zip(&locks) {
        guard.verify_for(&config.data_dir)?;
    }
    Ok(
        json!({"operation":plan.operation,"database":plan.database,"workers":workers,
        "status":"workers_fenced_in_place","network_used":false,"queue_replaced":false,"smtp_started":false}),
    )
}

enum Markers {
    Fresh,
    Pending(Value),
    Completed(Value),
}

fn check_markers(
    tx: &rusqlite::Transaction<'_>,
    selected: &Selection,
    operation: &str,
) -> Result<Markers> {
    use super::worker_release::value;
    ensure!(
        value(tx, "management_console_activation")?.is_none(),
        "Console recovery storage cannot be attached as a worker"
    );
    let pending = value(tx, "management_recovery_required")?;
    let previous = value(tx, "management_worker_recovery")?;
    let released = value(tx, "management_worker_release")?;
    let renewal = value(tx, "management_worker_key_renewal")?;
    let replay = value(tx, "management_recovery_outbox")?;
    ensure!(
        !tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM cluster_state WHERE key=?1)",
            [format!("management_worker_history_{operation}")],
            |r| r.get::<_, bool>(0)
        )?,
        "An archived recovery operation cannot be reused"
    );
    match (&pending, &previous, &released) {
        (None, None, None) => {
            ensure!(
                renewal.is_none() && replay.is_none(),
                "Orphaned worker recovery evidence"
            );
            Ok(Markers::Fresh)
        }
        (Some(pending), Some(previous), None) => {
            ensure!(
                pending["protocol"] == "noisefence-management-recovery-1"
                    && pending["operation"] == operation
                    && previous["protocol"] == "noisefence-worker-recovery-1"
                    && previous["operation"] == operation
                    && previous["selection"] == serde_json::to_value(selected)?
                    && renewal.is_none(),
                "Worker is attached to another recovery"
            );
            if let Some(replay) = replay {
                ensure!(
                    replay["protocol"] == "noisefence-management-replay-1"
                        && replay["operation"] == operation
                        && replay["selection"] == serde_json::to_value(selected)?,
                    "Worker replay differs from pending recovery"
                );
            }
            Ok(Markers::Pending(previous.clone()))
        }
        (None, Some(previous), Some(released)) => {
            let old = previous["operation"]
                .as_str()
                .context("Previous recovery operation missing")?;
            ensure!(
                uuid::Uuid::parse_str(old).is_ok_and(|id| id.to_string() == old)
                    && old != operation,
                "A completed recovery cannot be fenced again with the same operation"
            );
            super::worker_release::worker_state(tx, selected, old)?;
            super::worker_renewal::authorized_hash(tx, released)?;
            let replay = replay.context("Completed worker recovery has no replay receipt")?;
            ensure!(
                replay["protocol"] == "noisefence-management-replay-1"
                    && replay["operation"] == old
                    && replay["selection"] == serde_json::to_value(selected)?,
                "Completed worker replay differs from its release"
            );
            let sequence = replay["sequence"]
                .as_i64()
                .context("Replay sequence missing")?;
            let floor = replay["central_log_id_floor"]
                .as_i64()
                .context("Replay log floor missing")?;
            let recorded_allocator = replay["log_sequence"]
                .as_i64()
                .context("Replay allocator missing")?;
            let current: i64 = tx.query_row(
                "SELECT sequence FROM management_journal WHERE id=1",
                [],
                |r| r.get(0),
            )?;
            let allocator: i64 = tx.query_row("SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name='delivery_attempts'),0)", [], |r|r.get(0))?;
            ensure!(
                sequence >= 0
                    && floor >= 0
                    && recorded_allocator >= floor
                    && current >= sequence
                    && allocator >= recorded_allocator,
                "Worker replay counters regressed after release"
            );
            let count: i64 = tx.query_row("SELECT count(*) FROM cluster_state WHERE substr(key,1,26)='management_worker_history_'", [], |r|r.get(0))?;
            ensure!(
                count < 256
                    && !tx.query_row(
                        "SELECT EXISTS(SELECT 1 FROM cluster_state WHERE key=?1)",
                        [format!("management_worker_history_{old}")],
                        |r| r.get::<_, bool>(0)
                    )?,
                "Worker recovery archive is full or conflicting"
            );
            Ok(Markers::Completed(
                json!({"protocol":"noisefence-worker-recovery-history-1",
                "attachment":previous,"release":released,"key_renewal":renewal,"replay":replay,
                "next_operation":operation}),
            ))
        }
        _ => anyhow::bail!(
            "Worker recovery markers are incomplete; do not overwrite existing recovery state"
        ),
    }
}
