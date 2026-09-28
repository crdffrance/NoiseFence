//! Resume only the original worker queues authorized by the recovered console.
use crate::{
    central::{
        Central, admin::management_lock, bootstrap::Management, database_error,
        import::SourceLocks, outbox, selection::Selection,
    },
    cluster::{Role, activation::participant::Local},
    config::Config,
    store::Store,
};
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OptionalExtension};
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::Path};

pub(super) fn value(db: &Connection, key: &str) -> Result<Option<Value>> {
    let raw: Option<String> = db
        .query_row(
            "SELECT CASE WHEN length(value)<=16384 THEN value END FROM cluster_state WHERE key=?1",
            [key],
            |r| r.get(0),
        )
        .optional()?;
    raw.map(|s| serde_json::from_str(&s).map_err(Into::into))
        .transpose()
}
fn route(config: &Config) -> Result<String> {
    let cluster = config
        .cluster
        .as_ref()
        .context("Worker cluster identity missing")?;
    ensure!(
        cluster.role == Role::Worker
            && matches!(config.management, Some(Management::Coordinator {})),
        "Worker release requires coordinator transport"
    );
    let url = reqwest::Url::parse(
        cluster
            .coordinator_url
            .as_deref()
            .context("Worker authority URL missing")?,
    )?;
    ensure!(
        url.path() == "/" && url.query().is_none() && url.fragment().is_none(),
        "Worker authority must be an origin"
    );
    Ok(url.origin().ascii_serialization())
}
pub(super) fn route_hash(config: &Config) -> Result<String> {
    let cluster = config.cluster.as_ref().context("Worker cluster missing")?;
    let value = json!({"node":cluster.node_id,"authority":route(config)?,"credential_file":cluster.credential_file,
        "allow_loopback_http":cluster.allow_loopback_http,"management":config.management});
    Ok(crate::message::digest(&serde_json::to_vec(&value)?))
}
pub(super) fn worker_state(
    db: &Connection,
    selected: &Selection,
    operation: &str,
) -> Result<Option<Value>> {
    ensure!(
        selected.role == Role::Worker && value(db, "management_console_activation")?.is_none(),
        "Console storage cannot resume as a worker"
    );
    let attached =
        value(db, "management_worker_recovery")?.context("Worker was not attached in place")?;
    ensure!(
        attached["protocol"] == "noisefence-worker-recovery-1"
            && attached["operation"] == operation
            && attached["selection"] == serde_json::to_value(selected)?,
        "Worker recovery attachment mismatch"
    );
    let pending = value(db, "management_recovery_required")?;
    let released = value(db, "management_worker_release")?;
    match (&pending, &released) {
        (Some(p), None) => ensure!(
            p["protocol"] == "noisefence-management-recovery-1" && p["operation"] == operation,
            "Worker recovery fence mismatch"
        ),
        (None, Some(r)) => ensure!(
            r["protocol"] == "noisefence-worker-release-1"
                && r["operation"] == operation
                && r["selection"] == serde_json::to_value(selected)?,
            "Worker release authority mismatch"
        ),
        _ => anyhow::bail!("Incomplete worker release state"),
    }
    Ok(released)
}

/// Cold-start guard. Normal selected workers without recovery records are unchanged.
pub(crate) fn require_local_route(config: &Config, db: &Connection) -> Result<()> {
    let attached = value(db, "management_worker_recovery")?;
    let released = value(db, "management_worker_release")?;
    if attached.is_none() && released.is_none() {
        return Ok(());
    }
    let released = released.context("Worker recovery has no release authorization")?;
    let selected = Selection::read(db)?.context("Worker selection missing")?;
    let operation = released["operation"]
        .as_str()
        .context("Worker release operation missing")?;
    worker_state(db, &selected, operation)?;
    let path = config
        .cluster
        .as_ref()
        .and_then(|c| c.credential_file.as_deref())
        .context("Worker credential path missing")?;
    let token_hash = super::worker_renewal::authorized_hash(db, &released)?;
    ensure!(
        released["route_sha256"] == route_hash(config)?
            && token_hash == super::worker_installation::installed_hash(path)?,
        "Worker route or credential changed after recovery authorization"
    );
    Ok(())
}

pub async fn release(path: &Path) -> Result<Value> {
    tokio::time::timeout(std::time::Duration::from_secs(900), release_inner(path))
        .await
        .context("Worker release exceeded 15 minutes; resume the same operation")?
}
async fn release_inner(path: &Path) -> Result<Value> {
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
    let mut selections = Vec::new();
    let mut identities = BTreeMap::new();
    let mut workers = BTreeMap::new();
    let mut coordinator = None;
    let mut journal = None;
    for (i, (config, guard)) in configs.iter().zip(&locks).enumerate() {
        guard.verify_for(&config.data_dir)?;
        let mut db = Connection::open_with_flags(
            config.data_dir.join("state.sqlite3"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        db.busy_timeout(std::time::Duration::from_secs(2))?;
        let tx = db.transaction()?;
        let selected = Selection::read(&tx)?.context("Selected worker source missing")?;
        let cluster = config.cluster.as_ref().context("Source cluster missing")?;
        ensure!(
            selected.database == plan.database
                && selected.node.node == cluster.node_id
                && selected.role == cluster.role,
            "Source differs from recovery authority"
        );
        ensure!(
            identities
                .insert(selected.node.node.clone(), selected.node.epoch.clone())
                .is_none(),
            "Duplicate recovery source"
        );
        let local = Local::read(&tx)?.context("Source policy missing")?;
        ensure!(
            local.authority().released()
                && local.installed_epoch() == &local.authority().current_epoch(),
            "Recovery policy is not fully installed"
        );
        let current = super::policy::identity(local.authority())?;
        if let Some(before) = &journal {
            ensure!(before == &current, "Recovery sources disagree on policy");
        } else {
            journal = Some(current);
        }
        match selected.role {
            Role::Coordinator => ensure!(
                coordinator.replace(i).is_none(),
                "Multiple recovery coordinators"
            ),
            Role::Worker => {
                worker_state(&tx, &selected, &plan.operation)?;
                workers.insert(selected.node.node.clone(), selected.node.epoch.clone());
            }
        }
        selections.push(selected);
    }
    plan.check_sources(&plan.database, &plan.operation, &identities)?;
    let coordinator = coordinator.context("Recovery coordinator missing")?;
    let config = &configs[coordinator];
    let Management::PostgreSql { connection } = config
        .management
        .as_ref()
        .context("Recovery database missing")?
    else {
        anyhow::bail!("Recovery requires PostgreSQL coordinator");
    };
    let central = Central::new_bound(connection, &plan.database)?;
    central.require_recovered_console_activation(config).await?;
    let console = super::activation::local_receipt(config)?;
    ensure!(
        console["operation"] == plan.operation,
        "Console belongs to another recovery"
    );
    let authority = reqwest::Url::parse(&config.web.public_origin)?
        .origin()
        .ascii_serialization();
    let current = central
        .policy_journal(&selections[coordinator].node)
        .await?;
    ensure!(
        Some(super::policy::identity(&current)?) == journal,
        "Central policy differs from worker installation"
    );
    let policy_fingerprint = crate::message::digest(&serde_json::to_vec(
        &json!({"journal":super::policy::identity(&current)?,"sources":identities}),
    )?);
    ensure!(
        console["policy_fingerprint"] == policy_fingerprint,
        "Policy changed after console authorization"
    );
    let mut worker_filename = plan
        .credentials_file
        .file_name()
        .context("Recovery credential filename missing")?
        .to_os_string();
    worker_filename.push(".workers.json");
    let installation = central
        .verify_recovered_worker_installation(
            &configs,
            &plan.operation,
            &plan.credentials_file.with_file_name(worker_filename),
            &workers,
        )
        .await?;
    ensure!(
        installation["fingerprint"] == console["worker_installation_fingerprint"],
        "Worker installation differs from console authorization"
    );
    let mut releases = BTreeMap::new();
    for (config, selected) in configs.iter().zip(&selections) {
        if selected.role != Role::Worker {
            continue;
        }
        ensure!(
            route(config)? == authority,
            "Worker still points to another console origin"
        );
        let store = Store::open_bound(&config.data_dir, selected, None)?;
        let status = store.read(|db| outbox::status(db)).await?;
        ensure!(
            status.pending == 0 && status.pending_logs == 0,
            "Worker management history is not fully synchronized"
        );
        let inventory = central.recovered_inventory(&store, selected).await?;
        ensure!(
            console["history"][&selected.node.node]["epoch"] == selected.node.epoch
                && console["history"][&selected.node.node]["inventory"]
                    == inventory["inventory_sha256"],
            "Worker history changed after console authorization"
        );
        let key = config
            .cluster
            .as_ref()
            .unwrap()
            .credential_file
            .as_ref()
            .context("Worker key missing")?;
        releases.insert(selected.node.node.clone(),json!({"protocol":"noisefence-worker-release-1","operation":plan.operation,
            "selection":selected,"route_sha256":route_hash(config)?,"token_hash":super::worker_installation::installed_hash(key)?,
            "coordinator_url":authority,"console_fingerprint":console["fingerprint"],"inventory_sha256":inventory["inventory_sha256"]}));
    }
    let fingerprint = crate::message::digest(&serde_json::to_vec(&releases)?);
    let mut pg = central
        .interactive
        .get()
        .await
        .context("Worker release authority unavailable")?;
    let tx = pg.transaction().await.map_err(database_error)?;
    management_lock(&tx).await?;
    let mut report: Value = tx
        .query_one(
            "SELECT report FROM noisefence.migration_state WHERE id=1 FOR UPDATE",
            &[],
        )
        .await
        .map_err(database_error)?
        .get(0);
    ensure!(
        report["console_recoveries"][&plan.operation] == console
            && report["worker_installation_recoveries"][&plan.operation] == installation,
        "Recovery evidence changed before worker release"
    );
    let live_sources: BTreeMap<String, String> = tx
        .query(
            "SELECT node,epoch FROM noisefence.sources WHERE enabled ORDER BY node FOR SHARE",
            &[],
        )
        .await
        .map_err(database_error)?
        .into_iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect();
    ensure!(
        live_sources == identities,
        "Recovery membership changed before worker release"
    );
    let authority_row = tx.query_one("SELECT node,epoch,journal,membership FROM noisefence.policy_authority WHERE id=1 FOR SHARE", &[]).await.map_err(database_error)?;
    ensure!(
        authority_row.get::<_, String>(0) == current.owner()
            && authority_row.get::<_, String>(1) == identities[current.owner()]
            && authority_row.get::<_, Value>(2) == serde_json::to_value(&current)?
            && authority_row.get::<_, Value>(3) == serde_json::to_value(&identities)?,
        "Policy authority changed before worker release"
    );
    let head = tx.query_one("SELECT revision,activation_epoch,activated_at IS NOT NULL FROM noisefence.policy_head WHERE id=1 FOR SHARE", &[]).await.map_err(database_error)?;
    ensure!(
        head.get::<_, i64>(0) == current.current().revision
            && head.get::<_, Value>(1) == serde_json::to_value(current.current_epoch())?
            && head.get::<_, bool>(2),
        "Policy head changed before worker release"
    );
    let actor = report["access_recoveries"][&plan.operation]["username"]
        .as_str()
        .context("Recovery actor missing")?
        .to_owned();
    for (node, release) in &releases {
        let epoch = selections
            .iter()
            .find(|s| &s.node.node == node)
            .unwrap()
            .node
            .epoch
            .as_str();
        let token = release["token_hash"].as_str().unwrap();
        ensure!(tx.query_opt("SELECT n.node FROM noisefence.cluster_nodes n JOIN noisefence.sources s USING(node,epoch) WHERE n.node=$1 AND n.epoch=$2 AND n.token_hash=$3 AND n.enabled AND s.enabled FOR SHARE OF n,s",&[node,&epoch,&token]).await.map_err(database_error)?.is_some(),"Worker credential authority changed before release");
    }
    let prior = &report["worker_release_recoveries"][&plan.operation];
    if prior.is_null() {
        let records = report
            .as_object_mut()
            .context("Invalid migration receipt")?
            .entry("worker_release_recoveries")
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .context("Invalid worker release receipts")?;
        ensure!(records.len() < 256, "Worker release receipt limit reached");
        records.insert(
            plan.operation.clone(),
            json!({"fingerprint":fingerprint,"releases":releases,"created":crate::now()}),
        );
        tx.execute(
            "UPDATE noisefence.migration_state SET report=$1 WHERE id=1",
            &[&report],
        )
        .await
        .map_err(database_error)?;
        tx.execute("INSERT INTO noisefence.audit(created,username,action,object_id) VALUES($1,$2,'authorize_recovery_workers',$3)",&[&crate::now(),&actor,&plan.operation]).await.map_err(database_error)?;
    } else {
        ensure!(
            prior["fingerprint"] == fingerprint
                && prior["releases"] == serde_json::to_value(&releases)?,
            "Another worker configuration is already authorized"
        );
    }
    tx.commit().await.map_err(database_error)?;
    for ((config, selected), guard) in configs.iter().zip(&selections).zip(&locks) {
        guard.verify_for(&config.data_dir)?;
        if selected.role != Role::Worker {
            continue;
        }
        let release = &releases[&selected.node.node];
        let mut db = Connection::open_with_flags(
            config.data_dir.join("state.sqlite3"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
        )?;
        db.busy_timeout(std::time::Duration::from_secs(2))?;
        db.execute_batch("PRAGMA synchronous=FULL")?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        ensure!(
            Selection::read(&tx)?.as_ref() == Some(selected),
            "Worker selection changed during release"
        );
        if let Some(previous) = worker_state(&tx, selected, &plan.operation)? {
            ensure!(
                previous == *release,
                "Local worker release differs from central authority"
            );
        } else {
            tx.execute(
                "INSERT INTO cluster_state VALUES('management_worker_release',?1)",
                [serde_json::to_string(release)?],
            )?;
            tx.execute(
                "DELETE FROM cluster_state WHERE key='management_recovery_required'",
                [],
            )?;
        }
        require_local_route(config, &tx)?;
        tx.commit()?;
    }
    Ok(
        json!({"operation":plan.operation,"database":plan.database,"status":"workers_authorized_not_started",
        "workers":releases.keys().collect::<Vec<_>>(),"queue_replaced":false,"services_started":false,"console_smtp_fenced":true}),
    )
}
