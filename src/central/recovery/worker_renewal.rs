//! Verify a later central credential rotation without repeating recovery or changing routes.
use super::worker_release::{route_hash, value, worker_state};
use crate::{
    central::{
        Central, admin::management_lock, bootstrap::Management, database_error,
        import::SourceLocks, selection::Selection,
    },
    cluster::Role,
    config::Config,
};
use anyhow::{Context, Result, ensure};
use rusqlite::Connection;
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::Path};

pub(super) fn authorized_hash(db: &Connection, release: &Value) -> Result<String> {
    let token = if let Some(renewal) = value(db, "management_worker_key_renewal")? {
        ensure!(
            renewal["protocol"] == "noisefence-worker-key-renewal-1"
                && renewal["release_sha256"]
                    == crate::message::digest(&serde_json::to_vec(release)?)
                && renewal["operation"] == release["operation"]
                && renewal["selection"] == release["selection"],
            "Worker key renewal authority mismatch"
        );
        renewal["token_hash"]
            .as_str()
            .context("Worker renewal token hash missing")?
            .to_owned()
    } else {
        release["token_hash"]
            .as_str()
            .context("Worker release token hash missing")?
            .to_owned()
    };
    ensure!(
        token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit()),
        "Invalid worker authorization hash"
    );
    Ok(token)
}

pub async fn renew(path: &Path) -> Result<Value> {
    tokio::time::timeout(std::time::Duration::from_secs(300), renew_inner(path))
        .await
        .context("Worker key renewal timed out; retry with the same installed keys")?
}
async fn renew_inner(path: &Path) -> Result<Value> {
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
    let mut renewals = BTreeMap::new();
    let mut releases = BTreeMap::new();
    let mut coordinator = None;
    for (index, (config, lock)) in configs.iter().zip(&locks).enumerate() {
        lock.verify_for(&config.data_dir)?;
        let db = Connection::open_with_flags(
            config.data_dir.join("state.sqlite3"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        db.busy_timeout(std::time::Duration::from_secs(2))?;
        let selected =
            Selection::read(&db)?.context("Worker key renewal requires selected storage")?;
        let cluster = config.cluster.as_ref().context("Source cluster missing")?;
        ensure!(
            selected.database == plan.database
                && selected.node.node == cluster.node_id
                && selected.role == cluster.role,
            "Source identity changed before key renewal"
        );
        ensure!(
            identities
                .insert(selected.node.node.clone(), selected.node.epoch.clone())
                .is_none(),
            "Duplicate renewal source"
        );
        if selected.role == Role::Coordinator {
            ensure!(
                coordinator.replace(index).is_none(),
                "Multiple renewal coordinators"
            );
            continue;
        }
        let release = worker_state(&db, &selected, &plan.operation)?
            .context("Only released workers may renew credentials")?;
        authorized_hash(&db, &release)?;
        ensure!(
            release["route_sha256"] == route_hash(config)?,
            "Key renewal cannot change worker authority or key path"
        );
        let key = cluster
            .credential_file
            .as_ref()
            .context("Worker key path missing")?;
        let hash = super::worker_installation::installed_hash(key)?;
        renewals.insert(selected.node.node.clone(), json!({"protocol":"noisefence-worker-key-renewal-1",
            "operation":plan.operation,"selection":selected,"release_sha256":crate::message::digest(&serde_json::to_vec(&release)?),"token_hash":hash}));
        releases.insert(selected.node.node.clone(), release);
    }
    plan.check_sources(&plan.database, &plan.operation, &identities)?;
    ensure!(!renewals.is_empty(), "No released workers to renew");
    let config = &configs[coordinator.context("Renewal coordinator missing")?];
    let Some(Management::PostgreSql { connection }) = &config.management else {
        anyhow::bail!("Renewal requires the selected PostgreSQL coordinator");
    };
    let central = Central::new_bound(connection, &plan.database)?;
    central.require_recovered_console_activation(config).await?;
    let console = super::activation::local_receipt(config)?;
    ensure!(
        console["operation"] == plan.operation,
        "Console recovery operation changed"
    );
    let fingerprint = crate::message::digest(&serde_json::to_vec(&renewals)?);
    let mut pg = central
        .interactive
        .get()
        .await
        .context("Worker key authority unavailable")?;
    let tx = pg.transaction().await.map_err(database_error)?;
    management_lock(&tx).await?;
    let mut report: Value = tx.query_one("SELECT report FROM noisefence.migration_state WHERE id=1 AND source_digest=$1 AND report->>'instance'=$2 AND activated_at IS NOT NULL FOR UPDATE", &[&plan.database.source_digest, &plan.database.instance]).await.map_err(database_error)?.get(0);
    ensure!(
        report["console_recoveries"][&plan.operation] == console,
        "Console authorization changed"
    );
    let sources: BTreeMap<String, String> = tx
        .query(
            "SELECT node,epoch FROM noisefence.sources WHERE enabled ORDER BY node FOR SHARE",
            &[],
        )
        .await
        .map_err(database_error)?
        .into_iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect();
    ensure!(sources == identities, "Renewal source membership changed");
    for (node, renewal) in &renewals {
        ensure!(
            report["worker_release_recoveries"][&plan.operation]["releases"][node]
                == releases[node],
            "Worker release differs from central authority"
        );
        let token = renewal["token_hash"].as_str().unwrap();
        let epoch = &identities[node];
        ensure!(tx.query_opt("SELECT node FROM noisefence.cluster_nodes WHERE node=$1 AND epoch=$2 AND token_hash=$3 AND enabled FOR SHARE", &[node,epoch,&token]).await.map_err(database_error)?.is_some(), "Installed worker key is not currently authorized centrally");
    }
    let receipt = json!({"operation":plan.operation,"fingerprint":fingerprint,"workers":renewals});
    let prior = &report["worker_key_renewals"][&fingerprint];
    if prior.is_null() {
        let actor = report["access_recoveries"][&plan.operation]["username"]
            .as_str()
            .context("Recovery actor missing")?
            .to_owned();
        let records = report
            .as_object_mut()
            .context("Invalid migration report")?
            .entry("worker_key_renewals")
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .context("Invalid renewal records")?;
        ensure!(
            records.len() < 256,
            "Worker key renewal receipt limit reached"
        );
        records.insert(fingerprint.clone(), receipt.clone());
        tx.execute(
            "UPDATE noisefence.migration_state SET report=$1 WHERE id=1",
            &[&report],
        )
        .await
        .map_err(database_error)?;
        tx.execute("INSERT INTO noisefence.audit(created,username,action,object_id) VALUES($1,$2,'renew_recovered_worker_keys',$3)", &[&crate::now(),&actor,&fingerprint]).await.map_err(database_error)?;
    } else {
        ensure!(prior == &receipt, "Worker key renewal receipt conflict");
    }
    tx.commit().await.map_err(database_error)?;
    for (config, lock) in configs.iter().zip(&locks) {
        lock.verify_for(&config.data_dir)?;
        let cluster = config.cluster.as_ref().unwrap();
        if cluster.role != Role::Worker {
            continue;
        }
        let mut db = Connection::open_with_flags(
            config.data_dir.join("state.sqlite3"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
        )?;
        db.busy_timeout(std::time::Duration::from_secs(2))?;
        db.execute_batch("PRAGMA synchronous=FULL")?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let selected = Selection::read(&tx)?.context("Worker selection missing")?;
        let renewal = &renewals[&cluster.node_id];
        ensure!(
            renewal["selection"] == serde_json::to_value(&selected)?
                && worker_state(&tx, &selected, &plan.operation)?.as_ref()
                    == Some(&releases[&cluster.node_id]),
            "Worker release changed during key renewal"
        );
        tx.execute("INSERT INTO cluster_state VALUES('management_worker_key_renewal',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value", [serde_json::to_string(renewal)?])?;
        super::worker_release::require_local_route(config, &tx)?;
        tx.commit()?;
    }
    Ok(
        json!({"status":"worker_keys_renewed","operation":plan.operation,"workers":renewals.keys().collect::<Vec<_>>(),"services_started":false,"queue_replaced":false}),
    )
}
