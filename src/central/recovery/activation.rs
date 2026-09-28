//! Durable, console-only recovery authorization. The SMTP fence is never removed.
use crate::{
    central::{Central, admin::management_lock, database_error, selection::Selection},
    config::Config,
};
use anyhow::{Context, Result, ensure};
use rusqlite::OptionalExtension;
use serde_json::{Value, json};
use std::collections::BTreeMap;

fn config_hash(config: &Config) -> Result<String> {
    let mut value = serde_json::to_value(config)?;
    value.sort_all_objects();
    Ok(crate::message::digest(&serde_json::to_vec(&value)?))
}

/// Offline half of the startup check. A matching PostgreSQL receipt is required
/// separately, under the daemon lock, before any console listener is opened.
pub fn local_receipt(config: &Config) -> Result<Value> {
    let stage = super::console::validate_console_stage(config)?;
    let db = rusqlite::Connection::open_with_flags(
        config.data_dir.join("state.sqlite3"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    db.busy_timeout(std::time::Duration::from_secs(2))?;
    let raw:String=db.query_row("SELECT CASE WHEN length(value)<=16384 THEN value END FROM cluster_state WHERE key='management_console_activation'",[],|r|r.get(0)).context("Console recovery activation is missing")?;
    let receipt: Value = serde_json::from_str(&raw)?;
    let selected = Selection::read(&db)?.context("Console selection missing")?;
    ensure!(
        receipt["protocol"] == "noisefence-management-console-1"
            && receipt["operation"] == stage["operation"]
            && receipt["database"] == stage["database"]
            && receipt["node"] == serde_json::to_value(&selected.node)?
            && receipt["config_sha256"] == config_hash(config)?
            && receipt["console_only"] == true,
        "Console recovery activation differs from this installation"
    );
    Ok(receipt)
}

impl Central {
    /// Caller retains all source locks and has just verified history inventories,
    /// policy, MFA, fencing attestations and installed worker credentials.
    pub(super) async fn activate_recovered_console(
        &self,
        config: &Config,
        operation: &str,
        history: &[Value],
        policy: &Value,
        workers: &Value,
    ) -> Result<Value> {
        let binding = self
            .binding()
            .context("Selected console authority required")?;
        let stage = super::console::validate_console_stage(config)?;
        ensure!(
            stage["operation"] == operation
                && stage["database"] == serde_json::to_value(binding)?
                && config.data_dir.join("ha-recovery-budget-hold").is_file(),
            "Console stage or provider budget hold differs from recovery"
        );
        let mut local = rusqlite::Connection::open_with_flags(
            config.data_dir.join("state.sqlite3"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
        )?;
        local.busy_timeout(std::time::Duration::from_secs(2))?;
        local.execute_batch("PRAGMA synchronous=FULL")?;
        let selected = Selection::read(&local)?.context("Console selection missing")?;
        let mut inventories = BTreeMap::new();
        for item in history {
            let node = item["node"]["node"]
                .as_str()
                .context("Recovery history node missing")?;
            let hash = item["inventory_sha256"]
                .as_str()
                .context("Recovery inventory digest missing")?;
            ensure!(
                item["operation"] == operation
                    && item["history_inventory_verified"] == true
                    && crate::compatibility::valid_hash(hash)
                    && inventories
                        .insert(
                            node.to_owned(),
                            json!({"epoch":item["node"]["epoch"],"inventory":hash})
                        )
                        .is_none(),
                "Invalid verified recovery inventory"
            );
        }
        let identity = json!({"protocol":"noisefence-management-console-1","operation":operation,"database":binding,
            "node":selected.node,"config_sha256":config_hash(config)?,"console_only":true,
            "history":inventories,"policy_fingerprint":policy["fingerprint"],
            "worker_installation_fingerprint":workers["fingerprint"]});
        let fingerprint = crate::message::digest(&serde_json::to_vec(&identity)?);
        let mut db = self
            .interactive
            .get()
            .await
            .context("Console activation capacity unavailable")?;
        let tx = db.transaction().await.map_err(database_error)?;
        management_lock(&tx).await?;
        let mut report:Value=tx.query_one("SELECT report FROM noisefence.migration_state WHERE id=1 AND source_digest=$1 AND report->>'instance'=$2 AND activated_at IS NOT NULL FOR UPDATE",&[&binding.source_digest,&binding.instance]).await.map_err(database_error)?.get(0);
        let actor = report["access_recoveries"][operation]["username"]
            .as_str()
            .context("Recovery access receipt missing")?
            .to_owned();
        ensure!(
            report["policy_recoveries"][operation] == *policy
                && report["worker_installation_recoveries"][operation] == *workers
                && workers["worker_credentials_verified"] == true,
            "Console recovery evidence changed"
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
        ensure!(
            sources.len() == inventories.len()
                && sources.iter().all(|(node, epoch)| inventories
                    .get(node)
                    .is_some_and(|v| v["epoch"] == *epoch)),
            "Console recovery source inventories are incomplete"
        );
        let existing = &report["console_recoveries"][operation];
        let receipt = if !existing.is_null() {
            ensure!(
                existing["fingerprint"] == fingerprint,
                "Another console installation is already authorized for this recovery"
            );
            existing.clone()
        } else {
            let mut receipt = identity;
            receipt["fingerprint"] = json!(fingerprint);
            receipt["created"] = json!(crate::now());
            let entries = report
                .as_object_mut()
                .context("Invalid migration receipt")?
                .entry("console_recoveries")
                .or_insert_with(|| json!({}))
                .as_object_mut()
                .context("Invalid console recovery receipts")?;
            ensure!(
                entries.len() < 256,
                "Console recovery receipt limit reached"
            );
            entries.insert(operation.into(), receipt.clone());
            tx.execute(
                "UPDATE noisefence.migration_state SET report=$1 WHERE id=1",
                &[&report],
            )
            .await
            .map_err(database_error)?;
            tx.execute("INSERT INTO noisefence.audit(created,username,action,object_id) VALUES($1,$2,'authorize_recovery_console',$3)",&[&crate::now(),&actor,&operation]).await.map_err(database_error)?;
            receipt
        };
        tx.commit().await.map_err(database_error)?;
        // Central first, local second. A crash between commits authorizes no local
        // process; an exact retry can safely publish the already committed receipt.
        let tx = local.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        ensure!(
            Selection::read(&tx)?.as_ref() == Some(&selected),
            "Console selection changed during activation"
        );
        let pending: String = tx.query_row(
            "SELECT value FROM cluster_state WHERE key='management_recovery_required'",
            [],
            |r| r.get(0),
        )?;
        let pending: Value = serde_json::from_str(&pending)?;
        ensure!(
            pending["protocol"] == "noisefence-management-recovery-1"
                && pending["operation"] == operation,
            "Console recovery fence changed"
        );
        let previous: Option<String> = tx
            .query_row(
                "SELECT value FROM cluster_state WHERE key='management_console_activation'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(previous) = previous {
            ensure!(
                serde_json::from_str::<Value>(&previous)? == receipt,
                "Local console activation conflicts with authority"
            );
        } else {
            tx.execute(
                "INSERT INTO cluster_state VALUES('management_console_activation',?1)",
                [serde_json::to_string(&receipt)?],
            )?;
        }
        tx.commit()?;
        Ok(receipt)
    }

    /// Called under the daemon lock before opening the recovered console socket.
    pub async fn require_recovered_console_activation(&self, config: &Config) -> Result<()> {
        let receipt = local_receipt(config)?;
        ensure!(
            Some(&serde_json::from_value::<crate::central::binding::Binding>(
                receipt["database"].clone()
            )?) == self.binding(),
            "Console activation database differs from runtime"
        );
        let operation = receipt["operation"]
            .as_str()
            .context("Console activation operation missing")?;
        let db = self
            .interactive
            .get()
            .await
            .context("Console activation authority unavailable")?;
        let central:Option<Value>=db.query_one("SELECT report->'console_recoveries'->$1::text FROM noisefence.migration_state WHERE id=1",&[&operation]).await.map_err(database_error)?.get(0);
        ensure!(
            central.as_ref() == Some(&receipt),
            "Central console activation receipt is missing or differs"
        );
        drop(db);
        self.validate_mfa_key(&config.data_dir).await?;
        Ok(())
    }
}

/// Read-only operator check for checkpointing an authorized, possibly running
/// console. This never grants startup authority or removes the permanent fence.
pub async fn check(config: &Config) -> Result<Value> {
    use crate::central::{binding::Binding, bootstrap::Management};
    let receipt = local_receipt(config)?;
    let binding: Binding = serde_json::from_value(receipt["database"].clone())?;
    let Some(Management::PostgreSql { connection }) = &config.management else {
        anyhow::bail!("Recovered console requires PostgreSQL management");
    };
    let central = Central::new_bound(connection, &binding)?;
    tokio::time::timeout(
        std::time::Duration::from_secs(15),
        central.require_recovered_console_activation(config),
    )
    .await
    .context("Recovered console verification exceeded 15 seconds")??;
    ensure!(
        local_receipt(config)? == receipt,
        "Console authorization changed during verification"
    );
    Ok(
        json!({"status":"console_authorization_verified", "receipt":receipt,
        "smtp_enabled":false,"state_changed":false}),
    )
}
