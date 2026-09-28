//! Offline recovery building blocks. No Web route calls these operations.
use super::{Central, admin::management_lock, database_error};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
pub mod activation;
pub mod console;
mod credentials;
mod node_credentials;
mod nodes;
pub mod operator;
pub mod outbox;
mod payload;
mod policy;
mod prepare;
mod replay;
pub mod worker_fence;
mod worker_installation;
pub mod worker_release;
pub mod worker_renewal;

/// Immutable source bounds recorded before recovery changes any history.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplayBounds {
    pub generation: i64,
    pub log_id: i64,
}

impl Central {
    /// Persist credentials before any database mutation and reuse them on retry.
    /// As with recover_access, the offline caller must already fence every writer.
    pub async fn recover_access_saved(
        &self,
        operation: &str,
        path: &std::path::Path,
    ) -> Result<serde_json::Value> {
        let binding = self
            .binding()
            .context("Recovery requires a selected database")?
            .clone();
        let operation = operation.to_owned();
        let target = path.to_owned();
        let prepare_operation = operation.clone();
        let credentials = tokio::task::spawn_blocking(move || {
            credentials::prepare(&target, &binding, &prepare_operation)
        })
        .await
        .context("Recovery credential preparation failed")??;
        let changed = self
            .recover_access(
                &operation,
                &credentials.username,
                &credentials.password_hash,
            )
            .await?;
        Ok(
            json!({"operation":operation,"username":credentials.username,"credentials_file":path,
            "access_changed":changed,"central_management_recovery_required":true}),
        )
    }

    /// Revoke snapshot-era access and establish one recovery administrator atomically.
    /// The caller must fence all writers and persist the operation and credentials
    /// before calling. This does not clear a local recovery fence or permit startup.
    /// Returns false when the exact operation already committed (e.g. a lost reply).
    pub async fn recover_access(
        &self,
        operation: &str,
        username: &str,
        password_hash: &str,
    ) -> Result<bool> {
        let binding = self
            .binding()
            .context("Recovery requires a selected database")?;
        ensure!(
            uuid::Uuid::parse_str(operation).is_ok_and(|id| id.to_string() == operation),
            "Invalid recovery operation"
        );
        ensure!(
            username.starts_with("recovery-"),
            "Recovery account prefix required"
        );
        crate::operator::AccountChange::Create {
            password_hash: password_hash.into(),
            admin: true,
            addresses: Vec::new(),
        }
        .validate(username)?;
        let mut db = self
            .interactive
            .get()
            .await
            .context("Central recovery capacity unavailable")?;
        let tx = db.transaction().await.map_err(database_error)?;
        management_lock(&tx).await?;
        let row = tx.query_one(
            "SELECT report FROM noisefence.migration_state WHERE id=1 AND source_digest=$1 AND report->>'instance'=$2 AND activated_at IS NOT NULL FOR UPDATE",
            &[&binding.source_digest, &binding.instance],
        ).await.map_err(database_error)?;
        let mut report: serde_json::Value = row.get(0);
        let object = report
            .as_object_mut()
            .context("Invalid migration receipt")?;
        let receipts = object
            .entry("access_recoveries")
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .context("Invalid access recovery receipts")?;
        let digest = crate::message::digest(password_hash.as_bytes());
        if let Some(receipt) = receipts.get(operation) {
            ensure!(
                receipt["username"] == username && receipt["credential_digest"] == digest,
                "Recovery operation was committed with different credentials"
            );
            // Never disable accounts or revoke newly issued sessions on replay.
            tx.commit().await.map_err(database_error)?;
            return Ok(false);
        }
        ensure!(receipts.len() < 256, "Recovery receipt limit reached");
        // Capture the replay floors once, before any source is resynchronized.
        // A retry must not chase its own newly ingested generations.
        tx.batch_execute("LOCK TABLE noisefence.sources,noisefence.message_versions,noisefence.delivery_log_versions,noisefence.delivery_logs IN SHARE MODE")
            .await.map_err(database_error)?;
        let sources = tx.query("SELECT s.node,s.epoch,s.enabled,GREATEST(s.last_sequence,COALESCE((SELECT MAX(v.generation) FROM noisefence.message_versions v WHERE v.node=s.node AND v.epoch=s.epoch),0),COALESCE((SELECT MAX(v.generation) FROM noisefence.delivery_log_versions v WHERE v.node=s.node AND v.epoch=s.epoch),0)),GREATEST(COALESCE((SELECT MAX(v.local_id) FROM noisefence.delivery_log_versions v WHERE v.node=s.node AND v.epoch=s.epoch),0),COALESCE((SELECT MAX(l.local_id) FROM noisefence.delivery_logs l WHERE l.node=s.node AND l.epoch=s.epoch),0)) FROM noisefence.sources s ORDER BY s.node LIMIT 65", &[])
            .await.map_err(database_error)?;
        ensure!(sources.len() <= 64, "Recovery source limit exceeded");
        let replay_sources: Vec<Value> = sources
            .iter()
            .map(|r| {
                json!({
                    "identity":{"node":r.get::<_,String>(0),"epoch":r.get::<_,String>(1)},
                    "enabled":r.get::<_,bool>(2),"high_water":r.get::<_,i64>(3),"log_id_high_water":r.get::<_,i64>(4)
                })
            })
            .collect();
        ensure!(
            tx.query_opt(
                "SELECT username FROM noisefence.users WHERE username=$1",
                &[&username]
            )
            .await
            .map_err(database_error)?
            .is_none(),
            "Recovery account already exists"
        );
        // Lock all users before deleting sessions: a login in flight either commits
        // first and is revoked here, or sees its now-disabled user afterwards.
        tx.query(
            "SELECT username FROM noisefence.users ORDER BY username FOR UPDATE",
            &[],
        )
        .await
        .map_err(database_error)?;
        tx.execute(
            "UPDATE noisefence.users SET disabled=true,version=version+1",
            &[],
        )
        .await
        .map_err(database_error)?;
        tx.execute("DELETE FROM noisefence.sessions", &[])
            .await
            .map_err(database_error)?;
        let now = crate::now();
        // Restored authorizations must never dispatch old release/retry/delete
        // requests. Preserve a later execution receipt if a worker reports one.
        tx.execute("UPDATE noisefence.queue_commands SET result='revoked',finished=$1 WHERE finished IS NULL", &[&now])
            .await.map_err(database_error)?;
        tx.execute(
            "UPDATE noisefence.invitations SET revoked=$1,version=version+1 WHERE revoked IS NULL",
            &[&now],
        )
        .await
        .map_err(database_error)?;
        tx.execute(
            "INSERT INTO noisefence.users(username,password,admin,version) VALUES($1,$2,true,1)",
            &[&username, &password_hash],
        )
        .await
        .map_err(database_error)?;
        tx.execute("INSERT INTO noisefence.audit(created,username,action,object_id) VALUES($1,$2,'revoke_stale_snapshot_access',$3)", &[&now,&username,&operation])
            .await.map_err(database_error)?;
        receipts.insert(
            operation.into(),
            json!({"username":username,"credential_digest":digest,"created":now,"replay_sources":replay_sources}),
        );
        // Keep idempotency receipts outside the expiring audit history.
        tx.execute(
            "UPDATE noisefence.migration_state SET report=$1 WHERE id=1",
            &[&report],
        )
        .await
        .map_err(database_error)?;
        tx.commit().await.map_err(database_error)?;
        Ok(true)
    }

    /// Read the immutable floor captured with access revocation, not today's
    /// changing ingestion cursor. The caller persists this in the source plan.
    pub async fn recovery_replay_floor(
        &self,
        operation: &str,
        source: &super::outbox::Identity,
    ) -> Result<i64> {
        Ok(self
            .recovery_replay_bounds(operation, source)
            .await?
            .generation)
    }

    /// Transcript IDs and journal generations are separate monotonic sequences.
    /// Include deleted transcript identities so a restored allocator cannot reuse them.
    pub async fn recovery_replay_bounds(
        &self,
        operation: &str,
        source: &super::outbox::Identity,
    ) -> Result<ReplayBounds> {
        ensure!(
            self.binding().is_some(),
            "Recovery requires a selected database"
        );
        let db = self
            .interactive
            .get()
            .await
            .context("Central recovery capacity unavailable")?;
        let receipt: Value = db.query_one("SELECT report->'access_recoveries'->$1::text FROM noisefence.migration_state WHERE id=1", &[&operation])
            .await.map_err(database_error)?.get::<_,Option<Value>>(0)
            .context("Access recovery has not committed")?;
        let sources = receipt["replay_sources"]
            .as_array()
            .context("Recovery has no replay plan")?;
        let identity = serde_json::to_value(source)?;
        let entry = sources
            .iter()
            .find(|r| r["identity"] == identity && r["enabled"] == true)
            .context("Source is not enabled in this recovery")?;
        let floor = entry["high_water"]
            .as_i64()
            .context("Invalid recorded recovery floor")?;
        let log_id = entry["log_id_high_water"]
            .as_i64()
            .context("Recovery has no recorded transcript allocator bound")?;
        ensure!(
            floor >= 0 && (0..i64::MAX).contains(&log_id),
            "Invalid or exhausted recovery bounds"
        );
        Ok(ReplayBounds {
            generation: floor,
            log_id,
        })
    }
}
