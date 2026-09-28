//! Bounded offline synchronization. Startup remains fenced after this step.
use crate::central::{
    Central, database_error, history, import::SourceLocks, logs, outbox, selection::Selection,
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::path::Path;

impl Central {
    /// Caller must fence the original authority and all other writers first.
    /// This acquires local process locks; it never promotes or starts a service.
    pub async fn replay_recovered_source(&self, root: &Path, operation: &str) -> Result<Value> {
        let locks = SourceLocks::acquire(root)?;
        self.replay_recovered_source_held(root, operation, &locks)
            .await
    }

    pub(super) async fn replay_recovered_source_held(
        &self,
        root: &Path,
        operation: &str,
        locks: &SourceLocks,
    ) -> Result<Value> {
        locks.verify_for(root)?;
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(900),
            self.replay_locked(root, operation),
        )
        .await
        .context("Recovery replay deadline exceeded")??;
        locks.verify_for(root)?;
        Ok(result)
    }

    async fn replay_locked(&self, root: &Path, operation: &str) -> Result<Value> {
        let selected = {
            let db = rusqlite::Connection::open_with_flags(
                root.join("state.sqlite3"),
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )?;
            Selection::read(&db)?.context("Recovery source is not selected")?
        };
        ensure!(
            self.binding() == Some(&selected.database),
            "Recovery database differs from selected source"
        );
        let floor = self
            .recovery_replay_bounds(operation, &selected.node)
            .await?;
        let backend = (selected.role == crate::cluster::Role::Coordinator).then(|| self.clone());
        let store = crate::store::Store::open_bound(root, &selected, backend)?;
        let expected = selected.clone();
        let op = operation.to_owned();
        let prepared = store
            .run(move |db| {
                super::outbox::requeue(db, &expected, &op, floor.generation, floor.log_id)
            })
            .await?;
        let mut batches = 0;
        loop {
            let status = store.read(|db| outbox::status(db)).await?;
            if status.pending == 0 && status.pending_logs == 0 {
                break;
            }
            ensure!(batches < 200_000, "Recovery replay batch limit exceeded");
            let mut progressed = 0;
            let (identity, mut messages) = history::export(&store).await?;
            ensure!(
                identity == selected.node,
                "Recovery source identity changed"
            );
            if !messages.is_empty() {
                let receipts = self.ingest(&identity, &mut messages).await?;
                // Ordinary ingestion permits acknowledgements of superseded versions.
                // Recovery requires this exact generation before clearing its outbox.
                let db = self
                    .interactive
                    .get()
                    .await
                    .context("Recovery verification capacity unavailable")?;
                for event in &messages {
                    let r = &event.receipt;
                    let ok:bool=db.query_one("SELECT EXISTS(SELECT 1 FROM noisefence.message_versions v WHERE id=$1 AND node=$2 AND epoch=$3 AND generation=$4 AND deleted=$5 AND (v.deleted OR EXISTS(SELECT 1 FROM noisefence.messages m WHERE m.id=v.id)))", &[&r.id,&identity.node,&identity.epoch,&r.generation,&r.deleted]).await.map_err(database_error)?.get(0);
                    ensure!(ok, "Recovery metadata generation was not applied exactly");
                }
                drop(db);
                progressed += store
                    .run(move |db| outbox::acknowledge(db, &identity, &receipts))
                    .await?;
            }
            let (identity, mut traces) = logs::export(&store).await?;
            ensure!(
                identity == selected.node,
                "Recovery transcript source changed"
            );
            if !traces.is_empty() {
                let receipts = self.ingest_logs(&identity, &mut traces).await?;
                let db = self
                    .interactive
                    .get()
                    .await
                    .context("Recovery verification capacity unavailable")?;
                for event in &traces {
                    let r = &event.receipt;
                    let ok:bool=db.query_one("SELECT EXISTS(SELECT 1 FROM noisefence.delivery_log_versions v WHERE node=$1 AND epoch=$2 AND local_id=$3 AND generation=$4 AND deleted=$5 AND message_id=$6 AND (v.deleted OR EXISTS(SELECT 1 FROM noisefence.delivery_logs l WHERE l.node=v.node AND l.epoch=v.epoch AND l.local_id=v.local_id))) OR EXISTS(SELECT 1 FROM noisefence.message_versions WHERE id=$6 AND node=$1 AND epoch=$2 AND deleted)", &[&identity.node,&identity.epoch,&r.local_id,&r.generation,&r.deleted,&event.message_id]).await.map_err(database_error)?.get(0);
                    ensure!(ok, "Recovery transcript generation was not applied exactly");
                }
                drop(db);
                progressed += logs::acknowledge(&store, identity, receipts).await? as u64;
            }
            ensure!(progressed > 0, "Recovery replay cannot make progress");
            batches += 1;
        }
        let inventory = self.recovered_inventory(&store, &selected).await?;
        Ok(
            json!({"operation":operation,"node":selected.node,"preparation":prepared,
            "messages":inventory["messages"],"transcripts":inventory["transcripts"],"batches":batches,
            "history_inventory_verified":true,"inventory_sha256":inventory["inventory_sha256"],"central_management_recovery_required":true}),
        )
    }

    /// Read-only inventory verification, also used before releasing stopped workers.
    pub(super) async fn recovered_inventory(
        &self,
        store: &crate::store::Store,
        selected: &Selection,
    ) -> Result<Value> {
        let (messages,traces)=store.read(|db| {
            let messages=db.prepare("SELECT id FROM messages m WHERE NOT EXISTS(SELECT 1 FROM cluster_origin c WHERE c.message_id=m.id) ORDER BY id LIMIT 1000001")?
                .query_map([],|r|r.get::<_,String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
            let traces=db.prepare("SELECT a.id,d.message_id,d.address FROM delivery_attempts a JOIN deliveries d ON d.id=a.delivery_id WHERE NOT EXISTS(SELECT 1 FROM cluster_origin c WHERE c.message_id=d.message_id) ORDER BY a.id LIMIT 1000001")?
                .query_map([],|r|Ok((r.get::<_,i64>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
            Ok((messages,traces))
        }).await?;
        ensure!(
            messages.len() + traces.len() <= 1_000_000,
            "Recovery inventory exceeds source limit"
        );
        let db = self
            .interactive
            .get()
            .await
            .context("Recovery inventory capacity unavailable")?;
        let central=db.query("SELECT m.id FROM noisefence.messages m JOIN noisefence.message_versions v ON v.id=m.id WHERE v.node=$1 AND v.epoch=$2 AND NOT v.deleted ORDER BY m.id COLLATE \"C\" LIMIT 1000001", &[&selected.node.node,&selected.node.epoch]).await.map_err(database_error)?;
        ensure!(
            central
                .iter()
                .map(|r| r.get::<_, String>(0))
                .collect::<Vec<_>>()
                == messages,
            "Recovery message inventories differ; reconcile missing or stale history"
        );
        let central=db.query("SELECT l.local_id,l.message_id,d.address FROM noisefence.delivery_logs l JOIN noisefence.delivery_log_versions v USING(node,epoch,local_id) JOIN noisefence.deliveries d ON d.id=v.delivery_id WHERE l.node=$1 AND l.epoch=$2 AND NOT v.deleted ORDER BY l.local_id LIMIT 1000001", &[&selected.node.node,&selected.node.epoch]).await.map_err(database_error)?;
        ensure!(
            central
                .iter()
                .map(|r| (
                    r.get::<_, i64>(0),
                    r.get::<_, String>(1),
                    r.get::<_, String>(2)
                ))
                .collect::<Vec<_>>()
                == traces,
            "Recovery transcript inventories differ; reconcile log identities"
        );
        super::payload::verify(&db, store, selected, &messages, &traces).await?;
        let inventory_sha256 = crate::message::digest(&serde_json::to_vec(
            &json!({"messages":messages,"transcripts":traces}),
        )?);
        Ok(
            json!({"messages":messages.len(),"transcripts":traces.len(),"inventory_sha256":inventory_sha256}),
        )
    }
}
