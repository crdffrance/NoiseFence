use super::Controller;
use crate::identity::{
    connections::{Reference, vault::Key},
    schedule::{Grant, PROTOCOL},
};
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::sync::Arc;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Save {
    pub operation: String,
    pub revision: i64,
    pub catalog_sha256: Option<String>,
    pub connection: Reference,
    pub expected_grant: Option<String>,
    pub interval_seconds: i64,
    pub expires: i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stop {
    pub connection: Reference,
    pub expected_grant: String,
}
impl Controller {
    pub async fn save_directory_schedule(
        &self,
        input: Save,
        actor: String,
        session: String,
    ) -> Result<super::identity_connections::ConnectionsView> {
        self.directory_authorize(actor.clone(), session.clone())
            .await?;
        let _permit = self
            .applying
            .clone()
            .try_acquire_owned()
            .context("Policy operation in progress")?;
        let record = self
            .store
            .identity_connection_get(
                input.connection.source_id.clone(),
                input.connection.generation.clone(),
                actor.clone(),
                session.clone(),
            )
            .await?;
        self.directory_context(
            input.revision,
            input.catalog_sha256,
            &record.metadata.source,
        )
        .await?;
        let grant = Grant {
            protocol: PROTOCOL.into(),
            id: input.operation,
            connection: input.connection.clone(),
            created: crate::now(),
            expires: input.expires,
            interval_seconds: input.interval_seconds,
        };
        grant.validate(&record.metadata)?;
        let root = self.base.data_dir.clone();
        let key = tokio::task::spawn_blocking(move || Key::load(&root)).await??;
        self.store
            .identity_schedule_save(
                input.connection,
                input.expected_grant,
                grant,
                key,
                actor.clone(),
                session.clone(),
            )
            .await?;
        self.directory_connections(actor, session).await
    }
    pub async fn stop_directory_schedule(
        &self,
        input: Stop,
        actor: String,
        session: String,
    ) -> Result<super::identity_connections::ConnectionsView> {
        ensure!(
            !crate::cluster::is_worker(&self.base),
            "Use the management instance"
        );
        self.store
            .identity_schedule_stop(
                input.connection,
                input.expected_grant,
                actor.clone(),
                session.clone(),
            )
            .await?;
        self.directory_connections(actor, session).await
    }
    /// Started only by a serving daemon, never by load(), test tools or workers.
    /// Grants/leases survive restart; a lost result stays unknown, not successful.
    pub async fn run_directory_schedules(
        self: Arc<Self>,
        mut stop: tokio::sync::watch::Receiver<bool>,
    ) -> Result<()> {
        let mut tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();
        let mut ticks = tokio::time::interval(std::time::Duration::from_secs(30));
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut next_warning = 0;
        loop {
            if *stop.borrow() {
                break;
            }
            tokio::select! {_=stop.changed()=>{break;},_=ticks.tick()=>{}}
            if *stop.borrow() {
                break;
            }
            if crate::cluster::is_worker(&self.base) {
                continue;
            }
            tasks.retain(|t| !t.is_finished());
            let records = match self
                .store
                .identity_schedule_due(self.snapshot().revision)
                .await
            {
                Ok(rows) => rows,
                Err(_) => {
                    if crate::now() >= next_warning {
                        tracing::warn!(
                            "Directory schedule unavailable; installed directory retained"
                        );
                        next_warning = crate::now() + 300;
                    }
                    continue;
                }
            };
            for record in records {
                if *stop.borrow() || tasks.len() >= 2 {
                    break;
                }
                match self.start_scheduled_directory_sync(record).await {
                    Ok((_, task)) => tasks.push(task),
                    Err(_) => {
                        if crate::now() >= next_warning {
                            tracing::warn!(
                                "Directory collection deferred; check access, scope, quota and schedule status"
                            );
                            next_warning = crate::now() + 300;
                        }
                    }
                }
            }
        }
        // Cancellation cannot recall transmitted requests. No ready result is
        // fabricated; the durable lease prevents restart from immediately retrying.
        for task in &tasks {
            task.abort();
        }
        for task in tasks {
            let _ = task.await;
        }
        Ok(())
    }
}
