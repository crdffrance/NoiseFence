//! Daemon lifecycle for the optional isolated analysis connector. This service
//! owns its client; HTTP API and offline scans cannot submit attachments.
use crate::{config::Config, sandbox, sandbox_pipeline, store::Store};
use anyhow::Result;
use std::{path::PathBuf, time::Duration};

pub struct Service {
    client: Option<sandbox::Client>,
    worker: Option<sandbox_pipeline::Worker>,
    state_dir: Option<PathBuf>,
    retention_days: i64,
}
impl Service {
    pub fn new(config: &Config) -> Result<Self> {
        let client = config
            .sandbox
            .as_ref()
            .filter(|s| s.enabled)
            .map(|s| sandbox::Client::new(s.clone()))
            .transpose()?;
        let worker = config
            .sandbox_pipeline
            .as_ref()
            .filter(|s| s.enabled)
            .map(|s| {
                let mut settings = s.clone();
                settings.bind_backend(
                    config
                        .sandbox
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("sandbox backend missing"))?,
                )?;
                sandbox_pipeline::Worker::new(settings)
            })
            .transpose()?;
        Ok(Self {
            client,
            worker,
            state_dir: config.sandbox.as_ref().map(|s| s.state_dir.clone()),
            retention_days: config
                .sandbox_pipeline
                .as_ref()
                .map_or(30, |s| i64::from(s.retention_days)),
        })
    }
    async fn prune(&self) -> Result<()> {
        let cutoff = (crate::now() - self.retention_days * 86400) * 1000;
        // Each pass is bounded by the connector; the total configured store is
        // bounded too. Yield between batches so maintenance does not monopolize.
        loop {
            let removed = match (&self.client, &self.state_dir) {
                (Some(client), _) => client.prune_before(cutoff).await?,
                (None, Some(path)) => sandbox::Client::prune_local(path, cutoff).await?,
                _ => 0,
            };
            if removed == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
        Ok(())
    }
    pub async fn run(
        self,
        store: Store,
        mut stop: tokio::sync::watch::Receiver<bool>,
    ) -> Result<()> {
        let mut maintenance = tokio::time::Instant::now();
        loop {
            if *stop.borrow() {
                return Ok(());
            }
            if maintenance <= tokio::time::Instant::now() {
                if self.prune().await.is_err() {
                    tracing::warn!(
                        "sandbox retention maintenance unavailable; retrying in 60 seconds"
                    );
                }
                maintenance = tokio::time::Instant::now() + Duration::from_secs(60);
            }
            if let Some(client) = &self.client {
                if let Some(worker) = &self.worker {
                    match worker.tick(&store, client).await {
                        Ok(report)
                            if report.claimed > 0
                                || report.results_updated > 0
                                || report.backend_unavailable =>
                        {
                            tracing::info!(
                                claimed = report.claimed,
                                handed_off = report.handed_off,
                                results_updated = report.results_updated,
                                inconclusive = report.inconclusive,
                                retrying = report.retrying,
                                backend_unavailable = report.backend_unavailable,
                                "sandbox worker pass"
                            );
                        }
                        Ok(_) => {}
                        Err(_) => {
                            tracing::warn!("sandbox worker unavailable; durable jobs retained")
                        }
                    }
                } else if client.tick().await.is_err() {
                    tracing::warn!("sandbox connector unavailable; durable jobs retained");
                }
            }
            tokio::select! {
                changed = stop.changed() => if changed.is_err() || *stop.borrow() { return Ok(()); },
                _ = tokio::time::sleep(Duration::from_secs(1)) => {},
            }
        }
    }
}
