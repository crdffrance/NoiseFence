//! Participant driver. The transport must authenticate the authority before
//! calling this entry point; no Web or cluster-v1 route enables it implicitly.
use super::{Controller, Snapshot};
use crate::cluster::{
    activation::{Acknowledgement, Epoch, Journal, Phase, participant::Local},
    artifacts,
};
use anyhow::{Result, ensure};
use rusqlite::params;
use std::sync::Arc;

pub(super) struct Prepared {
    epoch: Epoch,
    keys: String,
    snapshot: Arc<Snapshot>,
}
impl Controller {
    /// Volatile proof from a successful runtime transition, never reconstructed
    /// from a stored readiness flag before loading models after restart.
    pub fn activation_receipt(&self) -> Option<Acknowledgement> {
        self.activation_receipt.lock().unwrap().clone()
    }
    async fn activation_runtime(
        self: &Arc<Self>,
        bundle: &artifacts::Bundle,
        epoch: &Epoch,
        credentials: &crate::credentials::Snapshot,
    ) -> Result<Arc<Snapshot>> {
        let keys = credentials.fingerprint();
        if let Some(staged) = self.prepared_activation.lock().unwrap().as_ref()
            && staged.epoch == *epoch
            && staged.keys == keys
        {
            return Ok(staged.snapshot.clone());
        }
        let base = self.base.clone();
        let bundle = bundle.clone();
        let epoch = epoch.clone();
        let current = self.snapshot();
        let credentials = Arc::new(credentials.clone());
        let next = tokio::task::spawn_blocking(move || -> Result<_> {
            // Re-verify every byte after download and on recovery, and force a
            // model reload: a matching path alone cannot prove the resident model.
            let mut config = artifacts::materialize(&base, &bundle, true)?;
            config.provider_credentials = Some(credentials);
            let config = Arc::new(config);
            let engine = Arc::new(current.engine.reload_cluster_models(config.clone())?);
            let publication =
                artifacts::capture(&config, bundle.settings.clone(), bundle.revision)?;
            ensure!(
                serde_json::to_value(&publication.bundle.files)?
                    == serde_json::to_value(&bundle.files)?,
                "Prepared models differ from the authority manifest"
            );
            engine.validate_cluster_publication(&publication)?;
            let rbl = Arc::new(current.rbl.reconfigure(
                config.rbl.as_ref(),
                crate::management::dqs_key(&config)?.as_deref(),
            )?);
            Ok(Arc::new(Snapshot {
                activation_epoch: Some(epoch),
                rbl,
                revision: bundle.revision,
                settings: bundle.settings,
                config,
                engine,
            }))
        })
        .await??;
        *self.prepared_activation.lock().unwrap() = Some(Prepared {
            epoch: next.activation_epoch.clone().unwrap(),
            keys,
            snapshot: next.clone(),
        });
        Ok(next)
    }
    fn install_activation(&self, snapshot: Arc<Snapshot>, keys: &str, server_time: i64) {
        snapshot.engine.activate_limits();
        snapshot.rbl.activate();
        self.store
            .admission
            .activate(snapshot.config.smtp_admission.as_ref());
        self.store
            .archive
            .configure(snapshot.config.research_archive.clone().unwrap_or_default());
        *self.template.write().unwrap() = snapshot.engine.clone();
        *self.cluster_hash.write().unwrap() =
            snapshot.activation_epoch.as_ref().unwrap().digest.clone();
        *self.cluster_keys.write().unwrap() = keys.into();
        *self.active.write().unwrap() = snapshot;
        self.cluster_until.store(
            server_time + self.base.cluster.as_ref().unwrap().max_stale_seconds,
            std::sync::atomic::Ordering::Release,
        );
    }
    async fn persist_activation(&self, local: Local, keys: String, server_time: i64) -> Result<()> {
        self.store
            .run(move |db| {
                let tx = db.transaction()?;
                local.save(&tx)?;
                for (key, value) in [("last_sync", server_time.to_string()), ("keys_hash", keys)] {
                    tx.execute(
                        "INSERT OR REPLACE INTO cluster_state(key,value) VALUES(?1,?2)",
                        params![key, value],
                    )?;
                }
                tx.commit()?;
                Ok(())
            })
            .await
    }
    /// Authenticated coordinated-activation input, deliberately separate from
    /// legacy immediate apply. Owned task finishes local persistence/runtime swap
    /// even if its network caller disappears. Admission opens only on release.
    pub async fn synchronize_activation(
        self: &Arc<Self>,
        authority: Journal,
        credentials: crate::credentials::Snapshot,
        server_time: i64,
    ) -> Result<Option<Acknowledgement>> {
        let keys = credentials.fingerprint();
        ensure!(
            server_time.abs_diff(crate::now()) <= 300,
            "Activation clock skew"
        );
        ensure!(
            crate::compatibility::valid_hash(&keys),
            "Invalid credential fingerprint"
        );
        let node = self
            .base
            .cluster
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Not a cluster node"))?
            .node_id
            .clone();
        let this = self.clone();
        let receipt = tokio::spawn(async move {
            let _permit = this.applying.clone().acquire_owned().await?;
            // Reject stale/conflicting replies before disrupting a live runtime.
            let (enrolling, mut local) = this
                .store
                .run(move |db| {
                    let tx = db.transaction()?;
                    let previous = Local::read(&tx)?;
                    Ok((
                        previous.is_none(),
                        Local::observe(previous, &node, authority)?,
                    ))
                })
                .await?;
            let rollout = local.authority().rollout().unwrap().clone();
            let phase = rollout.phase();
            let snapshot = this.snapshot();
            if enrolling {
                if crate::cluster::is_worker(&this.base) {
                    let installed = this.cluster_digest();
                    // An unsynchronized, empty new worker may bootstrap behind
                    // the fence. A previously synchronized worker must not be
                    // silently rewound by an enrollment using an older base.
                    ensure!(
                        (installed.is_empty() && snapshot.revision == 0)
                            || (installed == rollout.base_epoch().digest
                                && snapshot.revision == rollout.base_epoch().revision),
                        "Enrollment base differs from the installed worker policy"
                    );
                } else {
                    ensure!(
                        this.publication().await?.bundle.digest == rollout.base_epoch().digest,
                        "Enrollment base differs from the resident authority policy"
                    );
                }
            }
            if matches!(phase, Phase::Released | Phase::Aborted)
                && this.store.activation.ready()
                && snapshot.activation_epoch.as_ref() == Some(local.installed_epoch())
            {
                ensure!(
                    *this.cluster_keys.read().unwrap() == keys,
                    "Credentials changed; prepare a new activation"
                );
                this.persist_activation(local.clone(), keys, server_time)
                    .await?;
                this.cluster_until.store(
                    server_time + this.base.cluster.as_ref().unwrap().max_stale_seconds,
                    std::sync::atomic::Ordering::Release,
                );
                return Ok(local.acknowledgement());
            }
            let proof = this.store.activation.drain(rollout.epoch()).await?;
            // Persist the fence before any preparation acknowledgement. Startup
            // reads this journal and always keeps acceptance closed.
            this.persist_activation(local.clone(), keys.clone(), server_time)
                .await?;
            if this.store.activation.epoch().is_none() {
                let initial = this
                    .activation_runtime(local.installed(), local.installed_epoch(), &credentials)
                    .await?;
                this.install_activation(initial, &keys, server_time);
                this.store
                    .activation
                    .bind_initial(&proof, local.installed_epoch())?;
            }
            match phase {
                Phase::Preparing => {
                    this.activation_runtime(rollout.candidate(), rollout.epoch(), &credentials)
                        .await?;
                    local.prepared()?;
                    this.persist_activation(local.clone(), keys, server_time)
                        .await?;
                }
                Phase::Committed => {
                    let prepared = this
                        .activation_runtime(rollout.candidate(), rollout.epoch(), &credentials)
                        .await?;
                    local.applied()?;
                    this.persist_activation(local.clone(), keys.clone(), server_time)
                        .await?;
                    this.install_activation(prepared, &keys, server_time);
                }
                Phase::Released | Phase::Aborted => {
                    let installed = this
                        .activation_runtime(
                            local.installed(),
                            local.installed_epoch(),
                            &credentials,
                        )
                        .await?;
                    this.install_activation(installed, &keys, server_time);
                    this.store
                        .activation
                        .resume(&proof, local.installed_epoch())?;
                }
            }
            Ok(local.acknowledgement())
        })
        .await??;
        *self.activation_receipt.lock().unwrap() = receipt.clone();
        Ok(receipt)
    }
}
