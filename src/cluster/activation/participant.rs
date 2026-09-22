//! A participant's durable view of an authenticated authority decision. A stored
//! readiness receipt never opens admission: the resident runtime must be verified
//! again after restart, and a matching release (or pre-commit abort) is required.
use super::{Acknowledgement, Bundle, Epoch, Journal, Phase, Progress};
use anyhow::{Result, ensure};
use rusqlite::{OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};

const KEY: &str = "activation_participant";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Local {
    version: u8,
    node: String,
    authority: Journal,
    installed: Bundle,
    installed_epoch: Epoch,
    prepared: Option<Epoch>,
}
impl Local {
    pub fn installed(&self) -> &Bundle {
        &self.installed
    }
    pub fn installed_epoch(&self) -> &Epoch {
        &self.installed_epoch
    }
    pub fn authority(&self) -> &Journal {
        &self.authority
    }
    pub fn acknowledgement(&self) -> Option<Acknowledgement> {
        let r = self.authority.rollout.as_ref()?;
        if r.phase == Phase::Aborted {
            return None;
        }
        let progress = if self.installed_epoch == r.epoch {
            Progress::Applied
        } else if self.prepared.as_ref() == Some(&r.epoch) {
            Progress::Prepared
        } else {
            return None;
        };
        Some(Acknowledgement {
            epoch: r.epoch.clone(),
            progress,
        })
    }
    fn validate(&self) -> Result<()> {
        self.authority.validate()?;
        self.installed.validate()?;
        self.installed_epoch.validate()?;
        let r = self
            .authority
            .rollout
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Missing participant rollout"))?;
        ensure!(
            self.version == 1
                && r.participants.contains_key(&self.node)
                && self.installed_epoch
                    == Epoch::new(self.installed_epoch.sequence, &self.installed)
                && self.installed_epoch.sequence <= r.epoch.sequence
                && self.prepared.as_ref().is_none_or(|e| e == &r.epoch),
            "Invalid participant journal"
        );
        match r.phase {
            Phase::Preparing => ensure!(
                self.installed_epoch.sequence < r.epoch.sequence,
                "Uncommitted runtime installed"
            ),
            Phase::Committed => ensure!(
                self.prepared.as_ref() == Some(&r.epoch),
                "Commit without local preparation"
            ),
            Phase::Released => ensure!(
                self.prepared.as_ref() == Some(&r.epoch) && self.installed_epoch == r.epoch,
                "Release without local application"
            ),
            Phase::Aborted => ensure!(
                self.installed_epoch == r.base_epoch,
                "Abort would restore a different runtime"
            ),
        }
        Ok(())
    }
    pub fn read(tx: &Transaction<'_>) -> Result<Option<Self>> {
        let raw: Option<String> = tx
            .query_row("SELECT value FROM cluster_state WHERE key=?1", [KEY], |r| {
                r.get(0)
            })
            .optional()?;
        raw.map(|raw| {
            ensure!(
                raw.len() <= super::MAX_BYTES,
                "Participant journal too large"
            );
            let value: Self = serde_json::from_str(&raw)?;
            value.validate()?;
            value.storage_identity(tx)?;
            Ok(value)
        })
        .transpose()
    }
    fn storage_identity(&self, tx: &Transaction<'_>) -> Result<()> {
        let node: String = tx.query_row(
            "SELECT value FROM cluster_state WHERE key='node_id'",
            [],
            |r| r.get(0),
        )?;
        let role: String = tx.query_row(
            "SELECT value FROM cluster_state WHERE key='role'",
            [],
            |r| r.get(0),
        )?;
        ensure!(
            node == self.node
                && ((role == "coordinator" && node == self.authority.owner)
                    || (role == "worker" && node != self.authority.owner)),
            "Participant storage identity mismatch"
        );
        Ok(())
    }
    /// Pure transition validation; call before fencing so stale replies cannot
    /// interrupt an already released runtime. Caller authenticates the authority.
    pub(crate) fn observe(previous: Option<Self>, node: &str, authority: Journal) -> Result<Self> {
        authority.validate()?;
        let r = authority
            .rollout
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Missing activation directive"))?;
        ensure!(
            r.participants.contains_key(node),
            "Node excluded from activation"
        );
        let mut local = if let Some(local) = previous {
            ensure!(
                local.node == node && local.authority.owner == authority.owner,
                "Activation authority changed"
            );
            let old = local.authority.rollout.as_ref().unwrap();
            ensure!(
                r.epoch.sequence >= old.epoch.sequence,
                "Stale activation directive"
            );
            if r.epoch.sequence == old.epoch.sequence {
                ensure!(
                    r.epoch == old.epoch
                        && r.base_epoch == old.base_epoch
                        && r.recovery_of == old.recovery_of
                        && r.participants.keys().eq(old.participants.keys())
                        && r.participants
                            .iter()
                            .all(|(n, p)| p >= &old.participants[n]),
                    "Conflicting activation directive"
                );
                ensure!(
                    r.phase == old.phase
                        || matches!(
                            (old.phase, r.phase),
                            (Phase::Preparing, Phase::Committed | Phase::Aborted)
                                | (Phase::Committed, Phase::Released)
                        ),
                    "Activation phase regressed or skipped"
                );
            } else if let Some(recovery) = &r.recovery_of {
                ensure!(
                    recovery == &old.epoch
                        && r.base_epoch == old.epoch
                        && matches!(old.phase, Phase::Preparing | Phase::Committed)
                        && r.phase == Phase::Preparing
                        && r.participants.keys().eq(old.participants.keys()),
                    "Invalid recovery transition"
                );
            } else {
                // A release/abort reply may be lost before the authority stages
                // again. Only the exact durably installed base can be superseded;
                // this never skips application of an uninstalled committed epoch.
                ensure!(
                    r.phase == Phase::Preparing && r.base_epoch == local.installed_epoch,
                    "Previous activation not resolved locally"
                );
            }
            local
        } else {
            ensure!(
                matches!(r.phase, Phase::Preparing | Phase::Aborted) && r.recovery_of.is_none(),
                "An unprepared node cannot enroll into a committed rollout"
            );
            Self {
                version: 1,
                node: node.into(),
                installed: r.base.clone(),
                installed_epoch: r.base_epoch.clone(),
                prepared: None,
                authority: authority.clone(),
            }
        };
        if local.authority.rollout.as_ref().unwrap().epoch != r.epoch {
            local.prepared = None;
        }
        local.authority = authority;
        local.validate()?;
        Ok(local)
    }
    /// The driver calls this only after loading the exact candidate behind a
    /// drained fence. A peer JSON request cannot manufacture that runtime.
    pub(crate) fn prepared(&mut self) -> Result<()> {
        let r = self.authority.rollout.as_ref().unwrap();
        ensure!(r.phase == Phase::Preparing, "Not preparing");
        self.prepared = Some(r.epoch.clone());
        self.validate()
    }
    pub(crate) fn applied(&mut self) -> Result<()> {
        let r = self.authority.rollout.as_ref().unwrap();
        ensure!(
            r.phase == Phase::Committed && self.prepared.as_ref() == Some(&r.epoch),
            "Not prepared for commit"
        );
        self.installed = r.candidate.clone();
        self.installed_epoch = r.epoch.clone();
        self.validate()
    }
    pub(crate) fn save(&self, tx: &Transaction<'_>) -> Result<()> {
        self.validate()?;
        self.storage_identity(tx)?;
        let raw = serde_json::to_string(self)?;
        ensure!(
            raw.len() <= super::MAX_BYTES,
            "Participant journal too large"
        );
        crate::store::require_format(tx, 6)?;
        tx.execute(
            "INSERT OR REPLACE INTO cluster_state(key,value) VALUES(?1,?2)",
            params![KEY, raw],
        )?;
        tx.execute(
            "INSERT OR REPLACE INTO cluster_state(key,value) VALUES('bundle',?1)",
            [serde_json::to_string(&self.installed)?],
        )?;
        Ok(())
    }
}
