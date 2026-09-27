//! Durable coordinator protocol for coordinated policy/model activation.
//!
//! This is the transaction layer, not a deployment entry point. The controller
//! driver must authenticate acknowledgements, prepare engines behind admission
//! fences, and commit its console revision in the SAME transaction as `commit`.
//! No timer or missing participant counts as readiness.
pub mod gate;
pub mod participant;
pub mod transport;

use super::artifacts::Bundle;
use anyhow::{Result, ensure};
use rusqlite::{OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const KEY: &str = "coordinated_activation";
const MAX_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Epoch {
    pub sequence: u64,
    pub revision: i64,
    pub digest: String,
}
impl Epoch {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.sequence <= i64::MAX as u64
                && self.revision >= 0
                && crate::compatibility::valid_hash(&self.digest),
            "Invalid activation epoch"
        );
        Ok(())
    }
    fn new(sequence: u64, bundle: &Bundle) -> Self {
        Self {
            sequence,
            revision: bundle.revision,
            digest: bundle.digest.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Preparing,
    Committed,
    Released,
    Aborted,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Progress {
    Waiting,
    Prepared,
    Applied,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Acknowledgement {
    pub epoch: Epoch,
    pub progress: Progress,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rollout {
    epoch: Epoch,
    base_epoch: Epoch,
    base: Bundle,
    candidate: Bundle,
    phase: Phase,
    participants: BTreeMap<String, Progress>,
    started: i64,
    updated: i64,
    /// A partially committed rollout can only recover behind closed fences.
    /// Its successor cannot abort and reopen a mixture of old/new policies.
    recovery_of: Option<Epoch>,
}
impl Rollout {
    pub fn epoch(&self) -> &Epoch {
        &self.epoch
    }
    pub fn phase(&self) -> Phase {
        self.phase
    }
    pub fn candidate(&self) -> &Bundle {
        &self.candidate
    }
    pub fn base(&self) -> &Bundle {
        &self.base
    }
    pub fn base_epoch(&self) -> &Epoch {
        &self.base_epoch
    }
    pub fn participants(&self) -> &BTreeMap<String, Progress> {
        &self.participants
    }
    pub fn recovery_of(&self) -> Option<&Epoch> {
        self.recovery_of.as_ref()
    }
    pub fn abortable(&self) -> bool {
        self.phase == Phase::Preparing && self.recovery_of.is_none()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Journal {
    version: u8,
    owner: String,
    current: Bundle,
    sequence: u64,
    current_sequence: u64,
    rollout: Option<Rollout>,
}
impl Journal {
    pub fn owner(&self) -> &str {
        &self.owner
    }
    pub fn bundles(&self) -> Vec<&Bundle> {
        let mut bundles = vec![&self.current];
        if let Some(r) = &self.rollout {
            bundles.extend([&r.base, &r.candidate]);
        }
        bundles
    }
    pub fn current(&self) -> &Bundle {
        &self.current
    }
    pub fn current_epoch(&self) -> Epoch {
        Epoch::new(self.current_sequence, &self.current)
    }
    pub fn rollout(&self) -> Option<&Rollout> {
        self.rollout.as_ref()
    }
    pub fn released(&self) -> bool {
        self.rollout
            .as_ref()
            .is_none_or(|r| matches!(r.phase, Phase::Released | Phase::Aborted))
    }
    pub fn read(tx: &Transaction<'_>) -> Result<Option<Self>> {
        let raw: Option<String> = tx
            .query_row("SELECT value FROM cluster_state WHERE key=?1", [KEY], |r| {
                r.get(0)
            })
            .optional()?;
        raw.map(|s| {
            ensure!(s.len() <= MAX_BYTES, "Activation journal too large");
            let value: Self = serde_json::from_str(&s)?;
            value.validate()?;
            ensure!(tx.query_row("SELECT EXISTS(SELECT 1 FROM cluster_state WHERE key='node_id' AND value=?1) AND EXISTS(SELECT 1 FROM cluster_state WHERE key='role' AND value='coordinator')", [&value.owner], |r| r.get::<_, bool>(0))?,
                "Activation authority does not match this storage identity");
            Ok(value)
        })
        .transpose()
    }
    pub fn initialize(tx: &Transaction<'_>, owner: &str, active: Bundle) -> Result<Self> {
        ensure!(Self::read(tx)?.is_none(), "Activation already initialized");
        ensure!(tx.query_row("SELECT EXISTS(SELECT 1 FROM cluster_state WHERE key='node_id' AND value=?1) AND EXISTS(SELECT 1 FROM cluster_state WHERE key='role' AND value='coordinator')", [owner], |r| r.get::<_, bool>(0))?,
            "Activation authority does not match this storage identity");
        let state = Self {
            version: 1,
            owner: owner.into(),
            current: active,
            sequence: 0,
            current_sequence: 0,
            rollout: None,
        };
        state.save(tx)?;
        Ok(state)
    }
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1 && super::valid_id(&self.owner),
            "Invalid activation journal"
        );
        self.current.validate()?;
        self.current_epoch().validate()?;
        ensure!(
            self.current_sequence <= self.sequence,
            "Invalid current activation sequence"
        );
        if let Some(r) = &self.rollout {
            r.epoch.validate()?;
            r.base_epoch.validate()?;
            r.base.validate()?;
            r.candidate.validate()?;
            ensure!(
                self.sequence == r.epoch.sequence
                    && self.sequence > 0
                    && r.base_epoch.sequence < self.sequence
                    && r.base_epoch == Epoch::new(r.base_epoch.sequence, &r.base)
                    && r.epoch == Epoch::new(self.sequence, &r.candidate)
                    && r.candidate.revision > r.base.revision
                    && (1..=64).contains(&r.participants.len())
                    && r.participants.contains_key(&self.owner)
                    && r.participants.keys().all(|n| super::valid_id(n))
                    && r.started >= 0
                    && r.updated >= r.started,
                "Invalid rollout identity or membership"
            );
            if let Some(previous) = &r.recovery_of {
                previous.validate()?;
                ensure!(
                    previous.sequence < r.epoch.sequence
                        && previous.revision == r.base.revision
                        && previous.digest == r.base.digest
                        && r.phase != Phase::Aborted,
                    "Invalid recovery lineage"
                );
            }
            match r.phase {
                Phase::Preparing | Phase::Aborted => {
                    ensure!(
                        self.current_sequence < self.sequence
                            && self.current_epoch() == r.base_epoch
                            && self.current.digest == r.base.digest
                            && r.participants.values().all(|p| *p != Progress::Applied),
                        "Uncommitted rollout cannot contain an applied acknowledgement"
                    );
                }
                Phase::Committed => ensure!(
                    self.current_sequence == self.sequence
                        && self.current.digest == r.candidate.digest
                        && r.participants.values().all(|p| *p >= Progress::Prepared),
                    "Incomplete commit barrier"
                ),
                Phase::Released => ensure!(
                    self.current_sequence == self.sequence
                        && self.current.digest == r.candidate.digest
                        && r.participants.values().all(|p| *p == Progress::Applied),
                    "Incomplete release barrier"
                ),
            }
        } else {
            ensure!(self.sequence == 0, "Missing activation rollout");
        }
        Ok(())
    }
    fn save(&self, tx: &Transaction<'_>) -> Result<()> {
        self.validate()?;
        let raw = serde_json::to_string(self)?;
        ensure!(raw.len() <= MAX_BYTES, "Activation journal too large");
        // Readers predating coordinated activation must refuse the database on
        // restart rather than ignore a durable fence and accept old-policy mail.
        crate::store::require_format(tx, 6)?;
        tx.execute(
            "INSERT OR REPLACE INTO cluster_state(key,value) VALUES(?1,?2)",
            params![KEY, raw],
        )?;
        Ok(())
    }
    fn load(tx: &Transaction<'_>) -> Result<Self> {
        Self::read(tx)?.ok_or_else(|| anyhow::anyhow!("Activation not initialized"))
    }
    fn checked_rollout(&mut self, epoch: &Epoch, at: i64) -> Result<&mut Rollout> {
        let rollout = self
            .rollout
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("No activation rollout"))?;
        ensure!(
            rollout.epoch == *epoch && at >= rollout.updated,
            "Stale activation operation"
        );
        Ok(rollout)
    }
    pub fn begin(
        tx: &Transaction<'_>,
        candidate: Bundle,
        participants: Vec<String>,
        at: i64,
    ) -> Result<Self> {
        let mut state = Self::load(tx)?;
        ensure!(
            state.released(),
            "Finish or explicitly recover the current activation"
        );
        let mut nodes = BTreeMap::new();
        for id in participants {
            ensure!(
                nodes.insert(id, Progress::Waiting).is_none(),
                "Duplicate activation participant"
            );
        }
        state.start(candidate, nodes, at, None)?;
        state.save(tx)?;
        Ok(state)
    }
    fn start(
        &mut self,
        candidate: Bundle,
        participants: BTreeMap<String, Progress>,
        at: i64,
        recovery_of: Option<Epoch>,
    ) -> Result<()> {
        ensure!(
            at >= self.rollout.as_ref().map_or(0, |r| r.updated),
            "Stale activation clock"
        );
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("Activation sequence exhausted"))?;
        self.rollout = Some(Rollout {
            epoch: Epoch::new(self.sequence, &candidate),
            base_epoch: self.current_epoch(),
            base: self.current.clone(),
            candidate,
            phase: Phase::Preparing,
            participants,
            started: at,
            updated: at,
            recovery_of,
        });
        Ok(())
    }
    /// `node` comes from authenticated node identity, never a JSON claim.
    pub fn acknowledge(
        tx: &Transaction<'_>,
        node: &str,
        ack: &Acknowledgement,
        at: i64,
    ) -> Result<Self> {
        let mut state = Self::load(tx)?;
        let r = state.checked_rollout(&ack.epoch, at)?;
        let previous = r
            .participants
            .get_mut(node)
            .ok_or_else(|| anyhow::anyhow!("Node is not an activation participant"))?;
        ensure!(
            ack.progress != Progress::Waiting && r.phase != Phase::Aborted,
            "Invalid activation acknowledgement"
        );
        ensure!(
            ack.progress != Progress::Applied
                || matches!(r.phase, Phase::Committed | Phase::Released),
            "Cannot apply before durable commit"
        );
        *previous = (*previous).max(ack.progress); // duplicate/late receipts never downgrade readiness
        r.updated = at;
        state.save(tx)?;
        Ok(state)
    }
    /// Caller commits the console revision in this same SQLite transaction.
    pub fn commit(tx: &Transaction<'_>, epoch: &Epoch, at: i64) -> Result<Self> {
        let mut state = Self::load(tx)?;
        let r = state.checked_rollout(epoch, at)?;
        ensure!(
            r.phase != Phase::Aborted && r.participants.values().all(|p| *p >= Progress::Prepared),
            "Every participant must be prepared behind a drained admission fence"
        );
        if r.phase == Phase::Preparing {
            r.phase = Phase::Committed;
        }
        r.updated = at;
        state.current = r.candidate.clone();
        state.current_sequence = epoch.sequence;
        state.save(tx)?;
        Ok(state)
    }
    pub fn release(tx: &Transaction<'_>, epoch: &Epoch, at: i64) -> Result<Self> {
        let mut state = Self::load(tx)?;
        let r = state.checked_rollout(epoch, at)?;
        ensure!(
            matches!(r.phase, Phase::Committed | Phase::Released)
                && r.participants.values().all(|p| *p == Progress::Applied),
            "Every participant must apply before admission resumes"
        );
        r.phase = Phase::Released;
        r.updated = at;
        state.save(tx)?;
        Ok(state)
    }
    pub fn abort(tx: &Transaction<'_>, epoch: &Epoch, at: i64) -> Result<Self> {
        let mut state = Self::load(tx)?;
        let r = state.checked_rollout(epoch, at)?;
        ensure!(
            r.abortable() || r.phase == Phase::Aborted,
            "Committed or recovery activation cannot abort into mixed policies"
        );
        r.phase = Phase::Aborted;
        r.updated = at;
        state.save(tx)?;
        Ok(state)
    }
    /// Recovery of a partially committed activation is another fenced rollout,
    /// never an in-place rewind. The exact previous policy/model set is required.
    pub fn recover_previous(
        tx: &Transaction<'_>,
        epoch: &Epoch,
        rollback: Bundle,
        at: i64,
    ) -> Result<Self> {
        let mut state = Self::load(tx)?;
        let r = state.checked_rollout(epoch, at)?;
        ensure!(
            r.phase == Phase::Committed && r.recovery_of.is_none(),
            "Only an original partially committed rollout can recover its previous policy"
        );
        ensure!(
            serde_json::to_value(&rollback.settings)? == serde_json::to_value(&r.base.settings)?
                && rollback.shared == r.base.shared
                && serde_json::to_value(&rollback.files)? == serde_json::to_value(&r.base.files)?,
            "Recovery must restore the exact previous policy and model bytes"
        );
        let nodes = r
            .participants
            .keys()
            .map(|n| (n.clone(), Progress::Waiting))
            .collect();
        state.start(rollback, nodes, at, Some(epoch.clone()))?;
        state.save(tx)?;
        Ok(state)
    }
}
