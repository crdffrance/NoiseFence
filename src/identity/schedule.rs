//! Explicit, finite background collection grants. No automatic policy activation.
//! Credentials remain in the connection vault; no browser session is retained.
pub(crate) mod local;
mod repository;
use super::{
    connections::{Metadata, Record, Reference},
    sync::{Event, Outcome, Request},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
pub const PROTOCOL: &str = "identity-schedule-1";
pub const MIN_INTERVAL: i64 = 900;
pub const MAX_INTERVAL: i64 = 86400;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub protocol: String,
    pub id: String,
    pub connection: Reference,
    pub created: i64,
    pub expires: i64,
    pub interval_seconds: i64,
}
impl Grant {
    pub fn validate(&self, metadata: &Metadata) -> Result<()> {
        self.connection.validate()?;
        ensure!(
            !matches!(
                metadata.source.provider,
                super::directory::Provider::ActiveDirectory | super::directory::Provider::Scim
            ),
            "Inbound directory credentials cannot authorize remote collection"
        );
        ensure!(
            self.protocol == PROTOCOL
                && uuid(&self.id)
                && self.connection.source_id == metadata.source.id
                && self.connection.generation == metadata.generation
                && self.created >= metadata.created
                && self.expires > self.created
                && self.expires <= metadata.expires
                && (MIN_INTERVAL..=MAX_INTERVAL).contains(&self.interval_seconds),
            "Invalid directory collection grant"
        );
        Ok(())
    }
    pub(crate) fn signed_bytes(&self, metadata: &Metadata) -> Result<Vec<u8>> {
        self.validate(metadata)?;
        // Canonical typed JSON binds every credential/source/owner/authority field.
        let mut data = b"noisefence:directory-schedule-1\0".to_vec();
        data.extend(serde_json::to_vec(&(metadata, self))?);
        Ok(data)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub grant_id: String,
    pub authorization_sha256: String,
}
impl Binding {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            uuid(&self.grant_id) && crate::compatibility::valid_hash(&self.authorization_sha256),
            "Invalid collection grant reference"
        );
        Ok(())
    }
}
fn uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|v| v.to_string() == value)
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Schedule {
    pub grant: Grant,
    pub signature: String,
    pub revoked_at: Option<i64>,
    pub next_due: i64,
    pub failures: u8,
    pub last_run: Option<Run>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Run {
    pub request: Request,
    pub state: RunState,
    pub completed_at: Option<i64>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RunState {
    Running,
    Ready,
    Failed,
}
impl Schedule {
    pub fn validate(&self, metadata: &Metadata) -> Result<()> {
        self.grant.validate(metadata)?;
        ensure!(
            crate::compatibility::valid_hash(&self.signature)
                && self.revoked_at.is_none_or(|t| t >= self.grant.created)
                && self.next_due >= self.grant.created
                && self.failures <= 8,
            "Invalid directory schedule state"
        );
        if let Some(run) = &self.last_run {
            run.request.validate()?;
            ensure!(
                run.request.connection.as_ref() == Some(&self.grant.connection)
                    && run.request.scheduled.as_ref() == Some(&self.binding(metadata)?)
                    && run.request.created >= self.grant.created
                    && run.request.created < self.grant.expires
                    && match run.state {
                        RunState::Running => run.completed_at.is_none(),
                        _ => run.completed_at.is_some_and(|t| t >= run.request.created),
                    },
                "Invalid scheduled collection receipt"
            );
        }
        Ok(())
    }
    pub fn binding(&self, metadata: &Metadata) -> Result<Binding> {
        let mut data = self.grant.signed_bytes(metadata)?;
        data.extend(self.signature.as_bytes());
        Ok(Binding {
            grant_id: self.grant.id.clone(),
            authorization_sha256: crate::message::digest(&data),
        })
    }
    pub fn live(&self, metadata: &Metadata, now: i64) -> Result<()> {
        self.validate(metadata)?;
        ensure!(
            self.revoked_at.is_none() && now >= self.grant.created && now < self.grant.expires,
            "Directory collection grant is revoked or expired"
        );
        Ok(())
    }
    pub fn due(&self, now: i64, revision: i64) -> bool {
        self.revoked_at.is_none()
            && now >= self.grant.created
            && now < self.grant.expires
            && now >= self.next_due
            && self.last_run.as_ref().is_none_or(|r| match r.state {
                RunState::Running => now > r.request.deadline,
                // Do not keep writing unused candidates while review is pending.
                RunState::Ready => revision != r.request.revision,
                RunState::Failed => true,
            })
    }
}
/// Public administrative metadata. No grant signature or credential is exposed.
#[derive(Clone, Debug, Serialize)]
pub struct View {
    pub id: String,
    pub expires: i64,
    pub interval_seconds: i64,
    pub next_due: i64,
    pub revoked_at: Option<i64>,
    pub last_run: Option<Run>,
    pub state: String,
}
impl Schedule {
    pub fn view(&self, now: i64, revision: Option<i64>) -> View {
        let state = if self.revoked_at.is_some() {
            "stopped"
        } else if now >= self.grant.expires {
            "expired"
        } else if now < self.grant.created {
            "not_yet_valid"
        } else if let Some(run) = &self.last_run {
            match run.state {
                RunState::Running if now <= run.request.deadline => "running",
                RunState::Running => "outcome_unknown",
                RunState::Ready if revision.is_none_or(|r| r == run.request.revision) => {
                    "awaiting_review"
                }
                RunState::Failed if now < self.next_due => "backoff",
                _ => "scheduled",
            }
        } else {
            "scheduled"
        };
        View {
            id: self.grant.id.clone(),
            expires: self.grant.expires,
            interval_seconds: self.grant.interval_seconds,
            next_due: self.next_due,
            revoked_at: self.revoked_at,
            last_run: self.last_run.clone(),
            state: state.into(),
        }
    }
}
pub(crate) fn enable(
    record: &mut Record,
    expected: Option<&str>,
    grant: Grant,
    signature: String,
    actor: &str,
    version: i64,
    now: i64,
) -> Result<()> {
    ensure!(
        record.view(now, true).status == "configured"
            && actor == record.metadata.owner
            && version == record.metadata.owner_version,
        "Only the current credential owner may authorize background collection"
    );
    grant.validate(&record.metadata)?;
    ensure!(
        (now - 30..=now + 5).contains(&grant.created) && grant.expires > now,
        "Collection grant lifetime changed"
    );
    if let Some(old) = &record.schedule
        && old.grant.id == grant.id
    {
        ensure!(
            old.grant == grant && old.signature == signature && old.revoked_at.is_none(),
            "Collection grant ID already used"
        );
        return Ok(());
    }
    ensure!(
        record.schedule.as_ref().map(|s| s.grant.id.as_str()) == expected,
        "Collection schedule changed; reload"
    );
    record.schedule = Some(Schedule {
        next_due: grant.created,
        grant,
        signature,
        revoked_at: None,
        failures: 0,
        last_run: None,
    });
    record.validate()
}
pub(crate) fn disable(record: &mut Record, expected: &Binding, now: i64) -> Result<()> {
    let schedule = record.schedule.as_mut().context("No directory schedule")?;
    ensure!(
        &schedule.binding(&record.metadata)? == expected,
        "Collection schedule changed; reload"
    );
    schedule.revoked_at.get_or_insert(now);
    record.validate()
}
pub(crate) fn authorize(record: &Record, request: &Request, now: i64) -> Result<()> {
    request.validate()?;
    ensure!(
        record.view(now, true).status == "configured",
        "Directory credential unavailable"
    );
    let schedule = record.schedule.as_ref().context("No collection grant")?;
    schedule.live(&record.metadata, now)?;
    ensure!(
        request.scheduled.as_ref() == Some(&schedule.binding(&record.metadata)?)
            && request.connection.as_ref() == Some(&schedule.grant.connection)
            && schedule
                .last_run
                .as_ref()
                .is_some_and(|run| run.state == RunState::Running && run.request == *request)
            && now <= request.deadline,
        "Scheduled collection lease changed or expired"
    );
    Ok(())
}
pub(crate) fn claim(record: &mut Record, request: &Request, now: i64) -> Result<()> {
    request.validate()?;
    ensure!(
        record.view(now, true).status == "configured",
        "Directory credential unavailable"
    );
    let schedule = record.schedule.as_mut().context("No collection grant")?;
    schedule.live(&record.metadata, now)?;
    ensure!(
        request.scheduled.as_ref() == Some(&schedule.binding(&record.metadata)?)
            && request.connection.as_ref() == Some(&schedule.grant.connection)
            && schedule.due(now, request.revision),
        "Collection is not due or awaits review"
    );
    schedule.next_due = now
        .checked_add(schedule.grant.interval_seconds)
        .context("Schedule time overflow")?;
    schedule.last_run = Some(Run {
        request: request.clone(),
        state: RunState::Running,
        completed_at: None,
    });
    record.validate()
}
/// Terminal audit always uses the original lease. A replaced grant is not mutated.
pub(crate) fn completed(record: &mut Record, event: &Event, now: i64) -> Result<bool> {
    let Some(schedule) = record.schedule.as_mut() else {
        return Ok(false);
    };
    if event.request.scheduled.as_ref() != Some(&schedule.binding(&record.metadata)?)
        || !schedule
            .last_run
            .as_ref()
            .is_some_and(|r| r.request == event.request && r.state == RunState::Running)
    {
        return Ok(false);
    }
    let state = match event.outcome {
        Outcome::Ready { .. } => RunState::Ready,
        Outcome::Failed { .. } => RunState::Failed,
        Outcome::Running => anyhow::bail!("Expected terminal collection result"),
    };
    if state == RunState::Failed {
        schedule.failures = schedule.failures.saturating_add(1).min(8);
        let delay =
            (schedule.grant.interval_seconds * (1i64 << schedule.failures)).min(MAX_INTERVAL);
        schedule.next_due = now.checked_add(delay).context("Schedule time overflow")?;
    } else {
        schedule.failures = 0;
    }
    schedule.last_run = Some(Run {
        request: event.request.clone(),
        state,
        completed_at: Some(now),
    });
    record.validate()?;
    Ok(true)
}
#[cfg(test)]
mod tests;
