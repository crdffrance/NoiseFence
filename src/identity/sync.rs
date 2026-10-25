//! Durable, bounded synchronization receipts in the selected authority's audit
//! journal. No credentials, tokens or raw provider records are written here.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
pub const ACTION: &str = "identity_sync";
pub const MAX_EVENT_BYTES: usize = 16384;
pub const MAX_EVENTS: usize = 128;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Request {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connection: Option<super::connections::Reference>,
    pub id: String,
    pub source_id: String,
    pub runner: String,
    pub revision: i64,
    pub catalog_sha256: Option<String>,
    pub created: i64,
    pub deadline: i64,
}
impl Request {
    pub fn validate(&self) -> Result<()> {
        if let Some(reference) = &self.connection {
            reference.validate()?;
            ensure!(
                reference.source_id == self.source_id,
                "Directory connection source mismatch"
            );
        }
        ensure!(
            uuid::Uuid::parse_str(&self.id).is_ok()
                && self.id.len() == 36
                && uuid::Uuid::parse_str(&self.runner).is_ok()
                && self.runner.len() == 36,
            "Invalid synchronization ID"
        );
        ensure!(
            super::text(&self.source_id, 100)
                && self.revision >= 0
                && self.created > 0
                && self.deadline > self.created
                && self.deadline <= self.created + 360,
            "Invalid synchronization request"
        );
        ensure!(
            self.catalog_sha256
                .as_deref()
                .is_none_or(crate::compatibility::valid_hash),
            "Invalid source revision"
        );
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum Outcome {
    Running,
    Ready {
        prepared: Box<crate::control::identity::PreparedDirectory>,
    },
    Failed {
        reason: Failure,
    },
}
/// Bounded coverage accounting; no raw provider text or member identifiers.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CollectionSummary {
    pub requests: usize,
    pub pages: usize,
    pub bytes: usize,
    pub excluded_members: BTreeMap<String, usize>,
}
impl CollectionSummary {
    pub fn from_collected(value: &super::connectors::entra::Collected) -> Result<Self> {
        let result = Self {
            requests: value.requests,
            pages: value.pages,
            bytes: value.bytes,
            excluded_members: value.excluded_members.clone(),
        };
        result.validate()?;
        Ok(result)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (1..=10000).contains(&self.requests)
                && self.pages > 0
                && self.pages <= self.requests
                && self.bytes <= 128 * 1024 * 1024,
            "Invalid collection accounting"
        );
        let mut total = 0usize;
        for (kind, count) in &self.excluded_members {
            ensure!(
                matches!(
                    kind.as_str(),
                    "device"
                        | "servicePrincipal"
                        | "orgContact"
                        | "external_membership"
                        | "customer_wide_membership"
                        | "inactive_or_unknown_membership"
                ) && *count > 0,
                "Invalid excluded membership accounting"
            );
            total = total
                .checked_add(*count)
                .context("Excluded membership count overflow")?;
        }
        ensure!(
            total <= super::directory::MAX_MEMBERSHIPS,
            "Excluded membership limit exceeded"
        );
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Failure {
    Collection,
    Stale,
    Preparation,
    Authorization,
    Deadline,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub request: Request,
    pub outcome: Outcome,
}
impl Event {
    pub fn encode(&self) -> Result<String> {
        self.request.validate()?;
        if let Outcome::Ready { prepared } = &self.outcome {
            if let Some(summary) = &prepared.collection {
                summary.validate()?;
                ensure!(
                    summary.excluded_members.is_empty() || prepared.review.requires_attention,
                    "Excluded memberships require review"
                );
            }
            ensure!(
                !prepared.active
                    && prepared.revision == self.request.revision
                    && prepared.selection.reviewed_from == self.request.catalog_sha256
                    && prepared
                        .selection
                        .sha256
                        .as_deref()
                        .is_some_and(crate::compatibility::valid_hash)
                    && prepared.review.source_id == self.request.source_id,
                "Invalid synchronization result"
            );
        }
        let data = format!("{};{}", self.request.id, serde_json::to_string(self)?);
        ensure!(
            data.len() <= MAX_EVENT_BYTES,
            "Synchronization receipt too large"
        );
        Ok(data)
    }
    pub fn decode(raw: &str) -> Result<Self> {
        ensure!(
            raw.len() <= MAX_EVENT_BYTES,
            "Synchronization receipt too large"
        );
        let (id, json) = raw
            .split_once(';')
            .context("Invalid synchronization receipt")?;
        let event: Self = serde_json::from_str(json).context("Invalid synchronization receipt")?;
        ensure!(
            id == event.request.id && event.encode()? == raw,
            "Invalid synchronization receipt"
        );
        Ok(event)
    }
}
/// Input is oldest first from a bounded SELECT. Any truncation fails closed.
pub fn latest(raw: &[String]) -> Result<BTreeMap<String, Event>> {
    ensure!(
        raw.len() <= MAX_EVENTS,
        "Synchronization journal capacity reached"
    );
    let mut jobs = BTreeMap::new();
    for item in raw {
        let event = Event::decode(item)?;
        if let Some(before) = jobs.get(&event.request.id) {
            let before: &Event = before;
            ensure!(
                before.request == event.request
                    && matches!(before.outcome, Outcome::Running)
                    && !matches!(event.outcome, Outcome::Running),
                "Conflicting synchronization receipt"
            );
        } else {
            ensure!(
                matches!(event.outcome, Outcome::Running),
                "Missing synchronization intent"
            );
        }
        jobs.insert(event.request.id.clone(), event);
    }
    Ok(jobs)
}
pub fn admit(raw: &[String], request: &Request, now: i64) -> Result<()> {
    request.validate()?;
    ensure!(
        raw.len() <= MAX_EVENTS,
        "Synchronization journal capacity reached"
    );
    ensure!(
        request.created <= now + 5 && request.created >= now - 30 && request.deadline > now,
        "Synchronization request expired"
    );
    // A completed job may straddle the rolling rate window. Filter both its
    // events by intent time before reconstructing; never treat its tail as an
    // orphaned active job. The query includes the full maximum job lifetime.
    let eligible = raw
        .iter()
        .map(|s| Ok((s, Event::decode(s)?)))
        .collect::<Result<Vec<_>>>()?;
    let eligible: Vec<_> = eligible
        .into_iter()
        .filter(|(_, e)| e.request.created >= now - 3600)
        .map(|(s, _)| s.clone())
        .collect();
    let jobs = latest(&eligible)?;
    ensure!(
        !jobs.contains_key(&request.id),
        "Synchronization already exists"
    );
    ensure!(
        jobs.len() < 20,
        "At most 20 directory synchronizations per hour"
    );
    let active: Vec<_> = jobs
        .values()
        .filter(|e| matches!(e.outcome, Outcome::Running) && e.request.deadline >= now)
        .collect();
    ensure!(
        active.len() < 2
            && active
                .iter()
                .all(|e| e.request.source_id != request.source_id),
        "Directory synchronization already in progress"
    );
    Ok(())
}
pub fn finish(raw: &[String], result: &Event, now: i64) -> Result<()> {
    ensure!(
        !matches!(result.outcome, Outcome::Running),
        "Expected a terminal synchronization receipt"
    );
    let jobs = latest(raw)?;
    let before = jobs
        .get(&result.request.id)
        .context("Missing synchronization intent")?;
    ensure!(
        before.request == result.request && matches!(before.outcome, Outcome::Running),
        "Synchronization already completed or changed"
    );
    ensure!(
        now <= result.request.deadline || matches!(result.outcome, Outcome::Failed { .. }),
        "Synchronization result expired"
    );
    result.encode()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    const NOW: i64 = 1800000000;
    fn request(source: &str) -> Request {
        Request {
            connection: None,
            id: uuid::Uuid::new_v4().to_string(),
            source_id: source.into(),
            runner: uuid::Uuid::new_v4().to_string(),
            revision: 4,
            catalog_sha256: None,
            created: NOW,
            deadline: NOW + 360,
        }
    }
    fn running(r: &Request) -> String {
        Event {
            request: r.clone(),
            outcome: Outcome::Running,
        }
        .encode()
        .unwrap()
    }
    fn failed(r: &Request) -> Event {
        Event {
            request: r.clone(),
            outcome: Outcome::Failed {
                reason: Failure::Collection,
            },
        }
    }
    #[test]
    fn journal_enforces_capacity_source_lease_and_exact_terminal_transition() {
        let a = request("entra");
        let b = request("other");
        let c = request("third");
        admit(&[], &a, NOW).unwrap();
        let mut rows = vec![running(&a)];
        assert!(admit(&rows, &request("entra"), NOW).is_err());
        admit(&rows, &b, NOW).unwrap();
        rows.push(running(&b));
        assert!(admit(&rows, &c, NOW).is_err());
        finish(&rows, &failed(&a), NOW + 5).unwrap();
        rows.push(failed(&a).encode().unwrap());
        admit(&rows, &c, NOW).unwrap();
        assert!(finish(&rows, &failed(&a), NOW + 5).is_err());
        let mut changed = failed(&b);
        changed.request.revision += 1;
        assert!(finish(&rows, &changed, NOW + 5).is_err());
        assert!(latest(&vec![running(&a); MAX_EVENTS + 1]).is_err());
        assert!(Event::decode("invalid").is_err());
    }
    #[test]
    fn expired_and_rolling_window_records_are_not_mistaken_for_live_jobs() {
        let mut old = request("entra");
        old.created = NOW - 3601;
        old.deadline = old.created + 360;
        // Only the completion falls within the rate window, but it cannot create
        // an orphan failure or conceal a live lease.
        admit(&[failed(&old).encode().unwrap()], &request("entra"), NOW).unwrap();
        let mut expired = request("entra");
        expired.created = NOW - 400;
        expired.deadline = NOW - 40;
        admit(&[running(&expired)], &request("entra"), NOW).unwrap();
        let mut rows = vec![];
        for _ in 0..20 {
            let r = request("entra");
            rows.push(running(&r));
            rows.push(failed(&r).encode().unwrap());
        }
        assert!(admit(&rows, &request("entra"), NOW).is_err());
        assert!(finish(&[], &failed(&old), NOW).is_err());
    }
}

/// Request-only credential: never Debug, Serialize or persisted as a job body.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntraInput {
    pub operation: String,
    pub revision: i64,
    pub catalog_sha256: Option<String>,
    pub source: super::directory::Source,
    pub client_id: String,
    pub client_secret: String,
}

/// One-shot scoped OAuth token, never serialized or persisted.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OktaInput {
    pub operation: String,
    pub revision: i64,
    pub catalog_sha256: Option<String>,
    pub source: super::directory::Source,
    pub access_token: String,
}

/// Short-lived Google token, request-only; never persisted or debug formatted.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoogleInput {
    pub operation: String,
    pub revision: i64,
    pub catalog_sha256: Option<String>,
    pub source: super::directory::Source,
    pub access_token: String,
}
