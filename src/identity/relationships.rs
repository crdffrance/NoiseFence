//! Recipient-isolated, expiring contact observations. Frequency is descriptive,
//! never a safe-sender list; explicit human labels remain separate from traffic.
use super::{mailbox, scope};
use anyhow::{Result, ensure};
use ring::hmac;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const MAX_EDGES: usize = 50_000;
const MAX_CAMPAIGNS_PER_EDGE: usize = 100;
const MAX_CAMPAIGNS: usize = 100_000;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Request {
    Payment,
    Credentials,
    Secret,
    SoftwareInstall,
    PersonalData,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Label {
    Unlabelled,
    HumanWanted,
    HumanUnwanted,
    Conflict,
}
impl Label {
    fn merge(self, other: Self) -> Self {
        match (self, other) {
            (Self::Conflict, _) | (_, Self::Conflict) => Self::Conflict,
            (Self::Unlabelled, label) | (label, Self::Unlabelled) => label,
            (a, b) if a == b => a,
            _ => Self::Conflict,
        }
    }
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Inbound,
    Outbound,
}

/// Populated only from trusted SMTP or an explicitly authorized mailbox
/// connector. Quoted headers, References and In-Reply-To cannot supply this.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Provenance {
    SmtpAlignedDkim,
    AuthorizedMailboxMetadata,
}

/// Private HMAC join keys prevent offline mailbox guessing in exported metrics.
/// Key material is installation-managed and never serialized into snapshots.
pub struct Keys(hmac::Key);
impl Keys {
    pub fn new(secret: &[u8]) -> Result<Self> {
        ensure!(
            secret.len() == 32,
            "Relationship key must contain 32 random bytes"
        );
        Ok(Self(hmac::Key::new(hmac::HMAC_SHA256, secret)))
    }
    fn hash(&self, parts: &[&str]) -> String {
        let mut state = hmac::Context::with_key(&self.0);
        for part in parts {
            state.update(&(part.len() as u64).to_be_bytes());
            state.update(part.as_bytes());
        }
        hex::encode(state.sign().as_ref())
    }
    pub fn contact(&self, tenant: &str, recipient: &str, sender: &str) -> Result<Contact> {
        ensure!(scope(tenant), "Invalid relationship scope");
        let recipient = mailbox(recipient)?;
        ensure!(
            recipient.rsplit_once('@').is_some_and(|(_, d)| d == tenant),
            "Recipient outside relationship scope"
        );
        let sender = mailbox(sender)?;
        Ok(Contact {
            scope: self.hash(&["relationship-scope-1", tenant, &recipient]),
            sender: self.hash(&["relationship-sender-1", tenant, &recipient, &sender]),
        })
    }
    pub fn indicator(&self, contact: &Contact, value: &str) -> Result<String> {
        ensure!(
            contact.valid()
                && !value.is_empty()
                && value.len() <= 320
                && !value.chars().any(char::is_control),
            "Invalid relationship indicator"
        );
        Ok(self.hash(&[
            "relationship-indicator-1",
            &contact.scope,
            &contact.sender,
            value,
        ]))
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct Contact {
    scope: String,
    sender: String,
}
impl Contact {
    fn valid(&self) -> bool {
        crate::compatibility::valid_hash(&self.scope)
            && crate::compatibility::valid_hash(&self.sender)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Sample {
    pub contact: Contact,
    /// Content/campaign fingerprint calculated locally, not Message-ID.
    pub campaign: String,
    pub at: i64,
    pub provenance: Provenance,
    pub direction: Direction,
    pub label: Label,
    /// Time of the authorized human correction, distinct from receipt time.
    pub labelled_at: Option<i64>,
    pub reply_to: Option<String>,
    pub link_domains: BTreeSet<String>,
    pub requests: BTreeSet<Request>,
}
impl Sample {
    pub fn validate(&self, now: i64, retention_days: u32) -> Result<()> {
        ensure!(
            (1..=90).contains(&retention_days),
            "Invalid relationship retention"
        );
        ensure!(
            self.contact.valid() && crate::compatibility::valid_hash(&self.campaign),
            "Invalid relationship keys"
        );
        ensure!(
            self.at > 0
                && self.at <= now
                && self.at >= now.saturating_sub(i64::from(retention_days) * 86400),
            "Relationship observation outside retention window"
        );
        ensure!(
            self.reply_to
                .as_ref()
                .is_none_or(|s| crate::compatibility::valid_hash(s))
                && self.link_domains.len() <= 8
                && self
                    .link_domains
                    .iter()
                    .all(|s| crate::compatibility::valid_hash(s)),
            "Invalid relationship indicators"
        );
        ensure!(
            self.direction != Direction::Outbound
                || self.provenance == Provenance::AuthorizedMailboxMetadata,
            "Outbound observation requires authorized mailbox metadata"
        );
        ensure!(
            match self.label {
                Label::Unlabelled => self.labelled_at.is_none(),
                _ => self
                    .labelled_at
                    .is_some_and(|at| at >= self.at && at <= now),
            },
            "Invalid human correction time"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Campaign {
    first: i64,
    last: i64,
    /// Repetition never changes the baseline of a previously recorded campaign.
    sample: Sample,
    conflict: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub status: &'static str,
    pub observation_only: bool,
    pub inbound_campaigns: usize,
    pub outbound_campaigns: usize,
    pub human_wanted_campaigns: usize,
    pub human_unwanted_campaigns: usize,
    pub observed_days: usize,
    pub last_seen_at: Option<i64>,
    pub reciprocal_observed: bool,
    pub new_reply_to: bool,
    pub new_link_domain: bool,
    pub new_sensitive_request: bool,
    pub limited: bool,
}
impl Default for Report {
    fn default() -> Self {
        Self {
            status: "insufficient_history",
            observation_only: true,
            inbound_campaigns: 0,
            outbound_campaigns: 0,
            human_wanted_campaigns: 0,
            human_unwanted_campaigns: 0,
            observed_days: 0,
            last_seen_at: None,
            reciprocal_observed: false,
            new_reply_to: false,
            new_link_domain: false,
            new_sensitive_request: false,
            limited: false,
        }
    }
}

/// Bounded in-memory materialization built outside SMTP from retained metadata.
/// Persistence consumers must apply the same time/provenance validation on load.
pub struct History {
    retention_days: u32,
    edges: BTreeMap<Contact, BTreeMap<(String, u8), Campaign>>,
    /// A capacity failure cannot be interpreted as a complete, empty history.
    limited: bool,
    limited_edges: BTreeMap<Contact, i64>,
    campaigns: usize,
    last_expiry: Option<i64>,
}
impl History {
    pub fn new(retention_days: u32) -> Result<Self> {
        ensure!(
            (1..=90).contains(&retention_days),
            "Invalid relationship retention"
        );
        Ok(Self {
            retention_days,
            edges: BTreeMap::new(),
            limited: false,
            limited_edges: BTreeMap::new(),
            campaigns: 0,
            last_expiry: None,
        })
    }
    pub fn expire(&mut self, now: i64) {
        let cutoff = now.saturating_sub(i64::from(self.retention_days) * 86400);
        self.edges.retain(|_, rows| {
            // The first observation bounds retention even when a campaign floods
            // continuously. Later duplicates cannot keep old context alive.
            rows.retain(|_, row| row.first >= cutoff && row.last <= now);
            !rows.is_empty()
        });
        self.campaigns = self.edges.values().map(BTreeMap::len).sum();
        self.limited_edges
            .retain(|contact, at| *at >= cutoff && self.edges.contains_key(contact));
        self.last_expiry = Some(now);
    }
    pub fn add(&mut self, sample: Sample, now: i64) -> Result<()> {
        sample.validate(now, self.retention_days)?;
        if self
            .last_expiry
            .is_none_or(|at| now < at || now.saturating_sub(at) >= 60)
        {
            self.expire(now);
        }
        if !self.edges.contains_key(&sample.contact) && self.edges.len() >= MAX_EDGES {
            self.limited = true;
            anyhow::bail!("Relationship capacity exceeded");
        }
        let rows = self.edges.entry(sample.contact.clone()).or_default();
        let key = (
            sample.campaign.clone(),
            u8::from(sample.direction == Direction::Outbound),
        );
        if let Some(row) = rows.get_mut(&key) {
            row.sample.label = row.sample.label.merge(sample.label);
            row.sample.labelled_at = row.sample.labelled_at.max(sample.labelled_at);
            row.conflict |= row.sample.reply_to != sample.reply_to
                || row.sample.requests != sample.requests
                || row.sample.link_domains != sample.link_domains;
            row.first = row.first.min(sample.at);
            row.last = row.last.max(sample.at);
        } else {
            if rows.len() >= MAX_CAMPAIGNS_PER_EDGE {
                self.limited_edges.insert(sample.contact.clone(), now);
                anyhow::bail!("Relationship campaign capacity exceeded");
            }
            if self.campaigns >= MAX_CAMPAIGNS {
                self.limited = true;
                anyhow::bail!("Relationship total capacity exceeded");
            }
            self.campaigns += 1;
            rows.insert(
                key,
                Campaign {
                    first: sample.at,
                    last: sample.at,
                    sample,
                    conflict: false,
                },
            );
        }
        Ok(())
    }
    /// Evaluate against strictly earlier campaigns. The current campaign cannot
    /// train its own assessment. No other recipient's contact data is inspected.
    pub fn inspect(&self, current: &Sample, now: i64) -> Report {
        let mut report = Report {
            limited: self.limited || self.limited_edges.contains_key(&current.contact),
            ..Default::default()
        };
        if current.validate(now, self.retention_days).is_err() {
            report.status = "unavailable";
            return report;
        }
        let Some(rows) = self.edges.get(&current.contact) else {
            return report;
        };
        let cutoff = current
            .at
            .saturating_sub(i64::from(self.retention_days) * 86400);
        let mut days = BTreeSet::new();
        let mut replies = BTreeSet::new();
        let mut links = BTreeSet::new();
        let mut requests = BTreeSet::new();
        for row in rows.values() {
            if row.first < cutoff
                || row.last >= current.at
                || row.sample.campaign == current.campaign
            {
                continue;
            }
            report.last_seen_at = Some(report.last_seen_at.map_or(row.last, |at| at.max(row.last)));
            if row.sample.direction == Direction::Inbound {
                report.inbound_campaigns += 1;
            } else {
                report.outbound_campaigns += 1;
            }
            if row.conflict
                || row.sample.label == Label::Conflict
                || row.sample.labelled_at.is_some_and(|at| at >= current.at)
            {
                continue;
            }
            if row.sample.label == Label::HumanUnwanted {
                report.human_unwanted_campaigns += 1;
                continue;
            }
            // Only explicitly wanted, earlier INBOUND campaigns establish the
            // sensitive-request baseline. Reciprocity is a separate observation.
            if row.sample.label != Label::HumanWanted || row.sample.direction != Direction::Inbound
            {
                continue;
            }
            report.human_wanted_campaigns += 1;
            days.insert(row.first / 86400);
            replies.extend(row.sample.reply_to.iter().cloned());
            links.extend(row.sample.link_domains.iter().cloned());
            requests.extend(row.sample.requests.iter().cloned());
        }
        report.observed_days = days.len();
        report.reciprocal_observed = report.inbound_campaigns > 0 && report.outbound_campaigns > 0;
        if report.limited {
            report.status = "limited";
            return report;
        }
        if report.human_wanted_campaigns >= 5
            && days.len() >= 3
            && report.human_unwanted_campaigns == 0
        {
            report.status = "complete";
            report.new_reply_to = current
                .reply_to
                .as_ref()
                .is_some_and(|r| !replies.contains(r));
            report.new_link_domain = current.link_domains.iter().any(|l| !links.contains(l));
            report.new_sensitive_request = current.requests.iter().any(|r| !requests.contains(r));
        }
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const NOW: i64 = 1_800_000_000;
    fn sample(keys: &Keys, recipient: &str, index: usize, label: Label) -> Sample {
        Sample {
            contact: keys
                .contact("example.test", recipient, "supplier@external.test")
                .unwrap(),
            campaign: crate::message::digest(format!("campaign-{index}").as_bytes()),
            at: NOW - ((index + 1) * 86400) as i64,
            provenance: Provenance::SmtpAlignedDkim,
            direction: Direction::Inbound,
            label,
            labelled_at: (label != Label::Unlabelled).then_some(NOW - ((index + 1) * 86400) as i64),
            reply_to: None,
            link_domains: BTreeSet::new(),
            requests: BTreeSet::new(),
        }
    }
    fn current(keys: &Keys, recipient: &str) -> Sample {
        let mut s = sample(keys, recipient, 99, Label::Unlabelled);
        s.at = NOW;
        s.requests.insert(Request::Payment);
        s
    }
    #[test]
    fn repetition_and_unlabelled_traffic_never_establish_trust() {
        let keys = Keys::new(&[42; 32]).unwrap();
        let mut history = History::new(30).unwrap();
        for i in 0..25 {
            history
                .add(
                    sample(&keys, "alice@example.test", i, Label::Unlabelled),
                    NOW,
                )
                .unwrap();
        }
        let report = history.inspect(&current(&keys, "alice@example.test"), NOW);
        assert_eq!(report.inbound_campaigns, 25);
        assert_eq!(report.human_wanted_campaigns, 0);
        assert!(!report.new_sensitive_request);
        let mut history = History::new(30).unwrap();
        for i in 0..25 {
            let mut s = sample(&keys, "alice@example.test", 0, Label::HumanWanted);
            s.at -= i * 86400;
            history.add(s, NOW).unwrap();
        }
        let report = history.inspect(&current(&keys, "alice@example.test"), NOW);
        assert_eq!(report.human_wanted_campaigns, 1);
        assert_eq!(report.status, "insufficient_history");
    }
    #[test]
    fn scoped_keys_hide_recipients_and_do_not_merge_tenants_or_aliases() {
        let keys = Keys::new(&[42; 32]).unwrap();
        let mut history = History::new(30).unwrap();
        for i in 0..6 {
            history
                .add(
                    sample(&keys, "alice@example.test", i, Label::HumanWanted),
                    NOW,
                )
                .unwrap();
        }
        let alice = current(&keys, "alice@example.test");
        let report = history.inspect(&alice, NOW);
        assert_eq!(report.status, "complete");
        assert!(report.new_sensitive_request);
        assert!(report.observation_only);
        let bob = current(&keys, "bob@example.test");
        assert_eq!(history.inspect(&bob, NOW).human_wanted_campaigns, 0);
        assert!(!serde_json::to_string(&alice).unwrap().contains("alice"));
        assert_ne!(
            alice.contact,
            keys.contact("other.test", "alice@other.test", "supplier@external.test")
                .unwrap()
        );
        assert_ne!(
            alice.contact,
            Keys::new(&[43; 32])
                .unwrap()
                .contact(
                    "example.test",
                    "alice@example.test",
                    "supplier@external.test"
                )
                .unwrap()
        );
        assert!(
            keys.contact("other.test", "alice@example.test", "supplier@external.test")
                .is_err()
        );
    }
    #[test]
    fn contradictory_labels_and_campaign_payloads_are_not_safe_history() {
        let keys = Keys::new(&[42; 32]).unwrap();
        let mut history = History::new(30).unwrap();
        for i in 0..5 {
            history
                .add(
                    sample(&keys, "alice@example.test", i, Label::HumanWanted),
                    NOW,
                )
                .unwrap();
        }
        let mut s = sample(&keys, "alice@example.test", 0, Label::HumanUnwanted);
        history.add(s.clone(), NOW).unwrap();
        assert_eq!(
            history
                .inspect(&current(&keys, "alice@example.test"), NOW)
                .human_wanted_campaigns,
            4
        );
        s = sample(&keys, "alice@example.test", 1, Label::HumanWanted);
        s.requests.insert(Request::Credentials);
        history.add(s, NOW).unwrap();
        let r = history.inspect(&current(&keys, "alice@example.test"), NOW);
        assert_eq!(r.human_wanted_campaigns, 3);
        assert!(!r.new_sensitive_request);
    }
    #[test]
    fn future_self_and_expired_observations_cannot_train_current_message() {
        let keys = Keys::new(&[42; 32]).unwrap();
        let mut history = History::new(30).unwrap();
        for i in 0..5 {
            history
                .add(
                    sample(&keys, "alice@example.test", i, Label::HumanWanted),
                    NOW,
                )
                .unwrap();
        }
        let mut current = current(&keys, "alice@example.test");
        current.campaign = crate::message::digest(b"campaign-0");
        assert_eq!(history.inspect(&current, NOW).human_wanted_campaigns, 4);
        let mut future = current.clone();
        future.at = NOW + 1;
        assert!(history.add(future, NOW).is_err());
        current.at = NOW - 10 * 86400;
        assert_eq!(history.inspect(&current, NOW).inbound_campaigns, 0);
        history.expire(NOW + 31 * 86400);
        current.at = NOW + 31 * 86400;
        assert_eq!(history.inspect(&current, current.at).inbound_campaigns, 0);
    }
    #[test]
    fn reciprocity_requires_observed_outbound_metadata() {
        let keys = Keys::new(&[42; 32]).unwrap();
        let mut history = History::new(30).unwrap();
        let inbound = sample(&keys, "alice@example.test", 0, Label::Unlabelled);
        history.add(inbound.clone(), NOW).unwrap();
        let mut outbound = inbound;
        outbound.direction = Direction::Outbound;
        assert!(history.add(outbound.clone(), NOW).is_err());
        outbound.provenance = Provenance::AuthorizedMailboxMetadata;
        history.add(outbound, NOW).unwrap();
        let report = history.inspect(&current(&keys, "alice@example.test"), NOW);
        assert!(report.reciprocal_observed);
        assert_eq!(report.human_wanted_campaigns, 0);
    }
}

#[cfg(test)]
mod temporal_capacity_tests {
    use super::*;
    const NOW: i64 = 1_800_000_000;
    fn sample(keys: &Keys, who: &str, i: usize) -> Sample {
        Sample {
            contact: keys
                .contact("example.test", who, "sender@external.test")
                .unwrap(),
            campaign: crate::message::digest(format!("different-{i}").as_bytes()),
            at: NOW - 10 * 86400 + i as i64 * 60,
            provenance: Provenance::SmtpAlignedDkim,
            direction: Direction::Inbound,
            label: Label::HumanWanted,
            labelled_at: Some(NOW - 1),
            reply_to: None,
            link_domains: BTreeSet::new(),
            requests: BTreeSet::new(),
        }
    }
    #[test]
    fn corrections_made_later_are_not_available_to_historical_evaluation() {
        let keys = Keys::new(&[42; 32]).unwrap();
        let mut history = History::new(30).unwrap();
        for i in 0..5 {
            history
                .add(sample(&keys, "alice@example.test", i), NOW)
                .unwrap();
        }
        let mut current = sample(&keys, "alice@example.test", 100);
        current.at = NOW - 3600;
        current.label = Label::Unlabelled;
        current.labelled_at = None;
        let report = history.inspect(&current, NOW);
        assert_eq!(report.inbound_campaigns, 5);
        assert_eq!(report.human_wanted_campaigns, 0);
    }
    #[test]
    fn per_contact_capacity_does_not_disable_other_recipient_history() {
        let keys = Keys::new(&[42; 32]).unwrap();
        let mut history = History::new(30).unwrap();
        for i in 0..100 {
            history
                .add(sample(&keys, "alice@example.test", i), NOW)
                .unwrap();
        }
        assert!(
            history
                .add(sample(&keys, "alice@example.test", 101), NOW)
                .is_err()
        );
        for i in 0..5 {
            let mut s = sample(&keys, "bob@example.test", i);
            s.at -= i as i64 * 86400;
            history.add(s, NOW).unwrap();
        }
        let mut current = sample(&keys, "bob@example.test", 100);
        current.at = NOW;
        current.label = Label::Unlabelled;
        current.labelled_at = None;
        let report = history.inspect(&current, NOW);
        assert_eq!(report.status, "complete");
        assert!(!report.limited);
        current.contact = keys
            .contact("example.test", "alice@example.test", "sender@external.test")
            .unwrap();
        assert_eq!(history.inspect(&current, NOW).status, "limited");
    }
}
