//! Automatic recipient-scoped observations from accepted messages. Frequency is
//! descriptive: no predicted or Rspamd verdict becomes a human training label.
use crate::{
    engine::Scan,
    evidence::{AuthResult, Source, State},
    message::digest,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::{Arc, OnceLock},
    time::Duration,
};

pub const PROTOCOL: &str = "contact-learning-1";
pub const MAX_ROWS: usize = 2000;
pub const MAX_SNAPSHOT_ROWS: usize = 10000;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub enabled: bool,
    pub retention_days: u32,
    pub minimum_campaigns: usize,
    pub minimum_days: usize,
    /// Server receipt timestamps, never message Date headers.
    pub learn_since: i64,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            enabled: true,
            retention_days: 30,
            minimum_campaigns: 5,
            minimum_days: 3,
            learn_since: 0,
        }
    }
}
impl Settings {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (7..=30).contains(&self.retention_days),
            "Contact memory must retain 7 to 30 days"
        );
        ensure!(
            (5..=60).contains(&self.minimum_campaigns)
                && self.minimum_campaigns <= 2 * self.retention_days as usize,
            "Contact memory requires 5 to 60 distinct campaigns, within the two-per-day retention capacity"
        );
        ensure!(
            (3..=14).contains(&self.minimum_days)
                && self.minimum_days <= self.retention_days as usize,
            "Contact memory requires 3 to 14 observation days within retention"
        );
        ensure!(
            self.learn_since >= 0 && self.learn_since <= crate::now() + 5,
            "Invalid contact memory start time"
        );
        Ok(())
    }
}
/// Private, domain-separated fingerprints, NOT anonymization or secret HMACs.
/// Never exported by the message API. Exact local parts remain distinct.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Sample {
    pub protocol: String,
    pub key: String,
    pub campaign: String,
    pub name: Option<String>,
    pub reply: String,
    pub links: BTreeSet<String>,
    pub requests: BTreeSet<String>,
    pub content_complete: bool,
    pub content_policy: Option<String>,
}
impl Sample {
    pub fn valid(&self) -> bool {
        let hash = crate::compatibility::valid_hash;
        self.protocol == PROTOCOL
            && hash(&self.key)
            && hash(&self.campaign)
            && self.name.as_deref().is_none_or(hash)
            && hash(&self.reply)
            && self.content_policy.as_deref().is_none_or(hash)
            && (!self.content_complete || self.content_policy.is_some())
            && self.links.len() <= 8
            && self.links.iter().all(|s| hash(s))
            && self.requests.iter().all(|s| {
                [
                    "NF_CREDENTIALS",
                    "NF_FINANCIAL",
                    "NF_WALLET_SECRET",
                    "NF_FORM",
                ]
                .contains(&s.as_str())
            })
    }
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Alignment {
    Verified,
    NotVerified,
    Unavailable,
}
fn alignment(scan: &Scan) -> Alignment {
    match scan.evidence.as_ref() {
        Some(e)
            if e.source == Source::SmtpSession
                && e.authentication.dmarc_state == State::Complete =>
        {
            match e.authentication.dmarc_dkim {
                Some(AuthResult::Pass) => Alignment::Verified,
                Some(
                    AuthResult::Fail
                    | AuthResult::None
                    | AuthResult::Neutral
                    | AuthResult::SoftFail,
                ) => Alignment::NotVerified,
                _ => Alignment::Unavailable,
            }
        }
        _ => Alignment::Unavailable,
    }
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    /// Historical recurrence and current-message eligibility are separate facts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub learning_eligible: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dkim_alignment: Option<Alignment>,
    pub status: String,
    pub observation_only: bool,
    pub regular: bool,
    pub campaigns: usize,
    pub observed_days: usize,
    pub last_seen_at: Option<i64>,
    pub retention_days: u32,
    pub minimum_campaigns: usize,
    pub minimum_days: usize,
    pub blocked_by_feedback: bool,
    pub content_comparison_available: bool,
    pub changes: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub report: Report,
    pub sample: Option<Sample>,
}
pub type Reports = BTreeMap<String, Observation>;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Row {
    pub created: i64,
    pub sample: Sample,
    pub unwanted_at: Option<i64>,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub rows: Vec<Row>,
    pub limited: bool,
}
impl Snapshot {
    pub fn validate(&self, now: i64) -> Result<()> {
        ensure!(
            self.rows.len() <= MAX_SNAPSHOT_ROWS,
            "Contact snapshot exceeds capacity"
        );
        ensure!(
            self.rows.iter().all(|r| r.created > 0
                && r.created <= now + 5
                && r.created >= now - 30 * 86400
                && r.sample.valid()
                && r.unwanted_at
                    .is_none_or(|at| at >= r.created && at <= now + 5)),
            "Invalid contact snapshot"
        );
        Ok(())
    }
}
fn hash(parts: &[&str]) -> String {
    // Length framing prevents ambiguous concatenations. These fingerprints are
    // pseudonymous private metadata, not protection against dictionary attacks.
    digest(&serde_json::to_vec(parts).expect("contact fingerprint"))
}
fn base(settings: &Settings, status: &str) -> Report {
    Report {
        status: status.into(),
        observation_only: true,
        retention_days: settings.retention_days,
        minimum_campaigns: settings.minimum_campaigns,
        minimum_days: settings.minimum_days,
        ..Default::default()
    }
}
pub fn capture(
    raw: &[u8],
    scan: &Scan,
    recipient: &str,
    targets: &crate::protection::Targets,
) -> Option<Sample> {
    if alignment(scan) != Alignment::Verified
        || scan.antivirus.status == crate::antivirus::AntivirusStatus::Malware
    {
        return None;
    }
    comparison_sample(raw, scan, recipient, targets)
}
/// A claimed address can be compared with authenticated history even when the
/// current message fails authentication. This sample must never be persisted
/// unless it independently passes capture()'s learning eligibility requirements.
fn comparison_sample(
    raw: &[u8],
    scan: &Scan,
    recipient: &str,
    targets: &crate::protection::Targets,
) -> Option<Sample> {
    let evidence = scan.evidence.as_ref()?;
    if raw.len() > 2 * 1024 * 1024
        || !scan.features_complete.unwrap_or(false)
        || evidence.source != Source::SmtpSession
        || !crate::compatibility::valid_hash(&scan.fingerprint)
    {
        return None;
    }
    let parsed = mail_parser::MessageParser::default().parse(raw)?;
    if parsed.header_values(mail_parser::HeaderName::From).count() != 1
        || parsed
            .header_values(mail_parser::HeaderName::ReplyTo)
            .count()
            > 1
    {
        return None;
    }
    let from = parsed.from().filter(|v| v.iter().count() == 1)?.first()?;
    let address = super::mailbox(from.address()?).ok()?;
    let recipient = super::mailbox(recipient).ok()?;
    let domain = recipient.rsplit_once('@')?.1;
    let key = hash(&[PROTOCOL, domain, &recipient, &address]);
    let reply = match parsed.reply_to() {
        Some(v) => {
            if v.iter().count() != 1 {
                return None;
            }
            super::mailbox(v.first()?.address()?).ok()?
        }
        None => address,
    };
    let mut sample = Sample {
        protocol: PROTOCOL.into(),
        key: key.clone(),
        campaign: scan.fingerprint.clone(),
        name: from
            .name()
            .and_then(super::name_key)
            .map(|name| hash(&[&key, "name", &name])),
        reply: hash(&[&key, "reply", &reply]),
        links: BTreeSet::new(),
        requests: BTreeSet::new(),
        content_complete: false,
        content_policy: None,
    };
    if let Some(native) = scan
        .native_filter
        .as_ref()
        .filter(|n| n.report.status == crate::native_filter::Status::Complete)
        && !targets.urls_truncated
        && targets.urls.len() <= 8
        && scan
            .protection
            .as_ref()
            .is_some_and(|p| p.local_status == crate::protection::Status::Complete)
    {
        sample.content_complete = true;
        sample.content_policy = Some(native.report.policy_sha256.clone());
        for value in &targets.urls {
            let Some(host) = reqwest::Url::parse(value)
                .ok()
                .and_then(|u| u.host_str().map(str::to_owned))
            else {
                sample.content_complete = false;
                continue;
            };
            sample
                .links
                .insert(hash(&[&key, "link", &host.to_ascii_lowercase()]));
        }
        sample.requests = native
            .local_symbols
            .iter()
            .filter(|s| {
                [
                    "NF_CREDENTIALS",
                    "NF_FINANCIAL",
                    "NF_WALLET_SECRET",
                    "NF_FORM",
                ]
                .contains(&s.id.as_str())
            })
            .map(|s| s.id.clone())
            .collect();
    }
    sample.valid().then_some(sample)
}

pub fn assess(
    settings: &Settings,
    current: &Sample,
    rows: &[Row],
    limited: bool,
    at: i64,
) -> Report {
    let mut report = base(settings, "learning");
    if !current.valid() {
        report.status = "ineligible".into();
        return report;
    }
    if limited {
        report.status = "limited".into();
        return report;
    }
    let cutoff = (at - i64::from(settings.retention_days) * 86400).max(settings.learn_since);
    let mut campaigns: BTreeMap<&str, Vec<&Row>> = BTreeMap::new();
    for row in rows.iter().filter(|r| {
        r.sample.key == current.key && r.created < at && r.created >= cutoff && r.sample.valid()
    }) {
        // A later human rejection also vetoes an earlier regularity pattern.
        report.blocked_by_feedback |= row.unwanted_at.is_some_and(|t| t < at);
        if row.sample.campaign != current.campaign {
            campaigns.entry(&row.sample.campaign).or_default().push(row);
        }
    }
    let mut days: BTreeMap<i64, usize> = BTreeMap::new();
    let mut names: BTreeMap<&str, BTreeSet<i64>> = BTreeMap::new();
    let mut replies: BTreeMap<&str, BTreeSet<i64>> = BTreeMap::new();
    let mut links: BTreeMap<&str, BTreeSet<i64>> = BTreeMap::new();
    let mut requests: BTreeMap<&str, BTreeSet<i64>> = BTreeMap::new();
    let mut content_days = BTreeSet::new();
    let mut earliest = at;
    let mut latest = 0;
    // Stable chronological order makes the two-per-day cap independent of hashes.
    let mut unique: Vec<_> = campaigns
        .values()
        .filter_map(|copies| {
            let first = *copies.iter().min_by_key(|r| r.created)?;
            (!copies
                .iter()
                .any(|r| r.unwanted_at.is_some_and(|t| t < at) || r.sample != first.sample))
            .then_some(first)
        })
        .collect();
    unique.sort_by_key(|r| (r.created, &r.sample.campaign));
    for row in unique {
        let day = row.created / 86400;
        let count = days.entry(day).or_default();
        if *count >= 2 {
            continue;
        }
        *count += 1;
        report.campaigns += 1;
        earliest = earliest.min(row.created);
        latest = latest.max(row.created);
        if let Some(name) = &row.sample.name {
            names.entry(name).or_default().insert(day);
        }
        replies.entry(&row.sample.reply).or_default().insert(day);
        if row.sample.content_complete && row.sample.content_policy == current.content_policy {
            content_days.insert(day);
            for link in &row.sample.links {
                links.entry(link).or_default().insert(day);
            }
            for request in &row.sample.requests {
                requests.entry(request).or_default().insert(day);
            }
        }
    }
    report.observed_days = days.len();
    report.last_seen_at = (latest > 0).then_some(latest);
    report.regular = !report.blocked_by_feedback
        && report.campaigns >= settings.minimum_campaigns
        && report.observed_days >= settings.minimum_days
        && latest - earliest >= (settings.minimum_days as i64 - 1) * 86400;
    if report.blocked_by_feedback {
        report.status = "human_rejected".into();
    }
    if !report.regular {
        return report;
    }
    report.status = "regular".into();
    let changed = |known: &BTreeMap<&str, BTreeSet<i64>>, value: &str| {
        known.values().any(|days| days.len() >= 2)
            && known.get(value).is_none_or(|days| days.len() < 2)
    };
    if let Some(name) = &current.name
        && changed(&names, name)
    {
        report.changes.push("display_name".into());
    }
    if changed(&replies, &current.reply) {
        report.changes.push("reply_destination".into());
    }
    report.content_comparison_available =
        current.content_complete && content_days.len() >= settings.minimum_days;
    if report.content_comparison_available {
        if current
            .links
            .iter()
            .any(|s| links.get(s.as_str()).is_none_or(|days| days.len() < 2))
        {
            report.changes.push("link_domain".into());
        }
        if current
            .requests
            .iter()
            .any(|s| requests.get(s.as_str()).is_none_or(|days| days.len() < 2))
        {
            report.changes.push("sensitive_request".into());
        }
    }
    report
}

/// Reuse the selected, short-lived runtime cache on central installations. Never
/// fall back to a stale local database when the authority/cache is unavailable.
fn read(
    root: &Path,
    keys: &[String],
    cutoff: i64,
    at: i64,
    interrupt: tokio::sync::oneshot::Sender<rusqlite::InterruptHandle>,
) -> Result<(Vec<Row>, bool)> {
    let db = crate::runtime_history::open(root)?;
    db.busy_timeout(Duration::from_millis(30))?;
    ensure!(
        interrupt.send(db.get_interrupt_handle()).is_ok(),
        "Contact lookup cancelled"
    );
    let cache: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='snapshot')",
        [],
        |r| r.get(0),
    )?;
    let slots = (3..3 + keys.len())
        .map(|i| format!("?{i}"))
        .collect::<Vec<_>>()
        .join(",");
    let (sql, limited) = if cache {
        let (available, limited): (bool, bool) = db.query_row(
            "SELECT available,limited FROM contact_coverage WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        ensure!(available, "Contact runtime history unavailable");
        (
            format!(
                "SELECT created,sample,unwanted_at FROM automatic_contacts WHERE created>=?1 AND created<?2 AND contact_key IN ({slots}) ORDER BY created DESC LIMIT 2001"
            ),
            limited,
        )
    } else {
        (
            format!(
                "SELECT m.created,json_extract(m.scan,'$.contact_learning.sample'),(SELECT MIN(f.created) FROM training_feedback f JOIN users u ON u.username=f.username WHERE f.message_id=m.id AND f.spam=1 AND f.created<?2 AND u.disabled=0 AND EXISTS(SELECT 1 FROM deliveries d JOIN console_access a ON a.delivery_id=d.id WHERE d.message_id=m.id AND a.username=f.username)) FROM messages m WHERE m.is_dsn=0 AND m.created>=?1 AND m.created<?2 AND json_extract(m.scan,'$.contact_learning.sample.key') IN ({slots}) ORDER BY m.created DESC LIMIT 2001"
            ),
            false,
        )
    };
    let mut params: Vec<rusqlite::types::Value> = vec![cutoff.into(), at.into()];
    params.extend(keys.iter().cloned().map(Into::into));
    let mut query = db.prepare(&sql)?;
    let mut cursor = query.query(rusqlite::params_from_iter(params))?;
    let mut rows = Vec::new();
    while let Some(row) = cursor.next()? {
        if rows.len() == MAX_ROWS {
            return Ok((rows, true));
        }
        let raw: String = row.get(1)?;
        ensure!(raw.len() <= 4096, "Oversized contact observation");
        let sample: Sample = serde_json::from_str(&raw)?;
        ensure!(sample.valid(), "Invalid retained contact observation");
        rows.push(Row {
            created: row.get(0)?,
            sample,
            unwanted_at: row.get(2)?,
        });
    }
    Ok((rows, limited))
}

pub async fn prepare(
    root: &Path,
    settings: &Settings,
    raw: &[u8],
    scan: &Scan,
    recipients: &[crate::config::Recipient],
    targets: &crate::protection::Targets,
    envelope_sender: &str,
) -> Reports {
    if !settings.enabled {
        return Reports::new();
    }
    let current: BTreeMap<_, _> = recipients
        .iter()
        .filter_map(|r| {
            (!envelope_sender.is_empty())
                .then(|| comparison_sample(raw, scan, &r.address, targets))
                .flatten()
                .map(|sample| (r.address.clone(), sample))
        })
        .collect();
    let current_alignment = alignment(scan);
    let may_learn = current_alignment == Alignment::Verified
        && scan.antivirus.status != crate::antivirus::AntivirusStatus::Malware;
    let mut reports: Reports = recipients
        .iter()
        .map(|r| {
            let comparison = current.get(&r.address);
            let sample = comparison.filter(|_| may_learn).cloned();
            let mut report = base(
                settings,
                if comparison.is_some() {
                    "unavailable"
                } else {
                    "ineligible"
                },
            );
            report.learning_eligible = Some(sample.is_some());
            report.dkim_alignment = Some(current_alignment);
            (r.address.clone(), Observation { report, sample })
        })
        .collect();
    let keys: Vec<_> = current.values().map(|s| s.key.clone()).collect();
    if keys.is_empty() || keys.len() > 100 {
        return reports;
    }
    static CAPACITY: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
    let Ok(permit) = CAPACITY
        .get_or_init(|| Arc::new(tokio::sync::Semaphore::new(4)))
        .clone()
        .try_acquire_owned()
    else {
        return reports;
    };
    let root = root.to_owned();
    let at = crate::now();
    let cutoff = (at - i64::from(settings.retention_days) * 86400).max(settings.learn_since);
    let (send, receive) = tokio::sync::oneshot::channel();
    let task = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        read(&root, &keys, cutoff, at, send)
    });
    struct Interrupt(Option<rusqlite::InterruptHandle>);
    impl Drop for Interrupt {
        fn drop(&mut self) {
            if let Some(h) = &self.0 {
                h.interrupt();
            }
        }
    }
    let work = async {
        let _interrupt = Interrupt(receive.await.ok());
        task.await
    };
    if let Ok(Ok(Ok((rows, limited)))) =
        tokio::time::timeout(Duration::from_millis(200), work).await
    {
        for (recipient, observation) in &mut reports {
            if let Some(current) = current.get(recipient) {
                let mut report = assess(settings, current, &rows, limited, at);
                report.learning_eligible = observation.report.learning_eligible;
                report.dkim_alignment = Some(current_alignment);
                if report.regular && current_alignment == Alignment::NotVerified {
                    report.changes.insert(0, "dkim_alignment".into());
                }
                observation.report = report;
            }
        }
    }
    reports
}

#[cfg(test)]
mod tests {
    use super::*;
    const NOW: i64 = 1_800_000_000;
    fn sample(campaign: &str) -> Sample {
        Sample {
            protocol: PROTOCOL.into(),
            key: digest(b"alice:supplier"),
            campaign: digest(campaign.as_bytes()),
            name: Some(digest(b"Supplier")),
            reply: digest(b"supplier"),
            links: [digest(b"known.test")].into(),
            requests: ["NF_FINANCIAL".into()].into(),
            content_complete: true,
            content_policy: Some(digest(b"native-policy")),
        }
    }
    fn rows() -> Vec<Row> {
        (1..=6)
            .map(|day| Row {
                created: NOW - day * 86400,
                sample: sample(&format!("campaign {day}")),
                unwanted_at: None,
            })
            .collect()
    }
    #[test]
    fn learns_without_labels_but_does_not_grant_trust() {
        let result = assess(&Settings::default(), &sample("today"), &rows(), false, NOW);
        assert!(result.regular && result.observation_only);
        assert_eq!((result.campaigns, result.observed_days), (6, 6));
        assert!(result.changes.is_empty());
        assert!(result.content_comparison_available);
    }
    #[test]
    fn duplicates_floods_future_rows_and_current_campaign_do_not_manufacture_regularity() {
        let mut duplicate = rows();
        for r in &mut duplicate {
            r.sample.campaign = digest(b"one");
        }
        assert_eq!(
            assess(
                &Settings::default(),
                &sample("today"),
                &duplicate,
                false,
                NOW
            )
            .campaigns,
            1
        );
        let mut flood = rows();
        for row in &mut flood {
            row.created = NOW - 100;
        }
        let report = assess(&Settings::default(), &sample("today"), &flood, false, NOW);
        assert_eq!(report.campaigns, 2);
        assert!(!report.regular);
        let mut future = rows();
        for row in &mut future {
            row.created = NOW + 1;
        }
        assert_eq!(
            assess(&Settings::default(), &sample("today"), &future, false, NOW).campaigns,
            0
        );
        for row in &mut duplicate {
            row.sample.campaign = sample("today").campaign;
        }
        assert_eq!(
            assess(
                &Settings::default(),
                &sample("today"),
                &duplicate,
                false,
                NOW
            )
            .campaigns,
            0
        );
    }
    #[test]
    fn known_contacts_still_report_changed_identity_and_sensitive_requests() {
        let mut current = sample("today");
        current.name = Some(digest(b"different name"));
        current.reply = digest(b"attacker");
        current.links.insert(digest(b"new.test"));
        current.requests.insert("NF_CREDENTIALS".into());
        let result = assess(&Settings::default(), &current, &rows(), false, NOW);
        assert!(result.regular);
        assert_eq!(
            result.changes,
            vec![
                "display_name",
                "reply_destination",
                "link_domain",
                "sensitive_request"
            ]
        );
        // One poisoned campaign cannot silently establish a new reply baseline.
        let mut history = rows();
        history[0].sample.reply = current.reply.clone();
        assert!(
            assess(&Settings::default(), &current, &history, false, NOW)
                .changes
                .contains(&"reply_destination".into())
        );
    }
    #[test]
    fn feedback_expiry_reset_partial_history_and_recipient_boundaries() {
        let mut history = rows();
        history[0].unwanted_at = Some(NOW - 10);
        let current = sample("today");
        let rejected = assess(&Settings::default(), &current, &history, false, NOW);
        assert!(!rejected.regular && rejected.blocked_by_feedback);
        history[0].unwanted_at = Some(NOW + 10);
        assert!(assess(&Settings::default(), &current, &history, false, NOW).regular);
        let partial = assess(&Settings::default(), &current, &history, true, NOW);
        assert_eq!(partial.status, "limited");
        assert!(!partial.regular);
        let expired = assess(
            &Settings::default(),
            &current,
            &history,
            false,
            NOW + 31 * 86400,
        );
        assert_eq!(expired.campaigns, 0);
        let reset = Settings {
            learn_since: NOW - 100,
            ..Default::default()
        };
        assert_eq!(assess(&reset, &current, &history, false, NOW).campaigns, 0);
        let other = Sample {
            key: digest(b"bob:supplier"),
            ..current
        };
        assert_eq!(
            assess(&Settings::default(), &other, &history, false, NOW).campaigns,
            0
        );
    }
    #[test]
    fn conflicting_copies_and_missing_content_cannot_build_complete_baselines() {
        let mut changed_policy = sample("today");
        changed_policy.content_policy = Some(digest(b"new-policy"));
        let changed = assess(&Settings::default(), &changed_policy, &rows(), false, NOW);
        assert!(changed.regular && !changed.content_comparison_available);
        let mut history = rows();
        let mut conflict = history[0].clone();
        conflict.sample.reply = digest(b"different");
        history.push(conflict);
        assert_eq!(
            assess(&Settings::default(), &sample("today"), &history, false, NOW).campaigns,
            5
        );
        for r in &mut history {
            r.sample.content_complete = false;
        }
        let report = assess(&Settings::default(), &sample("today"), &history, false, NOW);
        assert!(!report.content_comparison_available);
        assert!(!report.changes.contains(&"sensitive_request".into()));
    }
}
