//! Resolve asynchronous coordinator mirrors without inventing queue ownership.
use super::SpoolSnapshot;
use anyhow::{Result, ensure};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Serialize)]
pub struct ReconciliationReport {
    pub sources: usize,
    pub owner_records: usize,
    pub owner_transcripts: usize,
    pub duplicate_mirrors: usize,
    pub duplicate_mirror_transcripts: usize,
}
/// Only owner events remain after every mirror has been accounted for. A mirror
/// absent at its owner is an unresolved migration conflict, never silently lost
/// or resurrected under a newly invented source identity.
pub struct ReconciledSpools {
    sources: Vec<SpoolSnapshot>,
    report: ReconciliationReport,
}
impl ReconciledSpools {
    pub fn verify(mut sources: Vec<SpoolSnapshot>) -> Result<Self> {
        ensure!(
            !sources.is_empty() && sources.len() <= 128,
            "Invalid migration source count"
        );
        let mut owners = BTreeMap::new();
        let mut nodes = BTreeSet::new();
        let mut transcript_counts = BTreeMap::new();
        let mut report = ReconciliationReport {
            sources: sources.len(),
            owner_records: 0,
            owner_transcripts: 0,
            duplicate_mirrors: 0,
            duplicate_mirror_transcripts: 0,
        };
        for source in &sources {
            ensure!(
                nodes.insert(source.identity.node.as_str()),
                "Duplicate migration source"
            );
            for event in &source.metadata {
                event.validate()?;
                ensure!(
                    owners
                        .insert(
                            event.receipt.id.as_str(),
                            (source.identity.node.as_str(), event.record.as_ref())
                        )
                        .is_none(),
                    "Message claimed by multiple migration sources"
                );
                if event.record.is_some() {
                    report.owner_records += 1;
                }
            }
            for event in &source.logs {
                if let Some(log) = &event.log {
                    let key = log_key(
                        &source.identity.node,
                        &event.message_id,
                        &event.recipient,
                        log,
                    )?;
                    *transcript_counts.entry(key).or_insert(0usize) += 1;
                    report.owner_transcripts += 1;
                }
            }
        }
        for source in &sources {
            let mut mirrored_ids = BTreeSet::new();
            for mirror in &source.mirrors {
                ensure!(
                    nodes.contains(mirror.owner.as_str()) && mirror.owner != source.identity.node,
                    "Mirror owner snapshot is missing"
                );
                ensure!(
                    mirrored_ids.insert(mirror.record.id.as_str()),
                    "Duplicate mirror in source"
                );
                let original = owners.get(mirror.record.id.as_str()).ok_or_else(|| {
                    anyhow::anyhow!(
                        "Retained mirror is missing at its owner; reconcile before migration"
                    )
                })?;
                ensure!(
                    original.0 == mirror.owner,
                    "Mirror ownership conflicts with source"
                );
                let original = original.1.ok_or_else(|| {
                    anyhow::anyhow!(
                        "Retained mirror conflicts with owner deletion; reconcile before migration"
                    )
                })?;
                ensure!(
                    original.created == mirror.record.created
                        && original.sender == mirror.record.sender
                        && original.is_dsn == mirror.record.is_dsn
                        && recipients(original) == recipients(&mirror.record),
                    "Mirror accepted envelope differs from owner"
                );
                report.duplicate_mirrors += 1;
            }
            // A coordinator may keep only the last five attempts. Every retained
            // mirror attempt must nevertheless exist at its owner, with counts
            // preserved when two SMTP attempts happen to have identical traces.
            let mut seen = BTreeMap::new();
            for log in &source.mirror_logs {
                ensure!(
                    mirrored_ids.contains(log.message_id.as_str()),
                    "Mirror transcript has no retained mirror"
                );
                let owner = owners.get(log.message_id.as_str()).unwrap().0;
                ensure!(owner == log.owner, "Mirror transcript ownership differs");
                let key = log_key(owner, &log.message_id, &log.recipient, &log.log)?;
                let count = seen.entry(key.clone()).or_insert(0usize);
                *count += 1;
                ensure!(
                    *count <= transcript_counts.get(&key).copied().unwrap_or(0),
                    "Retained mirror transcript is missing at owner; reconcile before migration"
                );
                report.duplicate_mirror_transcripts += 1;
            }
        }
        // All checks finish before dropping any duplicated projection.
        for source in &mut sources {
            source.mirrors.clear();
            source.mirror_logs.clear();
        }
        Ok(Self { sources, report })
    }
    pub fn into_sources(self) -> (Vec<SpoolSnapshot>, ReconciliationReport) {
        (self.sources, self.report)
    }
}
fn recipients(record: &crate::cluster::history::Record) -> BTreeSet<(&str, &str)> {
    record
        .deliveries
        .iter()
        .map(|d| (d.address.as_str(), d.destination.as_str()))
        .collect()
}
fn log_key(
    node: &str,
    message: &str,
    recipient: &str,
    log: &crate::central::logs::Log,
) -> Result<(String, String, String, u32, String)> {
    // Redaction is idempotent; reapply it so comparison never depends on whether
    // the original source or the mirror was written before a privacy fix.
    let mut trace = log.trace.clone();
    trace.sanitize();
    Ok((
        node.into(),
        message.into(),
        recipient.into(),
        log.attempt,
        crate::message::digest(&serde_json::to_vec(&trace)?),
    ))
}
