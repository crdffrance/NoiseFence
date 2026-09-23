//! Shared receipt-time eligibility for provider targets. No wall-clock rechecks,
//! content submission or verdict inferred from provider aggregate counters.
use super::{Provider, ProviderObservation, ProviderReport, Status};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const VERSION: &str = "provider-target-evidence-1";
pub const MAX_TARGETS: usize = 48;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Exclusion {
    InvalidTarget,
    InvalidResult,
    UnavailableProvider,
    MissingCaptureTime,
    InvalidObservationTime,
    StaleResult,
    DuplicateTarget,
    ConflictingTarget,
}
pub struct Target<'a> {
    pub index: usize,
    pub value: &'a ProviderObservation,
    pub exclusion: Option<Exclusion>,
}
impl Target<'_> {
    pub fn usable(&self) -> bool {
        self.exclusion.is_none()
    }
    pub fn malicious(&self) -> bool {
        self.usable() && self.value.verdict == "malicious"
    }
    pub fn group(&self) -> (&'static str, &str) {
        (
            if self.value.scope == "file" {
                "file"
            } else {
                "host"
            },
            &self.value.indicator_sha256,
        )
    }
}
pub struct Evaluation<'a> {
    pub status: Status,
    pub targets: Vec<Target<'a>>,
    pub omitted: usize,
}
fn exclusion(
    provider: Provider,
    report: &ProviderReport,
    target: &ProviderObservation,
) -> Option<Exclusion> {
    use Exclusion::*;
    let scope = match provider {
        Provider::Crdf => target.scope == "host_lookup",
        Provider::Virustotal => matches!(target.scope.as_str(), "domain" | "file"),
    };
    if !scope || !crate::compatibility::valid_hash(&target.indicator_sha256) {
        return Some(InvalidTarget);
    }
    if !matches!(
        target.verdict.as_str(),
        "malicious" | "suspicious" | "no_hit" | "unknown" | "stale"
    ) {
        return Some(InvalidResult);
    }
    if matches!(
        report.status,
        Status::Disabled | Status::NotConfigured | Status::NotRun | Status::Unknown
    ) {
        return Some(UnavailableProvider);
    }
    let Some(at) = report.captured_at.filter(|at| *at > 0) else {
        return Some(MissingCaptureTime);
    };
    if target.queried_at <= 0
        || target.queried_at < at.saturating_sub(300)
        || target.queried_at > at.saturating_add(60)
    {
        return Some(InvalidObservationTime);
    }
    if target.verdict == "stale" || report.status == Status::Stale {
        return Some(StaleResult);
    }
    None
}
pub fn evaluate(provider: Provider, report: &ProviderReport) -> Evaluation<'_> {
    let mut targets: Vec<_> = report
        .observations
        .iter()
        .take(MAX_TARGETS)
        .enumerate()
        .map(|(index, value)| Target {
            index,
            value,
            exclusion: exclusion(provider, report, value),
        })
        .collect();
    let mut groups = BTreeMap::<(&str, &str), Vec<usize>>::new();
    for t in &targets {
        if crate::compatibility::valid_hash(&t.value.indicator_sha256) {
            groups
                .entry((&t.value.scope, &t.value.indicator_sha256))
                .or_default()
                .push(t.index);
        }
    }
    for indexes in groups.values().filter(|v| v.len() > 1) {
        let verdicts: BTreeSet<_> = indexes
            .iter()
            .map(|i| targets[*i].value.verdict.as_str())
            .collect();
        if verdicts.len() > 1 {
            for i in indexes {
                if targets[*i].usable() {
                    targets[*i].exclusion = Some(Exclusion::ConflictingTarget);
                }
            }
        } else {
            let mut seen = false;
            for i in indexes {
                if targets[*i].usable() {
                    if seen {
                        targets[*i].exclusion = Some(Exclusion::DuplicateTarget);
                    } else {
                        seen = true;
                    }
                }
            }
        }
    }
    let omitted = report.observations.len().saturating_sub(MAX_TARGETS);
    let status = if report.status == Status::Complete
        && (omitted > 0
            || report.omitted > 0
            || targets
                .iter()
                .any(|t| t.exclusion.is_some_and(|e| e != Exclusion::DuplicateTarget)))
    {
        Status::Limited
    } else {
        report.status.clone()
    };
    Evaluation {
        status,
        targets,
        omitted,
    }
}

/// A repeated row from one provider is never cross-provider corroboration.
/// Host-root and domain lookups share a target group; file hashes stay separate.
pub fn shared_malicious_targets(crdf: &Evaluation<'_>, vt: &Evaluation<'_>) -> usize {
    let a: BTreeSet<_> = crdf
        .targets
        .iter()
        .filter(|t| t.malicious())
        .map(Target::group)
        .collect();
    let b: BTreeSet<_> = vt
        .targets
        .iter()
        .filter(|t| t.malicious())
        .map(Target::group)
        .collect();
    a.intersection(&b).count()
}
