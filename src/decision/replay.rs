//! Read-only context regression on a digest-bound original and recorded scan.
//! Reuses captured detector observations; never runs providers or delivery.
use crate::{engine::Scan, fusion::runtime::Decision, mailing::Category};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::{fs::File, io::Read, path::Path};

#[derive(Serialize)]
pub struct Report {
    pub policy_version: &'static str,
    pub recorded: Category,
    pub baseline: Category,
    pub candidate: Category,
    pub context: crate::message_context::Context,
    pub guard: Option<String>,
    pub complete: bool,
    pub threshold: f64,
    pub score: f64,
}

fn bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let file = File::open(path)?;
    ensure!(file.metadata()?.is_file(), "Replay requires regular files");
    let mut data = Vec::new();
    file.take((limit + 1) as u64).read_to_end(&mut data)?;
    ensure!(data.len() <= limit, "Replay input exceeds its size limit");
    Ok(data)
}

pub fn files(message: &Path, recorded: &Path) -> Result<Report> {
    let raw = bounded(message, 2 * 1024 * 1024)?;
    let scan = serde_json::from_slice(&bounded(recorded, 8 * 1024 * 1024)?)?;
    compare(&raw, &scan)
}

pub fn compare(raw: &[u8], original: &Scan) -> Result<Report> {
    ensure!(
        raw.len() <= 2 * 1024 * 1024,
        "Replay message exceeds size limit"
    );
    ensure!(
        original.raw_sha256.as_deref() == Some(&crate::message::digest(raw)),
        "Original digest does not match recorded analysis"
    );
    let threshold = crate::assessment::recorded_threshold(original)
        .context("Replay requires a recorded threshold")?;
    let policy = original
        .analysis_policy
        .as_ref()
        .context("Replay requires recorded analysis policy")?;
    ensure!(
        original
            .decision
            .as_ref()
            .is_some_and(|d| d.source == crate::fusion::runtime::DecisionSource::Legacy),
        "Context replay supports legacy decisions only"
    );
    // Explicit simulation: no receipt-time row or recipient policy is rewritten.
    let evaluate = |mut scan: Scan| {
        scan.recipient_decision = None;
        scan.analysis_result = None;
        scan.delivery_classification = None;
        scan.score_resolution = None;
        scan.arbitration = None;
        scan.reasons.retain(|r| {
            !matches!(
                r.id.as_str(),
                super::CONTEXT_REASON
                    | super::REVIEW_REASON
                    | super::SCORE_RESOLUTION_REASON
                    | super::OBSERVED_THREAT_REASON
                    | crate::confirmation::REVIEW_REASON
            )
        });
        scan.decision = Some(Decision::legacy(&scan, threshold));
        super::apply(&mut scan, policy.require_corroboration);
        super::finalize(&mut scan, threshold);
        scan
    };
    let baseline = evaluate(original.clone());
    let context = crate::message_context::inspect(raw);
    let mut candidate = original.clone();
    candidate.message_context = Some(context.clone());
    let candidate = evaluate(candidate);
    Ok(Report {
        policy_version: super::VERSION,
        recorded: crate::mailing::category(original, threshold),
        baseline: crate::mailing::category(&baseline, threshold),
        candidate: crate::mailing::category(&candidate, threshold),
        context,
        guard: candidate.score_resolution.and_then(|r| r.guard),
        complete: original.complete,
        threshold,
        score: original.score,
    })
}
