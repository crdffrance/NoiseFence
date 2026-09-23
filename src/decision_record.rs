//! Receipt-time contracts. Rendering and retries consume them without reclassification.
use crate::{
    assessment::{Assessment, Score},
    config::Config,
    custom_filtering,
    engine::{Scan, Signal},
    fusion::runtime::{Decision, Outcome},
    mailing::Category,
};
use serde::{Deserialize, Serialize};

pub const VERSION: u32 = 2;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Coverage {
    Complete,
    Partial,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    Legitimate,
    Publicity,
    Spam,
    Phishing,
    Malware,
    /// An unmeasured risk is not a verified legitimate message.
    Unassessed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnalysisResult {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activation_epoch: Option<crate::cluster::activation::Epoch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score_boundary: Option<crate::score_boundary::Boundary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fusion_combination: Option<crate::fusion::combination::Accounting>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scoring: Option<crate::scoring::Report>,
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observations: Option<crate::observations::Report>,
    pub raw_sha256: Option<String>,
    pub artifacts: Option<crate::evidence::Artifacts>,
    pub score: Score,
    pub detector_decision: Decision,
    pub coverage: Coverage,
    pub missing_checks: Vec<String>,
    pub supplementary_gaps: Vec<String>,
    pub reasons: Vec<Signal>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecipientDecision {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activation_epoch: Option<crate::cluster::activation::Epoch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_trace: Option<crate::policy_trace::Trace>,
    pub version: u32,
    pub recorded_at: i64,
    /// Digest of the effective threshold/action/rules and recipient-scoped trace.
    /// Only the digest, never the trace's addresses, is exposed in SMTP headers.
    pub policy_sha256: String,
    pub profile: Option<String>,
    pub rule_ids: Vec<String>,
    pub classification: Classification,
    pub coverage: Coverage,
    pub assessment: Assessment,
}

/// Old receipts may only have a transport epoch. Never backfill the canonical
/// decision from that field or today's runtime. Version 2 records bind it before
/// header generation and require exact preservation during transport.
pub fn validate_activation(scan: &Scan) -> anyhow::Result<()> {
    if let Some(epoch) = &scan.activation_epoch {
        epoch.validate()?;
    }
    for (version, epoch) in scan
        .analysis_result
        .as_ref()
        .map(|r| (r.version, r.activation_epoch.as_ref()))
        .into_iter()
        .chain(
            scan.recipient_decision
                .as_ref()
                .map(|r| (r.version, r.activation_epoch.as_ref())),
        )
    {
        anyhow::ensure!(
            (1..=VERSION).contains(&version),
            "Unsupported receipt contract version"
        );
        if let Some(epoch) = epoch {
            epoch.validate()?;
        }
        if version >= 2 || epoch.is_some() {
            anyhow::ensure!(
                epoch == scan.activation_epoch.as_ref(),
                "Receipt activation identity disagrees with its transport epoch"
            );
        }
    }
    Ok(())
}
pub fn recorded_activation(scan: &Scan) -> Option<&crate::cluster::activation::Epoch> {
    validate_activation(scan).ok()?;
    scan.recipient_decision
        .as_ref()
        .and_then(|r| r.activation_epoch.as_ref())
        .or_else(|| {
            scan.analysis_result
                .as_ref()
                .and_then(|r| r.activation_epoch.as_ref())
        })
}

fn coverage(scan: &Scan) -> Coverage {
    if scan.complete {
        Coverage::Complete
    } else if scan.features_complete == Some(false) {
        Coverage::Unavailable
    } else {
        Coverage::Partial
    }
}

/// Capture once, before recipient preferences and wire rewriting. Observers added
/// later (for example Rspamd) cannot change this decision input.
pub fn record_analysis(scan: &mut Scan, config: &Config) {
    if scan.analysis_result.is_some() {
        return;
    }
    let view = crate::assessment::assess_unrecorded(scan, config.filter.threshold);
    scan.analysis_result = Some(Box::new(AnalysisResult {
        activation_epoch: scan.activation_epoch.clone(),
        score_boundary: view.score_boundary,
        version: VERSION,
        scoring: scan.scoring.clone(),
        fusion_combination: scan.fusion_combination.clone(),
        observations: Some(crate::observations::capture(scan)),
        raw_sha256: scan.raw_sha256.clone(),
        artifacts: scan.evidence.as_ref().map(|e| e.artifacts.clone()),
        score: view.score,
        detector_decision: view.decision,
        coverage: coverage(scan),
        missing_checks: view.incomplete_reasons,
        supplementary_gaps: view.supplementary_gaps,
        reasons: scan.reasons.clone(),
    }));
}

/// Freeze the effective recipient policy before rendering headers. Calls on an
/// existing record are idempotent; policy simulation must use a separate Scan.
pub fn record_recipient(
    scan: &mut Scan,
    config: &Config,
    policy: Option<&custom_filtering::Assessment>,
    recorded_at: i64,
) {
    if scan.recipient_decision.is_some() {
        return;
    }
    record_analysis(scan, config);
    let mut view = crate::assessment::assess_unrecorded(scan, config.filter.threshold);
    if let Some(policy) = policy {
        view.content_threshold = Some(policy.threshold);
        view.category = policy.category;
        view.action = Some(policy.action.clone());
        view.classification_source = crate::assessment::ClassificationSource::RecipientPolicy;
    }
    view.content_threshold = view.content_threshold.or(Some(config.filter.threshold));
    view.score_boundary =
        crate::score_boundary::selected(scan, &view.score, view.content_threshold);
    view.mode = view.mode.or(Some(config.filter.mode));
    view.policy_version = view
        .policy_version
        .or_else(|| Some(crate::decision::VERSION.into()));
    let classification =
        if scan.antivirus.status == crate::antivirus::AntivirusStatus::Malware {
            Classification::Malware
        } else {
            match view.category {
                Category::Spam
                    if scan.llm.opinion() == Some(Outcome::Unwanted)
                        && scan.llm.verdict.as_ref().is_some_and(|v| {
                            matches!(v.category, crate::llm::Category::Phishing)
                        }) =>
                {
                    Classification::Phishing
                }
                Category::Spam => Classification::Spam,
                Category::Publicity => Classification::Publicity,
                Category::Legitimate if view.score.value.is_some() => Classification::Legitimate,
                Category::Legitimate | Category::Undetermined => Classification::Unassessed,
            }
        };
    // Automatic fail-open is a delivery policy, never a positive safety finding.
    if classification == Classification::Unassessed {
        view.category = Category::Undetermined;
    }
    let rule_ids = policy
        .map(|p| p.matched.iter().map(|r| r.id.clone()).collect())
        .unwrap_or_default();
    let policy_sha256 = crate::message::digest(&serde_json::to_vec(&serde_json::json!({
        "version": VERSION, "analysis_policy": scan.analysis_policy,
        "custom_policy": policy.map(|p| &p.policy), "profile": policy.and_then(|p| p.profile.as_ref()),
        "threshold": view.content_threshold, "category": view.category,
        "score_boundary": view.score_boundary,
        "classification": classification, "action": view.action, "rule_ids": rule_ids,
        "trace":policy.and_then(|p|p.trace.as_ref()),
    })).expect("typed receipt policy"));
    scan.recipient_decision = Some(Box::new(RecipientDecision {
        activation_epoch: scan.activation_epoch.clone(),
        policy_trace: policy.and_then(|p| p.trace.clone()),
        version: VERSION,
        recorded_at,
        policy_sha256,
        profile: policy.and_then(|p| p.profile.clone()),
        rule_ids,
        classification,
        coverage: coverage(scan),
        assessment: view,
    }));
}

/// The subject tag is a wire-format fact, recorded after render decides whether
/// it can modify the signed message. This does not alter score or policy.
pub fn record_subject_tag(scan: &mut Scan) {
    if let Some(record) = &mut scan.recipient_decision {
        record.assessment.subject_tag = if scan.tagged {
            crate::assessment::SubjectTag::Spam
        } else if scan.pub_tagged {
            crate::assessment::SubjectTag::Publicity
        } else {
            crate::assessment::SubjectTag::None
        };
    }
}
