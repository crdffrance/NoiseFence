//! Versioned accounting for the legacy content index. Native/Rspamd points and
//! provider probabilities are deliberately not inputs to this log-odds sum.
use crate::engine::{Scan, SemanticStatus};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const VERSION: &str = "content-logit-deduplicated-1";

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Adjustment {
    None,
    Duplicate,
    DetectorPolicy,
    ConflictingWeights,
    InvalidWeight,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Contribution {
    pub id: String,
    pub family: String,
    pub occurrences: usize,
    pub proposed: Option<f64>,
    pub retained: Option<f64>,
    pub adjustment: Adjustment,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Report {
    pub version: String,
    pub baseline: Option<f64>,
    pub lexical: Option<f64>,
    pub semantic: Option<f64>,
    pub contributions: Vec<Contribution>,
    /// Counts only invalid, nonzero, unrecognized rule inputs. Details and IDs
    /// are not copied: this bounded contract contains no email/provider text.
    pub invalid_inputs: usize,
    pub rules_total: Option<f64>,
    pub total_logit: Option<f64>,
    pub score: Option<f64>,
}

pub fn family(id: &str) -> &'static str {
    match id {
        "llm_advisory" => "llm",
        "spf_fail" | "dmarc_fail" => "authentication",
        "ip_reputation" | "domain_reputation" | "abused_domain_body" => "reputation",
        "smtp_policy_contribution" => "smtp",
        id if crate::rules::CATALOG.iter().any(|r| r.id == id) => "heuristics",
        _ => "other_rules",
    }
}
fn recognized(id: &str) -> bool {
    family(id) != "other_rules"
        || matches!(
            id,
            "antivirus" | "complementary_signature" | "vision_credential_lure"
        )
}
fn finite(value: f64) -> Option<f64> {
    value.is_finite().then_some(value)
}

/// `lexical` is the actual model output, or None only when no content model was
/// applied. Unavailable semantic analysis contributes nothing, not a clean vote.
/// Each message-level signal ID is counted once. Conflicting duplicates cannot
/// be silently resolved by choosing the most accusatory weight.
pub fn combine(scan: &Scan, lexical: Option<f64>, opaque: bool) -> Report {
    let baseline = lexical
        .is_none()
        .then_some(crate::engine::RULES_BASELINE_LOGIT);
    let invalid_content = lexical.is_some_and(|v| !v.is_finite());
    let lexical = lexical.and_then(finite);
    let semantic = if !opaque && scan.semantic.status == SemanticStatus::Complete {
        scan.semantic.contribution.and_then(finite)
    } else {
        None
    };
    let invalid_semantic =
        !opaque && scan.semantic.status == SemanticStatus::Complete && semantic.is_none();
    let mut inputs = BTreeMap::<&str, Vec<f64>>::new();
    let mut invalid_inputs = 0usize;
    for reason in &scan.reasons {
        // This is an output of the previous evaluation, never another input.
        if reason.id == "model_contribution" {
            continue;
        }
        if recognized(&reason.id) {
            inputs.entry(&reason.id).or_default().push(reason.weight);
        } else if reason.weight != 0.0 {
            invalid_inputs = invalid_inputs.saturating_add(1);
        }
    }
    let contributions: Vec<_> = inputs
        .into_iter()
        .map(|(id, weights)| {
            let invalid = weights.iter().any(|w| !w.is_finite());
            let conflict = weights.iter().any(|w| *w != weights[0]);
            let proposed = (!invalid && !conflict).then_some(weights[0]);
            let (retained, adjustment) = if id == "llm_advisory" {
                // A retained old advisory signal cannot revive a timed-out,
                // inconsistent or unsupported LLM opinion on reevaluation.
                let actual = scan.llm.advisory_weight();
                (
                    Some(actual),
                    if invalid || conflict || proposed != Some(actual) {
                        Adjustment::DetectorPolicy
                    } else if weights.len() > 1 {
                        Adjustment::Duplicate
                    } else {
                        Adjustment::None
                    },
                )
            } else if invalid {
                (None, Adjustment::InvalidWeight)
            } else if conflict {
                (None, Adjustment::ConflictingWeights)
            } else {
                (
                    proposed,
                    if weights.len() > 1 {
                        Adjustment::Duplicate
                    } else {
                        Adjustment::None
                    },
                )
            };
            Contribution {
                id: id.into(),
                family: family(id).into(),
                occurrences: weights.len(),
                proposed,
                retained,
                adjustment,
            }
        })
        .collect();
    let rules_total = contributions
        .iter()
        .try_fold(0., |sum, entry| finite(sum + entry.retained?));
    let total_logit = if invalid_inputs > 0 || invalid_content || invalid_semantic {
        None
    } else {
        rules_total.and_then(|rules| finite(lexical.or(baseline)? + semantic.unwrap_or(0.) + rules))
    };
    let score = total_logit.map(|value| {
        let score = crate::engine::sigmoid(value) * 100.;
        if scan.feature_version == crate::features::VERSION {
            score
        } else {
            (score * 10.).round() / 10.
        }
    });
    Report {
        version: VERSION.into(),
        baseline,
        lexical,
        semantic,
        contributions,
        invalid_inputs,
        rules_total,
        total_logit,
        score,
    }
}

/// Historical readers use the immutable analysis snapshot when one exists.
/// They never recreate a new report from today's model or policy.
pub fn recorded(scan: &Scan) -> Option<&Report> {
    match &scan.analysis_result {
        Some(record) => record.scoring.as_ref(),
        None => scan.scoring.as_ref(),
    }
}
