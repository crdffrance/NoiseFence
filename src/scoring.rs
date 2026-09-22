//! Versioned accounting for the legacy content index. Native/Rspamd points and
//! provider probabilities are deliberately not inputs to this log-odds sum.
use crate::engine::{Scan, SemanticStatus};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const VERSION: &str = "content-logit-deduplicated-1";
/// Wire-compatible storage sentinel, never a displayed risk index.
pub const UNAVAILABLE_SCORE: f64 = -1.0;

/// Shared boundary check for queue replication and central history. A negative
/// number alone is not an unavailable-score contract: require the producer's
/// ledger, incomplete status and explicit reason. Never recalculate old scores.
pub fn validate_transport(scan: &Scan) -> anyhow::Result<()> {
    use crate::assessment::{Score, ScoreKind, ScoreSource, valid_score};
    use crate::fusion::runtime::{Decision, DecisionSource};
    use anyhow::ensure;
    let valid_optional = |value: Option<f64>| value.is_none() || valid_score(value).is_some();
    let validate_decision = |decision: &Decision| -> anyhow::Result<()> {
        ensure!(valid_optional(decision.score), "Invalid detector score");
        ensure!(
            scan.score != UNAVAILABLE_SCORE
                || decision.source != DecisionSource::Legacy
                || decision.score.is_none(),
            "Unavailable content index replaced by a legacy decision score"
        );
        Ok(())
    };
    let validate_view = |score: &Score, decision: &Decision| -> anyhow::Result<()> {
        validate_decision(decision)?;
        ensure!(
            score.scale == 100
                && [score.value, score.raw, score.decision]
                    .into_iter()
                    .all(valid_optional),
            "Invalid recorded score"
        );
        let expected = score.decision.or(score.raw);
        let source = if score.decision.is_some() {
            ScoreSource::Decision
        } else if score.raw.is_some() {
            ScoreSource::Raw
        } else {
            ScoreSource::Unavailable
        };
        ensure!(
            score.value == expected
                && score.source == source
                && (score.kind == ScoreKind::Unavailable) == score.value.is_none(),
            "Inconsistent recorded score"
        );
        ensure!(
            scan.score != UNAVAILABLE_SCORE || score.raw.is_none(),
            "Unavailable raw score was replaced"
        );
        // Legacy decisions may be synthesized for display on records whose
        // selected score still comes from raw content, not a recorded vote.
        ensure!(
            match decision.source {
                DecisionSource::Legacy =>
                    score.decision.is_none() || score.decision == decision.score,
                DecisionSource::Fusion => score.decision == decision.score,
                DecisionSource::Antivirus => score.decision.is_none(),
            },
            "Recorded decision score disagrees with its source"
        );
        Ok(())
    };
    if let Some(decision) = &scan.decision {
        validate_decision(decision)?;
    }
    if let Some(record) = &scan.analysis_result {
        validate_view(&record.score, &record.detector_decision)?;
    }
    if let Some(record) = &scan.recipient_decision {
        validate_view(&record.assessment.score, &record.assessment.decision)?;
    }
    if valid_score(Some(scan.score)).is_some() {
        return Ok(());
    }
    ensure!(
        scan.score == UNAVAILABLE_SCORE && !scan.complete,
        "Invalid decision score"
    );
    let report = scan
        .scoring
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Missing unavailable-score ledger"))?;
    ensure!(
        report.version == VERSION
            && report.score.is_none()
            && report.total_logit.is_none()
            && scan
                .reasons
                .iter()
                .any(|r| r.id == "score_combination_invalid" && r.weight == 0.0),
        "Invalid unavailable-score ledger"
    );
    if let Some(record) = &scan.analysis_result {
        ensure!(
            record.version == crate::decision_record::VERSION
                && record.coverage != crate::decision_record::Coverage::Complete
                && record.scoring.as_ref() == Some(report),
            "Unavailable-score snapshot changed"
        );
    }
    if let Some(record) = &scan.recipient_decision {
        ensure!(
            record.version == crate::decision_record::VERSION
                && record.coverage != crate::decision_record::Coverage::Complete
                && !record.assessment.complete,
            "Unavailable recipient score marked complete"
        );
    }
    Ok(())
}

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
