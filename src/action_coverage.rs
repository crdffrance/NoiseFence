//! Decision-specific evidence requirements; delivery, coverage and wire marking
//! are distinct. This evaluator never changes a detector result or a score.
use crate::{actions::Action, config::Config, engine::Scan, mailing::Category};
use serde::{Deserialize, Serialize};

pub const VERSION: &str = "action-coverage-1";

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Basis {
    Delivery,
    CompleteAnalysis,
    PrimaryMalware,
    RecipientRule,
    EstablishedThreat,
    ScoreThreshold,
    ValidatedFusion,
    MessageKind,
    Unresolved,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Requirement {
    CompleteAnalysis,
    PrimaryMalware,
    MatchedRecipientRule,
    EstablishedThreat,
    UsableContent,
    UsableScore,
    ThresholdMet,
    AutomaticScorePolicy,
    ValidatedFusion,
    MessageKind,
    DeterminateClassification,
    SubjectRewrite,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Evaluation {
    pub version: String,
    pub partial_actions: bool,
    pub basis: Basis,
    pub required: Vec<Requirement>,
    pub missing: Vec<Requirement>,
}
impl Evaluation {
    pub fn eligible(&self) -> bool {
        self.missing.is_empty()
    }
    fn require(&mut self, requirement: Requirement, met: bool) {
        self.required.push(requirement);
        if !met {
            self.missing.push(requirement);
        }
    }
}

/// Facts already evaluated by the recipient policy. A matching explicit rule
/// can request an action without masquerading as detector evidence.
pub struct Context<'a> {
    pub reason: &'a str,
    pub threshold: f64,
    pub matched_rule: bool,
}

pub fn evaluate(
    scan: &Scan,
    config: &Config,
    category: Category,
    action: Action,
    context: &Context<'_>,
) -> Evaluation {
    use crate::{
        antivirus::AntivirusStatus,
        fusion::runtime::{DecisionSource, Mode, Outcome, Status},
    };
    use Requirement as R;
    let malware = scan.antivirus.status == AntivirusStatus::Malware;
    let mut report = Evaluation {
        version: VERSION.into(),
        partial_actions: config.filter.partial_actions,
        basis: Basis::Delivery,
        required: vec![],
        missing: vec![],
    };
    if action == Action::Deliver {
        return report;
    }

    if malware && action == Action::Quarantine {
        // Existing exception: a trusted malware finding survives every unrelated gap.
        report.basis = Basis::PrimaryMalware;
        report.require(R::PrimaryMalware, true);
    } else if scan.complete || !config.filter.partial_actions {
        report.basis = Basis::CompleteAnalysis;
        report.require(R::CompleteAnalysis, scan.complete);
    } else if malware {
        report.basis = Basis::PrimaryMalware;
        report.require(R::PrimaryMalware, true);
    } else if context.matched_rule {
        report.basis = Basis::RecipientRule;
        report.require(R::MatchedRecipientRule, true);
    } else if category == Category::Publicity {
        report.basis = Basis::MessageKind;
        report.require(
            R::MessageKind,
            scan.mailing.as_ref().is_some_and(|m| {
                m.status == crate::mailing::Status::Complete
                    && matches!(
                        m.verdict,
                        crate::mailing::Verdict::Promotion | crate::mailing::Verdict::Newsletter
                    )
            }),
        );
    } else if category == Category::Spam {
        if crate::decision::observed_threat_with_partial_coverage(scan) {
            report.basis = Basis::EstablishedThreat;
            report.require(R::EstablishedThreat, true);
        } else if scan
            .decision
            .as_ref()
            .is_some_and(|d| d.source == DecisionSource::Fusion)
            || config
                .fusion
                .as_ref()
                .is_some_and(|f| f.mode == Mode::Decision)
        {
            // A failed/expired fusion must not gain authority through a legacy fallback.
            report.basis = Basis::ValidatedFusion;
            report.require(
                R::ValidatedFusion,
                scan.fusion.mode == Mode::Decision
                    && scan.fusion.status == Status::Complete
                    && scan.decision.as_ref().is_some_and(|d| {
                        d.source == DecisionSource::Fusion
                            && d.outcome == Outcome::Unwanted
                            && crate::assessment::valid_score(d.score).is_some()
                    }),
            );
        } else {
            report.basis = Basis::ScoreThreshold;
            report.require(R::UsableContent, scan.features_complete == Some(true));
            let score = crate::assessment::valid_score(Some(scan.score));
            report.require(R::UsableScore, score.is_some());
            report.require(
                R::AutomaticScorePolicy,
                config.filter.resolve_uncertain_by_score,
            );
            report.require(
                R::ThresholdMet,
                score
                    .zip(crate::assessment::valid_score(Some(context.threshold)))
                    .is_some_and(|(s, t)| s >= t),
            );
        }
    } else {
        report.basis = Basis::Unresolved;
        report.require(R::DeterminateClassification, false);
    }
    if action == Action::Tag {
        // New partial actions require an explicit ready renderer. Legacy complete
        // records/callers lack this field; a known-unavailable renderer always wins.
        report.require(
            R::SubjectRewrite,
            if !scan.complete && config.filter.partial_actions {
                scan.subject_rewrite_ready == Some(true)
            } else {
                scan.subject_rewrite_ready != Some(false)
            },
        );
    }
    report
}
