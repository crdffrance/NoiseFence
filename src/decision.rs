//! Final classification is distinct from scan completeness and delivery tagging.
use crate::{
    antivirus::AntivirusStatus,
    engine::{Scan, Signal},
    fusion::runtime::{Decision, DecisionSource, Outcome},
};

pub const VERSION: &str = "decision-policy-6";
pub const MALWARE_REASON: &str = "malware_priority";
pub const REVIEW_REASON: &str = "advisory_disagreement";
pub const CONTEXT_REASON: &str = "context_requires_review";
pub const OBSERVED_THREAT_REASON: &str = "observed_threat_partial";

/// Successfully observed threats survive unrelated optional-check failures.
/// Direct extortion still needs observed failed authentication and a second
/// content signal; no raw score or unavailable check supplies confirmation.
fn observed_threat_with_partial_coverage(scan: &Scan) -> bool {
    use crate::evidence::{AuthResult, Source, State};
    let Some(context) = &scan.message_context else {
        return false;
    };
    let signature = scan.signatures.status == AntivirusStatus::Suspicious
        && scan
            .signatures
            .signature
            .as_deref()
            .is_some_and(|s| s.starts_with("Sanesecurity.Phishing."));
    let llm = scan.llm.opinion() == Some(Outcome::Unwanted)
        && scan.llm.verdict.as_ref().is_some_and(|v| {
            matches!(v.category, crate::llm::Category::Phishing)
                && v.confidence >= 0.9
                && v.spam_probability >= 0.9
        });
    let allowed_missing = |id: &str| {
        id == "smtp_policy_unavailable"
            || (context.direct_extortion && signature && id == "llm_unavailable")
    };
    if scan.complete || scan.features_complete != Some(true)
        || scan.antivirus.status != AntivirusStatus::Clean
        || context.encrypted || context.threat_report || context.transaction_notice
        || !scan.reasons.iter().any(|r| allowed_missing(&r.id))
        || scan.reasons.iter().any(|r| crate::assessment::INCOMPLETE_REASONS.contains(&r.id.as_str()) && !allowed_missing(&r.id))
        || !((signature && llm) || (context.direct_extortion && (signature || llm)))
        // A contradictory available opinion still requires human review.
        || scan.llm.opinion() == Some(Outcome::Legitimate)
    {
        return false;
    }
    let Some(e) = &scan.evidence else {
        return false;
    };
    let a = &e.authentication;
    e.source == Source::SmtpSession
        && a.state == State::Complete
        && a.spf_state == State::Complete
        && matches!(a.spf, Some(AuthResult::Fail | AuthResult::SoftFail))
        && a.dkim_state == State::Complete
        && a.dkim.as_ref().is_some_and(|results| {
            results
                .iter()
                .all(|r| matches!(r, AuthResult::None | AuthResult::Fail))
        })
        && a.dmarc_state == State::Complete
        && matches!(a.dmarc_spf, Some(AuthResult::None | AuthResult::Fail))
        && matches!(a.dmarc_dkim, Some(AuthResult::None | AuthResult::Fail))
        && a.arc_state == State::Complete
        && matches!(a.arc, Some(AuthResult::None | AuthResult::Fail))
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Arbitration {
    pub version: String,
    /// Historical combined score, already including any bounded LLM weight.
    /// Agreement is therefore not independent corroboration.
    pub baseline: Decision,
    pub opinion: Outcome,
    pub resolution: Resolution,
    pub decision: Decision,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Resolution {
    Agreement,
    Disagreement,
    Ambiguous,
    Corroborated,
}

fn arbitrate(scan: &mut Scan) -> Option<Arbitration> {
    let baseline = scan.decision.as_ref()?;
    if !scan.complete
        || baseline.source != DecisionSource::Legacy
        || baseline.outcome == Outcome::Undetermined
    {
        return None;
    }
    let opinion = scan.llm.opinion()?;
    let resolution = if opinion == baseline.outcome {
        Resolution::Agreement
    } else if opinion != Outcome::Undetermined {
        Resolution::Disagreement
    } else if baseline.outcome == Outcome::Unwanted && crate::confirmation::corroborated(scan) {
        Resolution::Corroborated
    } else {
        Resolution::Ambiguous
    };
    let baseline = baseline.clone();
    if matches!(resolution, Resolution::Disagreement | Resolution::Ambiguous) {
        let decision = scan.decision.as_mut()?;
        decision.outcome = Outcome::Undetermined;
        decision.score = None;
        scan.tagged = false;
        scan.pub_tagged = false;
        scan.reasons.push(Signal {
            id: REVIEW_REASON.into(),
            detail: if resolution == Resolution::Disagreement {
                "The historical ranking and the second opinion contradict each other: message to be checked. The raw score is kept as a diagnosis; neither opinion alone proves the legitimacy or undesirableness of the message."
            } else {
                "The second opinion is ambiguous or insufficiently assured: message to be checked. Uncertainty does not constitute a spam detection or proof of legitimacy."
            }.into(),
            weight: 0.0,
        });
    }
    Some(Arbitration {
        version: VERSION.into(),
        baseline,
        opinion,
        resolution,
        decision: scan.decision.as_ref()?.clone(),
    })
}

/// Resolve a fresh legacy/fusion decision. Only the main scanner's trusted
/// malware result takes precedence; advisory signatures and providers do not.
/// An unrelated failure never erases that observation, but `complete = false`
/// still prevents every subject prefix. No artificial probability is assigned.
pub fn apply(scan: &mut Scan, require_corroboration: bool) {
    let context_reviewed = scan.reasons.iter().any(|r| r.id == CONTEXT_REASON);
    // Re-evaluate from the saved input when applying recipient policies. Never
    // treat our own abstention as new evidence or accumulate explanation rows.
    if let Some(previous) = scan.arbitration.take()
        && previous.version == VERSION
        && scan.complete
        && scan.decision.as_ref() == Some(&previous.decision)
    {
        scan.decision = Some(previous.baseline);
    }
    scan.reasons.retain(|r| {
        r.id != MALWARE_REASON
            && r.id != REVIEW_REASON
            && r.id != CONTEXT_REASON
            && r.id != OBSERVED_THREAT_REASON
    });
    if scan.antivirus.status == AntivirusStatus::Malware {
        scan.reasons
            .retain(|r| r.id != crate::confirmation::REVIEW_REASON);
        scan.decision = Some(Decision {
            source: DecisionSource::Antivirus,
            outcome: Outcome::Unwanted,
            score: None,
            model: VERSION.into(),
        });
        scan.pub_tagged = false;
        if !scan.complete {
            scan.tagged = false;
        }
        scan.reasons.push(Signal {
            id: MALWARE_REASON.into(),
            detail: "The detection of malware by the main antivirus takes precedence over the suspicion index and the PUB category. This ranking does not correspond to a probability.".into(),
            weight: 0.0,
        });
    } else if scan
        .decision
        .as_ref()
        .is_some_and(|d| d.source == DecisionSource::Legacy)
        && observed_threat_with_partial_coverage(scan)
    {
        scan.decision = Some(Decision {
            source: DecisionSource::Legacy,
            outcome: Outcome::Unwanted,
            score: None,
            model: VERSION.into(),
        });
        scan.tagged = false;
        scan.pub_tagged = false;
        scan.reasons.push(Signal {
            id: OBSERVED_THREAT_REASON.into(),
            detail: if scan.message_context.as_ref().is_some_and(|c| c.direct_extortion) {
                "Explicit compromise, disclosure threat and cryptocurrency payment demand are corroborated by observed failed authentication and a phishing signature or strong phishing analysis. Coverage remains incomplete and automatic enforcement stays disabled."
            } else {
                "Phishing signature, coherent phishing analysis and observed unauthenticated sender evidence agree. The SMTP/DNS consistency check is unavailable; risk remains unwanted, coverage remains incomplete, and automatic enforcement stays disabled."
            }.into(),
            weight: 0.0,
        });
    } else {
        let mut arbitration = arbitrate(scan);
        crate::confirmation::apply(scan, require_corroboration);
        if scan.complete
            && scan.decision.as_ref().is_some_and(|d| {
                d.source == DecisionSource::Legacy
                    && (d.outcome == Outcome::Unwanted
                        || (context_reviewed && d.outcome == Outcome::Undetermined))
            })
            && crate::message_context::needs_review(scan)
        {
            let decision = scan.decision.as_mut().unwrap();
            decision.outcome = Outcome::Undetermined;
            decision.score = None;
            scan.tagged = false;
            scan.pub_tagged = false;
            scan.reasons.push(Signal {
                id: CONTEXT_REASON.into(),
                detail: "Authenticated threat-report or transaction context conflicts with an uncorroborated content score. Review required; context is not proof of legitimacy.".into(),
                weight: 0.0,
            });
        }
        if let Some(report) = &mut arbitration {
            report.decision = scan.decision.as_ref().unwrap().clone();
        }
        scan.arbitration = arbitration;
    }
}

/// Eligibility only: ARC sealing and Proton validation are still enforced by
/// the pipeline/configuration. Completeness controls rewriting, not whether a
/// successfully observed malware result may be shown to the operator.
pub fn subject_tag(
    scan: &Scan,
    config: &crate::config::Config,
) -> Option<crate::message::SubjectTag> {
    use crate::{actions::Action, mailing::Category, message::SubjectTag};
    if crate::actions::evaluate(scan, config).effective != Action::Tag {
        return None;
    }
    match crate::mailing::category(scan, config.filter.threshold) {
        Category::Spam => Some(SubjectTag::Spam),
        Category::Publicity => Some(SubjectTag::Publicity),
        _ => None,
    }
}
