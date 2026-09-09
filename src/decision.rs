//! Final classification is distinct from scan completeness and delivery tagging.
use crate::{
    antivirus::AntivirusStatus,
    engine::{Scan, Signal},
    fusion::runtime::{Decision, DecisionSource, Outcome},
};

pub const VERSION: &str = "decision-policy-1";
pub const MALWARE_REASON: &str = "malware_priority";

/// Resolve a fresh legacy/fusion decision. Only the main scanner's trusted
/// malware result takes precedence; advisory signatures and providers do not.
/// An unrelated failure never erases that observation, but `complete = false`
/// still prevents every subject prefix. No artificial probability is assigned.
pub fn apply(scan: &mut Scan, require_corroboration: bool) {
    scan.reasons.retain(|r| r.id != MALWARE_REASON);
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
            detail: "La détection de malware par l’antivirus principal prime sur le score de contenu et la catégorie PUB. Ce classement ne correspond pas à une probabilité.".into(),
            weight: 0.0,
        });
    } else {
        crate::confirmation::apply(scan, require_corroboration);
    }
}

/// Eligibility only: ARC sealing and Proton validation are still enforced by
/// the pipeline/configuration. Completeness controls rewriting, not whether a
/// successfully observed malware result may be shown to the operator.
pub fn subject_tag(
    scan: &Scan,
    config: &crate::config::Config,
) -> Option<crate::message::SubjectTag> {
    use crate::{config::Mode, mailing::Category, message::SubjectTag};
    if !scan.complete || config.filter.mode != Mode::Tag {
        return None;
    }
    match crate::mailing::category(scan, config.filter.threshold) {
        Category::Spam => Some(SubjectTag::Spam),
        Category::Publicity
            if config
                .mailing
                .as_ref()
                .is_some_and(|m| m.policy.tag_subject) =>
        {
            Some(SubjectTag::Publicity)
        }
        _ => None,
    }
}
