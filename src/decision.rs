//! Final classification is distinct from scan completeness and delivery tagging.
use crate::{
    antivirus::AntivirusStatus,
    engine::{Scan, Signal},
    fusion::runtime::{Decision, DecisionSource, Outcome},
};

pub const VERSION: &str = "decision-policy-2";
pub const MALWARE_REASON: &str = "malware_priority";
pub const REVIEW_REASON: &str = "advisory_disagreement";

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
                "Le classement historique et le second avis se contredisent : message à vérifier. Le score brut est conservé comme diagnostic ; aucun des deux avis ne prouve à lui seul la légitimité ou le caractère indésirable du message."
            } else {
                "Le second avis est ambigu ou insuffisamment assuré : message à vérifier. L’incertitude ne constitue ni une détection de spam ni une preuve de légitimité."
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
    // Re-evaluate from the saved input when applying recipient policies. Never
    // treat our own abstention as new evidence or accumulate explanation rows.
    if let Some(previous) = scan.arbitration.take()
        && previous.version == VERSION
        && scan.complete
        && scan.decision.as_ref() == Some(&previous.decision)
    {
        scan.decision = Some(previous.baseline);
    }
    scan.reasons
        .retain(|r| r.id != MALWARE_REASON && r.id != REVIEW_REASON);
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
            detail: "La détection de malware par l’antivirus principal prime sur l’indice de suspicion et la catégorie PUB. Ce classement ne correspond pas à une probabilité.".into(),
            weight: 0.0,
        });
    } else {
        let mut arbitration = arbitrate(scan);
        crate::confirmation::apply(scan, require_corroboration);
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
