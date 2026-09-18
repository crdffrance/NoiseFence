//! The read-only assessment shared by the API, SMTP diagnostics and console.
//! Values describe recorded evidence. They never feed classification or delivery.
use crate::{
    actions::Applied,
    antivirus::AntivirusStatus,
    config::Mode,
    engine::Scan,
    fusion::runtime::{Decision, DecisionSource, Outcome},
    mailing::Category,
};
use serde::Serialize;

pub const VERSION: u8 = 1;
pub const INCOMPLETE_REASONS: &[&str] = &[
    "encrypted_content",
    "analysis_budget",
    "signature_budget",
    "checks_unavailable",
    "llm_unavailable",
    "semantic_unavailable",
    "smtp_policy_unavailable",
    "vision_incomplete",
    "complementary_signature_unavailable",
];

pub fn valid_score(value: Option<f64>) -> Option<f64> {
    value.filter(|v| v.is_finite() && (0.0..=100.0).contains(v))
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScoreKind {
    Unavailable,
    Partial,
    Internal,
    Advisory,
    Decision,
    Content,
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScoreSource {
    Unavailable,
    Decision,
    Raw,
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClassificationSource {
    RecipientPolicy,
    RecordedDecision,
    HistoricalFallback,
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SubjectTag {
    None,
    Spam,
    Publicity,
}

#[derive(Clone, Debug, Serialize)]
pub struct Score {
    pub value: Option<f64>,
    pub raw: Option<f64>,
    pub decision: Option<f64>,
    pub kind: ScoreKind,
    pub source: ScoreSource,
    pub model: String,
    pub scale: u8,
}
#[derive(Clone, Debug, Serialize)]
pub struct Assessment {
    pub version: u8,
    pub score: Score,
    pub category: Category,
    pub classification_source: ClassificationSource,
    pub decision: Decision,
    pub decision_recorded: bool,
    pub complete: bool,
    pub incomplete_reasons: Vec<&'static str>,
    /// Optional observers do not change the core decision or its completeness.
    pub supplementary_gaps: Vec<&'static str>,
    /// The content threshold at analysis time, not a fusion threshold.
    /// Absent on old records; do not silently present today's setting as historical.
    pub content_threshold: Option<f64>,
    pub mode: Option<Mode>,
    pub policy_version: Option<String>,
    pub action: Option<Applied>,
    pub subject_tag: SubjectTag,
}

pub fn recorded_threshold(scan: &Scan) -> Option<f64> {
    valid_score(scan.analysis_policy.as_ref().map(|p| p.threshold))
}

pub fn supplementary_gaps(scan: &Scan) -> Vec<&'static str> {
    use crate::protection::Status;
    let mut gaps = Vec::new();
    if let Some(p) = &scan.protection {
        let missing = |s: &Status| {
            !matches!(
                s,
                Status::Complete | Status::Disabled | Status::NotConfigured
            )
        };
        for (name, result) in [("crdf", &p.crdf), ("virustotal", &p.virustotal)] {
            if missing(&result.status) || result.omitted > 0 {
                gaps.push(name);
            }
        }
        if missing(&p.local_status) {
            gaps.push("link_inventory");
        }
        if p.url_resolution.as_ref().is_some_and(|r| {
            r.omitted > 0
                || r.local_inventory_available == Some(false)
                || r.chains.iter().any(|c| !c.complete)
        }) {
            gaps.push("url_resolution");
        }
    }
    if scan.early_rbl.as_ref().is_some_and(|r| {
        r.checks.iter().any(|c| {
            matches!(
                c.status,
                crate::rbl::Status::Unavailable | crate::rbl::Status::Skipped
            )
        })
    }) {
        gaps.push("rbl");
    }
    if scan
        .mailing
        .as_ref()
        .is_some_and(|m| m.status == crate::mailing::Status::Limited)
    {
        gaps.push("mailing");
    }
    gaps
}

pub fn assess(scan: &Scan, fallback_threshold: f64) -> Assessment {
    let decision = scan.decision.as_ref();
    let decision_score = decision
        .filter(|d| d.source != DecisionSource::Antivirus)
        .and_then(|d| valid_score(d.score));
    let raw = valid_score(Some(scan.score));
    let value = decision_score.or(raw);
    let source = if decision_score.is_some() {
        ScoreSource::Decision
    } else if raw.is_some() {
        ScoreSource::Raw
    } else {
        ScoreSource::Unavailable
    };
    let kind = if value.is_none() {
        ScoreKind::Unavailable
    } else if !scan.complete {
        ScoreKind::Partial
    } else if scan.model == "dsn" {
        ScoreKind::Internal
    } else if decision.is_some_and(|d| {
        d.source == DecisionSource::Antivirus || d.outcome == Outcome::Undetermined
    }) {
        ScoreKind::Advisory
    } else if decision_score.is_some()
        && decision.is_some_and(|d| d.source == DecisionSource::Fusion)
    {
        ScoreKind::Decision
    } else {
        ScoreKind::Content
    };
    let model = if decision_score.is_some() {
        &decision.expect("selected decision").model
    } else {
        &scan.model
    };
    let mut incomplete_reasons = Vec::new();
    if !scan.complete {
        incomplete_reasons.extend(
            INCOMPLETE_REASONS
                .iter()
                .copied()
                .filter(|id| scan.reasons.iter().any(|r| r.id == *id)),
        );
        match scan.antivirus.status {
            AntivirusStatus::Unavailable => incomplete_reasons.push("antivirus_unavailable"),
            AntivirusStatus::Unscannable => incomplete_reasons.push("antivirus_unscannable"),
            _ => {}
        }
        if incomplete_reasons.is_empty() {
            incomplete_reasons.push("unspecified");
        }
    }
    Assessment {
        version: VERSION,
        score: Score {
            value,
            raw,
            decision: decision_score,
            kind,
            source,
            model: model.clone(),
            scale: 100,
        },
        category: crate::mailing::category(scan, fallback_threshold),
        classification_source: if scan.delivery_classification.is_some() {
            ClassificationSource::RecipientPolicy
        } else if scan.decision.is_some() {
            ClassificationSource::RecordedDecision
        } else {
            ClassificationSource::HistoricalFallback
        },
        decision: scan.decision.clone().unwrap_or_else(|| {
            Decision::legacy(scan, recorded_threshold(scan).unwrap_or(fallback_threshold))
        }),
        decision_recorded: scan.decision.is_some(),
        complete: scan.complete,
        incomplete_reasons,
        supplementary_gaps: supplementary_gaps(scan),
        content_threshold: recorded_threshold(scan),
        mode: scan.analysis_policy.as_ref().map(|p| p.mode),
        policy_version: scan.analysis_policy.as_ref().map(|p| p.version.clone()),
        action: scan.action.clone(),
        subject_tag: if scan.tagged {
            SubjectTag::Spam
        } else if scan.pub_tagged {
            SubjectTag::Publicity
        } else {
            SubjectTag::None
        },
    }
}
