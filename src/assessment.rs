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
use serde::{Deserialize, Serialize};

pub const VERSION: u8 = 1;
pub const INCOMPLETE_REASONS: &[&str] = &[
    "score_combination_invalid",
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

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScoreKind {
    Unavailable,
    Partial,
    Internal,
    Advisory,
    Decision,
    Content,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScoreSource {
    Unavailable,
    Decision,
    Raw,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClassificationSource {
    ScoreThreshold,
    RecipientPolicy,
    RecordedDecision,
    HistoricalFallback,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SubjectTag {
    None,
    Spam,
    Publicity,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Score {
    pub value: Option<f64>,
    pub raw: Option<f64>,
    pub decision: Option<f64>,
    pub kind: ScoreKind,
    pub source: ScoreSource,
    pub model: String,
    pub scale: u8,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Assessment {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score_boundary: Option<crate::score_boundary::Boundary>,
    pub score_resolution: Option<crate::decision::ScoreResolution>,
    pub version: u8,
    pub score: Score,
    pub category: Category,
    pub classification_source: ClassificationSource,
    pub decision: Decision,
    pub decision_recorded: bool,
    pub complete: bool,
    pub incomplete_reasons: Vec<String>,
    /// Optional observers do not change the core decision or its completeness.
    pub supplementary_gaps: Vec<String>,
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
    if let Some(record) = &scan.recipient_decision {
        return record.assessment.clone();
    }
    assess_unrecorded(scan, fallback_threshold)
}

/// History never borrows today's threshold or resolves yesterday's abstentions.
/// Very old rows without a recorded decision/policy remain explicitly unknown.
pub fn historical(scan: &Scan) -> Assessment {
    let mut view = assess(scan, f64::NAN);
    if scan.recipient_decision.is_none()
        && scan.decision.is_none()
        && recorded_threshold(scan).is_none()
    {
        view.decision.outcome = Outcome::Undetermined;
        view.category = scan
            .delivery_classification
            .unwrap_or(Category::Undetermined);
    }
    view
}

/// Shared SQL projection for list filters and statistics. Keep in parity with
/// `historical` using receipt/legacy matrix tests; never accept a live threshold.
pub(crate) fn category_sql() -> String {
    format!(
        "CASE WHEN json_type(m.scan,'$.recipient_decision')='object' THEN COALESCE(json_extract(m.scan,'$.recipient_decision.assessment.category'),'undetermined') WHEN json_extract(m.scan,'$.delivery_classification') IS NOT NULL THEN json_extract(m.scan,'$.delivery_classification') WHEN json_extract(m.scan,'$.decision.outcome')='unwanted' THEN 'spam' WHEN json_extract(m.scan,'$.decision.outcome')='legitimate' THEN CASE WHEN json_extract(m.scan,'$.complete')=1 AND {signal} THEN 'publicity' ELSE 'legitimate' END WHEN json_extract(m.scan,'$.decision.outcome') IS NULL AND json_extract(m.scan,'$.complete')=1 AND json_extract(m.scan,'$.analysis_policy.threshold') BETWEEN 0 AND 100 THEN CASE WHEN json_extract(m.scan,'$.score')>=json_extract(m.scan,'$.analysis_policy.threshold') THEN 'spam' WHEN {signal} THEN 'publicity' ELSE 'legitimate' END ELSE 'undetermined' END",
        signal = crate::mailing::SIGNAL_SQL
    )
}

/// Build the receipt-time snapshot. Read-side consumers must use `assess`.
pub(crate) fn assess_unrecorded(scan: &Scan, fallback_threshold: f64) -> Assessment {
    let decision = scan.decision.as_ref();
    let decision_score = decision
        .filter(|d| d.source != DecisionSource::Antivirus)
        .and_then(|d| valid_score(d.score));
    let raw = if scan.features_complete == Some(false)
        || scan
            .score_resolution
            .as_ref()
            .is_some_and(|r| r.score.is_none())
    {
        None
    } else {
        valid_score(Some(scan.score))
    };
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
    let mut view = Assessment {
        score_boundary: None,
        score_resolution: scan.score_resolution.clone(),
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
        } else if scan.score_resolution.is_some() {
            ClassificationSource::ScoreThreshold
        } else if scan.decision.is_some() {
            ClassificationSource::RecordedDecision
        } else {
            ClassificationSource::HistoricalFallback
        },
        decision: scan.decision.clone().unwrap_or_else(|| {
            Decision::legacy(scan, recorded_threshold(scan).unwrap_or(fallback_threshold))
        }),
        decision_recorded: scan.decision.is_some()
            && !scan.score_resolution.as_ref().is_some_and(|r| r.projected),
        complete: scan.complete,
        incomplete_reasons: incomplete_reasons.into_iter().map(str::to_owned).collect(),
        supplementary_gaps: supplementary_gaps(scan)
            .into_iter()
            .map(str::to_owned)
            .collect(),
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
    };
    view.score_boundary =
        crate::score_boundary::selected(scan, &view.score, view.content_threshold);
    view
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn history_sql_and_rust_have_identical_categories() {
        let db = rusqlite::Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE messages(scan TEXT NOT NULL)")
            .unwrap();
        let cases: Vec<serde_json::Value> =
            serde_json::from_str(include_str!("../tests/fixtures/assessment.json")).unwrap();
        for case in cases {
            let mut data = serde_json::to_value(Scan::default()).unwrap();
            for (key, value) in case["scan"].as_object().unwrap() {
                data[key] = value.clone();
            }
            let mut scan: Scan = serde_json::from_value(data).unwrap();
            let cfg = crate::config::Config::load(std::path::Path::new("config/development.toml"))
                .unwrap();
            for receipt in [false, true] {
                if receipt {
                    crate::decision_record::record_recipient(&mut scan, &cfg, None, 1);
                }
                db.execute("DELETE FROM messages", []).unwrap();
                db.execute(
                    "INSERT INTO messages VALUES (?1)",
                    [serde_json::to_string(&scan).unwrap()],
                )
                .unwrap();
                let sql: String = db
                    .query_row(
                        &format!("SELECT ({}) FROM messages m", category_sql()),
                        [],
                        |r| r.get(0),
                    )
                    .unwrap();
                assert_eq!(
                    sql,
                    historical(&scan).category.as_str(),
                    "{} / receipt={receipt}",
                    case["name"]
                );
            }
        }
    }
}
