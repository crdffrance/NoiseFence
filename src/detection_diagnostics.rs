//! Bounded score accounting from retained observations. Never exposes tokens,
//! hashed feature buckets, addresses, subjects or provider response text.
use crate::{
    engine::{Scan, SemanticStatus},
    fusion::runtime::Outcome,
};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Serialize)]
pub struct Breakdown {
    pub families: BTreeMap<&'static str, Option<f64>>,
    pub reconstructed_score: Option<f64>,
    pub matches_recorded_score: bool,
    pub saturated: bool,
}
fn finite(value: Option<f64>) -> Option<f64> {
    value.filter(|v| v.is_finite())
}
pub fn breakdown(scan: &Scan) -> Breakdown {
    let mut families = BTreeMap::from([
        ("heuristics", Some(0.)),
        ("authentication", Some(0.)),
        ("reputation", Some(0.)),
        ("smtp", Some(0.)),
        ("llm", Some(0.)),
        ("other_rules", Some(0.)),
    ]);
    let semantic = match scan.semantic.status {
        SemanticStatus::Disabled => Some(0.),
        SemanticStatus::Complete => finite(scan.semantic.contribution),
        _ => None,
    };
    let contributions: Vec<_> = scan
        .reasons
        .iter()
        .filter(|r| r.id == "model_contribution")
        .collect();
    let content = (contributions.len() == 1)
        .then(|| contributions[0].weight)
        .filter(|v| v.is_finite());
    let lexical = finite(scan.evidence.as_ref().and_then(|e| e.lexical_logit))
        .or_else(|| Some(content? - semantic?));
    if let (Some(lexical), Some(semantic)) = (lexical, semantic) {
        families.insert("lexical", Some(lexical));
        families.insert("semantic", Some(semantic));
    } else {
        // A combined historical contribution can be known without its split.
        families.insert("content_unseparated", content);
    }
    for reason in &scan.reasons {
        if reason.id == "model_contribution" {
            continue;
        }
        let family = match reason.id.as_str() {
            "llm_advisory" => "llm",
            "spf_fail" | "dmarc_fail" => "authentication",
            "ip_reputation" | "domain_reputation" | "abused_domain_body" => "reputation",
            "smtp_policy_contribution" => "smtp",
            id if crate::rules::CATALOG.iter().any(|r| r.id == id) => "heuristics",
            _ => "other_rules",
        };
        let entry = families.get_mut(family).unwrap();
        *entry = entry.and_then(|v| finite(Some(v + reason.weight)));
    }
    let total = families
        .values()
        .try_fold(0., |sum, v| finite(Some(sum + (*v)?)))
        .filter(|_| contributions.len() <= 1);
    let score = total.map(|total| crate::engine::sigmoid(total) * 100.);
    let tolerance = if scan.feature_version == crate::features::VERSION {
        1e-6
    } else {
        0.051
    };
    Breakdown {
        matches_recorded_score: scan.score.is_finite()
            && score.is_some_and(|s| (s - scan.score).abs() <= tolerance),
        saturated: scan.score.is_finite() && !(1. ..99.).contains(&scan.score),
        reconstructed_score: score,
        families,
    }
}

#[derive(Default, Serialize)]
pub struct Statistic {
    pub observations: usize,
    pub total_logit: f64,
    pub minimum: Option<f64>,
    pub maximum: Option<f64>,
}
impl Statistic {
    fn add(&mut self, value: f64) {
        self.observations += 1;
        self.total_logit += value;
        self.minimum = Some(self.minimum.map_or(value, |v| v.min(value)));
        self.maximum = Some(self.maximum.map_or(value, |v| v.max(value)));
    }
}
#[derive(Default, Serialize)]
pub struct Slice {
    pub messages: usize,
    pub saturated: usize,
    pub reconstructed: usize,
    pub unreconciled_or_missing: usize,
    pub families: BTreeMap<&'static str, Statistic>,
}
#[derive(Default, Serialize)]
pub struct Audit {
    pub slices: BTreeMap<&'static str, Slice>,
    pub second_opinion: SecondOpinion,
}
#[derive(Default, Serialize)]
pub struct SecondOpinion {
    pub evaluated: usize,
    pub unavailable_or_not_selected: usize,
    pub counts: crate::confirmation::Counts,
    pub status_counts: BTreeMap<String, usize>,
    pub accounted_micro_eur: u64,
    pub missing_accounting: usize,
    pub elapsed_ms_total: u64,
    pub elapsed_ms_maximum: u64,
}
impl Audit {
    pub fn add(&mut self, scan: &Scan, spam: bool) {
        let advice = &mut self.second_opinion;
        // Enum serialization yields a fixed identifier, never provider text.
        let status = serde_json::to_value(&scan.llm.status).unwrap();
        *advice
            .status_counts
            .entry(status.as_str().unwrap().into())
            .or_default() += 1;
        if let Some(outcome) = scan.llm.opinion() {
            advice.evaluated += 1;
            advice.counts.add(outcome, spam);
        } else {
            advice.unavailable_or_not_selected += 1;
        }
        if let Some(cost) = scan.llm.accounted_micro_eur {
            advice.accounted_micro_eur = advice.accounted_micro_eur.saturating_add(cost);
        } else {
            advice.missing_accounting += 1;
        }
        advice.elapsed_ms_total = advice.elapsed_ms_total.saturating_add(scan.llm.elapsed_ms);
        advice.elapsed_ms_maximum = advice.elapsed_ms_maximum.max(scan.llm.elapsed_ms);
        let Some(decision) = &scan.decision else {
            return;
        };
        let name = match (decision.outcome, spam) {
            (Outcome::Unwanted, true) => "spam_detected",
            (Outcome::Unwanted, false) => "false_positive",
            (Outcome::Undetermined, true) => "spam_to_review",
            (Outcome::Undetermined, false) => "legitimate_to_review",
            (Outcome::Legitimate, true) => "spam_missed",
            (Outcome::Legitimate, false) => "legitimate",
        };
        let slice = self.slices.entry(name).or_default();
        slice.messages += 1;
        let report = breakdown(scan);
        slice.saturated += usize::from(report.saturated);
        if !report.matches_recorded_score {
            slice.unreconciled_or_missing += 1;
            return;
        }
        slice.reconstructed += 1;
        for (family, value) in report.families {
            if let Some(value) = value {
                slice.families.entry(family).or_default().add(value);
            }
        }
    }
}
