//! Only explicit heuristic contributions are adjustable; model features are unchanged.
use anyhow::{Result, ensure};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Serialize)]
pub struct Rule {
    pub id: &'static str,
    pub label: &'static str,
    pub weight: f64,
}
pub const CATALOG: &[Rule] = &[
    Rule {
        id: "injected_reward_lure",
        label: "Off-site cryptocurrency reward injected into a subscription profile",
        weight: 1.5,
    },
    Rule {
        id: "urgency",
        label: "Urgency language",
        weight: 0.5,
    },
    Rule {
        id: "credential_request",
        label: "Credential request",
        weight: 1.5,
    },
    Rule {
        id: "financial_lure",
        label: "Suspicious financial promise",
        weight: 1.5,
    },
    Rule {
        id: "html_form",
        label: "Embedded HTML form",
        weight: 1.5,
    },
    Rule {
        id: "idn_url",
        label: "Link to an internationalized domain",
        weight: 0.4,
    },
    Rule {
        id: "ip_url",
        label: "Link using an IP address",
        weight: 1.5,
    },
    Rule {
        id: "reply_to",
        label: "Reply-To domain differs from sender",
        weight: 0.5,
    },
    Rule {
        id: "caps_subject",
        label: "Uppercase subject",
        weight: 0.5,
    },
];
pub fn validate(weights: &BTreeMap<String, f64>) -> Result<()> {
    for (id, weight) in weights {
        ensure!(
            CATALOG.iter().any(|r| r.id == id),
            "Unknown customizable rule: {id}"
        );
        ensure!(
            weight.is_finite() && (0.0..=3.0).contains(weight),
            "Rule weight must be between 0 and 3: {id}"
        );
    }
    Ok(())
}
pub fn apply(scan: &mut crate::engine::Scan, weights: &BTreeMap<String, f64>) {
    // Absolute weights (not multipliers) keep repeated scoring idempotent.
    for reason in &mut scan.reasons {
        if let Some(weight) = weights.get(&reason.id) {
            reason.weight = *weight;
        }
    }
}
