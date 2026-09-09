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
        id: "urgency",
        label: "Vocabulaire d’urgence",
        weight: 0.5,
    },
    Rule {
        id: "credential_request",
        label: "Demande liée aux identifiants",
        weight: 1.5,
    },
    Rule {
        id: "financial_lure",
        label: "Promesse financière suspecte",
        weight: 1.5,
    },
    Rule {
        id: "html_form",
        label: "Formulaire HTML intégré",
        weight: 1.5,
    },
    Rule {
        id: "idn_url",
        label: "Lien vers un domaine internationalisé",
        weight: 0.4,
    },
    Rule {
        id: "ip_url",
        label: "Lien utilisant une adresse IP",
        weight: 1.5,
    },
    Rule {
        id: "reply_to",
        label: "Domaine de réponse différent",
        weight: 0.5,
    },
    Rule {
        id: "caps_subject",
        label: "Objet en majuscules",
        weight: 0.5,
    },
];
pub fn validate(weights: &BTreeMap<String, f64>) -> Result<()> {
    for (id, weight) in weights {
        ensure!(
            CATALOG.iter().any(|r| r.id == id),
            "Règle personnalisable inconnue : {id}"
        );
        ensure!(
            weight.is_finite() && (0.0..=3.0).contains(weight),
            "Poids de règle attendu entre 0 et 3 : {id}"
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
