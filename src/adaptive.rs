//! Independent Rust category classifiers. Observation only; never a delivery vote.
pub mod data;
pub mod model;
#[cfg(test)]
mod tests;
pub mod training;

use crate::native_filter::{input::Input, rules::Symbol};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::PathBuf};

pub const SCHEMA: &str = "noisefence-adaptive-1";
pub const WIDTH: usize = 16;
pub const CLASSES: [Class; 5] = [
    Class::Legitimate,
    Class::Publicity,
    Class::Spam,
    Class::Phishing,
    Class::Scam,
];
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Class {
    Legitimate,
    Publicity,
    Spam,
    Phishing,
    Scam,
}
impl Class {
    pub fn index(self) -> usize {
        CLASSES.iter().position(|&c| c == self).unwrap()
    }
    pub fn as_str(self) -> &'static str {
        ["legitimate", "publicity", "spam", "phishing", "scam"][self.index()]
    }
}
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ProposedAction {
    #[default]
    Observe,
    Tag,
    Quarantine,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    pub min_strength: f64,
    pub min_margin: f64,
    pub proposed_action: ProposedAction,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            min_strength: 0.9,
            min_margin: 0.2,
            proposed_action: ProposedAction::Observe,
        }
    }
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Tenant {
    pub model: Option<PathBuf>,
    pub classes: BTreeMap<Class, Policy>,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub domains: BTreeMap<String, Tenant>,
}
impl Settings {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.domains.len() <= 16,
            "at most 16 adaptive tenants per process"
        );
        for (domain, tenant) in &self.domains {
            ensure!(
                crate::config::valid_domain(domain) && *domain == domain.to_ascii_lowercase(),
                "invalid adaptive domain"
            );
            for (&class, policy) in &tenant.classes {
                ensure!(
                    policy.min_strength.is_finite()
                        && (0.5..=1.0).contains(&policy.min_strength)
                        && policy.min_margin.is_finite()
                        && (0.0..=1.0).contains(&policy.min_margin),
                    "invalid adaptive class policy"
                );
                ensure!(
                    class != Class::Legitimate || policy.proposed_action == ProposedAction::Observe,
                    "legitimate category cannot propose a punitive action"
                );
            }
        }
        Ok(())
    }
}

// Fixed, local inputs. No model verdicts, composites, learned reputation, LLM
// results, sender identity or human labels can feed this neural classifier.
const SYMBOLS: [&str; 6] = [
    "NF_URGENCY",
    "NF_CREDENTIALS",
    "NF_FINANCIAL",
    "NF_WALLET_SECRET",
    "NF_FORM",
    "NF_UNSUBSCRIBE",
];
pub fn protocol(patterns: &[crate::native_filter::rules::Pattern]) -> String {
    crate::message::digest(
        &serde_json::to_vec(&(
            SCHEMA,
            crate::native_filter::input::PROTOCOL,
            SYMBOLS,
            patterns,
        ))
        .unwrap(),
    )
}
pub fn vector(input: &Input, symbols: &[Symbol]) -> Vec<f64> {
    let mut v = vec![0.0; WIDTH];
    v[0] = input.features.osb.len() as f64 / 8192.0;
    v[1] = input.features.text_shingles as f64 / 2048.0;
    v[2] = input.features.html_shingles as f64 / 2048.0;
    v[3] = f64::from(!input.html.is_empty());
    for (i, id) in SYMBOLS.iter().enumerate() {
        v[4 + i] = f64::from(symbols.iter().any(|s| s.id == *id));
    }
    v[10] = (input.body.len() as f64).ln_1p() / 15.0;
    v[11] = (input.subject.chars().count() as f64 / 200.0).min(1.0);
    let count = input.body.chars().count().max(1) as f64;
    v[12] = input.body.chars().filter(|c| c.is_uppercase()).count() as f64 / count;
    v[13] = input.body.chars().filter(|c| c.is_ascii_digit()).count() as f64 / count;
    v[14] = (input.body.matches("https://").count() as f64 / 20.0).min(1.0);
    v[15] = (input.body.matches('!').count() as f64 / 20.0).min(1.0);
    v.iter_mut().for_each(|x| *x = x.clamp(0.0, 1.0));
    v
}
pub fn valid_vector(v: &[f64]) -> bool {
    v.len() == WIDTH && v.iter().all(|x| x.is_finite() && (0.0..=1.0).contains(x))
}
pub(crate) fn hash(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Report {
    pub schema: String,
    pub protocol_sha256: String,
    pub status: String,
    pub model: Option<String>,
    pub model_sha256: Option<String>,
    pub bayes_strengths: Option<[f64; 5]>,
    pub neural_strengths: Option<[f64; 5]>,
    pub category: Option<Class>,
    pub proposed_action: Option<ProposedAction>,
    pub calibrated: bool,
    pub affects_delivery: bool,
}
pub struct Runtime {
    settings: Settings,
    protocol: String,
    models: BTreeMap<String, (model::Model, String)>,
}
impl Runtime {
    pub fn new(
        settings: Settings,
        patterns: &[crate::native_filter::rules::Pattern],
    ) -> Result<Self> {
        settings.validate()?;
        let protocol = protocol(patterns);
        let mut models = BTreeMap::new();
        for (domain, tenant) in &settings.domains {
            if let Some(path) = &tenant.model {
                let (model, sha) = model::Model::load(path)?;
                ensure!(
                    model.scope == *domain && model.protocol_sha256 == protocol,
                    "adaptive artifact domain/protocol mismatch"
                );
                models.insert(domain.clone(), (model, sha));
            }
        }
        Ok(Self {
            settings,
            protocol,
            models,
        })
    }
    pub fn predict(
        &self,
        input: &Input,
        symbols: &[Symbol],
        scopes: &[String],
    ) -> (Report, Option<Vec<f64>>) {
        let mut report = Report {
            schema: SCHEMA.into(),
            protocol_sha256: self.protocol.clone(),
            status: "scope_unavailable".into(),
            model: None,
            model_sha256: None,
            bayes_strengths: None,
            neural_strengths: None,
            category: None,
            proposed_action: None,
            calibrated: false,
            affects_delivery: false,
        };
        // One observation is visible to every authorized recipient. Never expose
        // another tenant's model, class policy or predictions on a shared message.
        let [scope] = scopes else {
            return (report, None);
        };
        let Some(tenant) = self.settings.domains.get(scope) else {
            return (report, None);
        };
        let v = vector(input, symbols);
        report.status = "untrained".into();
        if let Some((model, sha)) = self.models.get(scope) {
            report.model = Some(model.version.clone());
            report.model_sha256 = Some(sha.clone());
            report.status = if crate::now() >= model.expires {
                "expired"
            } else {
                "insufficient_features"
            }
            .into();
            if crate::now() < model.expires
                && let Some((bayes, neural)) = model.predict(&input.features, &v)
            {
                let class = model.select(&bayes, &neural, &tenant.classes);
                report.status = if class.is_some() {
                    "agreement"
                } else {
                    "abstained"
                }
                .into();
                report.bayes_strengths = Some(bayes);
                report.neural_strengths = Some(neural);
                report.category = class;
                report.proposed_action = class.map(|c| {
                    tenant
                        .classes
                        .get(&c)
                        .cloned()
                        .unwrap_or_default()
                        .proposed_action
                });
            }
        }
        (report, Some(v))
    }
}
