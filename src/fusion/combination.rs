//! Model-bound family limits in native log-odds units. These are not native-rule
//! points and never modify an already fitted legacy fusion model implicitly.
use super::Feature;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const SCHEMA: &str = "noisefence-fusion-family-caps-1";
pub const FAMILIES: [&str; 8] = [
    "lexical",
    "semantic",
    "authentication",
    "smtp_policy",
    "reputation",
    "antivirus",
    "signatures",
    "llm",
];
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limit {
    pub minimum: f64,
    pub maximum: f64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub schema: String,
    pub families: BTreeMap<String, Limit>,
}
impl Policy {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == SCHEMA && self.families.len() == FAMILIES.len(),
            "Unsupported fusion family-cap policy"
        );
        for name in FAMILIES {
            let limit = self
                .families
                .get(name)
                .ok_or_else(|| anyhow::anyhow!("Missing fusion family limit"))?;
            ensure!(
                limit.minimum.is_finite()
                    && limit.maximum.is_finite()
                    && (-32. ..=0.).contains(&limit.minimum)
                    && (0. ..=32.).contains(&limit.maximum),
                "Fusion family limits must contain zero and stay within -32..32 log-odds"
            );
        }
        Ok(())
    }
    pub fn sha256(&self) -> String {
        crate::message::digest(&serde_json::to_vec(self).expect("validated family policy"))
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Family {
    pub raw: f64,
    pub retained: f64,
    pub minimum: f64,
    pub maximum: f64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Accounting {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_sha256: Option<String>,
    pub version: String,
    pub policy_sha256: String,
    pub bias: f64,
    pub families: BTreeMap<String, Family>,
    pub total_logit: f64,
}
/// Returns the real logit and per-feature retained contributions. Family totals
/// are capped before calibration; the same function serves runtime and CLI.
pub fn apply(
    policy: &Policy,
    specs: &[Feature],
    values: &[f64],
    weights: &[f64],
    bias: f64,
) -> Result<(Accounting, Vec<f64>)> {
    policy.validate()?;
    ensure!(
        specs.len() == values.len() && values.len() == weights.len() && bias.is_finite(),
        "Invalid fusion combination dimensions"
    );
    let mut families: BTreeMap<_, _> = policy
        .families
        .iter()
        .map(|(name, limit)| {
            (
                name.clone(),
                Family {
                    raw: 0.,
                    retained: 0.,
                    minimum: limit.minimum,
                    maximum: limit.maximum,
                },
            )
        })
        .collect();
    let mut products = Vec::with_capacity(values.len());
    for ((spec, value), weight) in specs.iter().zip(values).zip(weights) {
        let product = value * weight;
        ensure!(product.is_finite(), "Nonfinite fusion contribution");
        let family = families
            .get_mut(&spec.family)
            .ok_or_else(|| anyhow::anyhow!("Unsupported fusion feature family"))?;
        family.raw += product;
        ensure!(family.raw.is_finite(), "Fusion family overflow");
        products.push(product);
    }
    let mut total_logit = bias;
    for name in FAMILIES {
        let family = families.get_mut(name).unwrap();
        family.retained = family.raw.clamp(family.minimum, family.maximum);
        total_logit += family.retained;
    }
    ensure!(total_logit.is_finite(), "Fusion logit overflow");
    for (spec, product) in specs.iter().zip(&mut products) {
        let family = &families[&spec.family];
        if family.raw != family.retained {
            // Signed contributions retain their relative attribution. The actual
            // decision uses the family total, never the rounded displayed rows.
            *product *= family.retained / family.raw;
        }
    }
    let policy_sha256 = policy.sha256();
    Ok((
        Accounting {
            model_sha256: None,
            version: SCHEMA.into(),
            policy_sha256,
            bias,
            families,
            total_logit,
        },
        products,
    ))
}
