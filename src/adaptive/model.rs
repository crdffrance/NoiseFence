//! Balanced document-frequency OSB Bayes and a regularized 16×16×5 MLP.
use super::{Class, Policy, SCHEMA, WIDTH, valid_vector};
use crate::native_filter::input::{DIMENSION, Features};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path};
pub const MAX_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Neural {
    pub input_weights: Vec<Vec<f64>>,
    pub hidden_bias: Vec<f64>,
    pub output_weights: Vec<Vec<f64>>,
    pub output_bias: Vec<f64>,
}
pub(crate) fn softmax(logits: [f64; 5]) -> [f64; 5] {
    let max = logits.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let mut p = logits.map(|v| (v - max).exp());
    let total: f64 = p.iter().sum();
    p.iter_mut().for_each(|v| *v /= total);
    p
}
impl Neural {
    pub fn validate(&self) -> Result<()> {
        let bounded =
            |v: &[f64], n| v.len() == n && v.iter().all(|v| v.is_finite() && v.abs() <= 32.0);
        ensure!(
            self.input_weights.len() == WIDTH
                && self.input_weights.iter().all(|v| bounded(v, WIDTH))
                && bounded(&self.hidden_bias, WIDTH)
                && self.output_weights.len() == 5
                && self.output_weights.iter().all(|v| bounded(v, WIDTH))
                && bounded(&self.output_bias, 5),
            "invalid adaptive neural tensor"
        );
        Ok(())
    }
    pub(crate) fn forward(&self, v: &[f64]) -> ([f64; WIDTH], [f64; 5]) {
        let hidden = std::array::from_fn(|h| {
            (self.hidden_bias[h]
                + self.input_weights[h]
                    .iter()
                    .zip(v)
                    .map(|(w, x)| w * x)
                    .sum::<f64>())
            .tanh()
        });
        let p = softmax(std::array::from_fn(|c| {
            self.output_bias[c]
                + self.output_weights[c]
                    .iter()
                    .zip(hidden)
                    .map(|(w, x)| w * x)
                    .sum::<f64>()
        }));
        (hidden, p)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Model {
    pub schema: String,
    pub protocol_sha256: String,
    pub version: String,
    pub scope: String,
    pub created: i64,
    pub expires: i64,
    pub dataset_sha256: String,
    pub classes: [u32; 5],
    pub counts: Vec<(u32, [u32; 5])>,
    pub neural: Neural,
    /// Validation-only lower bounds; 1.0 means abstain for that class.
    pub thresholds: [f64; 5],
}
pub fn winner(p: &[f64; 5]) -> (usize, f64) {
    let mut order = [0, 1, 2, 3, 4];
    order.sort_by(|a, b| p[*b].total_cmp(&p[*a]).then(a.cmp(b)));
    (order[0], p[order[0]] - p[order[1]])
}
impl Model {
    pub fn load(path: &Path) -> Result<(Self, String)> {
        let bytes = crate::native_filter::read_bounded(path, MAX_BYTES)?;
        let model: Self = serde_json::from_slice(&bytes)?;
        model.validate()?;
        Ok((model, crate::message::digest(&bytes)))
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == SCHEMA
                && super::hash(&self.protocol_sha256)
                && super::hash(&self.dataset_sha256)
                && !self.version.is_empty()
                && self.version.len() <= 80
                && self
                    .version
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                && crate::config::valid_domain(&self.scope)
                && self.scope == self.scope.to_ascii_lowercase()
                && self.created > 0
                && self.created <= crate::now()
                && self.expires > self.created
                && self.expires - self.created <= 30 * 86400
                && self.classes.iter().all(|c| (20..=5000).contains(c))
                && self.classes.iter().sum::<u32>() <= 5000
                && self
                    .thresholds
                    .iter()
                    .all(|x| x.is_finite() && (0.5..=1.0).contains(x)),
            "invalid adaptive provenance or support"
        );
        ensure!(
            self.counts.len() <= DIMENSION as usize
                && self.counts.windows(2).all(|w| w[0].0 < w[1].0)
                && self.counts.iter().all(|(id, n)| *id < DIMENSION
                    && n.iter().zip(self.classes).all(|(&n, c)| n <= c)
                    && n.iter().sum::<u32>() >= 2),
            "invalid adaptive Bayes counts"
        );
        self.neural.validate()
    }
    pub fn predict(&self, f: &Features, v: &[f64]) -> Option<([f64; 5], [f64; 5])> {
        if f.validate().is_err() || !valid_vector(v) {
            return None;
        }
        let mut evidence = Vec::new();
        for id in &f.osb {
            if let Ok(index) = self.counts.binary_search_by_key(id, |(id, _)| *id) {
                let n = self.counts[index].1;
                let logs = std::array::from_fn::<_, 5, _>(|c| {
                    ((n[c] as f64 + 1.0) / (self.classes[c] as f64 + 2.0)).ln()
                });
                let mean = logs.iter().sum::<f64>() / 5.0;
                let logs = logs.map(|x| (x - mean).clamp(-4.0, 4.0));
                let spread = logs.iter().copied().fold(f64::NEG_INFINITY, f64::max)
                    - logs.iter().copied().fold(f64::INFINITY, f64::min);
                if spread >= 0.05 {
                    evidence.push((*id, spread, logs));
                }
            }
        }
        if evidence.len() < 5 {
            return None;
        }
        evidence.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));
        let mut total = [0.0; 5];
        for (_, _, logs) in evidence.into_iter().take(150) {
            for c in 0..5 {
                total[c] += logs[c];
            }
        }
        Some((softmax(total), self.neural.forward(v).1))
    }
    pub fn select(
        &self,
        b: &[f64; 5],
        n: &[f64; 5],
        policies: &BTreeMap<Class, Policy>,
    ) -> Option<Class> {
        let (bc, bm) = winner(b);
        let (nc, nm) = winner(n);
        if bc != nc {
            return None;
        }
        let class = super::CLASSES[bc];
        let policy = policies.get(&class).cloned().unwrap_or_default();
        (b[bc].min(n[nc]) > self.thresholds[bc].max(policy.min_strength)
            && bm.min(nm) >= policy.min_margin)
            .then_some(class)
    }
}
