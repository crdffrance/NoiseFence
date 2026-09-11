//! Rust OSB document-frequency Bayes, trained only from explicit human labels.
use super::input::{DIMENSION, Features, PROTOCOL};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Read,
    path::Path,
};

pub const SCHEMA: &str = "noisefence-osb-model-1";
pub const MAX_MODEL_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Example {
    pub scope: String,
    pub id: String,
    pub observed_at: i64,
    pub labelled_at: i64,
    pub spam: bool,
    pub features: Features,
}
impl Example {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            crate::config::valid_domain(&self.scope)
                && self.scope == self.scope.to_ascii_lowercase()
                && self.id.len() == 64
                && self.id.bytes().all(|b| b.is_ascii_hexdigit())
                && self.observed_at > 0
                && self.labelled_at >= self.observed_at
                && self.labelled_at <= crate::now(),
            "invalid native learning example"
        );
        self.features.validate()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Model {
    pub schema: String,
    pub protocol: String,
    pub version: String,
    pub scope: String,
    pub created: i64,
    pub expires: i64,
    pub training_sha256: String,
    pub classes: [u32; 2],
    /// (feature id, legitimate document count, spam document count).
    pub counts: Vec<(u32, u32, u32)>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Prediction {
    pub status: String,
    pub model: Option<String>,
    pub raw_log_odds: Option<f64>,
    pub matched_features: usize,
    /// OSB likelihoods are not calibrated probabilities of abuse.
    pub calibrated: bool,
}
impl Default for Prediction {
    fn default() -> Self {
        Self {
            status: "untrained".into(),
            model: None,
            raw_log_odds: None,
            matched_features: 0,
            calibrated: false,
        }
    }
}
impl Model {
    pub fn load(path: &Path) -> Result<(Self, String)> {
        let bytes = super::read_bounded(path, MAX_MODEL_BYTES)?;
        let model: Self = serde_json::from_slice(&bytes)?;
        model.validate()?;
        ensure!(model.expires > crate::now(), "expired OSB model");
        Ok((model, crate::message::digest(&bytes)))
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == SCHEMA
                && self.protocol == PROTOCOL
                && !self.version.is_empty()
                && self.version.len() <= 80
                && self
                    .version
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c)),
            "invalid OSB model protocol/version"
        );
        ensure!(
            crate::config::valid_domain(&self.scope)
                && self.scope == self.scope.to_ascii_lowercase()
                && self.created > 0
                && self.created <= crate::now()
                && self.expires > self.created
                && self.expires - self.created <= 30 * 86400
                && self.classes.iter().all(|&n| (2..=50_000).contains(&n))
                && self.training_sha256.len() == 64
                && self.training_sha256.bytes().all(|c| c.is_ascii_hexdigit()),
            "invalid OSB model provenance"
        );
        ensure!(
            self.counts.len() <= DIMENSION as usize
                && self.counts.windows(2).all(|w| w[0].0 < w[1].0)
                && self.counts.iter().all(|&(id, ham, spam)| id < DIMENSION
                    && ham <= self.classes[0]
                    && spam <= self.classes[1]
                    && ham + spam >= 2),
            "invalid OSB document counts"
        );
        Ok(())
    }
    pub fn fit(examples: &[Example], version: &str, training_sha256: String) -> Result<Self> {
        ensure!(
            !examples.is_empty() && examples.len() <= 50_000,
            "invalid OSB training size"
        );
        let scope = examples[0].scope.clone();
        let mut seen = BTreeSet::new();
        let mut classes = [0u32; 2];
        let mut counts: BTreeMap<u32, [u32; 2]> = BTreeMap::new();
        for example in examples {
            example.validate()?;
            ensure!(
                example.scope == scope && seen.insert(&example.features.fingerprint),
                "mixed scopes or duplicate training campaigns"
            );
            let class = usize::from(example.spam);
            classes[class] += 1;
            for feature in &example.features.osb {
                counts.entry(*feature).or_default()[class] += 1;
            }
        }
        let model = Self {
            schema: SCHEMA.into(),
            protocol: PROTOCOL.into(),
            version: version.into(),
            scope,
            created: crate::now(),
            expires: crate::now() + 30 * 86400,
            training_sha256,
            classes,
            counts: counts
                .into_iter()
                .filter(|(_, n)| n[0] + n[1] >= 2)
                .map(|(id, n)| (id, n[0], n[1]))
                .collect(),
        };
        model.validate()?;
        Ok(model)
    }
    pub fn predict(&self, features: &Features, scopes: &[String], now: i64) -> Prediction {
        let mut result = Prediction {
            model: Some(self.version.clone()),
            ..Default::default()
        };
        result.status = if now >= self.expires {
            "expired"
        } else if scopes.len() != 1 || scopes[0] != self.scope {
            "scope_mismatch"
        } else if features.validate().is_err() {
            "incompatible"
        } else {
            "complete"
        }
        .into();
        if result.status != "complete" {
            return result;
        }
        let mut evidence = Vec::new();
        for id in &features.osb {
            if let Ok(index) = self.counts.binary_search_by_key(id, |&(id, _, _)| id) {
                let (_, ham, spam) = self.counts[index];
                let p_ham = (ham as f64 + 1.0) / (self.classes[0] as f64 + 2.0);
                let p_spam = (spam as f64 + 1.0) / (self.classes[1] as f64 + 2.0);
                let weight = (p_spam / p_ham).ln().clamp(-4.0, 4.0);
                if weight.abs() >= 0.05 {
                    evidence.push((*id, weight));
                }
            }
        }
        // Equal class priors avoid inheriting the reviewer/corpus spam prevalence.
        // Presence-only evidence and a fixed 150-feature budget bound repetitions.
        evidence.sort_by(|a, b| b.1.abs().total_cmp(&a.1.abs()).then(a.0.cmp(&b.0)));
        evidence.truncate(150);
        result.matched_features = evidence.len();
        if evidence.len() < 5 {
            result.status = "insufficient_features".into();
        } else {
            result.raw_log_odds = Some(evidence.iter().map(|(_, w)| w).sum());
        }
        result
    }
}

pub fn read_examples(path: &Path) -> Result<(Vec<Example>, String)> {
    use std::io::{BufRead, BufReader};
    let mut reader = BufReader::new(File::open(path)?);
    let mut rows = Vec::new();
    let mut bytes = Vec::new();
    let mut total = 0usize;
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    loop {
        bytes.clear();
        let count = reader
            .by_ref()
            .take(128 * 1024 + 1)
            .read_until(b'\n', &mut bytes)?;
        if count == 0 {
            break;
        }
        total += count;
        ensure!(
            count <= 128 * 1024 && total <= 512 * 1024 * 1024 && rows.len() < 50_000,
            "native dataset size limit"
        );
        digest.update(&bytes);
        let row: Example = serde_json::from_slice(&bytes)?;
        row.validate()?;
        rows.push(row);
    }
    Ok((rows, hex::encode(digest.finalize())))
}
