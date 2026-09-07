//! Optional, offline, pinned E5 inference. No model-hub client or executable weights.
use anyhow::{Context, Result, ensure};
use candle_core::{DType, Device, Tensor};
use candle_nn::VarBuilder;
use candle_transformers::models::bert::{BertModel, Config};
use serde::Deserialize;
use std::{io::Read, path::Path};
use tokenizers::{Tokenizer, TruncationParams};

pub use crate::learning::{DIMENSION, ENCODER_ID, ENCODER_REVISION, MAX_TOKENS};

#[derive(Deserialize)]
struct Artifact {
    path: String,
    size: u64,
    sha256: String,
}
#[derive(Deserialize)]
struct Lock {
    artifacts: Vec<Artifact>,
}

fn verified_bytes(directory: &Path, name: &str) -> Result<Vec<u8>> {
    let lock: Lock = serde_json::from_str(include_str!("../research/encoder-runtime.lock.json"))?;
    let record = lock
        .artifacts
        .iter()
        .find(|a| a.path == name)
        .context("unknown encoder artifact")?;
    let path = directory.join(name);
    let file = std::fs::File::open(&path)?;
    ensure!(
        file.metadata()?.len() == record.size,
        "encoder artifact size mismatch: {name}"
    );
    let mut bytes = Vec::with_capacity(record.size as usize);
    file.take(record.size + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == record.size,
        "encoder artifact changed while reading: {name}"
    );
    ensure!(
        crate::message::digest(&bytes) == record.sha256,
        "encoder artifact checksum mismatch: {name}"
    );
    Ok(bytes)
}

pub struct Encoder {
    model: BertModel,
    tokenizer: Tokenizer,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Combination {
    pub schema: String,
    pub version: String,
    pub lexical_model_sha256: String,
    pub encoder: String,
    pub revision: String,
    pub text_schema: u32,
    pub max_tokens: usize,
    pub head_weights: Vec<f64>,
    pub head_bias: f64,
    pub semantic_weight: f64,
    pub score_bias_delta: f64,
    pub threshold: f64,
}
impl Combination {
    pub fn validate(&self, lexical_hash: &str, threshold: f64) -> Result<()> {
        ensure!(
            self.schema == "noisefence-hybrid-1"
                && self.encoder == ENCODER_ID
                && self.revision == ENCODER_REVISION
                && self.text_schema == crate::features::VERSION
                && self.max_tokens == MAX_TOKENS,
            "incompatible semantic model schema or encoder"
        );
        ensure!(
            self.lexical_model_sha256 == lexical_hash && self.threshold == threshold,
            "semantic combination does not match lexical model or operating threshold"
        );
        ensure!(
            self.head_weights.len() == DIMENSION
                && self.head_weights.iter().all(|x| x.is_finite())
                && self.head_bias.is_finite()
                && self.semantic_weight.is_finite()
                && (0.0..=2.0).contains(&self.semantic_weight)
                && self.score_bias_delta.is_finite(),
            "invalid semantic coefficients"
        );
        ensure!(
            !self.version.is_empty()
                && self.version.len() <= 100
                && self
                    .version
                    .bytes()
                    .all(|x| x.is_ascii_alphanumeric() || b"-_.".contains(&x)),
            "invalid semantic model version"
        );
        Ok(())
    }
}

pub struct Hybrid {
    encoder: Encoder,
    combination: Combination,
    slots: std::sync::Arc<tokio::sync::Semaphore>,
    timeout: std::time::Duration,
}
impl Hybrid {
    pub fn version(&self) -> &str {
        &self.combination.version
    }
    pub fn load(
        config: &crate::config::SemanticFilter,
        lexical: &Path,
        threshold: f64,
    ) -> Result<Self> {
        ensure!(
            std::fs::metadata(&config.combination)?.len() <= 64 * 1024,
            "oversized semantic manifest"
        );
        let combination: Combination =
            serde_json::from_slice(&std::fs::read(&config.combination)?)?;
        combination.validate(&crate::message::digest(&std::fs::read(lexical)?), threshold)?;
        ensure!(
            (1..=2).contains(&config.max_parallel) && (50..=5000).contains(&config.timeout_ms),
            "invalid semantic limits"
        );
        let encoder = Encoder::load(&config.encoder_dir)?;
        Ok(Self {
            encoder,
            combination,
            slots: std::sync::Arc::new(tokio::sync::Semaphore::new(config.max_parallel)),
            timeout: std::time::Duration::from_millis(config.timeout_ms),
        })
    }
    fn outcome(&self, status: crate::engine::SemanticStatus) -> crate::engine::SemanticResult {
        crate::engine::SemanticResult {
            status,
            model: self.combination.version.clone(),
            encoder: ENCODER_ID.into(),
            protocol: Some(crate::learning::SemanticProtocol::pinned()),
            ..Default::default()
        }
    }
    fn infer(&self, raw: &[u8]) -> Result<crate::engine::SemanticResult> {
        let (subject, body) = crate::features::text(raw).context("semantic text unavailable")?;
        let (_, vector) = self.encoder.embed(&subject, &body)?;
        let logit = vector
            .iter()
            .zip(&self.combination.head_weights)
            .map(|(x, w)| f64::from(*x) * w)
            .sum::<f64>()
            + self.combination.head_bias;
        let contribution =
            self.combination.semantic_weight * logit + self.combination.score_bias_delta;
        ensure!(
            logit.is_finite() && contribution.is_finite(),
            "non-finite semantic contribution"
        );
        Ok(crate::engine::SemanticResult {
            logit: Some(logit),
            contribution: Some(contribution),
            features: vector,
            ..self.outcome(crate::engine::SemanticStatus::Complete)
        })
    }
    pub fn offline(&self, raw: &[u8]) -> crate::engine::SemanticResult {
        let started = std::time::Instant::now();
        let Ok(_permit) = self.slots.try_acquire() else {
            return self.outcome(crate::engine::SemanticStatus::Busy);
        };
        let mut result = self
            .infer(raw)
            .unwrap_or_else(|_| self.outcome(crate::engine::SemanticStatus::Unavailable));
        result.elapsed_ms = started.elapsed().as_millis() as u64;
        result
    }
    pub async fn analyze(
        self: &std::sync::Arc<Self>,
        raw: Vec<u8>,
    ) -> crate::engine::SemanticResult {
        let started = std::time::Instant::now();
        let model = self.clone();
        let result = bounded(self.slots.clone(), self.timeout, move || model.infer(&raw)).await;
        let mut result = match result {
            Ok(result) => result,
            Err(status) => self.outcome(status),
        };
        result.elapsed_ms = started.elapsed().as_millis() as u64;
        result
    }
}

async fn bounded<T: Send + 'static>(
    slots: std::sync::Arc<tokio::sync::Semaphore>,
    timeout: std::time::Duration,
    work: impl FnOnce() -> Result<T> + Send + 'static,
) -> std::result::Result<T, crate::engine::SemanticStatus> {
    use crate::engine::SemanticStatus;
    let permit = slots
        .try_acquire_owned()
        .map_err(|_| SemanticStatus::Busy)?;
    let task = tokio::task::spawn_blocking(move || {
        // Cancellation of the async waiter must not release the CPU slot early.
        let _permit = permit;
        work()
    });
    match tokio::time::timeout(timeout, task).await {
        Ok(Ok(Ok(result))) => Ok(result),
        _ => Err(SemanticStatus::Unavailable),
    }
}

impl Encoder {
    pub fn load(directory: &Path) -> Result<Self> {
        let config: Config = serde_json::from_slice(&verified_bytes(directory, "config.json")?)?;
        let mut tokenizer = Tokenizer::from_bytes(verified_bytes(directory, "tokenizer.json")?)
            .map_err(anyhow::Error::msg)?;
        tokenizer.with_padding(None);
        tokenizer
            .with_truncation(Some(TruncationParams {
                max_length: MAX_TOKENS,
                ..Default::default()
            }))
            .map_err(anyhow::Error::msg)?;
        let weights = verified_bytes(directory, "model.safetensors")?;
        let builder = VarBuilder::from_buffered_safetensors(weights, DType::F32, &Device::Cpu)?;
        let model = BertModel::load(builder, &config)?;
        Ok(Self { model, tokenizer })
    }

    pub fn tokens(&self, subject: &str, body: &str) -> Result<Vec<u32>> {
        ensure!(
            subject.chars().count() <= 500 && body.chars().count() <= 32_000,
            "semantic text exceeds extraction bounds"
        );
        let encoded = self
            .tokenizer
            .encode(format!("query: {subject}\n{body}"), true)
            .map_err(anyhow::Error::msg)?;
        let ids = encoded.get_ids().to_vec();
        ensure!(
            !ids.is_empty() && ids.len() <= MAX_TOKENS,
            "invalid token count"
        );
        Ok(ids)
    }

    pub fn embed(&self, subject: &str, body: &str) -> Result<(Vec<u32>, Vec<f32>)> {
        let ids = self.tokens(subject, body)?;
        let input = Tensor::new(ids.as_slice(), &Device::Cpu)?.unsqueeze(0)?;
        let types = input.zeros_like()?;
        let mask = input.ones_like()?;
        let hidden = self.model.forward(&input, &types, Some(&mask))?;
        // A single message has no padding. Attention-mask mean reduces to this mean.
        let pooled = (hidden.sum(1)? / ids.len() as f64)?;
        let norm = pooled.sqr()?.sum_keepdim(1)?.sqrt()?;
        let vector = pooled.broadcast_div(&norm)?.squeeze(0)?.to_vec1::<f32>()?;
        ensure!(
            vector.len() == DIMENSION && vector.iter().all(|x| x.is_finite()),
            "invalid semantic vector"
        );
        Ok((ids, vector))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::SemanticStatus;
    use std::{sync::Arc, time::Duration};

    #[tokio::test]
    async fn timed_out_inference_keeps_its_cpu_permit_until_work_finishes() {
        let slots = Arc::new(tokio::sync::Semaphore::new(1));
        let worker_slots = slots.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let task = tokio::spawn(async move {
            bounded(worker_slots, Duration::from_millis(30), move || {
                started_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok(42)
            })
            .await
        });
        started_rx.await.unwrap();
        assert_eq!(task.await.unwrap(), Err(SemanticStatus::Unavailable));
        assert_eq!(slots.available_permits(), 0);
        assert_eq!(
            bounded(slots.clone(), Duration::from_secs(1), || Ok(0)).await,
            Err(SemanticStatus::Busy)
        );
        release_tx.send(()).unwrap();
        let permit = tokio::time::timeout(Duration::from_secs(1), slots.clone().acquire_owned())
            .await
            .unwrap()
            .unwrap();
        drop(permit);
        assert_eq!(
            bounded(slots, Duration::from_secs(1), || Ok(7)).await,
            Ok(7)
        );
    }

    #[tokio::test]
    async fn failed_inference_is_unavailable_and_does_not_leak_capacity() {
        let slots = Arc::new(tokio::sync::Semaphore::new(1));
        let result = bounded::<()>(slots.clone(), Duration::from_secs(1), || {
            anyhow::bail!("failed backend")
        })
        .await;
        assert_eq!(result, Err(SemanticStatus::Unavailable));
        assert_eq!(slots.available_permits(), 1);
    }

    #[test]
    fn combination_rejects_a_different_lexical_fallback_or_encoder() {
        let mut c = Combination {
            schema: "noisefence-hybrid-1".into(),
            version: "fixture".into(),
            lexical_model_sha256: "a".repeat(64),
            encoder: ENCODER_ID.into(),
            revision: ENCODER_REVISION.into(),
            text_schema: 3,
            max_tokens: 256,
            head_weights: vec![0.0; DIMENSION],
            head_bias: 0.0,
            semantic_weight: 0.1,
            score_bias_delta: 0.0,
            threshold: 95.0,
        };
        assert!(c.validate(&"a".repeat(64), 95.0).is_ok());
        assert!(c.validate(&"b".repeat(64), 95.0).is_err());
        assert!(c.validate(&"a".repeat(64), 94.0).is_err());
        c.max_tokens = 512;
        assert!(c.validate(&"a".repeat(64), 95.0).is_err());
        c.max_tokens = 256;
        c.head_weights[0] = f64::NAN;
        assert!(c.validate(&"a".repeat(64), 95.0).is_err());
    }

    #[test]
    fn encoder_integrity_is_checked_before_parsing_or_loading_weights() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("config.json"), vec![b' '; 655]).unwrap();
        let error = Encoder::load(dir.path()).err().unwrap().to_string();
        assert!(error.contains("checksum mismatch"));
    }
}
