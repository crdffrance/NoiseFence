//! The common decision, separate from the legacy comparison score.
use super::{Model, Prediction};
use crate::{
    engine::Scan,
    evidence::{Artifacts, Source},
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    io::Read,
    path::{Path, PathBuf},
    time::Instant,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Observe,
    Decision,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub model: PathBuf,
    #[serde(default)]
    pub mode: Mode,
    pub validation_report: Option<PathBuf>,
}
impl Settings {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.model.as_os_str().is_empty(),
            "fusion needs a model path"
        );
        ensure!(
            self.mode != Mode::Decision || self.validation_report.is_some(),
            "fusion decision mode requires a validation report"
        );
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionSource {
    Legacy,
    Fusion,
    Antivirus,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Legitimate,
    Unwanted,
    Undetermined,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    pub source: DecisionSource,
    pub outcome: Outcome,
    /// 0..100. A fusion score is calibrated for its validated population;
    /// the historical score is only an index. None means no usable decision.
    pub score: Option<f64>,
    pub model: String,
}
impl Decision {
    pub fn legacy(scan: &Scan, threshold: f64) -> Self {
        Self {
            source: DecisionSource::Legacy,
            score: scan.complete.then_some(scan.score),
            model: scan.model.clone(),
            outcome: if !scan.complete {
                Outcome::Undetermined
            } else if scan.score >= threshold {
                Outcome::Unwanted
            } else {
                Outcome::Legitimate
            },
        }
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    #[default]
    Disabled,
    NotRun,
    Complete,
    Unavailable,
    UnsupportedProfile,
    ValidationExpired,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub mode: Mode,
    pub status: Status,
    pub model: String,
    pub model_sha256: Option<String>,
    pub elapsed_us: u64,
    pub prediction: Option<Prediction>,
}

/// An administrator's reviewed evidence bundle. Counts are checked again here;
/// a successful research run alone cannot enable an SMTP decision. This file
/// records the full-population audit, frozen test, latency and review references.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Validation {
    pub schema: String,
    pub model_sha256: String,
    pub manifest_sha256: String,
    pub test_report_sha256: String,
    pub population_report_sha256: String,
    pub latency_report_sha256: String,
    pub reviewed_at: i64,
    pub observation_start: i64,
    pub observation_end: i64,
    pub review_reference: String,
    pub sampling: String,
    pub tp: usize,
    pub fp: usize,
    pub fn_count: usize,
    pub tn: usize,
    pub unaccounted_messages: usize,
    pub pipeline_p95_ms: f64,
    pub pipeline_samples: usize,
}
impl Validation {
    pub fn load(path: &Path) -> Result<Self> {
        let mut bytes = Vec::new();
        std::fs::File::open(path)?
            .take(32 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= 32 * 1024,
            "oversized fusion validation report"
        );
        Ok(serde_json::from_slice(&bytes)?)
    }
    pub fn validate(&self, model: &Model, sha256: &str, now: i64) -> Result<()> {
        ensure!(
            self.schema == "noisefence-fusion-promotion-1"
                && self.model_sha256 == sha256
                && self.manifest_sha256 == model.manifest_sha256,
            "fusion validation is for another model"
        );
        for h in [
            &self.model_sha256,
            &self.manifest_sha256,
            &self.test_report_sha256,
            &self.population_report_sha256,
            &self.latency_report_sha256,
        ] {
            ensure!(super::valid_hash(h), "invalid validation artifact hash");
        }
        ensure!(
            self.reviewed_at > 0
                && self.reviewed_at <= now
                && now - self.reviewed_at <= 30 * 86400
                && self.observation_start > 0
                && self.observation_start <= self.observation_end
                && self.observation_end <= self.reviewed_at
                && now - self.observation_start <= 90 * 86400,
            "fusion validation or observations are stale"
        );
        ensure!(
            !self.review_reference.trim().is_empty()
                && self.review_reference.len() <= 1000
                && !self.review_reference.chars().any(char::is_control)
                && self.sampling == "representative_smtp"
                && self.unaccounted_messages == 0,
            "fusion validation needs a reviewed representative SMTP population with full accounting"
        );
        ensure!(
            [self.tp, self.fp, self.fn_count, self.tn]
                .into_iter()
                .all(|n| n <= 100_000),
            "invalid test counts"
        );
        let ham = self.tn + self.fp;
        let unwanted = self.tp + self.fn_count;
        ensure!(
            ham >= 10_000 && unwanted >= 2_000,
            "independent fusion test is too small"
        );
        let p = self.fp as f64 / ham as f64;
        let z = 1.959963984540054_f64;
        let n = ham as f64;
        let upper =
            (p + z * z / (2.0 * n) + z * (p * (1.0 - p) / n + z * z / (4.0 * n * n)).sqrt())
                / (1.0 + z * z / n);
        ensure!(
            self.tp as f64 / unwanted as f64 >= 0.95 && upper <= 0.001,
            "fusion quality targets are not demonstrated by the reviewed counts"
        );
        ensure!(
            self.pipeline_samples >= 1000
                && self.pipeline_p95_ms.is_finite()
                && (0.0..500.0).contains(&self.pipeline_p95_ms),
            "full pipeline latency target is not demonstrated"
        );
        Ok(())
    }
}

pub struct Runtime {
    model: Model,
    sha256: String,
    mode: Mode,
    validation: Option<Validation>,
}
impl Runtime {
    pub fn load(settings: &Settings, artifacts: &Artifacts) -> Result<Self> {
        settings.validate()?;
        let (model, sha256) = Model::load_bound(&settings.model)?;
        ensure!(
            model.artifacts.equivalent(artifacts),
            "fusion model does not match loaded detector artifacts"
        );
        let validation = settings
            .validation_report
            .as_deref()
            .map(Validation::load)
            .transpose()?;
        if settings.mode == Mode::Decision {
            validation
                .as_ref()
                .unwrap()
                .validate(&model, &sha256, crate::now())?;
        }
        Ok(Self {
            model,
            sha256,
            mode: settings.mode,
            validation,
        })
    }
    /// Always record a comparison, including on the fail-open completion path.
    /// Observation mode does not change the active decision or completeness.
    pub fn apply(&self, scan: &mut Scan) {
        let started = Instant::now();
        let mut observation = Observation {
            mode: self.mode,
            status: Status::NotRun,
            model: self.model.version.clone(),
            model_sha256: Some(self.sha256.clone()),
            ..Default::default()
        };
        if self.mode == Mode::Decision
            && self
                .validation
                .as_ref()
                .is_none_or(|v| v.validate(&self.model, &self.sha256, crate::now()).is_err())
        {
            observation.status = Status::ValidationExpired;
        } else if let Some(evidence) = scan
            .evidence
            .as_ref()
            .filter(|e| e.source != Source::ContentOnly)
        {
            match self.model.predict(evidence) {
                Ok(prediction) => {
                    observation.status = if prediction.profile_supported {
                        Status::Complete
                    } else {
                        Status::UnsupportedProfile
                    };
                    observation.prediction = Some(prediction);
                }
                Err(_) => observation.status = Status::Unavailable,
            }
        }
        if self.mode == Mode::Decision {
            let usable = observation.status == Status::Complete
                && observation
                    .prediction
                    .as_ref()
                    .is_some_and(|p| p.tag_eligible);
            let prediction = observation.prediction.as_ref().filter(|_| usable);
            scan.decision = Some(Decision {
                source: DecisionSource::Fusion,
                outcome: match prediction {
                    Some(p) if p.above_threshold => Outcome::Unwanted,
                    Some(_) => Outcome::Legitimate,
                    None => Outcome::Undetermined,
                },
                score: prediction.map(|p| p.probability * 100.0),
                model: self.model.version.clone(),
            });
            if !usable {
                scan.complete = false;
            }
        }
        observation.elapsed_us = started.elapsed().as_micros().min(u64::MAX as u128) as u64;
        scan.fusion = observation;
    }
}
