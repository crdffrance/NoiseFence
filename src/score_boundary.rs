//! Receipt-time operating point of the selected score, not a new classifier.
use crate::{
    assessment::{Score, ScoreSource},
    engine::Scan,
    fusion::runtime::DecisionSource,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    Content,
    Fusion,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Calibration {
    pub slope: f64,
    pub intercept: f64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Boundary {
    pub version: u8,
    pub source: Source,
    /// Native units: content index or uncalibrated fusion logit.
    pub value: f64,
    pub cutoff: f64,
    /// Display mapping only. Saturation/flat calibration can lose the ordering.
    pub index_cutoff: f64,
    pub above: bool,
    pub model: String,
    pub model_sha256: Option<String>,
    pub calibration: Option<Calibration>,
}

pub(crate) fn probability(logit: f64, slope: f64, intercept: f64) -> f64 {
    let x = slope * logit + intercept;
    if x >= 0. {
        1. / (1. + (-x).exp())
    } else {
        let p = x.exp();
        p / (1. + p)
    }
}

// libm exp can differ by a few ulps between supported hosts. This is validation
// tolerance only; never rewrite the recorded value or compare mapped cutoffs to
// make decisions. The stored native >= comparison remains exact.
fn same_mapping(actual: f64, expected: f64) -> bool {
    actual.is_finite()
        && expected.is_finite()
        && (actual - expected).abs() <= 8. * f64::EPSILON * expected.abs() + 8. * f64::from_bits(1)
}

impl Boundary {
    pub(crate) fn fusion(model: &crate::fusion::Model, hash: &str, logit: f64) -> Self {
        Self {
            version: 1,
            source: Source::Fusion,
            value: logit,
            cutoff: model.cutoff,
            index_cutoff: 100.
                * probability(
                    model.cutoff,
                    model.calibration.slope,
                    model.calibration.intercept,
                ),
            above: logit >= model.cutoff,
            model: model.version.clone(),
            model_sha256: Some(hash.into()),
            calibration: Some(Calibration {
                slope: model.calibration.slope,
                intercept: model.calibration.intercept,
            }),
        }
    }
    pub fn validate(&self, score: &Score) -> Result<()> {
        ensure!(
            self.version == 1
                && self.value.is_finite()
                && self.cutoff.is_finite()
                && self.above == (self.value >= self.cutoff)
                && self.model == score.model,
            "Invalid score boundary identity or comparison"
        );
        let index = match self.source {
            Source::Content => {
                ensure!(
                    self.calibration.is_none()
                        && self.model_sha256.is_none()
                        && crate::assessment::valid_score(Some(self.cutoff)).is_some()
                        && self.index_cutoff == self.cutoff,
                    "Invalid content boundary"
                );
                self.value
            }
            Source::Fusion => {
                let calibration = self
                    .calibration
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("Missing boundary calibration"))?;
                ensure!(
                    score.source == ScoreSource::Decision
                        && self
                            .model_sha256
                            .as_deref()
                            .is_some_and(crate::compatibility::valid_hash)
                        && calibration.slope.is_finite()
                        && (0. ..=1e6).contains(&calibration.slope)
                        && calibration.intercept.is_finite()
                        && calibration.intercept.abs() <= 1e6
                        && self.cutoff.abs() <= 1e6
                        && same_mapping(
                            self.index_cutoff,
                            100. * probability(
                                self.cutoff,
                                calibration.slope,
                                calibration.intercept
                            )
                        ),
                    "Invalid fusion boundary"
                );
                100. * probability(self.value, calibration.slope, calibration.intercept)
            }
        };
        ensure!(
            crate::assessment::valid_score(Some(index)).is_some()
                && crate::assessment::valid_score(Some(self.index_cutoff)).is_some()
                && score.value.is_some_and(|actual| match self.source {
                    Source::Content => actual == index,
                    Source::Fusion =>
                        crate::assessment::valid_score(Some(actual)).is_some()
                            && same_mapping(actual, index),
                }),
            "Boundary does not describe the selected score"
        );
        Ok(())
    }
}

/// Called only while constructing a new assessment. Persisted assessments retain
/// their own field, including None; never fill historical gaps with live models.
pub(crate) fn selected(scan: &Scan, score: &Score, threshold: Option<f64>) -> Option<Boundary> {
    score.value?;
    if score.source == ScoreSource::Decision
        && scan.decision.as_ref()?.source == DecisionSource::Fusion
    {
        let boundary = scan.fusion_boundary.as_ref()?;
        if boundary.model_sha256 != scan.fusion.model_sha256 || boundary.source != Source::Fusion {
            return None;
        }
        return boundary.validate(score).ok().map(|_| boundary.clone());
    }
    // Malware/evidence overrides may retain a diagnostic content index; its
    // boundary is a reference, never proof that the decision came from a score.
    let cutoff = crate::assessment::valid_score(threshold)?;
    let boundary = Boundary {
        version: 1,
        source: Source::Content,
        value: score.value?,
        cutoff,
        index_cutoff: cutoff,
        above: score.value? >= cutoff,
        model: score.model.clone(),
        model_sha256: None,
        calibration: None,
    };
    boundary.validate(score).ok().map(|_| boundary)
}
