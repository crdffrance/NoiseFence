//! Joint, versioned observations and shadow predictions. Never changes delivery.
pub mod evaluation;
pub mod history;
use crate::{engine::Scan, fusion, message, protection::Status};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io::Read,
    path::{Path, PathBuf},
    sync::OnceLock,
};

pub const PROTOCOL: &[u8] = include_bytes!("../research/quality-protocol.json");
pub const KINDS: [&str; 6] = [
    "conversation",
    "transactional",
    "notification",
    "newsletter",
    "promotion",
    "other",
];
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    /// A data-only candidate, evaluated in shadow mode even if its metrics are good.
    pub candidate: Option<PathBuf>,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Conversation,
    Transactional,
    Notification,
    Newsletter,
    Promotion,
    Other,
}
impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Conversation => "conversation",
            Self::Transactional => "transactional",
            Self::Notification => "notification",
            Self::Newsletter => "newsletter",
            Self::Promotion => "promotion",
            Self::Other => "other",
        }
    }
}
pub fn specs() -> &'static [fusion::Feature] {
    static SPECS: OnceLock<Vec<fusion::Feature>> = OnceLock::new();
    SPECS.get_or_init(|| {
        serde_json::from_slice::<serde_json::Value>(PROTOCOL)
            .and_then(|v| serde_json::from_value(v["features"].clone()))
            .expect("quality protocol")
    })
}
pub fn protocol_hash() -> String {
    message::digest(PROTOCOL)
}
pub fn policy_hash(config: &crate::config::Config) -> String {
    let policy = serde_json::json!({"schema":protocol_hash(),
        "protection":config.protection.as_ref().map(|p|serde_json::json!({"policy":p.policy,"timeout_ms":p.timeout_ms,"max_parallel":p.max_parallel,"url_resolution":p.url_resolution,
            "crdf_quota":[p.crdf_per_minute,p.crdf_per_day],"vt_quota":[p.virustotal_per_minute,p.virustotal_per_day]})),
        "mailing":config.mailing.as_ref().map(|m|&m.policy),
        "protected_domains":config.domains.iter().map(|d|&d.name).collect::<Vec<_>>()});
    message::digest(&serde_json::to_vec(&policy).expect("quality policy"))
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Report {
    pub schema: String,
    pub protocol_sha256: String,
    pub artifacts_sha256: String,
    pub source: String,
    pub availability_profile: String,
    pub complete_features: bool,
    pub values: Vec<f64>,
    pub candidate_status: String,
    pub prediction: Option<Prediction>,
    pub sender: history::Report,
}
impl Report {
    /// Console view excludes feature vectors and the private sender join key.
    pub fn public(&self) -> serde_json::Value {
        serde_json::json!({"schema":self.schema,"candidate_status":self.candidate_status,
            "complete_features":self.complete_features,"prediction":self.prediction,
            "sender":{"status":self.sender.status,"established":self.sender.established,
                "conflict":self.sender.conflict,"legitimate_campaigns":self.sender.legitimate_campaigns,
                "unwanted_campaigns":self.sender.unwanted_campaigns,"observed_days":self.sender.observed_days}})
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Prediction {
    pub model: String,
    pub observation_only: bool,
    pub risk_probability: f64,
    pub risk: String,
    pub kind: String,
    pub kind_probabilities: Vec<f64>,
    pub contributions: Vec<Contribution>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Contribution {
    pub family: String,
    pub value: f64,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Linear {
    pub bias: f64,
    pub weights: Vec<f64>,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Model {
    pub schema: String,
    pub version: String,
    pub protocol_sha256: String,
    pub artifacts_sha256: String,
    pub trained_at: i64,
    pub dataset_sha256: String,
    pub profiles: Vec<String>,
    pub risk: Linear,
    pub calibration: [f64; 2],
    pub thresholds: [f64; 2],
    pub kinds: Vec<String>,
    pub kind_models: Vec<Linear>,
    pub kind_temperature: f64,
}
fn hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
impl Model {
    pub fn load(path: &Path) -> Result<Self> {
        let mut bytes = vec![];
        std::fs::File::open(path)?
            .take(2 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= 2 * 1024 * 1024,
            "oversized quality candidate"
        );
        let model: Self = serde_json::from_slice(&bytes)?;
        model.validate()?;
        Ok(model)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == "noisefence-quality-model-1"
                && self.protocol_sha256 == protocol_hash()
                && hash(&self.artifacts_sha256)
                && hash(&self.dataset_sha256)
                && !self.version.is_empty()
                && self.version.len() <= 100
                && !self.version.chars().any(char::is_control)
                && self.trained_at > 0
                && self.trained_at <= crate::now() + 60
                && self.kinds == KINDS
                && self.kind_models.len() == KINDS.len()
                && !self.profiles.is_empty()
                && self.profiles.len() <= 256
                && self.profiles.iter().all(|s| !s.is_empty()
                    && s.len() <= 1024
                    && s.bytes()
                        .all(|b| b.is_ascii_lowercase() || b == b'/' || b == b'_'))
                && self.calibration.iter().all(|v| v.is_finite())
                && self.calibration[0] > 0.0
                && self.calibration[0] <= 100.0
                && self.calibration[1].abs() <= 100.0
                && self.thresholds[0] >= 0.0
                && self.thresholds[0] < self.thresholds[1]
                && self.thresholds[1] <= 1.0
                && self.kind_temperature.is_finite()
                && (0.05..=20.0).contains(&self.kind_temperature),
            "invalid quality candidate contract"
        );
        for linear in std::iter::once(&self.risk).chain(&self.kind_models) {
            ensure!(
                linear.bias.is_finite()
                    && linear.bias.abs() <= 10000.0
                    && linear.weights.len() == specs().len()
                    && linear
                        .weights
                        .iter()
                        .all(|x| x.is_finite() && x.abs() <= 10000.0),
                "invalid quality weights"
            );
        }
        Ok(())
    }
    pub fn predict(&self, report: &Report) -> Result<Prediction> {
        ensure!(
            report.protocol_sha256 == self.protocol_sha256
                && report.artifacts_sha256 == self.artifacts_sha256
                && report.complete_features
                && report.source == "smtp_session"
                && self.profiles.contains(&report.availability_profile),
            "candidate profile or artifacts mismatch"
        );
        validate_values(&report.values)?;
        let linear = |model: &Linear| {
            model.bias
                + model
                    .weights
                    .iter()
                    .zip(&report.values)
                    .map(|(w, x)| w * x)
                    .sum::<f64>()
        };
        let probability =
            crate::engine::sigmoid(self.calibration[0] * linear(&self.risk) + self.calibration[1]);
        let logits: Vec<_> = self
            .kind_models
            .iter()
            .map(|m| linear(m) / self.kind_temperature)
            .collect();
        let max = logits.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        let mut probabilities: Vec<_> = logits.iter().map(|x| (x - max).exp()).collect();
        let sum: f64 = probabilities.iter().sum();
        for p in &mut probabilities {
            *p /= sum;
        }
        let kind = probabilities
            .iter()
            .enumerate()
            .max_by(|a, b| a.1.total_cmp(b.1))
            .unwrap()
            .0;
        let mut families: BTreeMap<String, f64> = BTreeMap::new();
        for ((feature, weight), value) in specs().iter().zip(&self.risk.weights).zip(&report.values)
        {
            *families.entry(feature.family.clone()).or_default() += weight * value;
        }
        let mut contributions: Vec<_> = families
            .into_iter()
            .map(|(family, value)| Contribution { family, value })
            .collect();
        contributions.sort_by(|a, b| {
            b.value
                .abs()
                .total_cmp(&a.value.abs())
                .then(a.family.cmp(&b.family))
        });
        contributions.truncate(6);
        Ok(Prediction {
            model: self.version.clone(),
            observation_only: true,
            risk_probability: probability,
            risk: if probability >= self.thresholds[1] {
                "spam"
            } else if probability <= self.thresholds[0] {
                "legitimate"
            } else {
                "review"
            }
            .into(),
            kind: KINDS[kind].into(),
            kind_probabilities: probabilities,
            contributions,
        })
    }
}
pub fn validate_values(values: &[f64]) -> Result<()> {
    ensure!(
        values.len() == specs().len()
            && values
                .iter()
                .zip(specs())
                .all(|(v, s)| v.is_finite() && *v >= s.minimum && *v <= s.maximum),
        "invalid joint observations"
    );
    Ok(())
}
fn token<T: Serialize>(value: T) -> String {
    serde_json::to_value(value)
        .expect("enum")
        .as_str()
        .unwrap_or("unknown")
        .into()
}

pub fn snapshot(scan: &Scan, model: Option<&Model>) -> Report {
    snapshot_bound(scan, model, None)
}
pub fn snapshot_bound(scan: &Scan, model: Option<&Model>, policy: Option<&str>) -> Report {
    let history = scan.sender_history.clone().unwrap_or_default();
    let mut report = Report {
        schema: "noisefence-quality-observation-1".into(),
        protocol_sha256: protocol_hash(),
        candidate_status: "not_configured".into(),
        sender: history.clone(),
        ..Default::default()
    };
    let Some(evidence) = &scan.evidence else {
        report.candidate_status = "missing_evidence".into();
        return report;
    };
    report.source = token(evidence.source);
    report.artifacts_sha256 =
        message::digest(&serde_json::to_vec(&(&evidence.artifacts, policy)).expect("artifacts"));
    report.availability_profile = fusion::availability_profile(evidence);
    let Ok(base) = fusion::features(evidence) else {
        report.candidate_status = "unsupported_evidence".into();
        return report;
    };
    let mut values: BTreeMap<String, f64> = fusion::specs()
        .iter()
        .zip(base)
        .map(|(s, v)| (s.name.clone(), v))
        .collect();
    if let Some(protection) = &scan.protection {
        let mut hits: BTreeMap<&str, usize> = BTreeMap::new();
        for (name, p) in [
            ("crdf", &protection.crdf),
            ("virustotal", &protection.virustotal),
        ] {
            values.insert(format!("provider.{name}.{}", token(&p.status)), 1.0);
            report
                .availability_profile
                .push_str(&format!("/{}", token(&p.status)));
            for observation in p.observations.iter().take(12) {
                if !hash(&observation.indicator_sha256)
                    || observation.queried_at > crate::now() + 60
                    || observation.queried_at < crate::now() - 5 * 60
                {
                    continue;
                }
                let key = format!(
                    "provider.{name}.{}.{}",
                    observation.scope, observation.verdict
                );
                *values.entry(key).or_default() += 1.0;
                if observation.verdict == "malicious" {
                    *hits.entry(&observation.indicator_sha256).or_default() += 1;
                }
            }
        }
        values.insert(
            "provider.shared_indicator_hits".into(),
            hits.values().filter(|n| **n > 1).count().min(12) as f64,
        );
        for f in &protection.findings {
            values.insert(format!("phishing.{}", f.id), 1.0);
        }
        values.insert(
            "campaign.campaign_match".into(),
            f64::from(protection.campaign_status == Status::Complete && protection.campaign_match),
        );
        values.insert(
            "campaign.campaign_conflict".into(),
            f64::from(protection.campaign_conflict),
        );
    } else {
        report.availability_profile.push_str("/disabled/disabled");
    }
    values.insert(format!("sender.{}", history.status), 1.0);
    report.availability_profile.push_str(&format!(
        "/{}/{}",
        history.status,
        token(scan.vision.status)
    ));
    values.insert("sender.conflict".into(), f64::from(history.conflict));
    values.insert(
        "sender.legitimate_campaigns".into(),
        history.legitimate_campaigns.min(30) as f64,
    );
    values.insert(
        "sender.unwanted_campaigns".into(),
        history.unwanted_campaigns.min(30) as f64,
    );
    values.insert(
        "sender.observed_days".into(),
        history.observed_days.min(30) as f64,
    );
    if let Some(mailing) = &scan.mailing {
        report
            .availability_profile
            .push_str(&format!("/{}", token(mailing.status)));
        values.insert(
            "mailing.complete".into(),
            f64::from(mailing.status == crate::mailing::Status::Complete),
        );
        for (key, value) in &mailing.features {
            values.insert(format!("mailing.{key}"), f64::from(*value));
        }
    } else {
        report.availability_profile.push_str("/disabled");
    }
    values.insert(format!("vision.{}", token(scan.vision.status)), 1.0);
    values.insert(
        "vision.credential_request".into(),
        f64::from(scan.vision.credential_request),
    );
    values.insert("vision.urgency".into(), f64::from(scan.vision.urgency));
    values.insert(
        "vision.codes".into(),
        (scan.vision.qr_codes + scan.vision.other_codes).min(32) as f64,
    );
    values.insert(
        "vision.link_domains".into(),
        scan.vision.link_domains.min(12) as f64,
    );
    if scan.vision.status == crate::vision::Status::Complete {
        values.insert(
            "vision.lexical_logit".into(),
            scan.vision.lexical_logit.unwrap_or(0.0).clamp(-32.0, 32.0),
        );
    }
    report.values = specs()
        .iter()
        .map(|f| {
            values
                .get(&f.name)
                .copied()
                .unwrap_or(0.0)
                .clamp(f.minimum, f.maximum)
        })
        .collect();
    report.complete_features = scan.features_complete.unwrap_or(false);
    if let Some(model) = model {
        if crate::now() - model.trained_at > 30 * 86400 {
            report.candidate_status = "expired".into();
        } else {
            match model.predict(&report) {
                Ok(prediction) => {
                    report.prediction = Some(prediction);
                    report.candidate_status = "complete".into();
                }
                Err(_) => {
                    report.candidate_status = "incompatible".into();
                }
            }
        }
    }
    report
}
