//! Native Rust transposition of multi-pattern, composite, fuzzy and OSB techniques.
//! This independent observation NEVER participates in delivery or model selection.
pub mod bayes;
pub mod benchmark;
pub mod content_rules;
pub mod input;
pub mod learning;
pub mod memory;
pub mod rules;

use crate::capacity::Capacity;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

pub const VERSION: &str = "native-filter-2";

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Observe,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub mode: Mode,
    pub max_bytes: usize,
    pub max_parallel: usize,
    pub timeout_ms: u64,
    pub fuzzy_memory: bool,
    pub bayes_model: Option<PathBuf>,
    pub adaptive: Option<crate::adaptive::Settings>,
    pub content_rules: content_rules::Settings,
    pub patterns: Vec<rules::Pattern>,
    pub composites: Vec<rules::Composite>,
    pub caps: BTreeMap<rules::Family, rules::Bounds>,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            mode: Mode::Observe,
            max_bytes: 1024 * 1024,
            max_parallel: 2,
            timeout_ms: 500,
            fuzzy_memory: true,
            bayes_model: None,
            adaptive: None,
            content_rules: content_rules::Settings::default(),
            patterns: rules::default_patterns(),
            composites: rules::default_composites(),
            caps: rules::default_caps(),
        }
    }
}
impl Settings {
    pub fn validate(&self) -> Result<()> {
        self.content_rules.validate()?;
        if let Some(adaptive) = &self.adaptive {
            adaptive.validate()?;
        }
        ensure!(
            (1024..=2 * 1024 * 1024).contains(&self.max_bytes)
                && (1..=8).contains(&self.max_parallel)
                && (50..=1000).contains(&self.timeout_ms),
            "invalid native resource limits"
        );
        for cap in self.caps.values() {
            ensure!(
                cap.min.is_finite()
                    && cap.max.is_finite()
                    && (-5.0..=0.0).contains(&cap.min)
                    && (0.0..=5.0).contains(&cap.max),
                "invalid native family cap"
            );
        }
        rules::Matcher::compile(&self.patterns)?;
        rules::Composites::compile(&self.composites, &self.patterns)?;
        Ok(())
    }
    fn complete_caps(&self) -> BTreeMap<rules::Family, rules::Bounds> {
        let mut caps = rules::default_caps();
        caps.extend(self.caps.clone());
        caps
    }
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Complete,
    NotRun,
    Limited,
    Busy,
    Unavailable,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Report {
    pub version: String,
    pub policy_sha256: String,
    pub mode: Mode,
    pub status: Status,
    pub elapsed_ms: u64,
    pub score: Option<rules::Score>,
    pub bayes: bayes::Prediction,
    pub bayes_sha256: Option<String>,
    pub fuzzy: memory::Report,
    pub calibrated: bool,
    pub affects_delivery: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adaptive: Option<crate::adaptive::Report>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Observation {
    pub report: Report,
    /// Private retained features, stripped from every user-facing report.
    pub features: Option<input::Features>,
    /// Original local symbols allow idempotent recalculation after external checks.
    pub local_symbols: Vec<rules::Symbol>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adaptive_vector: Option<Vec<f64>>,
}

pub struct Runtime {
    pub settings: Settings,
    adaptive: Option<Arc<crate::adaptive::Runtime>>,
    matcher: rules::Matcher,
    composites: rules::Composites,
    model: Option<Arc<bayes::Model>>,
    model_sha256: Option<String>,
    policy_sha256: String,
    permits: Arc<Capacity>,
    memory_permits: Arc<Capacity>,
}
impl Runtime {
    pub fn new(settings: Settings) -> Result<Arc<Self>> {
        settings.validate()?;
        let model = settings
            .bayes_model
            .as_deref()
            .map(bayes::Model::load)
            .transpose()?;
        let (model, model_sha256) = match model {
            Some((m, h)) => (Some(Arc::new(m)), Some(h)),
            None => (None, None),
        };
        let adaptive = settings
            .adaptive
            .clone()
            .map(|s| crate::adaptive::Runtime::new(s, &settings.patterns).map(Arc::new))
            .transpose()?;
        let matcher = rules::Matcher::compile(&settings.patterns)?;
        let composites = rules::Composites::compile(&settings.composites, &settings.patterns)?;
        let policy_sha256 = crate::message::digest(&serde_json::to_vec(
            &serde_json::json!({"version":VERSION,"detector_build":crate::compatibility::DETECTOR_BUILD_SHA256,"content":input::PROTOCOL,"settings":settings,"bayes":model_sha256}),
        )?);
        Ok(Arc::new(Self {
            permits: Capacity::new(settings.max_parallel),
            memory_permits: Capacity::new(settings.max_parallel),
            settings,
            matcher,
            adaptive,
            composites,
            model,
            model_sha256,
            policy_sha256,
        }))
    }
    pub(crate) fn reload_cluster(&self, settings: Settings) -> Result<Arc<Self>> {
        let mut next = Self::new(settings)?;
        let next_mut = Arc::get_mut(&mut next).expect("new native runtime");
        next_mut.permits = self.permits.clone();
        next_mut.memory_permits = self.memory_permits.clone();
        Ok(next)
    }
    pub(crate) fn reconfigure(&self, settings: Settings) -> Result<Arc<Self>> {
        settings.validate()?;
        ensure!(
            settings.bayes_model == self.settings.bayes_model
                && settings.adaptive == self.settings.adaptive,
            "Les modèles entraînés nécessitent leur procédure de validation."
        );
        // Adaptive vectors depend on exact pattern order; never silently change their protocol.
        ensure!(
            self.settings.adaptive.is_none() || settings.patterns == self.settings.patterns,
            "Les motifs sont liés au protocole adaptatif ; modifier les règles de contenu ou les composites."
        );
        let policy_sha256 = crate::message::digest(&serde_json::to_vec(
            &serde_json::json!({"version":VERSION,"detector_build":crate::compatibility::DETECTOR_BUILD_SHA256,"content":input::PROTOCOL,"settings":settings,"bayes":self.model_sha256}),
        )?);
        Ok(Arc::new(Self {
            matcher: rules::Matcher::compile(&settings.patterns)?,
            composites: rules::Composites::compile(&settings.composites, &settings.patterns)?,
            settings,
            adaptive: self.adaptive.clone(),
            model: self.model.clone(),
            model_sha256: self.model_sha256.clone(),
            policy_sha256,
            permits: self.permits.clone(),
            memory_permits: self.memory_permits.clone(),
        }))
    }
    pub(crate) fn activate(&self) {
        self.permits.set_limit(self.settings.max_parallel);
        self.memory_permits.set_limit(self.settings.max_parallel);
    }
    fn empty(&self, status: Status) -> Observation {
        Observation {
            report: Report {
                version: VERSION.into(),
                policy_sha256: self.policy_sha256.clone(),
                mode: Mode::Observe,
                status,
                elapsed_ms: 0,
                score: None,
                bayes: bayes::Prediction::default(),
                bayes_sha256: self.model_sha256.clone(),
                fuzzy: memory::Report::default(),
                calibrated: false,
                affects_delivery: false,
                adaptive: None,
            },
            features: None,
            local_symbols: vec![],
            adaptive_vector: None,
        }
    }
    pub fn offline(&self, raw: &[u8], scopes: &[String]) -> Observation {
        let started = Instant::now();
        let mut out = match input::extract(raw, self.settings.max_bytes).and_then(|input| {
            self.settings
                .content_rules
                .inspect(raw)
                .map(|symbols| (input, symbols))
        }) {
            Ok((input, content_symbols)) => {
                let mut out = self.empty(Status::Complete);
                out.local_symbols = self.matcher.inspect(&input);
                out.local_symbols.extend(content_symbols);
                if let Some(runtime) = &self.adaptive {
                    let (report, vector) = runtime.predict(&input, &out.local_symbols, scopes);
                    out.report.adaptive = Some(report);
                    out.adaptive_vector = vector;
                }
                if let Some(model) = &self.model {
                    out.report.bayes = model.predict(&input.features, scopes, crate::now());
                }
                out.features = Some(input.features);
                out
            }
            Err(_) => self.empty(Status::Limited),
        };
        out.report.elapsed_ms = started.elapsed().as_millis() as u64;
        if out.report.elapsed_ms > self.settings.timeout_ms {
            out = self.empty(Status::Limited);
            out.report.elapsed_ms = started.elapsed().as_millis() as u64;
        }
        out
    }
    pub async fn inspect(self: &Arc<Self>, raw: &[u8], scopes: &[String]) -> Observation {
        if raw.len() > self.settings.max_bytes {
            return self.empty(Status::Limited);
        }
        let started = Instant::now();
        let deadline =
            tokio::time::Instant::now() + Duration::from_millis(self.settings.timeout_ms);
        let Ok(Ok(permit)) =
            tokio::time::timeout_at(deadline, self.permits.clone().acquire_owned()).await
        else {
            let mut out = self.empty(Status::Busy);
            out.report.elapsed_ms = started.elapsed().as_millis() as u64;
            return out;
        };
        let runtime = self.clone();
        let raw = raw.to_vec();
        let scopes = scopes.to_vec();
        let task = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            runtime.offline(&raw, &scopes)
        });
        // A cancelled blocking worker retains its permit until it actually exits.
        match tokio::time::timeout_at(deadline, task).await {
            Ok(Ok(mut observation)) => {
                observation.report.elapsed_ms = started.elapsed().as_millis() as u64;
                observation
            }
            _ => {
                let mut out = self.empty(Status::Unavailable);
                out.report.elapsed_ms = started.elapsed().as_millis() as u64;
                out
            }
        }
    }
    pub async fn remember(
        self: &Arc<Self>,
        root: &Path,
        observation: &mut Observation,
        scopes: &[String],
        raw_sha256: &str,
    ) {
        if !self.settings.fuzzy_memory || observation.report.status != Status::Complete {
            return;
        }
        let Some(features) = &observation.features else {
            return;
        };
        let Ok(permit) = self.memory_permits.clone().try_acquire() else {
            observation.report.fuzzy.status = Status::Busy;
            return;
        };
        let started = Instant::now();
        observation.report.fuzzy =
            memory::inspect_with_permit(root, features, scopes, raw_sha256, Some(permit)).await;
        observation.report.elapsed_ms += started.elapsed().as_millis() as u64;
    }
    pub fn finish(&self, observation: &mut Observation, scan: &crate::engine::Scan) {
        if observation.report.status != Status::Complete {
            return;
        }
        let mut symbols = observation.local_symbols.clone();
        symbols.extend(rules::context(scan));
        if observation.report.fuzzy.status == Status::Complete
            && observation.report.fuzzy.corroborated_spam
        {
            symbols.push(rules::Symbol {
                id: "NF_FUZZY_SPAM".into(),
                label: "Campagne proche de deux exemples humains concordants".into(),
                family: rules::Family::Campaign,
                weight: 1.5,
                absorbed_by: vec![],
            });
        }
        if let Some(log_odds) = observation.report.bayes.raw_log_odds {
            // A bounded comparative contribution, explicitly not a probability.
            symbols.push(rules::Symbol {
                id: "NF_BAYES".into(),
                label: "Classifieur OSB Bayes en observation".into(),
                family: rules::Family::Bayes,
                weight: log_odds.clamp(-1.0, 1.0),
                absorbed_by: vec![],
            });
        }
        observation.report.score = Some(
            self.composites
                .apply(symbols, &self.settings.complete_caps()),
        );
    }
}
pub fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let file = File::open(path)?;
    ensure!(
        file.metadata()?.is_file(),
        "native input must be a regular file"
    );
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "native file size limit");
    Ok(bytes)
}
