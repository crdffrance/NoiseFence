//! A shared CPU budget for optional local research detectors. A timed-out
//! blocking decoder retains its permit until it exits; cancellation cannot
//! create an unbounded backlog of detached analyses.
use crate::{content_inspection, heuristics};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

pub const VERSION: &str = "local-research-1";
const TIMEOUT: Duration = Duration::from_millis(500);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Complete,
    Busy,
    Limited,
    Unavailable,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Execution {
    pub version: String,
    pub status: Status,
    pub elapsed_ms: u64,
}

pub struct Inspection {
    pub execution: Execution,
    pub heuristics: Option<heuristics::Report>,
    pub content: Option<content_inspection::Report>,
}
impl Inspection {
    fn empty(status: Status, started: Instant) -> Self {
        Self {
            execution: Execution {
                version: VERSION.into(),
                status,
                elapsed_ms: started.elapsed().as_millis() as u64,
            },
            heuristics: None,
            content: None,
        }
    }
    pub fn apply(self, scan: &mut crate::engine::Scan) {
        if let Some(report) = &self.heuristics {
            // A single bounded contribution: per-rule observations may be
            // correlated and are not added a second time. Production modes
            // reject experimental contribution in Config::validate.
            let weight = if report.status == heuristics::Status::Complete {
                report.contribution
            } else {
                0.0
            };
            if weight != 0.0 && weight.is_finite() {
                scan.reasons.push(crate::engine::Signal {
                    id: "heuristics_experiment".into(),
                    detail: "Contribution expérimentale des heuristiques ; mode observation".into(),
                    weight,
                });
            }
        }
        scan.research_execution = Some(self.execution);
        scan.heuristics = self.heuristics;
        scan.content_inspection = self.content;
    }
}

pub struct Runtime {
    heuristics: Option<heuristics::Runtime>,
    content: Option<content_inspection::Settings>,
    sandbox: Option<crate::sandbox_pipeline::Settings>,
    max_bytes: usize,
    slots: Arc<tokio::sync::Semaphore>,
}
impl Runtime {
    pub fn new(config: &crate::config::Config) -> Result<Self> {
        let mut sandbox = config.sandbox_pipeline.clone();
        if let Some(settings) = &mut sandbox
            && settings.enabled
        {
            settings.bind_backend(
                config
                    .sandbox
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("sandbox backend missing"))?,
            )?;
        }
        Ok(Self {
            heuristics: config
                .heuristics
                .clone()
                .map(heuristics::Runtime::new)
                .transpose()?,
            content: config.content_inspection.clone(),
            sandbox,
            max_bytes: config.filter.max_analysis_bytes,
            slots: Arc::new(tokio::sync::Semaphore::new(
                config.smtp.max_processing.clamp(1, 4),
            )),
        })
    }
    /// SMTP-only local selection. Network submission happens after the durable
    /// queue transaction, in the independent sandbox worker.
    pub async fn prepare_sandbox(
        self: &Arc<Self>,
        raw: &[u8],
        scan: &crate::engine::Scan,
    ) -> Result<(
        Option<crate::sandbox_pipeline::Report>,
        Option<crate::sandbox_pipeline::Plan>,
    )> {
        use crate::sandbox_pipeline::{Detail, Preparation, Report};
        let Some(settings) = &self.sandbox else {
            return Ok((None, None));
        };
        let unavailable = |detail| -> Result<_> {
            anyhow::ensure!(
                !settings.enabled || !settings.quarantine_selected,
                "sandbox preparation unavailable; retry before accepting mail"
            );
            Ok((
                Some(Report {
                    version: crate::sandbox_pipeline::VERSION.into(),
                    status: if settings.enabled {
                        Preparation::Limited
                    } else {
                        Preparation::Disabled
                    },
                    disposition: crate::sandbox::Disposition::ResearchOnly,
                    selected: 0,
                    skipped: 0,
                    details: vec![detail],
                }),
                None,
            ))
        };
        if raw.len() > settings.max_raw_bytes {
            return unavailable(Detail::RawLimit);
        }
        let Ok(permit) = self.slots.clone().try_acquire_owned() else {
            return unavailable(Detail::QueueBusy);
        };
        let settings = settings.clone();
        let bytes = raw.to_vec();
        // Only the original digest is required; do not clone private feature vectors.
        let identity = crate::engine::Scan {
            raw_sha256: scan.raw_sha256.clone(),
            ..Default::default()
        };
        let work = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            crate::sandbox_pipeline::prepare(&bytes, &identity, &settings)
        });
        match tokio::time::timeout(TIMEOUT, work).await {
            Ok(Ok(Ok(plan))) => Ok((Some(plan.report()), Some(plan))),
            Ok(Ok(Err(e))) => Err(e),
            _ => unavailable(Detail::QueueBusy),
        }
    }
    /// Offline callers deliberately run on their own thread. No DNS, HTTP,
    /// database, sandbox or message delivery is triggered by this method.
    pub fn offline(&self, raw: &[u8]) -> Inspection {
        let started = Instant::now();
        if raw.len() > self.max_bytes {
            return Inspection::empty(Status::Limited, started);
        }
        let heuristics = self.heuristics.as_ref().map(|runtime| runtime.inspect(raw));
        let content = self
            .content
            .as_ref()
            .map(|settings| content_inspection::analyze(raw, settings));
        Inspection {
            execution: Execution {
                version: VERSION.into(),
                status: Status::Complete,
                elapsed_ms: started.elapsed().as_millis() as u64,
            },
            heuristics,
            content,
        }
    }
    pub async fn inspect(self: &Arc<Self>, raw: &[u8]) -> Inspection {
        let started = Instant::now();
        if raw.len() > self.max_bytes {
            return Inspection::empty(Status::Limited, started);
        }
        let Ok(permit) = self.slots.clone().try_acquire_owned() else {
            return Inspection::empty(Status::Busy, started);
        };
        let runtime = self.clone();
        let bytes = raw.to_vec();
        let work = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            runtime.offline(&bytes)
        });
        match tokio::time::timeout(TIMEOUT, work).await {
            Ok(Ok(mut report)) => {
                report.execution.elapsed_ms = started.elapsed().as_millis() as u64;
                report
            }
            Ok(Err(_)) => Inspection::empty(Status::Unavailable, started),
            Err(_) => Inspection::empty(Status::Limited, started),
        }
    }
}
