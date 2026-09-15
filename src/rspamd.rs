//! An independent, asynchronous comparison. Nothing in this module contributes
//! to classification, SMTP responses, message headers, delivery or learning.
use crate::{capacity::Capacity, engine::Scan, fusion::runtime::Outcome, store::Store};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::oneshot;

const MAX_RESPONSE: usize = 128 * 1024;
const COMMIT_TIMEOUT: u64 = 600;

#[derive(Serialize)]
pub struct Summary {
    pub rows: u64,
    pub total: u64,
    pub completed: u64,
    pub agreements: u64,
    pub disagreements: u64,
    pub inconclusive: u64,
    pub pending: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    /// Installation parameters: never accepted from a Web patch or a peer.
    pub endpoint: SocketAddr,
    pub profile: String,
    pub enabled: bool,
    pub sample_percent: u8,
    pub max_bytes: usize,
    pub max_parallel: usize,
    pub queue_capacity: usize,
    pub timeout_ms: u64,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            endpoint: "127.0.0.1:11333".parse().unwrap(),
            profile: "unverified".into(),
            enabled: false,
            sample_percent: 100,
            max_bytes: 4 * 1024 * 1024,
            max_parallel: 2,
            queue_capacity: 4,
            timeout_ms: 5000,
        }
    }
}
impl Settings {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.endpoint.ip().is_loopback() && self.endpoint.port() != 0,
            "Rspamd must use a literal loopback endpoint."
        );
        ensure!(
            !self.profile.is_empty()
                && self.profile.len() <= 128
                && self
                    .profile
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".-_:".contains(&b)),
            "Invalid Rspamd profile identifier."
        );
        ensure!(
            self.sample_percent <= 100 && (1024..=8 * 1024 * 1024).contains(&self.max_bytes),
            "Invalid Rspamd sampling or size limit."
        );
        ensure!(
            (1..=8).contains(&self.max_parallel)
                && self.queue_capacity <= 32
                && (self.max_parallel + self.queue_capacity) * self.max_bytes <= 64 * 1024 * 1024,
            "Rspamd: at most 8 scans, 32 waiting jobs and 64 MiB of original message buffers."
        );
        ensure!(
            (100..=5000).contains(&self.timeout_ms),
            "Rspamd timeout must be between 100 and 5000 ms."
        );
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Pending,
    Complete,
    Busy,
    Timeout,
    Unavailable,
    InvalidResponse,
    Skipped,
    Oversize,
    NotSampled,
    Interrupted,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Comparison {
    Agreement,
    Disagreement,
    Inconclusive,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Symbol {
    pub name: String,
    pub score: f64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Report {
    pub status: Status,
    pub job_id: String,
    pub started_at: i64,
    pub expires_at: i64,
    pub raw_sha256: String,
    pub profile: String,
    pub settings_sha256: String,
    pub server: Option<String>,
    pub elapsed_ms: u64,
    pub score: Option<f64>,
    pub required_score: Option<f64>,
    pub action: Option<String>,
    pub symbols: Vec<Symbol>,
    pub noisefence_outcome: Option<Outcome>,
    pub comparison: Comparison,
}
impl Report {
    /// A crashed process cannot resume its RAM-only job. Never leave a historical
    /// row looking like an active comparison, or invent a result for it.
    pub fn visible(mut self) -> Self {
        if self.status == Status::Pending && self.expires_at < crate::now() {
            self.status = Status::Interrupted;
        }
        self
    }
    pub(crate) fn bind(&mut self, scan: &Scan) {
        self.noisefence_outcome = scan.decision.as_ref().map(|d| d.outcome);
        self.comparison = self.compare();
    }
    fn compare(&self) -> Comparison {
        if self.status != Status::Complete {
            return Comparison::Inconclusive;
        }
        let other = match self.action.as_deref() {
            Some("no action" | "accept") => Some(false),
            Some("reject" | "add header" | "rewrite subject") => Some(true),
            // Greylisting, soft rejection and custom actions are not spam labels.
            _ => None,
        };
        let native = match self.noisefence_outcome {
            Some(Outcome::Unwanted) => Some(true),
            Some(Outcome::Legitimate) => Some(false),
            _ => None,
        };
        match (native, other) {
            (Some(a), Some(b)) if a == b => Comparison::Agreement,
            (Some(_), Some(_)) => Comparison::Disagreement,
            _ => Comparison::Inconclusive,
        }
    }
}

pub(crate) struct Runtime {
    settings: Option<Settings>,
    client: Option<reqwest::Client>,
    outstanding: Arc<Capacity>,
    workers: Arc<Capacity>,
    memory: Arc<tokio::sync::Semaphore>,
}
pub(crate) struct Envelope<'a> {
    pub ip: IpAddr,
    pub helo: &'a str,
    pub sender: &'a str,
    pub recipients: &'a [crate::config::Recipient],
    pub id: &'a str,
}
pub(crate) struct Ticket {
    pub report: Report,
    accepted: Option<oneshot::Sender<Vec<String>>>,
}
impl Ticket {
    pub fn commit(mut self, ids: Vec<String>) {
        if let Some(tx) = self.accepted.take() {
            let _ = tx.send(ids);
        }
    }
}
impl Runtime {
    pub fn new(settings: Option<Settings>, previous: Option<&Self>) -> Result<Self> {
        if let Some(s) = &settings {
            s.validate()?;
            let _ = rustls::crypto::ring::default_provider().install_default();
        }
        let client = settings
            .as_ref()
            .map(|_| {
                reqwest::Client::builder()
                    .no_proxy()
                    .redirect(reqwest::redirect::Policy::none())
                    .connect_timeout(Duration::from_secs(1))
                    .build()
            })
            .transpose()?;
        Ok(Self {
            memory: previous
                .map(|p| p.memory.clone())
                .unwrap_or_else(|| Arc::new(tokio::sync::Semaphore::new(64 * 1024 * 1024))),
            outstanding: previous.map(|p| p.outstanding.clone()).unwrap_or_else(|| {
                Capacity::new(
                    settings
                        .as_ref()
                        .map_or(0, |s| s.max_parallel + s.queue_capacity),
                )
            }),
            workers: previous
                .map(|p| p.workers.clone())
                .unwrap_or_else(|| Capacity::new(settings.as_ref().map_or(0, |s| s.max_parallel))),
            settings,
            client,
        })
    }
    pub fn activate(&self) {
        self.outstanding.set_limit(
            self.settings
                .as_ref()
                .filter(|s| s.enabled)
                .map_or(0, |s| s.max_parallel + s.queue_capacity),
        );
        self.workers.set_limit(
            self.settings
                .as_ref()
                .filter(|s| s.enabled)
                .map_or(0, |s| s.max_parallel),
        );
    }
    /// Admission never waits. The task owns a bounded copy of the original, and
    /// a commit notification only; SMTP never joins the comparison task.
    pub fn begin(
        self: &Arc<Self>,
        raw: &[u8],
        envelope: Envelope<'_>,
        store: Store,
    ) -> Option<Ticket> {
        let settings = self.settings.as_ref().filter(|s| s.enabled)?;
        let mut report = Report {
            status: Status::Pending,
            job_id: uuid::Uuid::new_v4().to_string(),
            started_at: crate::now(),
            expires_at: crate::now() + COMMIT_TIMEOUT as i64 + 10,
            raw_sha256: crate::message::digest(raw),
            profile: settings.profile.clone(),
            settings_sha256: crate::message::digest(
                &serde_json::to_vec(settings).expect("typed Rspamd settings"),
            ),
            server: None,
            elapsed_ms: 0,
            score: None,
            required_score: None,
            action: None,
            symbols: vec![],
            noisefence_outcome: None,
            comparison: Comparison::Inconclusive,
        };
        let sample = crate::message::digest(envelope.id.as_bytes());
        if raw.len() > settings.max_bytes {
            report.status = Status::Oversize;
        } else if u32::from_str_radix(&sample[..8], 16).unwrap() % 100
            >= u32::from(settings.sample_percent)
        {
            report.status = Status::NotSampled;
        }
        if report.status != Status::Pending {
            return Some(Ticket {
                report,
                accepted: None,
            });
        }
        let Ok(permit) = self.outstanding.try_acquire() else {
            report.status = Status::Busy;
            return Some(Ticket {
                report,
                accepted: None,
            });
        };
        // A fixed byte budget also covers overlapping configuration revisions:
        // many new small-message slots cannot coexist with 64 MiB of older jobs.
        let Ok(memory) = self
            .memory
            .clone()
            .try_acquire_many_owned(raw.len().max(1) as u32)
        else {
            report.status = Status::Busy;
            return Some(Ticket {
                report,
                accepted: None,
            });
        };
        let request = self
            .client
            .as_ref()
            .unwrap()
            .post(format!("http://{}/checkv2", settings.endpoint))
            .header("Content-Type", "message/rfc822")
            .header("IP", envelope.ip.to_string())
            .header("Helo", envelope.helo)
            .header(
                "From",
                if envelope.sender.is_empty() {
                    "<>"
                } else {
                    envelope.sender
                },
            )
            .header("Queue-Id", envelope.id)
            .header("Flags", "pass_all,no_log")
            .header("Log", "no");
        let mut headers = reqwest::header::HeaderMap::new();
        for recipient in envelope.recipients {
            let Ok(value) = reqwest::header::HeaderValue::from_str(&recipient.address) else {
                report.status = Status::InvalidResponse;
                return Some(Ticket {
                    report,
                    accepted: None,
                });
            };
            headers.append("Rcpt", value);
        }
        let request = request.headers(headers).body(raw.to_vec());
        let (tx, mut rx) = oneshot::channel();
        let runtime = self.clone();
        let mut result = report.clone();
        let timeout = Duration::from_millis(settings.timeout_ms);
        tokio::spawn(async move {
            let _permit = permit;
            let _memory = memory;
            let started = Instant::now();
            let scan = async {
                let _worker = runtime.workers.acquire().await.map_err(|_| Status::Busy)?;
                query(request).await
            };
            // Cancellation on enqueue failure also cancels DNS/HTTP and frees RAM.
            let mut ids = None;
            let response = {
                let query = tokio::time::timeout(timeout, scan);
                tokio::pin!(query);
                tokio::select! {
                    response = &mut query => response,
                    accepted = &mut rx => match accepted {
                        Ok(accepted) => { ids = Some(accepted); query.await },
                        Err(_) => return,
                    }
                }
            };
            result.elapsed_ms = started.elapsed().as_millis() as u64;
            match response {
                Ok(Ok(response)) => {
                    result.status = if response.skipped {
                        Status::Skipped
                    } else {
                        Status::Complete
                    };
                    result.score = response.score;
                    result.required_score = response.required_score;
                    result.action = response.action;
                    result.symbols = response.symbols;
                    result.server = response.server;
                }
                Ok(Err(status)) => result.status = status,
                Err(_) => result.status = Status::Timeout,
            }
            // The HTTP request and raw buffer have been dropped before this wait.
            let ids = match ids {
                Some(ids) => ids,
                None => match tokio::time::timeout(Duration::from_secs(COMMIT_TIMEOUT), rx).await {
                    Ok(Ok(ids)) => ids,
                    _ => return,
                },
            };
            if let Err(error) = save(&store, ids, result).await {
                tracing::warn!(%error, "Rspamd comparison metadata could not be saved");
            }
        });
        Some(Ticket {
            report,
            accepted: Some(tx),
        })
    }
}

struct Response {
    skipped: bool,
    score: Option<f64>,
    required_score: Option<f64>,
    action: Option<String>,
    symbols: Vec<Symbol>,
    server: Option<String>,
}
async fn query(request: reqwest::RequestBuilder) -> std::result::Result<Response, Status> {
    let mut response = request.send().await.map_err(|_| Status::Unavailable)?;
    if !response.status().is_success() {
        return Err(Status::Unavailable);
    }
    if response
        .content_length()
        .is_some_and(|n| n > MAX_RESPONSE as u64)
    {
        return Err(Status::InvalidResponse);
    }
    let server = response
        .headers()
        .get("server")
        .and_then(|v| v.to_str().ok())
        .filter(|s| s.len() <= 128 && s.bytes().all(|b| b.is_ascii_graphic() || b == b' '))
        .map(String::from);
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| Status::Unavailable)? {
        if bytes.len() + chunk.len() > MAX_RESPONSE {
            return Err(Status::InvalidResponse);
        }
        bytes.extend_from_slice(&chunk);
    }
    parse(&bytes, server).map_err(|_| Status::InvalidResponse)
}
fn parse(bytes: &[u8], server: Option<String>) -> Result<Response> {
    #[derive(Deserialize)]
    struct Raw {
        #[serde(default)]
        is_skipped: bool,
        score: Option<f64>,
        required_score: Option<f64>,
        action: Option<String>,
        symbols: Option<BTreeMap<String, RawSymbol>>,
    }
    #[derive(Deserialize)]
    struct RawSymbol {
        score: f64,
    }
    let raw: Raw = serde_json::from_slice(bytes)?;
    if raw.is_skipped
        && raw.score.is_none()
        && raw.required_score.is_none()
        && raw.action.is_none()
        && raw.symbols.is_none()
    {
        return Ok(Response {
            skipped: true,
            score: None,
            required_score: None,
            action: None,
            symbols: vec![],
            server,
        });
    }
    let score = raw
        .score
        .filter(|v| v.is_finite() && v.abs() <= 1e9)
        .ok_or_else(|| anyhow::anyhow!("Invalid score"))?;
    let required_score = raw
        .required_score
        .filter(|v| v.is_finite() && *v > 0. && *v <= 1e9)
        .ok_or_else(|| anyhow::anyhow!("Invalid threshold"))?;
    let action = raw
        .action
        .ok_or_else(|| anyhow::anyhow!("Missing action"))?;
    ensure!(
        !action.is_empty()
            && action.len() <= 64
            && action
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b" _-".contains(&b)),
        "Invalid action"
    );
    let symbols = raw
        .symbols
        .ok_or_else(|| anyhow::anyhow!("Missing symbols"))?;
    ensure!(symbols.len() <= 512, "Too many symbols");
    let mut symbols = symbols
        .into_iter()
        .map(|(name, value)| {
            ensure!(
                !name.is_empty()
                    && name.len() <= 128
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
                    && value.score.is_finite()
                    && value.score.abs() <= 1e9,
                "Invalid symbol"
            );
            Ok(Symbol {
                name,
                score: value.score,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    symbols.sort_by(|a, b| {
        b.score
            .abs()
            .total_cmp(&a.score.abs())
            .then(a.name.cmp(&b.name))
    });
    Ok(Response {
        skipped: raw.is_skipped,
        score: Some(score),
        required_score: Some(required_score),
        action: Some(action),
        symbols,
        server,
    })
}

async fn save(store: &Store, ids: Vec<String>, result: Report) -> Result<()> {
    use rusqlite::{OptionalExtension, params};
    store.run(move |db| {
        let tx = db.transaction()?;
        for id in ids {
            let previous: Option<String> = tx.query_row("SELECT json_extract(scan,'$.rspamd') FROM messages m WHERE id=?1 AND json_extract(scan,'$.rspamd.job_id')=?2 AND json_extract(scan,'$.rspamd.status')='pending' AND json_extract(scan,'$.rspamd.raw_sha256')=?3 AND NOT EXISTS(SELECT 1 FROM cluster_origin o WHERE o.message_id=m.id)", params![id, result.job_id, result.raw_sha256], |r| r.get(0)).optional()?;
            let Some(previous) = previous else { continue; };
            let previous: Report = serde_json::from_str(&previous)?;
            let mut next = result.clone();
            next.noisefence_outcome = previous.noisefence_outcome;
            next.comparison = next.compare();
            // JSON path update preserves all decision fields, even future ones.
            // Existing HA and cluster triggers replicate only this metadata delta.
            tx.execute("UPDATE messages SET scan=json_set(scan,'$.rspamd',json(?2)) WHERE id=?1", params![id, serde_json::to_string(&next)?])?;
        }
        tx.commit()?;
        Ok(())
    }).await
}

#[cfg(test)]
mod tests;
