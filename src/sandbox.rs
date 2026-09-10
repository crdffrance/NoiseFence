//! Durable, opt-in CAPEv2 connector. This module never opens or executes documents.
//! See docs/sandbox.md for the API contract, recovery and quarantine integration.
use anyhow::{Context, Result, ensure};
use reqwest::{Client as HttpClient, Method, Url, header};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    net::IpAddr,
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Semaphore;

pub const VERSION: &str = "noisefence-sandbox-1";
pub const MAX_RETENTION_MS: i64 = 30 * 24 * 60 * 60 * 1000;
pub const PRUNE_BATCH_SIZE: usize = 100;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub enabled: bool,
    pub state_dir: PathBuf,
    /// Literal loopback/private IP only; HTTPS required outside loopback.
    pub endpoint: String,
    pub token_file: Option<PathBuf>,
    pub ca_certificate: Option<PathBuf>,
    /// Operator identifiers, not an attestation of the VM's isolation.
    pub instance_id: String,
    pub environment_id: String,
    /// Exactly one CAPE VM label. Empty and "all" are forbidden when enabled.
    pub machine: String,
    pub expected_version: Option<String>,
    pub request_timeout_ms: u64,
    pub analysis_timeout_secs: u64,
    pub job_timeout_secs: u64,
    pub poll_interval_ms: u64,
    /// Includes remote pending/running tasks and ambiguous submissions.
    pub max_parallel: usize,
    pub max_attachment_bytes: usize,
    pub max_total_bytes: usize,
    /// All retained rows, including terminal summaries. Explicit pruning required.
    pub max_jobs: usize,
    pub max_response_bytes: usize,
    pub max_findings: usize,
    /// CAPE's litereport JSON endpoint, never the "lite" artifact archive.
    pub use_lite_report: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            enabled: false,
            state_dir: "/var/lib/noisefence/sandbox".into(),
            endpoint: "http://127.0.0.1:8000/apiv2/".into(),
            token_file: None,
            ca_certificate: None,
            instance_id: "cape-local".into(),
            environment_id: "office-lab".into(),
            machine: String::new(),
            expected_version: None,
            request_timeout_ms: 3000,
            analysis_timeout_secs: 120,
            job_timeout_secs: 1800,
            poll_interval_ms: 15_000,
            max_parallel: 1,
            max_attachment_bytes: 16 * 1024 * 1024,
            max_total_bytes: 128 * 1024 * 1024,
            max_jobs: 1000,
            max_response_bytes: 8 * 1024 * 1024,
            max_findings: 64,
            use_lite_report: false,
        }
    }
}

impl Settings {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.state_dir.is_absolute(),
            "sandbox.state_dir must be absolute"
        );
        endpoint(&self.endpoint)?;
        ensure!(
            identifier(&self.instance_id) && identifier(&self.environment_id),
            "invalid sandbox provenance identifier"
        );
        ensure!(
            !self.enabled
                || (identifier(&self.machine) && !self.machine.eq_ignore_ascii_case("all")),
            "sandbox.machine must name one VM"
        );
        ensure!(
            self.expected_version.as_deref().is_none_or(identifier),
            "invalid sandbox expected_version"
        );
        ensure!(
            self.token_file.as_ref().is_none_or(|p| p.is_absolute())
                && self.ca_certificate.as_ref().is_none_or(|p| p.is_absolute()),
            "sandbox credential paths must be absolute"
        );
        ensure!(
            (100..=30_000).contains(&self.request_timeout_ms),
            "invalid sandbox request deadline"
        );
        ensure!(
            (1..=600).contains(&self.analysis_timeout_secs)
                && (1..=86_400).contains(&self.job_timeout_secs)
                && self.job_timeout_secs >= self.analysis_timeout_secs,
            "invalid sandbox analysis/job deadline"
        );
        ensure!(
            (100..=300_000).contains(&self.poll_interval_ms)
                && (1..=8).contains(&self.max_parallel),
            "invalid sandbox poll/parallel limits"
        );
        ensure!(
            (1..=32 * 1024 * 1024).contains(&self.max_attachment_bytes)
                && self.max_total_bytes >= self.max_attachment_bytes
                && self.max_total_bytes <= 512 * 1024 * 1024,
            "invalid sandbox input byte limits"
        );
        ensure!(
            (1..=10_000).contains(&self.max_jobs)
                && (1024..=16 * 1024 * 1024).contains(&self.max_response_bytes)
                && (1..=128).contains(&self.max_findings),
            "invalid sandbox storage/output limits"
        );
        Ok(())
    }

    /// Changes to any policy setting require a fresh store; credentials can rotate.
    pub fn policy_sha256(&self) -> String {
        let mut policy = self.clone();
        policy.token_file = None;
        policy.ca_certificate = None;
        policy.state_dir = PathBuf::new();
        digest(&serde_json::to_vec(&(VERSION, policy)).expect("settings serialize"))
    }
}

fn endpoint(value: &str) -> Result<Url> {
    let url = Url::parse(value).map_err(|_| anyhow::anyhow!("invalid sandbox endpoint"))?;
    let host = url.host_str().unwrap_or("").trim_matches(['[', ']']);
    let ip: IpAddr = host
        .parse()
        .map_err(|_| anyhow::anyhow!("sandbox endpoint requires a literal local/private IP"))?;
    let private = match ip {
        IpAddr::V4(ip) => ip.is_loopback() || ip.is_private(),
        IpAddr::V6(ip) => ip.is_loopback() || ip.is_unique_local(),
    };
    ensure!(
        private && (url.scheme() == "https" || (url.scheme() == "http" && ip.is_loopback())),
        "sandbox endpoint requires private HTTPS or loopback HTTP"
    );
    ensure!(
        url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.path() == "/apiv2/",
        "sandbox endpoint must end in /apiv2/ without credentials or query"
    );
    Ok(url)
}

fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
fn valid_digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OfficeKind {
    Doc,
    Docx,
    Docm,
    Xls,
    Xlsx,
    Xlsm,
    Xlsb,
    Ppt,
    Pptx,
    Pptm,
}
impl OfficeKind {
    pub fn from_extension(extension: &str) -> Option<Self> {
        match extension
            .trim_start_matches('.')
            .to_ascii_lowercase()
            .as_str()
        {
            "doc" => Some(Self::Doc),
            "docx" => Some(Self::Docx),
            "docm" => Some(Self::Docm),
            "xls" => Some(Self::Xls),
            "xlsx" => Some(Self::Xlsx),
            "xlsm" => Some(Self::Xlsm),
            "xlsb" => Some(Self::Xlsb),
            "ppt" => Some(Self::Ppt),
            "pptx" => Some(Self::Pptx),
            "pptm" => Some(Self::Pptm),
            _ => None,
        }
    }
    pub fn extension(self) -> &'static str {
        match self {
            Self::Doc => "doc",
            Self::Docx => "docx",
            Self::Docm => "docm",
            Self::Xls => "xls",
            Self::Xlsx => "xlsx",
            Self::Xlsm => "xlsm",
            Self::Xlsb => "xlsb",
            Self::Ppt => "ppt",
            Self::Pptx => "pptx",
            Self::Pptm => "pptm",
        }
    }
    pub fn package(self) -> &'static str {
        match self {
            Self::Doc | Self::Docx | Self::Docm => "doc",
            Self::Xls | Self::Xlsx | Self::Xlsm | Self::Xlsb => "xls",
            Self::Ppt | Self::Pptx | Self::Pptm => "ppt",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    #[default]
    ResearchOnly,
    Quarantine,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    #[default]
    Disabled,
    Queued,
    Submitting,
    Uncertain,
    Submitted,
    Running,
    Reporting,
    Complete,
    Failed,
    TimedOut,
}
impl Status {
    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Disabled | Self::Complete | Self::Failed | Self::TimedOut
        )
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    #[default]
    Inconclusive,
    NoFindings,
    Findings,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Detail {
    RequestTimeout,
    JobTimeout,
    Unavailable,
    HttpError,
    InvalidResponse,
    ResponseLimit,
    ApiError,
    SubmissionUncertain,
    MultipleTasks,
    DigestMismatch,
    TaskMismatch,
    BackendMismatch,
    AnalysisFailed,
    IncompleteReport,
    FindingLimit,
    OperatorCleared,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub severity: u8,
    pub confidence: u8,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Provenance {
    pub instance_id: String,
    pub environment_id: String,
    pub policy_sha256: String,
    pub engine_version: Option<String>,
    pub engine_commit: Option<String>,
    pub report_sha256: Option<String>,
    /// Always false: the connector cannot attest a hypervisor or network boundary.
    pub isolation_verified: bool,
}

/// No sample, message, result, timestamps or per-job provenance survives here.
/// Presence of a row means its remote capacity reservation is still held.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemoteReservation {
    pub job_id: String,
    pub remote_task_id: Option<u64>,
    pub remote_fanout: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Summary {
    pub version: String,
    pub job_id: String,
    pub message_sha256: String,
    pub attachment_sha256: String,
    pub attachment_bytes: usize,
    pub kind: Option<OfficeKind>,
    pub disposition: Disposition,
    pub status: Status,
    pub outcome: Outcome,
    pub detail: Option<Detail>,
    /// CAPE report's aggregate `malscore` (0..10), not a calibrated probability
    /// or a gateway verdict. It never controls Outcome, delivery or release.
    #[serde(default)]
    pub cape_malscore: Option<f64>,
    pub remote_task_id: Option<u64>,
    /// Remains true after uncertain submission, binding failure or local expiry.
    pub remote_slot_held: bool,
    /// Unexpected CAPE fanout freezes new admission until operator reconciliation.
    pub remote_fanout: bool,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub deadline_at_ms: i64,
    pub next_poll_at_ms: i64,
    pub requests: u64,
    pub findings: Vec<Finding>,
    pub findings_total: usize,
    pub findings_truncated: bool,
    pub provenance: Provenance,
}
impl Default for Summary {
    fn default() -> Self {
        Self {
            version: VERSION.into(),
            job_id: String::new(),
            message_sha256: String::new(),
            attachment_sha256: String::new(),
            attachment_bytes: 0,
            kind: None,
            disposition: Disposition::default(),
            status: Status::Disabled,
            outcome: Outcome::Inconclusive,
            detail: None,
            cape_malscore: None,
            remote_task_id: None,
            remote_slot_held: false,
            remote_fanout: false,
            created_at_ms: 0,
            updated_at_ms: 0,
            deadline_at_ms: 0,
            next_poll_at_ms: 0,
            requests: 0,
            findings: vec![],
            findings_total: 0,
            findings_truncated: false,
            provenance: Provenance::default(),
        }
    }
}
impl Summary {
    /// Convenience for integration. It never authorizes quarantine release.
    pub fn requires_quarantine(&self) -> bool {
        self.disposition == Disposition::Quarantine && self.status != Status::Disabled
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version == VERSION && !self.provenance.isolation_verified,
            "invalid sandbox summary version/provenance"
        );
        ensure!(
            self.cape_malscore
                .is_none_or(|score| score.is_finite() && (0.0..=10.0).contains(&score)),
            "invalid CAPE malscore"
        );
        if self.status == Status::Disabled {
            return Ok(());
        }
        ensure!(
            uuid::Uuid::parse_str(&self.job_id).is_ok()
                && valid_digest(&self.message_sha256)
                && valid_digest(&self.attachment_sha256)
                && valid_digest(&self.provenance.policy_sha256)
                && self.kind.is_some(),
            "invalid sandbox summary binding"
        );
        ensure!(
            self.attachment_bytes <= 32 * 1024 * 1024
                && self.findings.len() <= 128
                && self
                    .findings
                    .iter()
                    .all(|f| identifier(&f.id) && f.severity <= 5 && f.confidence <= 100),
            "invalid sandbox findings"
        );
        ensure!(
            self.remote_task_id
                .is_none_or(|id| (1..=i32::MAX as u64).contains(&id))
                && self
                    .provenance
                    .engine_version
                    .as_deref()
                    .is_none_or(identifier),
            "invalid sandbox backend metadata"
        );
        ensure!(
            self.provenance
                .report_sha256
                .as_deref()
                .is_none_or(valid_digest),
            "invalid sandbox report digest"
        );
        ensure!(
            self.status == Status::Complete || self.outcome == Outcome::Inconclusive,
            "incomplete sandbox result has a verdict"
        );
        Ok(())
    }
}

#[derive(Clone)]
pub struct Client {
    inner: Option<Arc<Inner>>,
}
struct Inner {
    settings: Settings,
    http: HttpClient,
    db: Mutex<Connection>,
    _lock: File,
    tick_lock: Arc<tokio::sync::Mutex<()>>,
    enqueue_slots: Arc<Semaphore>,
}

fn private_file(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let meta = file.metadata()?;
    // SAFETY: geteuid has no preconditions.
    ensure!(
        meta.is_file()
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.mode() & 0o077 == 0
            && meta.nlink() == 1,
        "sandbox state file must be private and singly linked"
    );
    Ok(file)
}
fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    ensure!(
        file.metadata()?.is_file(),
        "sandbox credential must be a regular file"
    );
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "sandbox credential exceeds limit");
    Ok(bytes)
}

fn install_retention(db: &Connection) -> Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS remote_reservations (
        id TEXT PRIMARY KEY, task_id INTEGER, fanout INTEGER NOT NULL CHECK(fanout IN (0,1)));",
    )?;
    Ok(())
}

fn prune_floor(db: &Connection) -> Result<Option<i64>> {
    db.query_row(
        "SELECT value FROM metadata WHERE key='pruned_before_ms'",
        [],
        |row| row.get::<_, String>(0),
    )
    .optional()?
    .map(|value| value.parse().context("invalid sandbox retention cutoff"))
    .transpose()
}

fn checked_cutoff(cutoff_ms: i64) -> Result<i64> {
    let now = now_ms();
    ensure!(
        (0..=now).contains(&cutoff_ms),
        "sandbox retention cutoff must be a past Unix millisecond timestamp"
    );
    Ok(cutoff_ms.max(now.saturating_sub(MAX_RETENTION_MS)))
}

fn prune_store(db: &mut Connection, cutoff_ms: i64) -> Result<usize> {
    let tx = db.transaction()?;
    let cutoff = prune_floor(&tx)?.unwrap_or(0).max(cutoff_ms);
    // The floor and scrubbing commit together, including after caller cancellation.
    tx.execute(
        "INSERT INTO metadata VALUES ('pruned_before_ms',?1)
        ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        [cutoff.to_string()],
    )?;
    let rows = {
        let mut query = tx.prepare(
            "SELECT summary FROM jobs
            WHERE json_extract(summary,'$.created_at_ms') <= ?1 ORDER BY rowid LIMIT ?2",
        )?;
        query
            .query_map(params![cutoff, PRUNE_BATCH_SIZE], |r| r.get::<_, String>(0))?
            .map(|row| decode_summary(&row?))
            .collect::<Result<Vec<_>>>()?
    };
    for row in &rows {
        if row.remote_slot_held {
            tx.execute(
                "INSERT INTO remote_reservations VALUES (?1,?2,?3)",
                params![row.job_id, row.remote_task_id, row.remote_fanout],
            )?;
        }
        // This removes the unsalted dedup digest too. Replay protection thereafter
        // relies on the persisted floor and the outbox's original creation time.
        tx.execute("DELETE FROM jobs WHERE id=?1", [&row.job_id])?;
    }
    tx.commit()?;
    Ok(rows.len())
}

impl Client {
    /// Opens a dedicated private SQLite spool and exclusive process lock. No network.
    /// Disabled settings create no files and do not read credentials.
    pub fn new(settings: Settings) -> Result<Self> {
        settings.validate()?;
        if !settings.enabled {
            return Ok(Self { inner: None });
        }
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&settings.state_dir)?;
        let meta = fs::symlink_metadata(&settings.state_dir)?;
        // SAFETY: geteuid has no preconditions.
        ensure!(
            meta.is_dir() && meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o077 == 0,
            "sandbox.state_dir must be an owned 0700 directory, not a symlink"
        );
        let lock = private_file(&settings.state_dir.join("worker.lock"))?;
        // SAFETY: valid owned fd; flock neither takes ownership nor stores a pointer.
        ensure!(
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "sandbox store already has a worker"
        );
        let db_path = settings.state_dir.join("jobs.sqlite3");
        let _db_file = private_file(&db_path)?;
        let db = Connection::open(&db_path)?;
        db.busy_timeout(Duration::from_millis(100))?;
        db.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON;
            CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, dedup TEXT UNIQUE NOT NULL, summary TEXT NOT NULL, payload BLOB);")?;
        install_retention(&db)?;
        let pages =
            (settings.max_total_bytes * 2 + settings.max_jobs * 65536 + 16 * 1024 * 1024) / 4096;
        db.pragma_update(None, "max_page_count", pages)?;
        let policy = settings.policy_sha256();
        db.execute(
            "INSERT OR IGNORE INTO metadata VALUES ('policy', ?1)",
            [&policy],
        )?;
        let existing: String =
            db.query_row("SELECT value FROM metadata WHERE key='policy'", [], |r| {
                r.get(0)
            })?;
        ensure!(
            existing == policy,
            "sandbox store policy changed; drain the old store and use a new state_dir"
        );
        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            header::HeaderValue::from_static("application/json"),
        );
        headers.insert(
            header::ACCEPT_ENCODING,
            header::HeaderValue::from_static("identity"),
        );
        if let Some(path) = &settings.token_file {
            let bytes = read_bounded(path, 512)?;
            let token = std::str::from_utf8(&bytes)
                .context("invalid sandbox token encoding")?
                .trim();
            ensure!(
                !token.is_empty() && token.bytes().all(|b| b.is_ascii_alphanumeric()),
                "invalid sandbox token"
            );
            let mut value = header::HeaderValue::from_str(&format!("Token {token}"))?;
            value.set_sensitive(true);
            headers.insert(header::AUTHORIZATION, value);
        }
        let mut builder = HttpClient::builder()
            .no_proxy()
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .default_headers(headers)
            .timeout(Duration::from_millis(settings.request_timeout_ms))
            .connect_timeout(Duration::from_millis(settings.request_timeout_ms))
            .pool_max_idle_per_host(settings.max_parallel);
        if let Some(path) = &settings.ca_certificate {
            builder = builder.add_root_certificate(reqwest::Certificate::from_pem(&read_bounded(
                path,
                128 * 1024,
            )?)?);
        }
        let http = builder
            .build()
            .map_err(|_| anyhow::anyhow!("sandbox HTTP client initialization failed"))?;
        let slots = settings.max_parallel;
        Ok(Self {
            inner: Some(Arc::new(Inner {
                settings,
                http,
                db: Mutex::new(db),
                _lock: lock,
                tick_lock: Arc::new(tokio::sync::Mutex::new(())),
                enqueue_slots: Arc::new(Semaphore::new(slots)),
            })),
        })
    }

    pub fn enabled(&self) -> bool {
        self.inner.is_some()
    }

    /// The policy of this actual client, for an outbox's frozen backend binding.
    /// Disabled clients have no active backend policy.
    pub fn policy_sha256(&self) -> Option<String> {
        self.inner
            .as_ref()
            .map(|inner| inner.settings.policy_sha256())
    }

    /// Bounded local persistence only. Repeating the same tuple returns the same job.
    /// message_sha256 must identify the original RFC822 bytes held by the caller.
    pub async fn enqueue(
        &self,
        message_sha256: &str,
        attachment: &[u8],
        kind: OfficeKind,
        disposition: Disposition,
    ) -> Result<Summary> {
        self.enqueue_inner(message_sha256, attachment, kind, disposition, None)
            .await
    }

    /// Use the immutable primary-outbox creation time, not retry time. Once local
    /// retention has run, older intents cannot recreate deleted connector jobs.
    pub async fn enqueue_created_at(
        &self,
        message_sha256: &str,
        attachment: &[u8],
        kind: OfficeKind,
        disposition: Disposition,
        created_at_ms: i64,
    ) -> Result<Summary> {
        self.enqueue_inner(
            message_sha256,
            attachment,
            kind,
            disposition,
            Some(created_at_ms),
        )
        .await
    }

    async fn enqueue_inner(
        &self,
        message_sha256: &str,
        attachment: &[u8],
        kind: OfficeKind,
        disposition: Disposition,
        created_at_ms: Option<i64>,
    ) -> Result<Summary> {
        let Some(inner) = &self.inner else {
            return Ok(Summary::default());
        };
        ensure!(
            valid_digest(message_sha256),
            "invalid sandbox message digest"
        );
        ensure!(
            !attachment.is_empty() && attachment.len() <= inner.settings.max_attachment_bytes,
            "sandbox attachment byte limit"
        );
        let inner = inner.clone();
        let permit = inner
            .enqueue_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| anyhow::anyhow!("sandbox enqueue busy"))?;
        let payload = attachment.to_vec();
        let message_digest = message_sha256.to_owned();
        let client = self.clone();
        client
            .db(move |db, settings| {
                let _permit = permit;
                let now = now_ms();
                let floor = prune_floor(db)?;
                let earliest = floor.unwrap_or(0).max(now.saturating_sub(MAX_RETENTION_MS));
                if let Some(created_at) = created_at_ms {
                    ensure!(
                        created_at > earliest && created_at <= now,
                        "sandbox outbox intent expired or has an invalid creation time"
                    );
                }
                let attachment_digest = digest(&payload);
                let dedup = digest(&serde_json::to_vec(&(
                    &message_digest,
                    &attachment_digest,
                    kind,
                    disposition,
                ))?);
                if let Some(summary) = db
                    .query_row("SELECT summary FROM jobs WHERE dedup=?1", [&dedup], |r| {
                        r.get::<_, String>(0)
                    })
                    .optional()?
                {
                    let existing = decode_summary(&summary)?;
                    ensure!(
                        existing.created_at_ms > earliest,
                        "sandbox job expired; local cleanup required"
                    );
                    return Ok(existing);
                }
                ensure!(
                    floor.is_none() || created_at_ms.is_some(),
                    "sandbox retention requires enqueue_created_at for new jobs"
                );
                let (count, total): (usize, usize) = db.query_row(
                    "SELECT COUNT(*), COALESCE(SUM(length(payload)),0) FROM jobs",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?;
                ensure!(
                    count < settings.max_jobs && total + payload.len() <= settings.max_total_bytes,
                    "sandbox durable queue limit"
                );
                let created_at = created_at_ms.unwrap_or(now);
                let summary = Summary {
                    job_id: uuid::Uuid::new_v4().to_string(),
                    message_sha256: message_digest,
                    attachment_sha256: attachment_digest,
                    attachment_bytes: payload.len(),
                    kind: Some(kind),
                    disposition,
                    status: Status::Queued,
                    created_at_ms: created_at,
                    updated_at_ms: now,
                    deadline_at_ms: (now + settings.job_timeout_secs as i64 * 1000)
                        .min(created_at + MAX_RETENTION_MS),
                    next_poll_at_ms: now,
                    provenance: Provenance {
                        instance_id: settings.instance_id.clone(),
                        environment_id: settings.environment_id.clone(),
                        policy_sha256: settings.policy_sha256(),
                        ..Default::default()
                    },
                    ..Default::default()
                };
                db.execute(
                    "INSERT INTO jobs VALUES (?1,?2,?3,?4)",
                    params![
                        summary.job_id,
                        dedup,
                        serde_json::to_string(&summary)?,
                        payload
                    ],
                )?;
                Ok(summary)
            })
            .await
    }

    pub async fn get(&self, job_id: &str) -> Result<Option<Summary>> {
        if !self.enabled() {
            return Ok(None);
        }
        ensure!(
            uuid::Uuid::parse_str(job_id).is_ok(),
            "invalid sandbox job id"
        );
        let id = job_id.to_owned();
        self.db(move |db, _| {
            let floor = prune_floor(db)?
                .unwrap_or(0)
                .max(now_ms().saturating_sub(MAX_RETENTION_MS));
            let result = db
                .query_row("SELECT summary FROM jobs WHERE id=?1", [id], |r| {
                    r.get::<_, String>(0)
                })
                .optional()?
                .map(|s| decode_summary(&s))
                .transpose()?;
            Ok(result.filter(|summary| summary.created_at_ms > floor))
        })
        .await
    }

    /// Bounded, local summary listing for restart recovery/diagnostics; no payloads.
    pub async fn list(&self, offset: usize, limit: usize) -> Result<Vec<Summary>> {
        ensure!(
            (1..=100).contains(&limit) && offset <= 10_000,
            "invalid sandbox list bounds"
        );
        if !self.enabled() {
            return Ok(vec![]);
        }
        self.db(move |db, _| {
            let floor = prune_floor(db)?.unwrap_or(0).max(now_ms().saturating_sub(MAX_RETENTION_MS));
            let mut query =
                db.prepare("SELECT summary FROM jobs WHERE json_extract(summary,'$.created_at_ms') > ?3 ORDER BY rowid LIMIT ?1 OFFSET ?2")?;
            query
                .query_map(params![limit, offset, floor], |r| r.get::<_, String>(0))?
                .map(|s| decode_summary(&s?))
                .collect()
        })
        .await
    }

    /// Scrub at most PRUNE_BATCH_SIZE expired rows, retaining only unresolved
    /// remote reservations. Repeat until zero; no network or remote cancellation.
    /// Call Client::prune_local instead when the backend is disabled/not open.
    pub async fn prune_before(&self, cutoff_ms: i64) -> Result<usize> {
        let cutoff = checked_cutoff(cutoff_ms)?;
        let inner = self
            .inner
            .as_ref()
            .context("sandbox disabled; use Client::prune_local")?;
        let guard = inner
            .tick_lock
            .clone()
            .try_lock_owned()
            .context("sandbox worker busy")?;
        self.db(move |db, _| {
            let _guard = guard;
            prune_store(db, cutoff)
        })
        .await
    }

    /// Cleanup without an HTTP client, credentials or an enabled backend. An
    /// absent store is a no-op; an active Client's exclusive lock refuses this
    /// path (use that client's prune_before instead). Does not create a spool.
    pub async fn prune_local(state_dir: &Path, cutoff_ms: i64) -> Result<usize> {
        let cutoff = checked_cutoff(cutoff_ms)?;
        ensure!(
            state_dir.is_absolute(),
            "sandbox cleanup path must be absolute"
        );
        let state_dir = state_dir.to_owned();
        tokio::task::spawn_blocking(move || {
            let meta = match fs::symlink_metadata(&state_dir) {
                Ok(meta) => meta,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
                Err(error) => return Err(error.into()),
            };
            // SAFETY: geteuid has no preconditions.
            ensure!(
                meta.is_dir()
                    && meta.uid() == unsafe { libc::geteuid() }
                    && meta.mode() & 0o077 == 0,
                "sandbox cleanup requires a private owned directory"
            );
            let db_path = state_dir.join("jobs.sqlite3");
            if let Err(error) = fs::symlink_metadata(&db_path) {
                if error.kind() == std::io::ErrorKind::NotFound {
                    return Ok(0);
                }
                return Err(error.into());
            }
            let lock = private_file(&state_dir.join("worker.lock"))?;
            // SAFETY: valid owned fd; flock stores no pointer and takes no ownership.
            ensure!(
                unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
                "sandbox store already has a worker; use its prune_before"
            );
            let _file = private_file(&db_path)?;
            let mut db =
                Connection::open_with_flags(&db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)?;
            db.busy_timeout(Duration::from_millis(100))?;
            db.execute_batch(
                "PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON;",
            )?;
            let _: String =
                db.query_row("SELECT value FROM metadata WHERE key='policy'", [], |r| {
                    r.get(0)
                })?;
            install_retention(&db)?;
            prune_store(&mut db, cutoff)
        })
        .await
        .context("sandbox local cleanup task failed")?
    }

    /// Minimal unresolved reservations after local data has been scrubbed.
    pub async fn tombstones(&self, offset: usize, limit: usize) -> Result<Vec<RemoteReservation>> {
        ensure!(
            (1..=100).contains(&limit) && offset <= 10_000,
            "invalid sandbox tombstone list bounds"
        );
        if !self.enabled() {
            return Ok(vec![]);
        }
        self.db(move |db, _| {
            let mut query = db.prepare("SELECT id,task_id,fanout FROM remote_reservations ORDER BY rowid LIMIT ?1 OFFSET ?2")?;
            Ok(query.query_map(params![limit, offset], |r| Ok(RemoteReservation {
                job_id: r.get(0)?, remote_task_id: r.get(1)?, remote_fanout: r.get(2)?,
            }))?.collect::<rusqlite::Result<Vec<_>>>()?)
        }).await
    }

    /// Runs at most max_parallel work items. Call periodically outside SMTP.
    /// Dropping this future leaves one bounded pass running, so cancellation cannot
    /// release its lock before network work/state commits finish.
    pub async fn tick(&self) -> Result<usize> {
        let Some(inner) = &self.inner else {
            return Ok(0);
        };
        let Ok(guard) = inner.tick_lock.clone().try_lock_owned() else {
            return Ok(0);
        };
        let client = self.clone();
        tokio::spawn(async move {
            let _guard = guard;
            let jobs = client.claim().await?;
            let count = jobs.len();
            let mut tasks = tokio::task::JoinSet::new();
            for (job, submit) in jobs {
                let client = client.clone();
                tasks.spawn(async move { client.advance(job, submit).await });
            }
            let mut failure = None;
            while let Some(result) = tasks.join_next().await {
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => failure = Some(e),
                    Err(_) => failure = Some(anyhow::anyhow!("sandbox background task failed")),
                }
            }
            if let Some(e) = failure {
                return Err(e);
            }
            Ok(count)
        })
        .await
        .context("sandbox worker failed")?
    }

    /// Operator-only: call AFTER verifying all remote tasks for this job are stopped
    /// or absent. This does not cancel CAPE work or release a quarantined message.
    pub async fn acknowledge_remote_stopped(&self, job_id: &str) -> Result<()> {
        let inner = self.inner.as_ref().context("sandbox disabled")?;
        let guard = inner
            .tick_lock
            .clone()
            .try_lock_owned()
            .context("sandbox worker busy")?;
        ensure!(
            uuid::Uuid::parse_str(job_id).is_ok(),
            "invalid sandbox job id"
        );
        let id = job_id.to_owned();
        self.db(move |db, _| {
            let _guard = guard;
            if db.execute("DELETE FROM remote_reservations WHERE id=?1", [&id])? > 0 {
                return Ok(());
            }
            let raw: String = db
                .query_row("SELECT summary FROM jobs WHERE id=?1", [&id], |r| r.get(0))
                .optional()?
                .context("sandbox job not found")?;
            let mut summary = decode_summary(&raw)?;
            ensure!(
                summary.status.terminal() && summary.remote_slot_held,
                "sandbox job does not need operator reconciliation"
            );
            summary.remote_slot_held = false;
            summary.detail = Some(Detail::OperatorCleared);
            summary.updated_at_ms = now_ms();
            db.execute(
                "UPDATE jobs SET summary=?1,payload=NULL WHERE id=?2",
                params![serde_json::to_string(&summary)?, id],
            )?;
            Ok(())
        })
        .await
    }

    /// Local retention only. Refuses active or unresolved remote work.
    pub async fn remove(&self, job_id: &str) -> Result<()> {
        let summary = self.get(job_id).await?.context("sandbox job not found")?;
        ensure!(
            summary.status.terminal() && !summary.remote_slot_held,
            "sandbox job is active or unresolved"
        );
        let id = job_id.to_owned();
        self.db(move |db, _| {
            db.execute("DELETE FROM jobs WHERE id=?1", [id])?;
            Ok(())
        })
        .await
    }

    async fn db<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Connection, &Settings) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let inner = self.inner.clone().context("sandbox disabled")?;
        tokio::task::spawn_blocking(move || {
            let mut db = inner
                .db
                .lock()
                .map_err(|_| anyhow::anyhow!("sandbox store lock failed"))?;
            f(&mut db, &inner.settings)
        })
        .await
        .context("sandbox store task failed")?
    }

    async fn save(&self, mut job: Summary, clear_payload: bool) -> Result<()> {
        job.updated_at_ms = now_ms();
        job.validate()?;
        self.db(move |db, _| {
            db.execute("UPDATE jobs SET summary=?1, payload=CASE WHEN ?2 THEN NULL ELSE payload END WHERE id=?3", params![serde_json::to_string(&job)?, clear_payload, job.job_id])?;
            Ok(())
        }).await
    }

    async fn claim(&self) -> Result<Vec<(Summary, bool)>> {
        self.db(|db, settings| {
            let transaction = db.transaction()?;
            let mut rows = {
                let mut query = transaction.prepare("SELECT summary FROM jobs ORDER BY rowid")?;
                query
                    .query_map([], |r| r.get::<_, String>(0))?
                    .map(|s| decode_summary(&s?))
                    .collect::<Result<Vec<_>>>()?
            };
            let now = now_ms();
            let floor = prune_floor(&transaction)?
                .unwrap_or(0)
                .max(now.saturating_sub(MAX_RETENTION_MS));
            for job in &mut rows {
                if !job.status.terminal() && now >= job.deadline_at_ms {
                    job.status = Status::TimedOut;
                    job.detail = Some(Detail::JobTimeout);
                    job.updated_at_ms = now;
                    transaction.execute(
                        "UPDATE jobs SET summary=?1, payload=NULL WHERE id=?2",
                        params![serde_json::to_string(job)?, job.job_id],
                    )?;
                }
            }
            let (tombstones, fanout): (usize, bool) = transaction.query_row(
                "SELECT COUNT(*), COALESCE(MAX(fanout),0) FROM remote_reservations",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            let mut reserved = rows.iter().filter(|s| s.remote_slot_held).count() + tombstones;
            let admission_stopped =
                fanout || rows.iter().any(|s| s.remote_slot_held && s.remote_fanout);
            let mut selected = Vec::new();
            // Existing remote work has priority; local queue never starves polling.
            rows.sort_by_key(|s| s.status == Status::Queued);
            for mut job in rows {
                if selected.len() == settings.max_parallel {
                    break;
                }
                if job.status.terminal() || job.created_at_ms <= floor || now < job.next_poll_at_ms
                {
                    continue;
                }
                let submit = job.status == Status::Queued;
                if submit {
                    if admission_stopped || reserved >= settings.max_parallel {
                        continue;
                    }
                    job.status = Status::Submitting;
                    job.remote_slot_held = true;
                    reserved += 1;
                }
                job.next_poll_at_ms = now + settings.poll_interval_ms as i64;
                job.updated_at_ms = now;
                transaction.execute(
                    "UPDATE jobs SET summary=?1 WHERE id=?2",
                    params![serde_json::to_string(&job)?, job.job_id],
                )?;
                selected.push((job, submit));
            }
            transaction.commit()?;
            Ok(selected)
        })
        .await
    }

    async fn advance(&self, mut job: Summary, submit: bool) -> Result<()> {
        let inner = self.inner.as_ref().expect("enabled");
        let result = if submit {
            let id = job.job_id.clone();
            let payload: Vec<u8> = self
                .db(move |db, _| {
                    Ok(db.query_row("SELECT payload FROM jobs WHERE id=?1", [id], |r| r.get(0))?)
                })
                .await?;
            if payload.len() != job.attachment_bytes || digest(&payload) != job.attachment_sha256 {
                job.status = Status::Failed;
                job.detail = Some(Detail::DigestMismatch);
                job.remote_slot_held = false;
                return self.save(job, true).await;
            }
            job.requests += 1;
            self.submit(&job, payload).await.map(|id| {
                job.remote_task_id = Some(id);
                job.status = Status::Submitted;
                job.detail = None;
            })
        } else if job.remote_task_id.is_none() {
            job.requests += 1;
            self.reconcile(&job).await.map(|id| {
                if let Some(id) = id {
                    job.remote_task_id = Some(id);
                    job.status = Status::Submitted;
                    job.detail = None;
                } else {
                    job.status = Status::Uncertain;
                    job.detail = Some(Detail::SubmissionUncertain);
                }
            })
        } else {
            self.poll(&mut job).await
        };
        if let Err(detail) = result {
            if detail == Detail::MultipleTasks {
                job.remote_fanout = true;
                job.remote_slot_held = true;
            }
            job.detail = Some(detail);
            job.outcome = Outcome::Inconclusive;
            if job.remote_fanout {
                job.status = Status::Failed;
            } else if submit || job.remote_task_id.is_none() {
                job.status = Status::Uncertain;
            } else if matches!(
                detail,
                Detail::DigestMismatch
                    | Detail::TaskMismatch
                    | Detail::BackendMismatch
                    | Detail::InvalidResponse
                    | Detail::ResponseLimit
                    | Detail::MultipleTasks
            ) {
                job.status = Status::Failed;
            }
        }
        if !job.status.terminal() && now_ms() >= job.deadline_at_ms {
            job.status = Status::TimedOut;
            job.outcome = Outcome::Inconclusive;
            job.detail = Some(Detail::JobTimeout);
        }
        job.next_poll_at_ms = now_ms() + inner.settings.poll_interval_ms as i64;
        // An ambiguous POST is never retried; local attachment bytes are no longer needed.
        self.save(job, true).await
    }

    async fn submit(&self, job: &Summary, payload: Vec<u8>) -> std::result::Result<u64, Detail> {
        let settings = &self.inner.as_ref().expect("enabled").settings;
        let kind = job.kind.ok_or(Detail::InvalidResponse)?;
        let boundary = format!("nf-{}", uuid::Uuid::new_v4());
        if payload
            .windows(boundary.len())
            .any(|w| w == boundary.as_bytes())
        {
            return Err(Detail::InvalidResponse);
        }
        let mut body = Vec::with_capacity(payload.len() + 2048);
        // Fixed field names and constrained values: no original filename or mail metadata.
        for (name, value) in [
            ("package", kind.package().to_owned()),
            ("machine", settings.machine.clone()),
            ("platform", "windows".into()),
            ("timeout", settings.analysis_timeout_secs.to_string()),
            ("custom", custom(job)),
            ("route", "drop".into()),
        ] {
            body.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n").as_bytes());
        }
        body.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"sample.{}\"\r\nContent-Type: application/octet-stream\r\n\r\n", kind.extension()).as_bytes());
        body.extend_from_slice(&payload);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let reply = self
            .request(
                job,
                Method::POST,
                "tasks/create/file/",
                Some((format!("multipart/form-data; boundary={boundary}"), body)),
            )
            .await?;
        if reply
            .pointer("/data/task_ids")
            .and_then(Value::as_array)
            .is_some_and(|ids| ids.len() > 1)
        {
            return Err(Detail::MultipleTasks);
        }
        api_ok(&reply)?;
        let ids = reply
            .pointer("/data/task_ids")
            .and_then(Value::as_array)
            .ok_or(Detail::InvalidResponse)?;
        if ids.len() != 1 {
            return Err(Detail::MultipleTasks);
        }
        task_id(&ids[0])
    }

    async fn reconcile(&self, job: &Summary) -> std::result::Result<Option<u64>, Detail> {
        let reply = self
            .request(
                job,
                Method::GET,
                &format!("tasks/search/sha256/{}/", job.attachment_sha256),
                None,
            )
            .await?;
        api_ok(&reply)?;
        let entries = reply
            .get("data")
            .and_then(Value::as_array)
            .ok_or(Detail::InvalidResponse)?;
        let matches: Vec<_> = entries
            .iter()
            .filter(|e| e.get("custom").and_then(Value::as_str) == Some(custom(job).as_str()))
            .collect();
        if matches.len() > 1 {
            return Err(Detail::MultipleTasks);
        }
        matches
            .first()
            .map(|entry| {
                let id = task_id(&entry["id"])?;
                bind_task(entry, job, id)?;
                Ok(id)
            })
            .transpose()
    }

    async fn poll(&self, job: &mut Summary) -> std::result::Result<(), Detail> {
        let id = job.remote_task_id.ok_or(Detail::InvalidResponse)?;
        job.requests += 1;
        let reply = self
            .request(job, Method::GET, &format!("tasks/view/{id}/"), None)
            .await?;
        api_ok(&reply)?;
        let task = reply.get("data").ok_or(Detail::InvalidResponse)?;
        bind_task(task, job, id)?;
        match task["status"].as_str().ok_or(Detail::InvalidResponse)? {
            "pending" | "distributed" => {
                job.status = Status::Submitted;
                job.detail = None;
            }
            "running" => {
                job.status = Status::Running;
                job.detail = None;
            }
            "completed" => {
                job.status = Status::Reporting;
                job.detail = None;
            }
            "failed_analysis" | "failed_processing" | "failed_reporting" | "banned" => {
                job.status = Status::Failed;
                job.detail = Some(Detail::AnalysisFailed);
                job.remote_slot_held = false;
            }
            "reported" => {
                // Execution ended according to the bound task. Report failures do not
                // consume a VM slot, but remain inconclusive and never release mail.
                job.status = Status::Reporting;
                job.remote_slot_held = false;
                job.requests += 1;
                let settings = &self.inner.as_ref().expect("enabled").settings;
                let format = if settings.use_lite_report {
                    "litereport"
                } else {
                    "json"
                };
                let report = self
                    .request(
                        job,
                        Method::GET,
                        &format!("tasks/get/report/{id}/{format}/"),
                        None,
                    )
                    .await?;
                apply_report(job, &report, settings)?;
                if task.get("errors").is_none_or(|e| !empty(e)) {
                    job.outcome = Outcome::Inconclusive;
                    job.detail = Some(Detail::IncompleteReport);
                }
            }
            _ => return Err(Detail::InvalidResponse),
        }
        Ok(())
    }

    async fn request(
        &self,
        job: &Summary,
        method: Method,
        path: &str,
        body: Option<(String, Vec<u8>)>,
    ) -> std::result::Result<Value, Detail> {
        let inner = self.inner.as_ref().expect("enabled");
        let remaining = job.deadline_at_ms.saturating_sub(now_ms());
        if remaining <= 0 {
            return Err(Detail::JobTimeout);
        }
        let deadline =
            Duration::from_millis(inner.settings.request_timeout_ms.min(remaining as u64));
        let work = async {
            let url = format!("{}{path}", inner.settings.endpoint);
            let mut request = inner.http.request(method, url);
            if let Some((content_type, body)) = body {
                request = request
                    .header(header::CONTENT_TYPE, content_type)
                    .body(body);
            }
            let mut reply = request.send().await.map_err(http_error)?;
            if !reply.status().is_success() {
                return Err(Detail::HttpError);
            }
            if reply
                .headers()
                .get(header::CONTENT_ENCODING)
                .is_some_and(|v| v != "identity")
            {
                return Err(Detail::InvalidResponse);
            }
            let limit = inner.settings.max_response_bytes;
            if reply.content_length().is_some_and(|n| n > limit as u64) {
                return Err(Detail::ResponseLimit);
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = reply.chunk().await.map_err(http_error)? {
                if chunk.len() > limit.saturating_sub(bytes.len()) {
                    return Err(Detail::ResponseLimit);
                }
                bytes.extend_from_slice(&chunk);
            }
            serde_json::from_slice(&bytes).map_err(|_| Detail::InvalidResponse)
        };
        tokio::time::timeout(deadline, work)
            .await
            .map_err(|_| Detail::RequestTimeout)?
    }
}

fn decode_summary(value: &str) -> Result<Summary> {
    ensure!(value.len() <= 65536, "sandbox stored summary exceeds limit");
    let summary: Summary = serde_json::from_str(value)?;
    summary.validate()?;
    Ok(summary)
}
fn http_error(error: reqwest::Error) -> Detail {
    if error.is_timeout() {
        Detail::RequestTimeout
    } else {
        Detail::Unavailable
    }
}
fn custom(job: &Summary) -> String {
    format!("noisefence:{}", job.job_id)
}
fn empty(value: &Value) -> bool {
    value.is_null()
        || value == &Value::Bool(false)
        || value.as_array().is_some_and(Vec::is_empty)
        || value.as_object().is_some_and(|m| m.is_empty())
}
fn api_ok(value: &Value) -> std::result::Result<(), Detail> {
    if !value.is_object() {
        return Err(Detail::InvalidResponse);
    }
    if value.get("error").is_some_and(|e| !empty(e)) {
        return Err(Detail::ApiError);
    }
    if value.get("errors").is_some_and(|e| !empty(e)) {
        return Err(Detail::ApiError);
    }
    Ok(())
}
fn task_id(value: &Value) -> std::result::Result<u64, Detail> {
    value
        .as_u64()
        .filter(|id| (1..=i32::MAX as u64).contains(id))
        .ok_or(Detail::InvalidResponse)
}
fn bind_task(task: &Value, job: &Summary, id: u64) -> std::result::Result<(), Detail> {
    if task_id(&task["id"])? != id
        || task["custom"].as_str() != Some(custom(job).as_str())
        || task["category"].as_str() != Some("file")
        || task["package"].as_str() != job.kind.map(OfficeKind::package)
    {
        return Err(Detail::TaskMismatch);
    }
    if task.pointer("/sample/sha256").and_then(Value::as_str) != Some(&job.attachment_sha256) {
        return Err(Detail::DigestMismatch);
    }
    Ok(())
}

fn apply_report(
    job: &mut Summary,
    report: &Value,
    settings: &Settings,
) -> std::result::Result<(), Detail> {
    api_ok(report)?;
    let info = &report["info"];
    if task_id(&info["id"])? != job.remote_task_id.ok_or(Detail::TaskMismatch)?
        || info["custom"].as_str() != Some(custom(job).as_str())
        || info["category"].as_str() != Some("file")
        || info["package"].as_str() != job.kind.map(OfficeKind::package)
    {
        return Err(Detail::TaskMismatch);
    }
    if report
        .pointer("/target/file/sha256")
        .and_then(Value::as_str)
        != Some(&job.attachment_sha256)
    {
        return Err(Detail::DigestMismatch);
    }
    let version = info["version"]
        .as_str()
        .filter(|s| identifier(s))
        .ok_or(Detail::InvalidResponse)?;
    if settings
        .expected_version
        .as_deref()
        .is_some_and(|v| v != version)
    {
        return Err(Detail::BackendMismatch);
    }
    // CAPE's static form field is intentionally omitted at submission: Python
    // treats nonempty strings such as "0" as true in this path.
    if let Some(machine) = info["machine"].as_object() {
        let label = machine
            .get("label")
            .or_else(|| machine.get("name"))
            .and_then(Value::as_str);
        if label != Some(settings.machine.as_str()) {
            return Err(Detail::BackendMismatch);
        }
    }
    let signatures = report["signatures"]
        .as_array()
        .ok_or(Detail::IncompleteReport)?;
    let cape_malscore = match report.get("malscore") {
        None | Some(Value::Null) => None,
        Some(value) => Some(
            value
                .as_f64()
                .filter(|score| score.is_finite() && (0.0..=10.0).contains(score))
                .ok_or(Detail::InvalidResponse)?,
        ),
    };
    let mut findings = Vec::new();
    for signature in signatures.iter().take(settings.max_findings) {
        let id = signature["name"]
            .as_str()
            .filter(|s| identifier(s))
            .ok_or(Detail::InvalidResponse)?;
        let severity = signature["severity"]
            .as_u64()
            .filter(|n| *n <= 5)
            .ok_or(Detail::InvalidResponse)? as u8;
        let confidence = signature["confidence"]
            .as_u64()
            .filter(|n| *n <= 100)
            .ok_or(Detail::InvalidResponse)? as u8;
        findings.push(Finding {
            id: id.into(),
            severity,
            confidence,
        });
    }
    job.provenance.engine_version = Some(version.into());
    job.provenance.engine_commit = info["CAPE_current_commit"]
        .as_str()
        .filter(|s| s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(str::to_owned);
    // Hash canonical parsed JSON; raw reports are neither persisted nor returned.
    job.provenance.report_sha256 = Some(digest(
        &serde_json::to_vec(report).map_err(|_| Detail::InvalidResponse)?,
    ));
    job.findings = findings;
    job.cape_malscore = cape_malscore;
    job.findings_total = signatures.len();
    job.findings_truncated = signatures.len() > settings.max_findings;
    job.status = Status::Complete;
    job.detail = None;
    job.outcome = if signatures.is_empty() {
        Outcome::NoFindings
    } else {
        Outcome::Findings
    };
    // A completed report alone does not prove that macros ran. Require useful
    // execution metadata and explicit absence of processing errors even for advisory output.
    let incomplete = !info["duration"]
        .as_f64()
        .is_some_and(|d| d.is_finite() && d > 0.0)
        || !info["machine"].is_object()
        || report.pointer("/debug/errors").is_none_or(|v| !empty(v));
    if incomplete {
        job.outcome = Outcome::Inconclusive;
        job.detail = Some(Detail::IncompleteReport);
    }
    if job.findings_truncated {
        job.outcome = Outcome::Inconclusive;
        job.detail = Some(Detail::FindingLimit);
    }
    Ok(())
}
