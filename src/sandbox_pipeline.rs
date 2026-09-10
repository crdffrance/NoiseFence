//! Atomic mail/outbox admission and recoverable local handoff to the CAPE client.
//! No backend calls on SMTP, no malware verdicts, no automatic quarantine release.
use crate::{engine::Scan, sandbox, store::Store};
use anyhow::{Result, ensure};
use mail_parser::{MessageParser, MimeHeaders, PartType};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::OpenOptions,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    sync::Arc,
};

pub const VERSION: &str = "sandbox-pipeline-1";
/// The outer messages table MUST be aliased m. Also guard the final tombstone UPDATE.
pub const NEEDS_RAW_SQL: &str = "EXISTS (SELECT 1 FROM sandbox_pipeline_outbox so WHERE so.message_id=m.id AND so.state IN ('pending','submitting'))";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub enabled: bool,
    pub quarantine_selected: bool,
    pub quarantine_days: u16,
    pub max_raw_bytes: usize,
    pub max_parts: usize,
    pub max_attachments: usize,
    pub max_attachment_bytes: usize,
    pub max_total_attachment_bytes: usize,
    pub max_outbox_jobs: usize,
    pub max_pending_raw_bytes: u64,
    pub submission_timeout_secs: u64,
    pub retry_interval_secs: u64,
    pub max_attempts: u32,
    pub batch_size: usize,
    pub retention_days: u16,
    #[serde(skip)]
    backend_policy: Option<String>,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            enabled: false,
            quarantine_selected: false,
            quarantine_days: 14,
            max_raw_bytes: 32 * 1024 * 1024,
            max_parts: 256,
            max_attachments: 8,
            max_attachment_bytes: 16 * 1024 * 1024,
            max_total_attachment_bytes: 32 * 1024 * 1024,
            max_outbox_jobs: 1000,
            max_pending_raw_bytes: 256 * 1024 * 1024,
            submission_timeout_secs: 3600,
            retry_interval_secs: 15,
            max_attempts: 256,
            batch_size: 8,
            retention_days: 30,
            backend_policy: None,
        }
    }
}
impl Settings {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (1..=30).contains(&self.quarantine_days) && (1..=30).contains(&self.retention_days),
            "invalid sandbox pipeline retention"
        );
        for (value, ceiling) in [
            (self.max_raw_bytes, 64 * 1024 * 1024),
            (self.max_parts, 512),
            (self.max_attachments, 32),
            (self.max_attachment_bytes, 32 * 1024 * 1024),
            (self.max_total_attachment_bytes, 64 * 1024 * 1024),
            (self.max_outbox_jobs, 10_000),
            (self.batch_size, 32),
            (self.max_attempts as usize, 10_000),
        ] {
            ensure!(
                (1..=ceiling).contains(&value),
                "invalid sandbox pipeline limit"
            );
        }
        ensure!(
            (1..=4 * 1024 * 1024 * 1024).contains(&self.max_pending_raw_bytes)
                && self.max_total_attachment_bytes >= self.max_attachment_bytes
                && (1..=86_400).contains(&self.submission_timeout_secs)
                && (1..=300).contains(&self.retry_interval_secs),
            "invalid sandbox pipeline budget"
        );
        Ok(())
    }
    /// Runtime-only binding: deserialize settings, validate, then bind the actual
    /// configured backend. Availability is never probed here or during prepare.
    pub fn bind_backend(&mut self, backend: &sandbox::Settings) -> Result<()> {
        self.validate()?;
        backend.validate()?;
        ensure!(
            !self.enabled || backend.enabled,
            "sandbox pipeline requires explicitly enabled backend"
        );
        ensure!(
            self.max_attachment_bytes <= backend.max_attachment_bytes,
            "pipeline attachment limit exceeds connector limit"
        );
        self.backend_policy = Some(backend.policy_sha256());
        Ok(())
    }
    fn policy(&self) -> Result<String> {
        ensure!(
            !self.enabled || self.backend_policy.is_some(),
            "sandbox pipeline backend is not bound"
        );
        Ok(digest(&serde_json::to_vec(&(
            VERSION,
            self,
            &self.backend_policy,
        ))?))
    }
    fn disposition(&self) -> sandbox::Disposition {
        if self.quarantine_selected {
            sandbox::Disposition::Quarantine
        } else {
            sandbox::Disposition::ResearchOnly
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Detail {
    RawLimit,
    PartLimit,
    AttachmentLimit,
    TotalAttachmentLimit,
    CandidateLimit,
    Encoding,
    InvalidMime,
    SpoolMissing,
    SpoolChanged,
    AttachmentChanged,
    QueueBusy,
    SubmissionExpired,
    PolicyChanged,
    ClientMissing,
    InvalidResult,
    ResultExpired,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Preparation {
    Disabled,
    NoCandidates,
    Prepared,
    Limited,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Report {
    pub version: String,
    pub status: Preparation,
    pub disposition: sandbox::Disposition,
    pub selected: usize,
    pub skipped: usize,
    pub details: Vec<Detail>,
}
impl Report {
    fn limited(&mut self, detail: Detail) {
        self.status = Preparation::Limited;
        self.skipped += 1;
        if !self.details.contains(&detail) {
            self.details.push(detail);
        }
    }
}
#[derive(Clone, Debug)]
struct Attachment {
    part: usize,
    sha256: String,
    bytes: usize,
    kind: sandbox::OfficeKind,
}
/// Only prepare can construct this receipt. Never serialize/deserialise it as Scan.
#[derive(Clone, Debug)]
pub struct Plan {
    settings: Settings,
    policy: String,
    message_sha256: String,
    spool_sha256: Option<String>,
    spool_bytes: usize,
    attachments: Vec<Attachment>,
    report: Report,
}
impl Plan {
    pub fn report(&self) -> Report {
        self.report.clone()
    }
    pub fn bind_queued(&mut self, raw: &[u8]) -> Result<()> {
        if self.attachments.is_empty() {
            return Ok(());
        }
        ensure!(
            raw.len() <= self.settings.max_raw_bytes,
            "sandbox retained raw exceeds prepared budget"
        );
        self.spool_sha256 = Some(digest(raw));
        self.spool_bytes = raw.len();
        Ok(())
    }
}
fn digest(raw: &[u8]) -> String {
    hex::encode(Sha256::digest(raw))
}
fn safe_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}
fn kind(part: &mail_parser::MessagePart<'_>) -> Option<sandbox::OfficeKind> {
    if let Some(name) = part.attachment_name()
        && let Some((_, ext)) = name.rsplit_once('.')
        && let Some(kind) = sandbox::OfficeKind::from_extension(ext)
    {
        return Some(kind);
    }
    let ct = part.content_type()?;
    let subtype = ct.c_subtype.as_deref()?;
    if !ct.c_type.eq_ignore_ascii_case("application") {
        return None;
    }
    Some(match subtype.to_ascii_lowercase().as_str() {
        "msword" => sandbox::OfficeKind::Doc,
        "vnd.openxmlformats-officedocument.wordprocessingml.document" => sandbox::OfficeKind::Docx,
        "vnd.ms-word.document.macroenabled.12" => sandbox::OfficeKind::Docm,
        "vnd.ms-excel" => sandbox::OfficeKind::Xls,
        "vnd.openxmlformats-officedocument.spreadsheetml.sheet" => sandbox::OfficeKind::Xlsx,
        "vnd.ms-excel.sheet.macroenabled.12" => sandbox::OfficeKind::Xlsm,
        "vnd.ms-excel.sheet.binary.macroenabled.12" => sandbox::OfficeKind::Xlsb,
        "vnd.ms-powerpoint" => sandbox::OfficeKind::Ppt,
        "vnd.openxmlformats-officedocument.presentationml.presentation" => {
            sandbox::OfficeKind::Pptx
        }
        "vnd.ms-powerpoint.presentation.macroenabled.12" => sandbox::OfficeKind::Pptm,
        _ => return None,
    })
}

pub fn prepare(raw: &[u8], scan: &Scan, settings: &Settings) -> Result<Plan> {
    settings.validate()?;
    let mut plan = Plan {
        settings: settings.clone(),
        policy: settings.policy()?,
        message_sha256: String::new(),
        spool_sha256: None,
        spool_bytes: 0,
        attachments: Vec::new(),
        report: Report {
            version: VERSION.into(),
            status: Preparation::NoCandidates,
            disposition: settings.disposition(),
            selected: 0,
            skipped: 0,
            details: Vec::new(),
        },
    };
    if !settings.enabled {
        plan.report.status = Preparation::Disabled;
        return Ok(plan);
    }
    if raw.len() > settings.max_raw_bytes {
        plan.report.limited(Detail::RawLimit);
    } else {
        plan.message_sha256 = digest(raw);
        ensure!(
            scan.raw_sha256.as_deref() == Some(&plan.message_sha256),
            "sandbox preparation does not match original scan"
        );
        if let Some(message) = MessageParser::default().parse(raw) {
            if message.parts.len() > settings.max_parts {
                plan.report.limited(Detail::PartLimit);
            } else {
                let mut total = 0usize;
                let mut seen = BTreeSet::new();
                for (index, part) in message.parts.iter().enumerate() {
                    // Embedded messages are not recursively opened, archives are
                    // not unpacked. Office selection is advisory metadata only.
                    if matches!(&part.body, PartType::Multipart(_) | PartType::Message(_)) {
                        continue;
                    }
                    let Some(kind) = kind(part) else {
                        continue;
                    };
                    if part.is_encoding_problem {
                        plan.report.limited(Detail::Encoding);
                        continue;
                    }
                    let bytes = part.contents();
                    if bytes.is_empty() || bytes.len() > settings.max_attachment_bytes {
                        plan.report.limited(Detail::AttachmentLimit);
                        continue;
                    }
                    let sha256 = digest(bytes);
                    if !seen.insert((sha256.clone(), kind.extension())) {
                        continue;
                    }
                    if plan.attachments.len() >= settings.max_attachments {
                        plan.report.limited(Detail::CandidateLimit);
                        continue;
                    }
                    if total + bytes.len() > settings.max_total_attachment_bytes {
                        plan.report.limited(Detail::TotalAttachmentLimit);
                        continue;
                    }
                    total += bytes.len();
                    plan.attachments.push(Attachment {
                        part: index,
                        sha256,
                        bytes: bytes.len(),
                        kind,
                    });
                }
            }
        } else {
            plan.report.limited(Detail::InvalidMime);
        }
    }
    ensure!(
        !settings.quarantine_selected || plan.report.status != Preparation::Limited,
        "sandbox quarantine selection incomplete; retry before accepting mail"
    );
    plan.report.selected = plan.attachments.len();
    if !plan.attachments.is_empty() && plan.report.status != Preparation::Limited {
        plan.report.status = Preparation::Prepared;
    }
    // Original raw is also a valid spool until the parent binds rewritten bytes.
    if !plan.attachments.is_empty() {
        plan.bind_queued(raw)?;
    }
    Ok(plan)
}

pub fn install(db: &Connection) -> Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS sandbox_pipeline_messages(
        message_id TEXT PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,
        message_sha256 TEXT NOT NULL,spool_sha256 TEXT NOT NULL,spool_bytes INTEGER NOT NULL,
        backend_policy TEXT NOT NULL,policy TEXT NOT NULL,created INTEGER NOT NULL,
        submission_deadline INTEGER NOT NULL,expires INTEGER NOT NULL,disposition TEXT NOT NULL,
        max_raw_bytes INTEGER NOT NULL,max_attempts INTEGER NOT NULL,retry_interval INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS sandbox_pipeline_outbox(
        message_id TEXT NOT NULL REFERENCES sandbox_pipeline_messages(message_id) ON DELETE CASCADE,
        part INTEGER NOT NULL,attachment_sha256 TEXT NOT NULL,attachment_bytes INTEGER NOT NULL,
        kind TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('pending','submitting','submitted','complete','inconclusive')),
        job_id TEXT,summary TEXT,detail TEXT,attempts INTEGER NOT NULL DEFAULT 0,
        next_attempt INTEGER NOT NULL,lease_until INTEGER NOT NULL DEFAULT 0,lease_token TEXT,
        updated INTEGER NOT NULL,PRIMARY KEY(message_id,part));
      CREATE INDEX IF NOT EXISTS sandbox_pipeline_due ON sandbox_pipeline_outbox(state,next_attempt,lease_until);
      CREATE INDEX IF NOT EXISTS sandbox_pipeline_expiry ON sandbox_pipeline_messages(expires);
      CREATE INDEX IF NOT EXISTS sandbox_pipeline_job ON sandbox_pipeline_outbox(job_id);")?;
    Ok(())
}

pub fn record(tx: &Transaction<'_>, id: &str, scan: &Scan, plan: &Plan) -> Result<()> {
    ensure!(safe_id(id), "invalid sandbox message id");
    if plan.attachments.is_empty() {
        return Ok(());
    }
    ensure!(
        scan.raw_sha256.as_deref() == Some(&plan.message_sha256),
        "sandbox receipt does not match scan"
    );
    let spool_sha = plan
        .spool_sha256
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("sandbox receipt lacks retained raw binding"))?;
    let settings = &plan.settings;
    let now = crate::now();
    ensure!(
        tx.query_row("SELECT raw_present FROM messages WHERE id=?1", [id], |r| {
            r.get::<_, bool>(0)
        })?,
        "sandbox outbox requires retained raw"
    );
    let exists: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM sandbox_pipeline_messages WHERE message_id=?1)",
        [id],
        |r| r.get(0),
    )?;
    ensure!(!exists, "sandbox receipt already recorded");
    let count: usize = tx.query_row("SELECT COUNT(*) FROM sandbox_pipeline_outbox", [], |r| {
        r.get(0)
    })?;
    let retained: u64 = tx.query_row("SELECT COALESCE(SUM(spool_bytes),0) FROM sandbox_pipeline_messages p WHERE EXISTS(SELECT 1 FROM sandbox_pipeline_outbox o WHERE o.message_id=p.message_id AND o.state IN ('pending','submitting'))", [], |r| r.get(0))?;
    ensure!(
        count + plan.attachments.len() <= settings.max_outbox_jobs
            && retained.saturating_add(plan.spool_bytes as u64) <= settings.max_pending_raw_bytes,
        "sandbox outbox quota; retry before accepting mail"
    );
    tx.execute(
        "INSERT INTO sandbox_pipeline_messages VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
        params![
            id,
            plan.message_sha256,
            spool_sha,
            plan.spool_bytes,
            settings.backend_policy,
            plan.policy,
            now,
            now + settings.submission_timeout_secs as i64,
            now + i64::from(settings.retention_days) * 86400,
            serde_json::to_string(&settings.disposition())?,
            settings.max_raw_bytes,
            settings.max_attempts,
            settings.retry_interval_secs
        ],
    )?;
    for attachment in &plan.attachments {
        tx.execute("INSERT INTO sandbox_pipeline_outbox(message_id,part,attachment_sha256,attachment_bytes,kind,state,next_attempt,updated) VALUES(?1,?2,?3,?4,?5,'pending',?6,?6)",
            params![id, attachment.part, attachment.sha256, attachment.bytes, serde_json::to_string(&attachment.kind)?, now])?;
    }
    let mut persisted = serde_json::to_value(scan)?;
    persisted["sandbox_pipeline"] = serde_json::to_value(&plan.report)?;
    if settings.quarantine_selected {
        let invalid: usize = tx.query_row("SELECT COUNT(*) FROM deliveries WHERE message_id=?1 AND status NOT IN ('pending','quarantined')", [id], |r| r.get(0))?;
        ensure!(
            invalid == 0,
            "sandbox hold must be recorded before delivery can start"
        );
        let held = tx.execute(
            "UPDATE deliveries SET status='quarantined' WHERE message_id=?1",
            [id],
        )?;
        ensure!(held > 0, "sandbox selected quarantine requires recipients");
        let until = now + i64::from(settings.quarantine_days) * 86400;
        let policies = tx.execute("UPDATE delivery_policy SET action='quarantine',held_until=MAX(COALESCE(held_until,0),?2) WHERE delivery_id IN (SELECT id FROM deliveries WHERE message_id=?1)", params![id, until])?;
        ensure!(
            policies == held,
            "sandbox hold requires every recipient policy"
        );
        persisted["action"] = serde_json::json!({"requested":"quarantine","effective":"quarantine","reason":"sandbox_selected","quarantine_days":settings.quarantine_days});
        tx.execute("INSERT INTO audit(created,username,action,object_id) VALUES(?1,'system','sandbox_selected_quarantine',?2)", params![now,id])?;
    }
    tx.execute(
        "UPDATE messages SET scan=?2 WHERE id=?1",
        params![id, serde_json::to_string(&persisted)?],
    )?;
    Ok(())
}

pub fn needs_raw(db: &Connection, message_id: &str) -> Result<bool> {
    Ok(db.query_row("SELECT EXISTS(SELECT 1 FROM sandbox_pipeline_outbox WHERE message_id=?1 AND state IN ('pending','submitting'))", [message_id], |r| r.get(0))?)
}
pub fn expire_pending(db: &Connection, now: i64) -> Result<usize> {
    Ok(db.execute("UPDATE sandbox_pipeline_outbox SET state='inconclusive',detail='\"submission_expired\"',lease_token=NULL,lease_until=0,updated=?1 WHERE state IN ('pending','submitting') AND message_id IN (SELECT message_id FROM sandbox_pipeline_messages WHERE submission_deadline<=?1 OR expires<=?1)", [now])?)
}

/// Housekeeping hook, also when pipeline/backend are disabled. Run within the
/// parent's cleanup transaction before raw tombstones; no network/client needed.
/// Connector payload/result cleanup is separately prune_before/prune_local.
pub fn prune_primary(db: &Connection, now: i64) -> Result<usize> {
    expire_pending(db, now)?;
    Ok(db.execute(
        "DELETE FROM sandbox_pipeline_messages WHERE expires<=?1",
        [now],
    )?)
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Pending,
    Submitting,
    Submitted,
    Complete,
    Inconclusive,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Entry {
    pub part: usize,
    pub state: State,
    pub job_id: Option<String>,
    pub detail: Option<Detail>,
    pub result: Option<sandbox::Summary>,
    pub updated: i64,
}
pub async fn list(store: &Store, message_id: &str) -> Result<Vec<Entry>> {
    ensure!(safe_id(message_id), "invalid sandbox message id");
    let id = message_id.to_owned();
    store.run(move |db| {
        let mut query = db.prepare("SELECT o.part,o.state,o.job_id,o.detail,o.summary,o.updated FROM sandbox_pipeline_outbox o JOIN sandbox_pipeline_messages p USING(message_id) WHERE o.message_id=?1 AND p.expires>?2 ORDER BY o.part LIMIT 32")?;
        let rows = query.query_map(params![id,crate::now()], |r| Ok((r.get::<_,usize>(0)?,r.get::<_,String>(1)?,r.get::<_,Option<String>>(2)?,r.get::<_,Option<String>>(3)?,r.get::<_,Option<String>>(4)?,r.get::<_,i64>(5)?)))?;
        rows.map(|row| { let (part,state,job_id,detail,summary,updated) = row?;
            Ok(Entry { part,state:serde_json::from_str(&format!("\"{state}\""))?,job_id,
                detail:detail.map(|s|serde_json::from_str(&s)).transpose()?,
                result:summary.map(|s|serde_json::from_str(&s)).transpose()?,updated })
        }).collect()
    }).await
}

#[derive(Clone)]
pub struct Worker {
    settings: Settings,
    policy: String,
    lock: Arc<tokio::sync::Mutex<()>>,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TickReport {
    pub claimed: usize,
    pub handed_off: usize,
    pub results_updated: usize,
    pub inconclusive: usize,
    pub retrying: usize,
    pub purged: usize,
    pub backend_advanced: usize,
    pub backend_unavailable: bool,
    pub busy: bool,
}
#[derive(Clone)]
struct Work {
    id: String,
    part: usize,
    message_sha: String,
    spool_sha: String,
    spool_bytes: usize,
    backend_policy: String,
    policy: String,
    attachment_sha: String,
    attachment_bytes: usize,
    kind: sandbox::OfficeKind,
    disposition: sandbox::Disposition,
    max_raw: usize,
    max_attempts: u32,
    attempts: u32,
    retry: i64,
    created: i64,
    token: String,
}

impl Worker {
    pub fn new(settings: Settings) -> Result<Self> {
        settings.validate()?;
        let policy = settings.policy()?;
        Ok(Self {
            settings,
            policy,
            lock: Arc::new(tokio::sync::Mutex::new(())),
        })
    }
    /// One cancellation-safe bounded pass; the owned lock outlives a lost waiter.
    pub async fn tick(&self, store: &Store, client: &sandbox::Client) -> Result<TickReport> {
        if !self.settings.enabled {
            return Ok(TickReport::default());
        }
        ensure!(
            client.policy_sha256() == self.settings.backend_policy,
            "sandbox worker/client policy mismatch"
        );
        let Ok(guard) = self.lock.clone().try_lock_owned() else {
            return Ok(TickReport {
                busy: true,
                ..Default::default()
            });
        };
        let worker = self.clone();
        let store = store.clone();
        let client = client.clone();
        tokio::spawn(async move {
            let _guard = guard;
            worker.pass(&store, &client).await
        })
        .await?
    }
    async fn pass(&self, store: &Store, client: &sandbox::Client) -> Result<TickReport> {
        let mut report = TickReport::default();
        report.inconclusive += store.run(|db| expire_pending(db, crate::now())).await?;
        self.purge(store, client, &mut report).await?;
        for _ in 0..self.settings.batch_size {
            let Some(work) = claim(store).await? else {
                break;
            };
            report.claimed += 1;
            if work.policy != self.policy
                || Some(&work.backend_policy) != self.settings.backend_policy.as_ref()
            {
                finish(store, &work, Detail::PolicyChanged).await?;
                report.inconclusive += 1;
                continue;
            }
            let task = work.clone();
            let path = store.raw_path(&work.id);
            let payload =
                tokio::task::spawn_blocking(move || load_attachment(&path, &task)).await?;
            let payload = match payload {
                Ok(bytes) => bytes,
                Err(detail) => {
                    finish(store, &work, detail).await?;
                    report.inconclusive += 1;
                    continue;
                }
            };
            // Expiry/cleanup may have resolved the row during a slow file read.
            let check = work.clone();
            let current = store.run(move |db| Ok(db.query_row("SELECT EXISTS(SELECT 1 FROM sandbox_pipeline_outbox o JOIN sandbox_pipeline_messages p USING(message_id) WHERE o.message_id=?1 AND o.part=?2 AND o.lease_token=?3 AND o.state='submitting' AND p.submission_deadline>?4)",params![check.id,check.part,check.token,crate::now()],|r|r.get::<_,bool>(0))?)).await?;
            if !current {
                continue;
            }
            match client
                .enqueue_created_at(
                    &work.message_sha,
                    &payload,
                    work.kind,
                    work.disposition,
                    work.created * 1000,
                )
                .await
            {
                Ok(summary) if bound(&summary, &work) => {
                    save_summary(store, &work.id, work.part, Some(&work.token), &summary).await?;
                    report.handed_off += 1;
                }
                Ok(_) => {
                    finish(store, &work, Detail::InvalidResult).await?;
                    report.inconclusive += 1;
                }
                Err(_) if work.attempts >= work.max_attempts => {
                    finish(store, &work, Detail::SubmissionExpired).await?;
                    report.inconclusive += 1;
                }
                Err(_) => {
                    let next = work.clone();
                    store.run(move |db| { db.execute("UPDATE sandbox_pipeline_outbox SET state='pending',detail='\"queue_busy\"',lease_until=0,lease_token=NULL,next_attempt=?4,updated=?5 WHERE message_id=?1 AND part=?2 AND lease_token=?3 AND state='submitting'",params![next.id,next.part,next.token,crate::now()+next.retry,crate::now()])?; Ok(()) }).await?;
                    report.retrying += 1;
                }
            }
        }
        match client.tick().await {
            Ok(n) => report.backend_advanced = n,
            Err(_) => report.backend_unavailable = true,
        }
        let batch = self.settings.batch_size;
        let rows = store.run(move |db| {
            let mut query = db.prepare("SELECT o.message_id,o.part,o.job_id,p.message_sha256,o.attachment_sha256,o.attachment_bytes,o.kind,p.disposition,p.backend_policy FROM sandbox_pipeline_outbox o JOIN sandbox_pipeline_messages p USING(message_id) WHERE o.state='submitted' AND p.expires>?1 ORDER BY o.updated,o.message_id,o.part LIMIT ?2")?;
            Ok(query.query_map(params![crate::now(),batch], |r| Ok((r.get::<_,String>(0)?,r.get::<_,usize>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,String>(4)?,r.get::<_,usize>(5)?,r.get::<_,String>(6)?,r.get::<_,String>(7)?,r.get::<_,String>(8)?)))?.collect::<rusqlite::Result<Vec<_>>>()?)
        }).await?;
        for (id, part, job, message_sha, attachment_sha, bytes, kind, disposition, policy) in rows {
            match client.get(&job).await {
                Ok(Some(summary))
                    if summary.validate().is_ok()
                        && summary.message_sha256 == message_sha
                        && summary.attachment_sha256 == attachment_sha
                        && summary.attachment_bytes == bytes
                        && summary.kind == Some(serde_json::from_str(&kind)?)
                        && summary.disposition
                            == serde_json::from_str::<sandbox::Disposition>(&disposition)?
                        && summary.provenance.policy_sha256 == policy =>
                {
                    report.results_updated +=
                        usize::from(save_summary(store, &id, part, None, &summary).await?);
                }
                Ok(_) => {
                    terminal_entry(store, &id, part, Detail::ClientMissing).await?;
                    report.inconclusive += 1;
                }
                Err(_) => report.backend_unavailable = true,
            }
        }
        Ok(report)
    }
    async fn purge(
        &self,
        store: &Store,
        client: &sandbox::Client,
        report: &mut TickReport,
    ) -> Result<()> {
        // Connector retention also scrubs orphan handoffs after primary commit
        // failures. Remote reservation tombstones are owned by the connector.
        report.purged += client
            .prune_before((crate::now() - i64::from(self.settings.retention_days) * 86400) * 1000)
            .await?;
        let batch = self.settings.batch_size;
        let expired=store.run(move|db| {
            let mut q=db.prepare("SELECT message_id FROM sandbox_pipeline_messages WHERE expires<=?1 ORDER BY expires LIMIT ?2")?;
            Ok(q.query_map(params![crate::now(),batch],|r|r.get::<_,String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?)
        }).await?;
        for id in expired {
            let key = id.clone();
            let jobs=store.run(move|db| {
                let mut q=db.prepare("SELECT DISTINCT job_id FROM sandbox_pipeline_outbox WHERE message_id=?1 AND job_id IS NOT NULL")?;
                Ok(q.query_map([key],|r|r.get::<_,String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?)
            }).await?;
            for job in jobs {
                // Best-effort immediate removal for ordinary settled jobs. Never
                // pretend an unresolved remote task stopped in order to prune.
                if let Ok(Some(summary)) = client.get(&job).await
                    && summary.status.terminal()
                    && !summary.remote_slot_held
                {
                    let _ = client.remove(&job).await;
                }
            }
            report.purged += store
                .run(move |db| {
                    Ok(db.execute(
                        "DELETE FROM sandbox_pipeline_messages WHERE message_id=?1 AND expires<=?2",
                        params![id, crate::now()],
                    )?)
                })
                .await?;
        }
        Ok(())
    }
}

async fn claim(store: &Store) -> Result<Option<Work>> {
    store.run(|db| {
        let tx=db.transaction()?; let now=crate::now();
        let row=tx.query_row("SELECT o.message_id,o.part,p.message_sha256,p.spool_sha256,p.spool_bytes,p.backend_policy,p.policy,o.attachment_sha256,o.attachment_bytes,o.kind,p.disposition,p.max_raw_bytes,p.max_attempts,o.attempts,p.retry_interval,p.created FROM sandbox_pipeline_outbox o JOIN sandbox_pipeline_messages p USING(message_id) WHERE o.state IN ('pending','submitting') AND o.next_attempt<=?1 AND o.lease_until<=?1 AND p.submission_deadline>?1 AND p.expires>?1 ORDER BY o.next_attempt,o.message_id,o.part LIMIT 1",[now],|r|Ok((r.get::<_,String>(0)?,r.get::<_,usize>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,usize>(4)?,r.get::<_,String>(5)?,r.get::<_,String>(6)?,r.get::<_,String>(7)?,r.get::<_,usize>(8)?,r.get::<_,String>(9)?,r.get::<_,String>(10)?,r.get::<_,usize>(11)?,r.get::<_,u32>(12)?,r.get::<_,u32>(13)?,r.get::<_,i64>(14)?,r.get::<_,i64>(15)?))).optional()?;
        let Some((id,part,message_sha,spool_sha,spool_bytes,backend_policy,policy,attachment_sha,attachment_bytes,kind,disposition,max_raw,max_attempts,attempts,retry,created))=row else { return Ok(None); };
        ensure!(safe_id(&id) && max_raw<=64*1024*1024 && attachment_bytes<=32*1024*1024, "invalid sandbox outbox row");
        let token=uuid::Uuid::new_v4().to_string();
        tx.execute("UPDATE sandbox_pipeline_outbox SET state='submitting',lease_token=?3,lease_until=?4,attempts=attempts+1,updated=?5 WHERE message_id=?1 AND part=?2",params![id,part,token,now+300,now])?;
        tx.commit()?;
        Ok(Some(Work { id,part,message_sha,spool_sha,spool_bytes,backend_policy,policy,attachment_sha,attachment_bytes,
            kind:serde_json::from_str(&kind)?,disposition:serde_json::from_str(&disposition)?,max_raw,max_attempts,attempts:attempts.saturating_add(1),retry,created,token }))
    }).await
}
fn load_attachment(path: &std::path::Path, work: &Work) -> std::result::Result<Vec<u8>, Detail> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| Detail::SpoolMissing)?;
    let meta = file.metadata().map_err(|_| Detail::SpoolMissing)?;
    if !meta.is_file()
        || meta.nlink() != 1
        || meta.len() != work.spool_bytes as u64
        || meta.len() > work.max_raw as u64
    {
        return Err(Detail::SpoolChanged);
    }
    let mut raw = Vec::with_capacity(work.spool_bytes);
    file.take(work.max_raw as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(|_| Detail::SpoolMissing)?;
    if raw.len() != work.spool_bytes || digest(&raw) != work.spool_sha {
        return Err(Detail::SpoolChanged);
    }
    let parsed = MessageParser::default()
        .parse(&raw)
        .ok_or(Detail::AttachmentChanged)?;
    let part = parsed
        .parts
        .get(work.part)
        .ok_or(Detail::AttachmentChanged)?;
    let bytes = part.contents();
    if part.is_encoding_problem
        || kind(part) != Some(work.kind)
        || bytes.len() != work.attachment_bytes
        || digest(bytes) != work.attachment_sha
    {
        return Err(Detail::AttachmentChanged);
    }
    Ok(bytes.to_vec())
}
fn bound(summary: &sandbox::Summary, work: &Work) -> bool {
    summary.validate().is_ok()
        && summary.status != sandbox::Status::Disabled
        && summary.message_sha256 == work.message_sha
        && summary.attachment_sha256 == work.attachment_sha
        && summary.attachment_bytes == work.attachment_bytes
        && summary.kind == Some(work.kind)
        && summary.disposition == work.disposition
        && summary.provenance.policy_sha256 == work.backend_policy
}
async fn finish(store: &Store, work: &Work, detail: Detail) -> Result<()> {
    let work = work.clone();
    store.run(move|db| { db.execute("UPDATE sandbox_pipeline_outbox SET state='inconclusive',detail=?4,lease_token=NULL,lease_until=0,updated=?5 WHERE message_id=?1 AND part=?2 AND lease_token=?3 AND state='submitting'",params![work.id,work.part,work.token,serde_json::to_string(&detail)?,crate::now()])?; Ok(()) }).await
}
async fn terminal_entry(store: &Store, id: &str, part: usize, detail: Detail) -> Result<()> {
    let id = id.to_owned();
    store.run(move|db| { db.execute("UPDATE sandbox_pipeline_outbox SET state='inconclusive',summary=NULL,detail=?3,updated=?4 WHERE message_id=?1 AND part=?2 AND state='submitted'",params![id,part,serde_json::to_string(&detail)?,crate::now()])?; Ok(()) }).await
}
async fn save_summary(
    store: &Store,
    id: &str,
    part: usize,
    token: Option<&str>,
    summary: &sandbox::Summary,
) -> Result<bool> {
    let id = id.to_owned();
    let token = token.map(str::to_owned);
    let state = if summary.status == sandbox::Status::Complete
        && summary.outcome != sandbox::Outcome::Inconclusive
    {
        "complete"
    } else if summary.status.terminal() {
        "inconclusive"
    } else {
        "submitted"
    };
    let json = serde_json::to_string(summary)?;
    let job = summary.job_id.clone();
    store.run(move|db| {
        let previous: Option<String> = db.query_row("SELECT summary FROM sandbox_pipeline_outbox WHERE message_id=?1 AND part=?2",params![id,part],|r|r.get(0)).optional()?.flatten();
        let changed = previous.as_deref() != Some(json.as_str());
        // Refresh scheduling even for an unchanged summary, so a full batch of
        // pending CAPE tasks cannot starve later rows. Log only actual updates.
        let updated = db.execute("UPDATE sandbox_pipeline_outbox SET state=?4,job_id=?5,summary=?6,detail=NULL,lease_token=NULL,lease_until=0,updated=?7 WHERE message_id=?1 AND part=?2 AND ((?3 IS NOT NULL AND lease_token=?3 AND state='submitting') OR (?3 IS NULL AND state='submitted'))",params![id,part,token,state,job,json,crate::now()])?;
        Ok(updated > 0 && changed)
    }).await
}
