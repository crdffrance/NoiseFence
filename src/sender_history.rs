//! Recipient-scoped, revocable observations. This module never changes a Scan.
use crate::{
    antivirus::AntivirusStatus,
    config::Recipient,
    engine::Scan,
    evidence::{AuthResult, Source, State},
    message,
};
use anyhow::{Result, ensure};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::{path::Path, sync::Arc, time::Duration};

pub const VERSION: &str = "sender-history-1";
pub const TTL_SECONDS: i64 = 30 * 86400;
pub const MAX_RECORDS: usize = 65_536;
pub const MAX_PAIR_RECORDS: usize = 256;
pub const MAX_RECIPIENTS: usize = 100;
const MAX_VOTES: usize = 64;
const MAX_RAW: usize = 32 * 1024 * 1024;
const MAX_SCAN: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Observation,
    CandidateCredit,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManualSender {
    Exact(String),
    Domain(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManualEntry {
    pub recipient: String,
    pub destination: String,
    pub sender: ManualSender,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub mode: Mode,
    pub manual: Vec<ManualEntry>,
}

// Both names support existing optional-module configuration conventions.
pub type Settings = Config;
pub type Policy = Config;

impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.manual.len() <= 256, "too many sender history entries");
        for entry in &self.manual {
            ensure!(
                mailbox(&entry.recipient).is_some() && mailbox(&entry.destination).is_some(),
                "invalid sender history recipient scope"
            );
            ensure!(
                match &entry.sender {
                    ManualSender::Exact(sender) => mailbox(sender).is_some(),
                    ManualSender::Domain(domain) => valid_domain(domain),
                },
                "invalid sender history identity"
            );
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Complete,
    NotRun,
    Limited,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ManualMatch {
    #[default]
    None,
    Exact,
    Domain,
}

/// Contains no addresses, message IDs, campaign hashes, timestamps or text.
/// Even these counts are private to the authorized recipient projection.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Report {
    pub version: String,
    pub status: Status,
    pub mode: Mode,
    pub distinct_campaigns: u16,
    pub distinct_days: u16,
    pub learned_candidate: bool,
    pub manual_match: ManualMatch,
    pub contradicted: bool,
    /// Advisory eligibility only. Never an allow, score delta or scanner bypass.
    pub candidate_credit: bool,
}

impl Report {
    fn empty(mode: Mode, status: Status) -> Self {
        Self {
            version: VERSION.into(),
            status,
            mode,
            distinct_campaigns: 0,
            distinct_days: 0,
            learned_candidate: false,
            manual_match: ManualMatch::None,
            contradicted: false,
            candidate_credit: false,
        }
    }
}

/// Intentionally not Serialize, with redacted Debug: never export in a shared Scan.
#[derive(Clone)]
pub struct Projection {
    reports: Vec<Report>,
    scopes: Vec<(String, String)>,
    raw_hash: Option<String>,
}

impl std::fmt::Debug for Projection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Projection { private delivery reports }")
    }
}

impl Projection {
    /// Index into the exact SMTP recipient slice passed to inspect. The caller
    /// must authorize that delivery before exporting its report.
    pub fn for_recipient(&self, index: usize) -> Option<&Report> {
        self.reports.get(index)
    }

    /// Multi-recipient reports require delivery-level projection, even when the
    /// counts happen to agree. This also avoids disclosing the presence of Bcc.
    pub fn shared_report(&self) -> Option<&Report> {
        (self.reports.len() == 1).then(|| &self.reports[0])
    }
}

fn valid_domain(value: &str) -> bool {
    crate::config::valid_domain(value) && value.contains('.')
}

// Conservative ASCII dot-atoms only. Preserve local-part case, plus tags and
// dots; folding them could merge different senders/tenants. Domain case is DNS.
fn mailbox(value: &str) -> Option<String> {
    let (local, domain) = value.rsplit_once('@')?;
    (value.len() <= 254
        && !local.is_empty()
        && local.len() <= 64
        && !local.starts_with('.')
        && !local.ends_with('.')
        && !local.contains("..")
        && local
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".!#$%&'+-/=?^_`{|}~".contains(&b))
        && valid_domain(domain))
    .then(|| format!("{local}@{}", domain.to_ascii_lowercase()))
}

fn authenticated(scan: &Scan) -> bool {
    let Some(e) = &scan.evidence else {
        return false;
    };
    let a = &e.authentication;
    e.source == Source::SmtpSession
        && a.state == State::Complete
        && a.dmarc_state == State::Complete
        && ((a.dmarc_spf == Some(AuthResult::Pass)
            && a.spf_state == State::Complete
            && a.spf == Some(AuthResult::Pass))
            || (a.dmarc_dkim == Some(AuthResult::Pass)
                && a.dkim_state == State::Complete
                && a.dkim
                    .as_ref()
                    .is_some_and(|v| v.contains(&AuthResult::Pass))))
}

fn content_eligible(scan: &Scan) -> bool {
    scan.complete
        && scan.features_complete != Some(false)
        && scan.antivirus.status != AntivirusStatus::Malware
        && scan.signatures.status != AntivirusStatus::Malware
}

fn verified_identity(raw: &[u8], scan: &Scan) -> Option<(String, String)> {
    if raw.len() > MAX_RAW || !authenticated(scan) {
        return None;
    }
    // Do not trust the first mailbox of an ambiguous From, or a supplied
    // Authentication-Results/display name. Bind checks to the original bytes.
    let headers = message::fields(raw).ok()?.0;
    if headers
        .iter()
        .filter(|h| message::name(h) == "from")
        .count()
        != 1
    {
        return None;
    }
    let parsed = mail_parser::MessageParser::default().parse_headers(raw)?;
    let addresses = parsed.from()?.as_list()?;
    if addresses.len() != 1 {
        return None;
    }
    let sender = mailbox(addresses[0].address()?)?;
    if mailbox(&scan.sender)? != sender {
        return None;
    }
    let hash = message::digest(raw);
    (scan.raw_sha256.as_deref() == Some(hash.as_str())).then_some((sender, hash))
}

/// Opaque proof prepared from original SMTP bytes, before queue rewriting.
/// No Deserialize/Serialize implementation: never accept this from an API.
#[derive(Clone)]
pub struct Receipt {
    sender: String,
    raw_hash: String,
    campaign: String,
    simhash: Option<String>,
    authentication_hash: String,
}

impl std::fmt::Debug for Receipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Receipt { verified original SMTP identity }")
    }
}

/// Call only with the engine-owned SMTP scan. Subsequent score/diagnostic
/// changes are allowed; source, authentication, original bytes and campaign
/// identity are immutable across the prepare/persist boundary.
pub fn prepare_receipt(raw: &[u8], auth_scan: &Scan) -> Option<Receipt> {
    let (sender, raw_hash) = verified_identity(raw, auth_scan)?;
    Some(Receipt {
        sender,
        raw_hash,
        campaign: auth_scan.fingerprint.clone(),
        simhash: auth_scan.campaign_simhash.clone(),
        authentication_hash: message::digest(
            &serde_json::to_vec(&auth_scan.evidence.as_ref()?.authentication).ok()?,
        ),
    })
}

/// Additive schema, no user_version change. Call once via Store::run at startup.
/// The receipts persist facts, NEVER cached feedback or learned trust.
pub fn install(db: &Connection) -> Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS sender_history_state (
           id INTEGER PRIMARY KEY CHECK(id=1), records INTEGER NOT NULL DEFAULT 0,
           overflow_until INTEGER NOT NULL DEFAULT 0);
         INSERT OR IGNORE INTO sender_history_state(id) VALUES(1);
         CREATE TABLE IF NOT EXISTS sender_history_receipts (
           message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
           delivery_id INTEGER NOT NULL REFERENCES deliveries(id) ON DELETE CASCADE,
           recipient TEXT NOT NULL, destination TEXT NOT NULL, sender TEXT NOT NULL,
           domain TEXT NOT NULL, received INTEGER NOT NULL, raw_hash TEXT NOT NULL,
           campaign TEXT, simhash TEXT, eligible INTEGER NOT NULL CHECK(eligible IN (0,1)),
           PRIMARY KEY(message_id,delivery_id));
         CREATE INDEX IF NOT EXISTS sender_history_pair
           ON sender_history_receipts(recipient,destination,sender,received);
         CREATE INDEX IF NOT EXISTS sender_history_domain
           ON sender_history_receipts(recipient,destination,domain,received);
         CREATE INDEX IF NOT EXISTS sender_history_expiry ON sender_history_receipts(received);
         CREATE INDEX IF NOT EXISTS sender_history_feedback ON feedback(message_id,created);
         CREATE TRIGGER IF NOT EXISTS sender_history_insert AFTER INSERT ON sender_history_receipts
           BEGIN UPDATE sender_history_state SET records=records+1 WHERE id=1; END;
         CREATE TRIGGER IF NOT EXISTS sender_history_delete AFTER DELETE ON sender_history_receipts
           BEGIN UPDATE sender_history_state SET records=records-1 WHERE id=1; END;
         CREATE TABLE IF NOT EXISTS recipient_research (
           delivery_id INTEGER PRIMARY KEY REFERENCES deliveries(id) ON DELETE CASCADE,
           sender_history TEXT NOT NULL);",
    )?;
    Ok(())
}

/// Prune expired receipts on the Store writer or inside its enqueue transaction.
/// Trust expires at query time even if there is no maintenance traffic.
pub fn prune(db: &Connection) -> Result<usize> {
    Ok(db.execute(
        "DELETE FROM sender_history_receipts WHERE received<=?1",
        [crate::now() - TTL_SECONDS],
    )?)
}

/// Run inside the SAME transaction that inserts the message and deliveries.
/// auth_scan must be the locally produced original SMTP scan, not API input.
/// Returns false for ineligible identities/DSNs or capacity suppression.
/// Errors MUST roll back enqueue; swallowing a lost receipt could hide a later
/// spam contradiction. Idempotent duplicates never refresh the receipt lifetime.
pub fn record_smtp(
    db: &Connection,
    message_id: &str,
    raw: &[u8],
    auth_scan: &Scan,
) -> Result<bool> {
    ensure!(
        !db.is_autocommit(),
        "sender history requires the enqueue transaction"
    );
    let Some(receipt) = prepare_receipt(raw, auth_scan) else {
        return Ok(false);
    };
    record_prepared(db, message_id, auth_scan, &receipt)
}

/// Persist an original-byte proof while enqueue writes rewritten queue bytes.
/// Requires the same transaction and exact persisted final Scan as record_smtp.
pub fn record_prepared(
    db: &Connection,
    message_id: &str,
    auth_scan: &Scan,
    receipt: &Receipt,
) -> Result<bool> {
    ensure!(
        !db.is_autocommit(),
        "sender history requires the enqueue transaction"
    );
    ensure!(
        authenticated(auth_scan),
        "sender history authentication changed"
    );
    ensure!(
        mailbox(&auth_scan.sender).as_deref() == Some(receipt.sender.as_str())
            && auth_scan.raw_sha256.as_deref() == Some(receipt.raw_hash.as_str())
            && auth_scan.fingerprint == receipt.campaign
            && auth_scan.campaign_simhash == receipt.simhash
            && message::digest(&serde_json::to_vec(
                &auth_scan.evidence.as_ref().unwrap().authentication
            )?) == receipt.authentication_hash,
        "sender history original proof mismatch"
    );
    let sender = &receipt.sender;
    let hash = &receipt.raw_hash;
    ensure!(message_id.len() <= 128, "invalid sender history message id");
    let now = crate::now();
    let stored: Option<(i64, bool, String)> = db
        .query_row(
            "SELECT created,is_dsn,CASE WHEN length(CAST(scan AS BLOB))<=?2 THEN scan ELSE '' END
         FROM messages WHERE id=?1",
            params![message_id, MAX_SCAN],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let Some((received, dsn, stored)) = stored else {
        anyhow::bail!("sender history message missing");
    };
    if dsn || received <= now - TTL_SECONDS || received > now {
        return Ok(false);
    }
    // Exact persistence binding prevents accidental attachment to another Scan.
    ensure!(
        stored == serde_json::to_string(auth_scan)?,
        "sender history scan mismatch"
    );
    prune(db)?;
    let deliveries = {
        let mut q = db.prepare(
            "SELECT id,address,destination FROM deliveries WHERE message_id=?1 LIMIT ?2",
        )?;
        q.query_map(params![message_id, MAX_RECIPIENTS + 1], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?
    };
    ensure!(!deliveries.is_empty(), "sender history deliveries missing");
    let records: usize = db.query_row(
        "SELECT records FROM sender_history_state WHERE id=1",
        [],
        |r| r.get(0),
    )?;
    let existing: usize = db.query_row(
        "SELECT COUNT(*) FROM sender_history_receipts WHERE message_id=?1",
        [message_id],
        |r| r.get(0),
    )?;
    if deliveries.len() > MAX_RECIPIENTS
        || records.saturating_add(deliveries.len().saturating_sub(existing)) > MAX_RECORDS
        || deliveries
            .iter()
            .any(|(_, a, d)| mailbox(a).is_none() || mailbox(d).is_none())
    {
        // Never evict a contradiction and keep positive credit. A fixed-size
        // durable circuit breaker suppresses ALL credit for the omitted window.
        db.execute(
            "UPDATE sender_history_state SET overflow_until=MAX(overflow_until,?1) WHERE id=1",
            [received + TTL_SECONDS],
        )?;
        return Ok(false);
    }
    let campaign = (auth_scan.fingerprint.len() == 64
        && auth_scan.fingerprint.bytes().all(|b| b.is_ascii_hexdigit()))
    .then(|| auth_scan.fingerprint.to_ascii_lowercase());
    let simhash = auth_scan
        .campaign_simhash
        .as_deref()
        .filter(|s| s.len() == 16 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(str::to_ascii_lowercase);
    let domain = sender.rsplit_once('@').unwrap().1;
    for (id, address, destination) in deliveries {
        db.execute(
            "INSERT OR IGNORE INTO sender_history_receipts
             (message_id,delivery_id,recipient,destination,sender,domain,received,raw_hash,campaign,simhash,eligible)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![message_id, id, mailbox(&address), mailbox(&destination), sender, domain,
                received, hash, campaign, simhash, content_eligible(auth_scan)],
        )?;
    }
    Ok(true)
}

/// Persist only reports for the exact inspected deliveries. Run after enqueue's
/// inserts, in its transaction. Console reads must JOIN console_access on THIS
/// delivery_id; do not aggregate another recipient's report into VisibleMail.
pub fn record_projection(
    db: &Connection,
    message_id: &str,
    scan: &Scan,
    projection: &Projection,
) -> Result<()> {
    ensure!(
        !db.is_autocommit(),
        "sender history requires the enqueue transaction"
    );
    ensure!(
        projection.scopes.len() == projection.reports.len(),
        "sender history projection scope missing"
    );
    if projection.reports.is_empty() {
        // Unsupported SMTP mailboxes and over-budget recipient sets carry no
        // findings. Nothing will be written or rebound, so an absent/different
        // observation hash must not turn optional history into an enqueue gate.
        return Ok(());
    }
    ensure!(
        projection.raw_hash == scan.raw_sha256,
        "sender history projection mismatch"
    );
    let stored: String = db.query_row(
        "SELECT CASE WHEN length(CAST(scan AS BLOB))<=?2 THEN scan ELSE '' END FROM messages WHERE id=?1",
        params![message_id, MAX_SCAN], |r| r.get(0),
    )?;
    ensure!(
        stored == serde_json::to_string(scan)?,
        "sender history scan mismatch"
    );
    let mut q =
        db.prepare("SELECT id,address,destination FROM deliveries WHERE message_id=?1 LIMIT ?2")?;
    let deliveries = q
        .query_map(params![message_id, MAX_RECIPIENTS + 1], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    ensure!(
        !deliveries.is_empty() && deliveries.len() <= MAX_RECIPIENTS,
        "sender history projection delivery limit"
    );
    let mut covered = std::collections::HashSet::new();
    for (id, address, destination) in deliveries {
        let scope = (mailbox(&address), mailbox(&destination));
        let mut matched =
            projection
                .scopes
                .iter()
                .zip(&projection.reports)
                .filter(|((a, d), _)| {
                    scope.0.as_deref() == Some(a.as_str()) && scope.1.as_deref() == Some(d.as_str())
                });
        let Some((key, report)) = matched.next() else {
            anyhow::bail!("sender history projection delivery mismatch");
        };
        ensure!(
            matched.all(|(_, other)| other == report),
            "sender history duplicate projection mismatch"
        );
        covered.insert(key);
        db.execute(
            "INSERT INTO recipient_research(delivery_id,sender_history) VALUES(?1,?2)
            ON CONFLICT(delivery_id) DO UPDATE SET sender_history=excluded.sender_history",
            params![id, serde_json::to_string(report)?],
        )?;
    }
    ensure!(
        projection
            .scopes
            .iter()
            .all(|scope| covered.contains(scope)),
        "sender history projection delivery missing"
    );
    Ok(())
}

#[derive(Clone)]
pub struct History {
    root: std::path::PathBuf,
    policy: Config,
    reads: Arc<tokio::sync::Semaphore>,
}

impl History {
    pub fn new(root: &Path, policy: Config) -> Self {
        Self {
            root: root.into(),
            policy,
            reads: Arc::new(tokio::sync::Semaphore::new(4)),
        }
    }

    pub async fn inspect(
        &self,
        raw: &[u8],
        auth_scan: &Scan,
        recipients: &[Recipient],
    ) -> Projection {
        let scopes = recipients
            .iter()
            .take(MAX_RECIPIENTS)
            .map(|r| Some((mailbox(&r.address)?, mailbox(&r.destination)?)))
            .collect::<Option<Vec<_>>>();
        let empty = |status| Projection {
            reports: vec![
                Report::empty(self.policy.mode, status);
                scopes.as_ref().map_or(0, Vec::len)
            ],
            scopes: scopes.clone().unwrap_or_default(),
            raw_hash: auth_scan.raw_sha256.clone(),
        };
        if recipients.len() > MAX_RECIPIENTS {
            // No partial projection for an over-budget recipient set.
            return Projection {
                reports: Vec::new(),
                scopes: Vec::new(),
                raw_hash: auth_scan.raw_sha256.clone(),
            };
        }
        if self.policy.validate().is_err() {
            return empty(Status::Unavailable);
        }
        if !content_eligible(auth_scan) || recipients.is_empty() {
            return empty(Status::NotRun);
        }
        let Some((sender, hash)) = verified_identity(raw, auth_scan) else {
            return empty(Status::NotRun);
        };
        let Some(scopes) = scopes.clone() else {
            return empty(Status::NotRun);
        };
        let Ok(permit) = self.reads.clone().try_acquire_owned() else {
            return empty(Status::Limited);
        };
        let path = self.root.join("state.sqlite3");
        let policy = self.policy.clone();
        let (send, receive) = tokio::sync::oneshot::channel();
        let task = tokio::task::spawn_blocking(move || -> Result<Projection> {
            let _permit = permit;
            let db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
            db.busy_timeout(Duration::from_millis(50))?;
            if send.send(db.get_interrupt_handle()).is_err() {
                anyhow::bail!("sender history cancelled");
            }
            // Feedback, disabled users and grants share one consistent snapshot.
            db.execute_batch("BEGIN")?;
            let now = crate::now();
            let overflow: i64 = db.query_row(
                "SELECT overflow_until FROM sender_history_state WHERE id=1",
                [],
                |r| r.get(0),
            )?;
            let reports = scopes
                .iter()
                .map(|(recipient, destination)| {
                    if overflow > now {
                        Ok(Report::empty(policy.mode, Status::Limited))
                    } else {
                        inspect_pair(&db, &policy, &sender, &hash, recipient, destination, now)
                    }
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(Projection {
                reports,
                scopes,
                raw_hash: Some(hash),
            })
        });
        // The guard interrupts on timeout AND future cancellation. If open is
        // still pending, closing receive makes the worker exit before querying.
        struct Interrupt(rusqlite::InterruptHandle);
        impl Drop for Interrupt {
            fn drop(&mut self) {
                self.0.interrupt();
            }
        }
        let work = async move {
            let _interrupt = Interrupt(receive.await?);
            task.await?
        };
        match tokio::time::timeout(Duration::from_millis(250), work).await {
            Ok(Ok(projection)) => projection,
            Ok(Err(_)) => empty(Status::Unavailable),
            Err(_) => empty(Status::Limited),
        }
    }
}

struct Example {
    received: i64,
    raw: String,
    campaign: String,
    simhash: u64,
}

fn inspect_pair(
    db: &Connection,
    policy: &Config,
    sender: &str,
    current_hash: &str,
    recipient: &str,
    destination: &str,
    now: i64,
) -> Result<Report> {
    let mut report = Report::empty(policy.mode, Status::Complete);
    let domain = sender.rsplit_once('@').unwrap().1;
    for entry in &policy.manual {
        if mailbox(&entry.recipient).as_deref() != Some(recipient)
            || mailbox(&entry.destination).as_deref() != Some(destination)
        {
            continue;
        }
        match &entry.sender {
            ManualSender::Exact(s) if mailbox(s).as_deref() == Some(sender) => {
                report.manual_match = ManualMatch::Exact;
            }
            ManualSender::Domain(d)
                if d.eq_ignore_ascii_case(domain) && report.manual_match != ManualMatch::Exact =>
            {
                report.manual_match = ManualMatch::Domain;
            }
            _ => {}
        }
    }
    // An exact entry is narrower and takes precedence. Domain credit checks
    // contradictions from the entire exact domain, never a suffix/subdomain.
    let domain_scope = report.manual_match == ManualMatch::Domain;
    let identity_column = if domain_scope { "domain" } else { "sender" };
    let mut q = db.prepare(&format!(
        "SELECT h.message_id,h.delivery_id,h.sender,h.received,h.raw_hash,h.campaign,h.simhash,h.eligible
         FROM sender_history_receipts h
         WHERE h.recipient=?1 AND h.destination=?2 AND h.{identity_column}=?3
           AND h.received>?4 AND h.received<=?5 ORDER BY h.received LIMIT ?6"
    ))?;
    let mut rows = q.query(params![
        recipient,
        destination,
        if domain_scope { domain } else { sender },
        now - TTL_SECONDS,
        now,
        MAX_PAIR_RECORDS + 1
    ])?;
    let mut examples = Vec::new();
    let mut count = 0;
    while let Some(row) = rows.next()? {
        count += 1;
        if count > MAX_PAIR_RECORDS {
            return Ok(Report::empty(policy.mode, Status::Limited));
        }
        let message_id: String = row.get(0)?;
        let delivery_id: i64 = row.get(1)?;
        let historical_sender: String = row.get(2)?;
        let received: i64 = row.get(3)?;
        let raw: String = row.get(4)?;
        let campaign: Option<String> = row.get(5)?;
        let simhash: Option<String> = row.get(6)?;
        let eligible: bool = row.get(7)?;
        // Access to some other delivery of the same message is insufficient.
        // Re-check original routing too: a changed/deleted alias is not a grant.
        let mut votes = db.prepare_cached(
            "SELECT f.spam,c.category FROM feedback f
             JOIN users u ON u.username=f.username AND u.disabled=0
             JOIN deliveries d ON d.id=?2 AND d.message_id=f.message_id
             JOIN messages m ON m.id=d.message_id AND m.is_dsn=0 AND m.created=?3
             LEFT JOIN feedback_categories c ON c.username=f.username AND c.message_id=f.message_id
             WHERE f.message_id=?1 AND f.created>=?3 AND f.created>?4 AND f.created<=?5
               AND d.address=?6 AND d.destination=?7
               AND EXISTS(SELECT 1 FROM console_access a WHERE a.delivery_id=d.id AND a.username=f.username)
             LIMIT ?8",
        )?;
        // d.address/destination retain the canonical configured case. Normalize
        // in Rust for scope keys, but use their original spelling for SQL ACLs.
        let routing: Option<(String, String)> = db
            .query_row(
                "SELECT address,destination FROM deliveries WHERE id=?1",
                [delivery_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((address, target)) = routing else {
            continue;
        };
        if mailbox(&address).as_deref() != Some(recipient)
            || mailbox(&target).as_deref() != Some(destination)
        {
            continue;
        }
        let mut labels = votes.query(params![
            message_id,
            delivery_id,
            received,
            now - TTL_SECONDS,
            now,
            address,
            target,
            MAX_VOTES + 1
        ])?;
        let mut legitimate = false;
        let mut vote_count = 0;
        while let Some(label) = labels.next()? {
            vote_count += 1;
            if vote_count > MAX_VOTES {
                return Ok(Report::empty(policy.mode, Status::Limited));
            }
            let spam: i64 = label.get(0)?;
            let category: Option<String> = label.get(1)?;
            match spam {
                1 => report.contradicted = true,
                // Binary non-spam is a human legitimate vote, but an explicit
                // publicity subtype is not evidence of a personal relationship.
                0 if category.as_deref().is_none_or(|c| c == "legitimate") => legitimate = true,
                0 => {}
                _ => return Ok(Report::empty(policy.mode, Status::Unavailable)),
            }
        }
        if legitimate
            && eligible
            && historical_sender == sender
            && raw != current_hash
            && let (Some(campaign), Some(simhash)) = (campaign, simhash)
            && let Ok(simhash) = u64::from_str_radix(&simhash, 16)
        {
            examples.push(Example {
                received,
                raw,
                campaign,
                simhash,
            });
        }
    }
    if report.contradicted {
        // Contradiction revokes manual and learned credit, not just one vote.
        return Ok(report);
    }
    let (campaigns, days) = diversity(&examples);
    report.distinct_campaigns = campaigns;
    report.distinct_days = days;
    report.learned_candidate = campaigns >= 3 && days >= 3;
    report.candidate_credit = policy.mode == Mode::CandidateCredit
        && (report.learned_candidate || report.manual_match != ManualMatch::None);
    Ok(report)
}

fn diversity(examples: &[Example]) -> (u16, u16) {
    // Connected components prevent a chain of small campaign mutations from
    // inventing diversity. Work is bounded by MAX_PAIR_RECORDS squared.
    let mut groups: Vec<usize> = (0..examples.len()).collect();
    for (i, a) in examples.iter().enumerate() {
        for (j, b) in examples.iter().enumerate().take(i) {
            if a.raw == b.raw
                || a.campaign == b.campaign
                || (a.simhash ^ b.simhash).count_ones() <= 3
            {
                let old = root(&mut groups, i);
                let new = root(&mut groups, j);
                groups[old] = new;
            }
        }
    }
    let mut first = std::collections::BTreeMap::new();
    for (i, example) in examples.iter().enumerate() {
        first
            .entry(root(&mut groups, i))
            .and_modify(|time: &mut i64| *time = (*time).min(example.received))
            .or_insert(example.received);
    }
    let campaigns = first.len() as u16;
    let mut times: Vec<_> = first.into_values().collect();
    times.sort_unstable();
    let mut previous = None;
    let mut days = 0;
    for time in times {
        if previous.is_none_or(|p| time - p >= 86400) {
            days += 1;
            previous = Some(time);
        }
    }
    (campaigns, days)
}

fn root(groups: &mut [usize], mut i: usize) -> usize {
    while groups[i] != i {
        groups[i] = groups[groups[i]];
        i = groups[i];
    }
    i
}
