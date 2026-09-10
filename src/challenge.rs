//! Explicit, recipient-scoped mailbox possession challenges. Disabled by default.
//! See docs/challenge.md for the SMTP trust boundary and HTTP workflow.
use crate::{engine::Scan, message, now, store::Store};
use anyhow::{Context, Result, ensure};
use rand::RngCore;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

pub mod visual;

/// Store initializes this additive schema alongside control-schema.sql.
/// Nothing is enabled or sent by installing the schema.
pub const SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS challenge_smtp_identity(
 message_id TEXT PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,
 mailbox TEXT NOT NULL, from_domain TEXT NOT NULL, raw_sha256 TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS challenge_requests(
 id TEXT PRIMARY KEY,
 delivery_id INTEGER NOT NULL REFERENCES deliveries(id) ON DELETE CASCADE,
 requested_by TEXT NOT NULL, account_stamp TEXT NOT NULL,
 destination TEXT NOT NULL, mailbox TEXT NOT NULL, raw_sha256 TEXT NOT NULL,
 token_hash TEXT NOT NULL UNIQUE CHECK(length(token_hash)=64),
 created INTEGER NOT NULL, expires INTEGER NOT NULL CHECK(expires>created),
 state TEXT NOT NULL CHECK(state IN ('pending','consumed','revoked')),
 finished INTEGER, notification_id TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS challenge_one_pending
 ON challenge_requests(delivery_id) WHERE state='pending';
CREATE INDEX IF NOT EXISTS challenge_mailbox_rate ON challenge_requests(mailbox,created);
CREATE INDEX IF NOT EXISTS challenge_user_rate ON challenge_requests(requested_by,created);
CREATE INDEX IF NOT EXISTS challenge_global_rate ON challenge_requests(created);
-- Independent of message retention: deleting old mail must not reset send limits.
CREATE TABLE IF NOT EXISTS challenge_rate_events(
 id TEXT PRIMARY KEY, delivery_key TEXT NOT NULL, mailbox_key TEXT NOT NULL,
 requested_by TEXT NOT NULL, created INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS challenge_rate_delivery ON challenge_rate_events(delivery_key,created);
CREATE INDEX IF NOT EXISTS challenge_rate_mailbox ON challenge_rate_events(mailbox_key,created);
CREATE INDEX IF NOT EXISTS challenge_rate_user ON challenge_rate_events(requested_by,created);
CREATE INDEX IF NOT EXISTS challenge_rate_time ON challenge_rate_events(created);
CREATE TABLE IF NOT EXISTS challenge_visual_codes(
 challenge_id TEXT PRIMARY KEY REFERENCES challenge_requests(id) ON DELETE CASCADE,
 nonce TEXT NOT NULL, answer_hash TEXT NOT NULL, expires INTEGER NOT NULL,
 issues INTEGER NOT NULL CHECK(issues BETWEEN 1 AND 8),
 attempts INTEGER NOT NULL CHECK(attempts BETWEEN 0 AND 8)
);
"#;

pub const PAGE_PATH: &str = "/challenge";
pub const SUBMIT_PATH: &str = "/challenge/submit";
pub const RETENTION_SECONDS: i64 = 30 * 86400;
const MAX_RAW_BYTES: u64 = 100 * 1024 * 1024;

/// Remove retained challenge metadata independently of message/spool retention.
/// Call from Store::cleanup, also while the feature is disabled. The returned
/// count includes requests (and their token hashes), identities, rate events and
/// cleared visual codes. Code counters survive until the parent request is pruned.
/// Safe inside an existing transaction; callers can wrap all cleanup in one.
/// A pending, unexpired request and the identity it needs are never removed.
pub fn prune(db: &Connection, time: i64) -> Result<usize> {
    let cutoff = time.saturating_sub(RETENTION_SECONDS);
    let requests = db.execute(
        "DELETE FROM challenge_requests WHERE created<=?1 AND (state<>'pending' OR expires<=?2)",
        params![cutoff, time],
    )?;
    let identities = db.execute(
        "DELETE FROM challenge_smtp_identity WHERE message_id IN
         (SELECT id FROM messages WHERE created<=?1)
         AND NOT EXISTS(SELECT 1 FROM challenge_requests c
             JOIN deliveries d ON d.id=c.delivery_id
             WHERE d.message_id=challenge_smtp_identity.message_id
             AND c.state='pending' AND c.expires>?2)",
        params![cutoff, time],
    )?;
    let rates = db.execute(
        "DELETE FROM challenge_rate_events WHERE created<=?1",
        [time.saturating_sub(86400)],
    )?;
    let codes = db.execute("UPDATE challenge_visual_codes SET nonce='',answer_hash='',expires=0
        WHERE (expires<=?1 OR challenge_id IN (SELECT id FROM challenge_requests WHERE state<>'pending' OR expires<=?1))
        AND (nonce<>'' OR answer_hash<>'')", [time])?;
    Ok(requests + identities + rates + codes)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    pub enabled: bool,
    /// Exact, operator-configured HTTPS origin. Never derive it from Host.
    pub public_origin: String,
    pub notification_from: String,
    pub ttl_seconds: u32,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            enabled: false,
            public_origin: String::new(),
            notification_from: String::new(),
            ttl_seconds: 3600,
        }
    }
}
impl Policy {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (60..=86400).contains(&self.ttl_seconds),
            "invalid challenge lifetime"
        );
        if self.enabled {
            let u = reqwest::Url::parse(&self.public_origin).context("invalid challenge origin")?;
            ensure!(
                u.scheme() == "https"
                    && u.host_str().is_some()
                    && u.username().is_empty()
                    && u.password().is_none()
                    && u.query().is_none()
                    && u.fragment().is_none()
                    && u.origin().ascii_serialization() == self.public_origin,
                "challenge requires a canonical HTTPS origin without path"
            );
            ensure!(
                crate::config::valid_address(&self.notification_from),
                "invalid challenge sender"
            );
        }
        Ok(())
    }
}

/// Construct only from a currently authenticated console session, after Origin/CSRF checks.
/// Database checks do not trust a cached role, grant list or session expiration.
pub struct Actor {
    pub username: String,
    pub session_hash: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub recipient: String,
}

/// Only accepted in a POST body; never derive Debug/Serialize for bearer material.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseRequest {
    pub token: String,
    #[serde(default)]
    pub nonce: String,
    #[serde(default)]
    pub code: String,
}
impl std::fmt::Debug for ResponseRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ResponseRequest { token: [REDACTED] }")
    }
}

#[derive(Debug, Serialize)]
pub struct Receipt {
    pub id: String,
    pub expires_at: i64,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Submission {
    pub message: &'static str,
}
impl Default for Submission {
    fn default() -> Self {
        Self {
            message: "Demande traitée. Si le lien était valide et le message toujours admissible, l’envoi sélectionné sera libéré.",
        }
    }
}

/// Opaque proof captured from the CURRENT SMTP verification result and original octets.
/// This is deliberately not deserializable and must never be reconstructed from headers,
/// a CLI-supplied domain, archived evidence, ARC, or a reputation/allowlist result.
#[derive(Clone)]
pub struct VerifiedSmtpFrom {
    mailbox: String,
    domain: String,
    original_sha256: String,
    queued_sha256: Option<String>,
}
impl std::fmt::Debug for VerifiedSmtpFrom {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifiedSmtpFrom { identity: [REDACTED] }")
    }
}
impl VerifiedSmtpFrom {
    pub fn from_dmarc(raw: &[u8], result: &mail_auth::DmarcOutput) -> Option<Self> {
        use mail_auth::DmarcResult;
        if result.spf_result() != &DmarcResult::Pass && result.dkim_result() != &DmarcResult::Pass {
            return None;
        }
        let mailbox = eligible_mailbox(raw)?;
        let domain = mailbox.rsplit_once('@')?.1.to_ascii_lowercase();
        // Exact author domain: never substitute the organizational/policy domain.
        if !domain.eq_ignore_ascii_case(result.domain()) {
            return None;
        }
        Some(Self {
            mailbox,
            domain,
            original_sha256: message::digest(raw),
            queued_sha256: None,
        })
    }

    /// Bind final queued octets after trusted header rewriting, before enqueue writes
    /// its file. No changed/ambiguous author or automatic mail may inherit the proof.
    /// False leaves the proof unusable; it need not prevent normal SMTP enqueue.
    pub fn bind_queued(&mut self, raw: &[u8]) -> bool {
        self.queued_sha256 =
            (eligible_mailbox(raw).as_deref() == Some(&self.mailbox)).then(|| message::digest(raw));
        self.queued_sha256.is_some()
    }

    /// Preferred integration: call after inserting messages in Store::enqueue's
    /// transaction. `scan` must be the very Scan serialized into that row.
    /// Bind final bytes with bind_queued before moving raw into the fsync task.
    /// An absent/invalid proof fails closed without blocking ordinary mail delivery.
    pub fn record(
        &self,
        tx: &rusqlite::Transaction<'_>,
        message_id: &str,
        scan: &Scan,
    ) -> Result<bool> {
        if uuid::Uuid::parse_str(message_id).is_err()
            || !trusted_scan(scan)
            || scan.raw_sha256.as_deref() != Some(&self.original_sha256)
        {
            return Ok(false);
        }
        let Some(queued_hash) = &self.queued_sha256 else {
            return Ok(false);
        };
        let matches: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM messages WHERE id=?1 AND raw_present=1 AND is_dsn=0 AND sender<>'' AND scan=?2 AND created>?3)",
            params![message_id,serde_json::to_string(scan)?,now().saturating_sub(RETENTION_SECONDS)], |r| r.get(0))?;
        if !matches {
            return Ok(false);
        }
        Ok(tx.execute("INSERT OR IGNORE INTO challenge_smtp_identity(message_id,mailbox,from_domain,raw_sha256) VALUES(?1,?2,?3,?4)",
            params![message_id,self.mailbox,self.domain,queued_hash])? == 1)
    }
}

fn trusted_scan(scan: &Scan) -> bool {
    use crate::{
        antivirus::AntivirusStatus as Av,
        evidence::{AuthResult, Source, State},
    };
    let Some(e) = &scan.evidence else {
        return false;
    };
    scan.complete
        && e.analysis_complete
        && e.schema == crate::evidence::SCHEMA
        && e.source == Source::SmtpSession
        && e.authentication.state == State::Complete
        && e.authentication.dmarc_state == State::Complete
        && (e.authentication.dmarc_spf == Some(AuthResult::Pass)
            || e.authentication.dmarc_dkim == Some(AuthResult::Pass))
        && scan.antivirus.status != Av::Malware
        && scan.signatures.status != Av::Malware
        && e.antivirus.as_ref().is_none_or(|v| v.status != Av::Malware)
        && e.signatures
            .as_ref()
            .is_none_or(|v| v.status != Av::Malware)
}

fn eligible_mailbox(raw: &[u8]) -> Option<String> {
    message::validate(raw).ok()?;
    let (headers, _) = message::fields(raw).ok()?;
    if headers
        .iter()
        .filter(|h| message::name(h) == "from")
        .count()
        != 1
    {
        return None;
    }
    for h in headers {
        let name = message::name(h);
        let value = std::str::from_utf8(h).ok()?.split_once(':')?.1.trim();
        // Conservative anti-loop suppression, including mailing lists and bulk mail.
        if (name == "auto-submitted" && !value.eq_ignore_ascii_case("no"))
            || matches!(
                name.as_str(),
                "list-id"
                    | "list-unsubscribe"
                    | "precedence"
                    | "x-auto-response-suppress"
                    | "x-noisefence-challenge"
            )
            || (name == "content-type"
                && value.to_ascii_lowercase().starts_with("multipart/report"))
        {
            return None;
        }
    }
    let parsed = mail_parser::MessageParser::default().parse_headers(raw)?;
    let addresses = parsed.from()?.as_list()?;
    if addresses.len() != 1 {
        return None;
    }
    let address = addresses[0].address.as_deref()?;
    if !crate::config::valid_address(address) {
        return None;
    }
    let (local, domain) = address.rsplit_once('@')?;
    Some(format!("{local}@{}", domain.to_ascii_lowercase()))
}

fn read_raw(root: &Path, id: &str) -> Result<Vec<u8>> {
    ensure!(
        uuid::Uuid::parse_str(id).is_ok(),
        "invalid challenge message id"
    );
    let mut raw = Vec::new();
    File::open(root.join("spool").join(format!("{id}.eml")))?
        .take(MAX_RAW_BYTES + 1)
        .read_to_end(&mut raw)?;
    ensure!(
        raw.len() as u64 <= MAX_RAW_BYTES,
        "challenge message too large"
    );
    Ok(raw)
}

/// After enqueue commits, persist a proof captured by from_dmarc in process_smtp.
/// A crash before this call leaves mail safely ineligible. No historical backfill.
pub async fn record_smtp_identity(
    store: &Store,
    message_id: String,
    mut proof: VerifiedSmtpFrom,
) -> Result<bool> {
    let root = store.root.clone();
    store
        .run(move |db| {
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let row: Option<(String, String)> = tx
                .query_row(
                    "SELECT scan,sender FROM messages WHERE id=?1 AND raw_present=1 AND is_dsn=0",
                    [&message_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let Some((scan, sender)) = row else {
                return Ok(false);
            };
            let scan: Scan = serde_json::from_str(&scan)?;
            if sender.is_empty()
                || !trusted_scan(&scan)
                || scan.raw_sha256.as_deref() != Some(&proof.original_sha256)
            {
                return Ok(false);
            }
            let raw = read_raw(&root, &message_id)?;
            if !proof.bind_queued(&raw) {
                return Ok(false);
            }
            let inserted = proof.record(&tx, &message_id, &scan)?;
            tx.commit()?;
            Ok(inserted)
        })
        .await
}

struct Candidate {
    delivery_id: i64,
    delivery_key: String,
    destination: String,
    mailbox: String,
    raw_hash: String,
    held_until: i64,
    identity_expires: i64,
}

fn candidate(
    db: &Connection,
    root: &Path,
    message_id: &str,
    recipient: &str,
    time: i64,
) -> Result<Option<Candidate>> {
    let row = db
        .query_row(
            "SELECT d.id,d.destination,m.scan,i.mailbox,i.from_domain,i.raw_sha256,p.held_until,m.created
         FROM deliveries d JOIN messages m ON m.id=d.message_id
         JOIN delivery_policy p ON p.delivery_id=d.id
         JOIN challenge_smtp_identity i ON i.message_id=m.id
         WHERE d.message_id=?1 AND d.address=?2 AND d.status='quarantined'
         AND m.raw_present=1 AND m.is_dsn=0 AND m.sender<>''
         AND p.action='quarantine' AND p.released_at IS NULL AND p.held_until>?3",
            params![message_id, recipient, time],
            |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                    r.get::<_, String>(5)?,
                    r.get::<_, i64>(6)?,
                    r.get::<_, i64>(7)?,
                ))
            },
        )
        .optional()?;
    let Some((delivery_id, destination, scan, mailbox, domain, raw_hash, held_until, created)) =
        row
    else {
        return Ok(None);
    };
    let Ok(scan) = serde_json::from_str::<Scan>(&scan) else {
        return Ok(None);
    };
    if !trusted_scan(&scan) {
        return Ok(None);
    }
    // Missing/changed spool fails closed; never release a different payload.
    let Ok(raw) = read_raw(root, message_id) else {
        return Ok(None);
    };
    if message::digest(&raw) != raw_hash
        || eligible_mailbox(&raw).as_deref() != Some(&mailbox)
        || mailbox.rsplit_once('@').is_none_or(|(_, d)| d != domain)
    {
        return Ok(None);
    }
    Ok(Some(Candidate {
        delivery_id,
        delivery_key: message::digest(serde_json::to_string(&(message_id, recipient))?.as_bytes()),
        destination,
        mailbox,
        raw_hash,
        held_until,
        identity_expires: created.saturating_add(RETENTION_SECONDS),
    }))
}

fn authorized(
    db: &Connection,
    actor: &Actor,
    message_id: &str,
    recipient: &str,
    time: i64,
) -> Result<bool> {
    Ok(db.query_row("SELECT EXISTS(SELECT 1 FROM deliveries d JOIN console_access g ON g.delivery_id=d.id JOIN sessions s ON s.username=g.username WHERE d.message_id=?1 AND d.address=?2 AND g.username=?3 AND s.token_hash=?4 AND s.expires>?5)",
        params![message_id,recipient,actor.username,actor.session_hash,time], |r| r.get(0))?)
}

fn account_stamp(db: &Connection, username: &str) -> Result<Option<String>> {
    let row: Option<(String,i64)> = db.query_row("SELECT u.password,COALESCE(v.version,0) FROM users u LEFT JOIN console_user_versions v ON v.username=u.username WHERE u.username=?1 AND u.disabled=0",
        [username], |r| Ok((r.get(0)?,r.get(1)?))).optional()?;
    Ok(row.map(|r| message::digest(serde_json::to_string(&(username, r)).unwrap().as_bytes())))
}

/// Server-only DNS preparation. Do not deserialize this from an HTTP request.
pub struct Prepared {
    message_id: String,
    recipient: String,
    destination: String,
    mailbox: String,
    raw_hash: String,
}
impl Prepared {
    pub fn mailbox(&self) -> &str {
        &self.mailbox
    }
    pub fn domain(&self) -> &str {
        self.mailbox.rsplit_once('@').unwrap().1
    }
}

/// Call only for an explicit authorized console action. Resolve MX AFTER this returns.
pub async fn prepare(
    store: &Store,
    policy: &Policy,
    actor: Actor,
    message_id: String,
    body: Request,
) -> Result<Option<Prepared>> {
    policy.validate()?;
    if !policy.enabled
        || uuid::Uuid::parse_str(&message_id).is_err()
        || !crate::config::valid_address(&body.recipient)
    {
        return Ok(None);
    }
    let root = store.root.clone();
    store
        .run(move |db| {
            let tx = db.transaction()?;
            let time = now();
            if !authorized(&tx, &actor, &message_id, &body.recipient, time)? {
                return Ok(None);
            }
            Ok(candidate(&tx, &root, &message_id, &body.recipient, time)?
                .filter(|c| c.identity_expires > time)
                .map(|c| Prepared {
                    message_id,
                    recipient: body.recipient,
                    destination: c.destination,
                    mailbox: c.mailbox,
                    raw_hash: c.raw_hash,
                }))
        })
        .await
}

fn rate_allowed(db: &Connection, c: &Candidate, username: &str, time: i64) -> Result<bool> {
    // Survive restarts, concurrent callers, revocation and token expiration.
    Ok(db.query_row("SELECT
        (SELECT COUNT(*) FROM challenge_rate_events WHERE delivery_key=?1 AND created>?4-86400)=0
        AND (SELECT COUNT(*) FROM challenge_rate_events WHERE mailbox_key=?2 AND created>?4-86400)<3
        AND (SELECT COUNT(*) FROM challenge_rate_events WHERE requested_by=?3 AND created>?4-3600)<20
        AND (SELECT COUNT(*) FROM challenge_rate_events WHERE created>?4-3600)<100",
        params![c.delivery_key,message::digest(c.mailbox.to_ascii_lowercase().as_bytes()),username,time], |r| r.get(0))?)
}

/// Atomically enqueue the notification, hash-only capability and audit. hosts is a
/// trusted resolver result; never take it from the browser. No direct SMTP here.
/// None covers disabled/unauthorized/ineligible/duplicate/rate-limited requests.
pub async fn request(
    store: &Store,
    policy: &Policy,
    actor: Actor,
    prepared: Prepared,
    hosts: Vec<String>,
) -> Result<Option<Receipt>> {
    policy.validate()?;
    if !policy.enabled {
        return Ok(None);
    }
    ensure!(
        !hosts.is_empty()
            && hosts.len() <= 32
            && hosts
                .iter()
                .all(|h| crate::config::endpoint(h, 25).is_some()),
        "invalid challenge route"
    );
    let policy = policy.clone();
    let root = store.root.clone();
    let result = store.run(move |db| {
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let time = now();
        if !authorized(&tx,&actor,&prepared.message_id,&prepared.recipient,time)? { return Ok(None); }
        let Some(c) = candidate(&tx,&root,&prepared.message_id,&prepared.recipient,time)? else { return Ok(None); };
        tx.execute("DELETE FROM challenge_rate_events WHERE created<=?1",[time-86400])?;
        if c.mailbox != prepared.mailbox || c.destination != prepared.destination || c.raw_hash != prepared.raw_hash
            || c.identity_expires <= time
            || c.mailbox.eq_ignore_ascii_case(&policy.notification_from)
            || !rate_allowed(&tx,&c,&actor.username,time)? { return Ok(None); }
        let Some(stamp) = account_stamp(&tx,&actor.username)? else { return Ok(None); };
        let expires = c.held_until.min(c.identity_expires).min(time + i64::from(policy.ttl_seconds));
        if expires <= time { return Ok(None); }
        // Retire expired pending capabilities without resetting their rate history.
        tx.execute("UPDATE challenge_requests SET state='revoked',finished=?2 WHERE delivery_id=?1 AND state='pending' AND expires<=?2",params![c.delivery_id,time])?;
        let active: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM challenge_requests WHERE delivery_id=?1 AND state='pending')",[c.delivery_id],|r|r.get(0))?;
        if active { return Ok(None); }
        let id = uuid::Uuid::new_v4().to_string();
        let notification = uuid::Uuid::new_v4().to_string();
        let mut secret = [0u8;32];
        rand::rngs::OsRng.try_fill_bytes(&mut secret).context("challenge entropy unavailable")?;
        let token = hex::encode(secret);
        let raw = notification_mail(&policy,&c.mailbox,&notification,&token,time);
        let path = root.join("spool").join(format!("{notification}.eml"));
        // Same durability ordering as Store::enqueue: fsync file/directory before DB commit.
        // Uncommitted orphan files are removed by Store::recover after a crash.
        let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path)?;
        let persisted = (|| -> Result<()> {
            file.write_all(&raw)?;
            file.sync_all()?;
            File::open(root.join("spool"))?.sync_all()?;
            let scan = Scan { complete:true, subject:"Confirmation de votre adresse".into(), model:"challenge-notification-1".into(), ..Scan::default() };
            tx.execute("INSERT INTO messages(id,created,sender,scan,is_dsn) VALUES(?1,?2,'',?3,1)",params![notification,time,serde_json::to_string(&scan)?])?;
            tx.execute("INSERT INTO deliveries(message_id,address,destination,hosts,next_attempt) VALUES(?1,?2,?2,?3,?4)",params![notification,c.mailbox,serde_json::to_string(&hosts)?,time])?;
            tx.execute("INSERT INTO delivery_policy(delivery_id,action) VALUES(?1,'deliver')",[tx.last_insert_rowid()])?;
            tx.execute("INSERT INTO challenge_requests(id,delivery_id,requested_by,account_stamp,destination,mailbox,raw_sha256,token_hash,created,expires,state,notification_id) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,'pending',?11)",
                params![id,c.delivery_id,actor.username,stamp,c.destination,c.mailbox,c.raw_hash,message::digest(token.as_bytes()),time,expires,notification])?;
            tx.execute("INSERT INTO challenge_rate_events(id,delivery_key,mailbox_key,requested_by,created) VALUES(?1,?2,?3,?4,?5)",
                params![id,c.delivery_key,message::digest(c.mailbox.to_ascii_lowercase().as_bytes()),actor.username,time])?;
            tx.execute("INSERT INTO audit(created,username,action,object_id) VALUES(?1,?2,'challenge_request',?3)",params![time,actor.username,c.delivery_id.to_string()])?;
            tx.commit()?;
            Ok(())
        })();
        if persisted.is_err() { let _ = std::fs::remove_file(path); }
        persisted?;
        Ok(Some(Receipt { id, expires_at: expires }))
    }).await?;
    if result.is_some() {
        store.notify_delivery();
    }
    Ok(result)
}

fn notification_mail(policy: &Policy, mailbox: &str, id: &str, token: &str, time: i64) -> Vec<u8> {
    use base64::Engine;
    let domain = policy.notification_from.rsplit_once('@').unwrap().1;
    let text = format!(
        "Un destinataire a demandé une confirmation pour un envoi placé en quarantaine.\r\nSi vous avez envoyé ce message, ouvrez ce lien puis recopiez le code affiché pour confirmer :\r\n{}{PAGE_PATH}#{}\r\n\r\nCe lien confirme l’accès à cette boîte, pas que vous êtes humain.\r\nIl autorise uniquement cet envoi ; les prochains messages restent filtrés.\r\nIgnorez cette demande si vous n’avez pas envoyé ce message. Ne répondez pas par e-mail.\r\n",
        policy.public_origin, token
    );
    // French accents without depending on upstream 8BITMIME support.
    let encoded = base64::engine::general_purpose::STANDARD.encode(text);
    let mut raw = format!("From: <{}>\r\nTo: <{}>\r\nDate: {}\r\nMessage-ID: <{}@{}>\r\nSubject: Confirmation de votre adresse\r\nAuto-Submitted: auto-generated\r\nX-Auto-Response-Suppress: All\r\nX-NoiseFence-Challenge: 1\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n",
        policy.notification_from,mailbox,mail_parser::DateTime::from_timestamp(time).to_rfc822(),id,domain).into_bytes();
    for line in encoded.as_bytes().chunks(76) {
        raw.extend_from_slice(line);
        raw.extend_from_slice(b"\r\n");
    }
    raw
}

/// Revoke even while Policy is disabled. Current admin/grantee + live session required.
/// Pending notifications are cancelled; an already claimed SMTP send cannot be recalled.
pub async fn revoke(
    store: &Store,
    actor: Actor,
    message_id: String,
    body: Request,
) -> Result<bool> {
    store.run(move |db| {
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let time = now();
        if !authorized(&tx,&actor,&message_id,&body.recipient,time)? { return Ok(false); }
        let delivery: i64 = tx.query_row("SELECT id FROM deliveries WHERE message_id=?1 AND address=?2",params![message_id,body.recipient],|r|r.get(0))?;
        tx.execute("UPDATE deliveries SET status='discarded',error=NULL WHERE status='pending' AND message_id IN (SELECT notification_id FROM challenge_requests WHERE delivery_id=?1 AND state='pending')",[delivery])?;
        let count = tx.execute("UPDATE challenge_requests SET state='revoked',finished=?2 WHERE delivery_id=?1 AND state='pending'",params![delivery,time])?;
        if count > 0 {
            tx.execute("INSERT INTO audit(created,username,action,object_id) VALUES(?1,?2,'challenge_revoke',?3)",params![time,actor.username,delivery.to_string()])?;
        }
        tx.commit()?;
        Ok(count > 0)
    }).await
}

/// Public POST: identical response for invalid, expired, revoked, replayed and successful
/// tokens. Never logs/returns the bearer or accepts a client-selected delivery/recipient.
pub async fn submit(store: &Store, policy: &Policy, body: ResponseRequest) -> Result<Submission> {
    policy.validate()?;
    if !policy.enabled
        || body.token.len() != 64
        || !body
            .token
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Ok(Submission::default());
    }
    let hash = message::digest(body.token.as_bytes());
    let root = store.root.clone();
    let changed = store.run(move |db| {
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let time = now();
        let row = tx.query_row("SELECT c.id,c.delivery_id,c.requested_by,c.account_stamp,c.destination,c.mailbox,c.raw_sha256,d.message_id,d.address FROM challenge_requests c JOIN deliveries d ON d.id=c.delivery_id WHERE c.token_hash=?1 AND c.state='pending' AND c.expires>?2",
            params![hash,time],|r|Ok((r.get::<_,String>(0)?,r.get::<_,i64>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,String>(4)?,r.get::<_,String>(5)?,r.get::<_,String>(6)?,r.get::<_,String>(7)?,r.get::<_,String>(8)?))).optional()?;
        let Some((id,delivery,username,stamp,destination,mailbox,raw_hash,message_id,recipient)) = row else { return Ok(false); };
        let access: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM console_access WHERE username=?1 AND delivery_id=?2)",params![username,delivery],|r|r.get(0))?;
        let authorized = access && account_stamp(&tx,&username)?.as_deref() == Some(&stamp);
        // Check the small durable proof before reading/parsing the queued MIME.
        // Bad codes and exhausted budgets must not repeatedly scan a large file.
        if authorized && !visual::verify(&tx, &id, &hash, &body.nonce, &body.code, time)? {
            tx.commit()?;
            return Ok(false);
        }
        let eligible = authorized && candidate(&tx,&root,&message_id,&recipient,time)?
            .is_some_and(|c| c.delivery_id == delivery && c.destination == destination && c.mailbox == mailbox && c.raw_hash == raw_hash);
        if !eligible {
            tx.execute("UPDATE challenge_requests SET state='revoked',finished=?2 WHERE id=?1",params![id,time])?;
            tx.execute("INSERT INTO audit(created,username,action,object_id) VALUES(?1,?2,'challenge_invalidate',?3)",params![time,username,delivery.to_string()])?;
            tx.commit()?;
            return Ok(false);
        }
        tx.execute("UPDATE challenge_requests SET state='consumed',finished=?2 WHERE id=?1",params![id,time])?;
        // Preserve the original quarantine action, scan, envelope, recipients and history.
        tx.execute("UPDATE deliveries SET status='pending',next_attempt=?2,error=NULL WHERE id=?1",params![delivery,time])?;
        tx.execute("UPDATE delivery_policy SET released_at=?2 WHERE delivery_id=?1",params![delivery,time])?;
        for action in ["challenge_complete", "quarantine_release"] {
            tx.execute("INSERT INTO audit(created,username,action,object_id) VALUES(?1,?2,?3,?4)",params![time,username,action,delivery.to_string()])?;
        }
        tx.commit()?;
        Ok(true)
    }).await?;
    if changed {
        store.notify_delivery();
    }
    Ok(Submission::default())
}

/// Stateless landing page: fragment is erased BEFORE any POST; user gesture required.
/// Do not add analytics, third-party scripts, external assets or token-bearing GETs.
pub fn page() -> axum::response::Response {
    use axum::{
        http::header,
        response::{Html, IntoResponse},
    };
    let mut response = Html(PAGE).into_response();
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    headers.insert("referrer-policy", "no-referrer".parse().unwrap());
    headers.insert("x-content-type-options", "nosniff".parse().unwrap());
    headers.insert("x-frame-options", "DENY".parse().unwrap());
    use base64::Engine;
    use sha2::Digest;
    let script = PAGE
        .split_once("<script>")
        .unwrap()
        .1
        .split_once("</script>")
        .unwrap()
        .0;
    let hash =
        base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(script.as_bytes()));
    let style = PAGE
        .split_once("<style>")
        .unwrap()
        .1
        .split_once("</style>")
        .unwrap()
        .0;
    let style_hash =
        base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(style.as_bytes()));
    headers.insert("content-security-policy",format!("default-src 'none'; script-src 'sha256-{hash}'; style-src 'sha256-{style_hash}'; img-src data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'").parse().unwrap());
    response
}

/// Ready-to-merge public routes at /challenge (NOT under /api/v1). The closure
/// reads the current policy on every request, including after operator disable.
/// Authenticated request/revoke routes remain in the parent console API.
pub fn public_router(
    store: Store,
    current_policy: impl Fn() -> Policy + Send + Sync + 'static,
) -> axum::Router {
    use axum::{
        extract::{DefaultBodyLimit, State},
        routing::{get, post},
    };
    #[derive(Clone)]
    struct Public {
        store: Store,
        policy: std::sync::Arc<dyn Fn() -> Policy + Send + Sync>,
        capacity: std::sync::Arc<tokio::sync::Semaphore>,
    }
    async fn landing(State(state): State<Public>) -> axum::response::Response {
        use axum::response::IntoResponse;
        let policy = (state.policy)();
        if !policy.enabled || policy.validate().is_err() {
            return axum::http::StatusCode::NOT_FOUND.into_response();
        }
        page()
    }
    async fn answer(
        State(state): State<Public>,
        uri: axum::http::Uri,
        headers: axum::http::HeaderMap,
        body: std::result::Result<
            axum::Json<ResponseRequest>,
            axum::extract::rejection::JsonRejection,
        >,
    ) -> axum::response::Response {
        use axum::{http::header, response::IntoResponse};
        let policy = (state.policy)();
        // No CORS: a JSON POST and exact Origin bind requests to the local page.
        // CLI clients can send the configured Origin explicitly.
        let same_origin = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok())
            == Some(&policy.public_origin)
            && headers.get_all(header::ORIGIN).iter().count() == 1;
        if policy.enabled
            && policy.validate().is_ok()
            && same_origin
            && uri.query().is_none()
            && let Ok(_permit) = state.capacity.try_acquire()
            && let Ok(axum::Json(body)) = body
            && submit(&state.store, &policy, body).await.is_err()
        {
            // Avoid printing database errors or request bodies: observability without secrets.
            tracing::error!("challenge submission storage failure");
        }
        let mut response = axum::Json(Submission::default()).into_response();
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
        response
            .headers_mut()
            .insert("referrer-policy", "no-referrer".parse().unwrap());
        response
            .headers_mut()
            .insert("x-content-type-options", "nosniff".parse().unwrap());
        response
    }
    async fn picture(
        State(state): State<Public>,
        uri: axum::http::Uri,
        headers: axum::http::HeaderMap,
        body: std::result::Result<
            axum::Json<visual::Request>,
            axum::extract::rejection::JsonRejection,
        >,
    ) -> axum::response::Response {
        use axum::{
            http::{StatusCode, header},
            response::IntoResponse,
        };
        let policy = (state.policy)();
        let result = async {
            if !policy.enabled || policy.validate().is_err() {
                return StatusCode::NOT_FOUND.into_response();
            }
            if uri.query().is_some()
                || headers.get_all(header::ORIGIN).iter().count() != 1
                || headers.get(header::ORIGIN).and_then(|v| v.to_str().ok())
                    != Some(&policy.public_origin)
            {
                return StatusCode::FORBIDDEN.into_response();
            }
            let Ok(_permit) = state.capacity.try_acquire() else {
                return StatusCode::TOO_MANY_REQUESTS.into_response();
            };
            let Ok(axum::Json(body)) = body else {
                return StatusCode::BAD_REQUEST.into_response();
            };
            match visual::issue(&state.store, &policy, body).await {
                Ok(puzzle) => axum::Json(puzzle).into_response(),
                Err(_) => {
                    tracing::error!("visual challenge unavailable");
                    StatusCode::SERVICE_UNAVAILABLE.into_response()
                }
            }
        }
        .await;
        let mut response = result;
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
        response
            .headers_mut()
            .insert("referrer-policy", "no-referrer".parse().unwrap());
        response
            .headers_mut()
            .insert("x-content-type-options", "nosniff".parse().unwrap());
        response
    }
    axum::Router::new()
        .route(PAGE_PATH, get(landing))
        .route(SUBMIT_PATH, post(answer))
        .route(visual::PATH, post(picture))
        .layer(DefaultBodyLimit::max(1024))
        .with_state(Public {
            store,
            policy: std::sync::Arc::new(current_policy),
            capacity: std::sync::Arc::new(tokio::sync::Semaphore::new(8)),
        })
}

const PAGE: &str = include_str!("challenge/page.html");
