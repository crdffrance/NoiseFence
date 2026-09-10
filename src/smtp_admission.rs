//! Experimental RCPT admission. No message acceptance, delivery, or challenge email.
//!
//! Run database methods on the Store's blocking executor. Release the database
//! lock before `delay`, and acquire DATA processing permits only after admission.
use anyhow::{Context, Result, ensure};
use rand::RngCore;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::sync::Semaphore;

pub const VERSION: &str = "smtp-admission-1";
pub const GREYLIST_REPLY: &str = "451 4.7.1 Temporary greylisting; please retry later\r\n";
pub const UNAVAILABLE_REPLY: &str = "451 4.3.0 Admission state unavailable; please retry later\r\n";
const PRUNE_BATCH: i64 = 256;

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Observe,
    Enforce,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub enabled: bool,
    pub mode: Mode,
    pub retry_delay_seconds: u64,
    /// Unsuccessful cycles expire at first_seen + max age, including the boundary.
    pub retry_max_age_seconds: u64,
    /// Fixed lifetime after a successful retry; traffic never extends it.
    pub retention_seconds: u64,
    /// Per mode; observe state cannot consume enforcement capacity.
    pub max_entries: usize,
    /// Zero disables tarpitting. Only greylist deferrals are delay candidates.
    pub tarpit_delay_ms: u64,
    pub tarpit_max_concurrent: usize,
    pub tarpit_session_budget_ms: u64,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: Mode::Observe,
            retry_delay_seconds: 300,
            retry_max_age_seconds: 86_400,
            retention_seconds: 604_800,
            max_entries: 10_000,
            tarpit_delay_ms: 0,
            tarpit_max_concurrent: 8,
            tarpit_session_budget_ms: 5_000,
        }
    }
}
impl Settings {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (1..=3600).contains(&self.retry_delay_seconds),
            "SMTP admission retry delay must be 1..3600 seconds"
        );
        ensure!(
            self.retry_max_age_seconds > self.retry_delay_seconds
                && self.retry_max_age_seconds <= 604_800,
            "SMTP admission retry max age must exceed retry delay and be at most 7 days"
        );
        ensure!(
            (1..=2_592_000).contains(&self.retention_seconds),
            "SMTP admission retention must be 1 second..30 days"
        );
        ensure!(
            (1..=100_000).contains(&self.max_entries),
            "SMTP admission capacity must be 1..100000 entries per mode"
        );
        ensure!(
            self.tarpit_delay_ms <= 5_000,
            "SMTP admission tarpit delay must be at most 5000 ms"
        );
        ensure!(
            (1..=64).contains(&self.tarpit_max_concurrent),
            "SMTP admission tarpit concurrency must be 1..64"
        );
        ensure!(
            self.tarpit_session_budget_ms <= 10_000,
            "SMTP admission session delay budget must be at most 10000 ms"
        );
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Disabled,
    FirstSeen,
    TooSoon,
    RetryPassed,
    Passed,
    /// No live rows are evicted to make room: capacity exhaustion fails open.
    Capacity,
    ClockSkew,
    Unavailable,
}

/// Evidence is safe to serialize: no peer or envelope identities are included.
#[derive(Clone, Debug, Serialize)]
pub struct Decision {
    pub version: &'static str,
    pub mode: Mode,
    pub status: Status,
    pub would_defer: bool,
    pub retry_after_seconds: Option<u64>,
    pub candidate_delay_ms: u64,
    enforced: bool,
}
impl Decision {
    /// None means this layer allows RCPT processing to continue, never that a
    /// message has been durably accepted or that another policy may be skipped.
    pub fn smtp_reply(&self) -> Option<&'static str> {
        if !self.enforced {
            None
        } else if matches!(self.status, Status::Unavailable | Status::ClockSkew) {
            Some(UNAVAILABLE_REPLY)
        } else {
            Some(GREYLIST_REPLY)
        }
    }
}

/// Keep for the entire TCP connection, including RSET/EHLO/STARTTLS resets.
/// Reservations are charged before sleep and are not refunded on cancellation.
#[derive(Debug, Default)]
pub struct DelayBudget {
    charged_ms: u64,
}
impl DelayBudget {
    pub fn charged_ms(&self) -> u64 {
        self.charged_ms
    }
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DelayOutcome {
    NotNeeded,
    Observe,
    Busy,
    BudgetExhausted,
    Slept { milliseconds: u64 },
}

/// Clone a single controller across sessions to share the sleeper semaphore.
#[derive(Clone)]
pub struct Admission {
    settings: Settings,
    sleepers: Arc<Semaphore>,
}
impl Admission {
    pub fn new(settings: Settings) -> Result<Self> {
        settings.validate()?;
        Ok(Self {
            sleepers: Arc::new(Semaphore::new(settings.tarpit_max_concurrent)),
            settings,
        })
    }

    /// Change only the effective policy mode while retaining the listener's
    /// shared sleeper capacity, including permits held by older SMTP sessions.
    pub fn with_mode(&self, mode: Mode) -> Self {
        let mut admission = self.clone();
        admission.settings.mode = mode;
        admission
    }

    /// Refresh policy while sharing the listener's sleeper capacity. Changing
    /// the semaphore size requires a listener restart so old sessions cannot
    /// multiply or exceed a newly configured concurrency limit. Initialize the
    /// database before activating a previously disabled controller.
    pub fn reconfigured(&self, settings: Settings) -> Result<Self> {
        settings.validate()?;
        ensure!(
            settings.tarpit_max_concurrent == self.settings.tarpit_max_concurrent,
            "changing SMTP admission tarpit concurrency requires a listener restart"
        );
        Ok(Self {
            settings,
            sleepers: self.sleepers.clone(),
        })
    }

    /// Idempotent, atomic schema setup. Leaves Store's user_version and PRAGMAs
    /// untouched. File-backed callers must use WAL + synchronous=FULL and a
    /// bounded busy timeout (Store already does). Disabled setup is a no-op.
    pub fn initialize(&self, db: &mut Connection) -> Result<()> {
        if !self.settings.enabled {
            return Ok(());
        }
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute_batch(
            "CREATE TABLE IF NOT EXISTS smtp_admission_meta_v1 (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                salt BLOB NOT NULL CHECK(length(salt)=32)
            );
            CREATE TABLE IF NOT EXISTS smtp_admission_entries_v1 (
                id INTEGER PRIMARY KEY,
                mode INTEGER NOT NULL CHECK(mode IN (0,1)),
                peer BLOB NOT NULL CHECK(length(peer) IN (4,16)),
                sender_hash BLOB NOT NULL CHECK(length(sender_hash)=32),
                recipient_hash BLOB NOT NULL CHECK(length(recipient_hash)=32),
                first_seen INTEGER NOT NULL CHECK(first_seen>=0),
                eligible_at INTEGER NOT NULL CHECK(eligible_at>first_seen),
                passed_at INTEGER CHECK(passed_at>=eligible_at),
                expires_at INTEGER NOT NULL CHECK(expires_at>first_seen),
                UNIQUE(mode,peer,sender_hash,recipient_hash)
            );
            CREATE INDEX IF NOT EXISTS smtp_admission_expiry_v1
                ON smtp_admission_entries_v1(expires_at);
            CREATE INDEX IF NOT EXISTS smtp_admission_mode_expiry_v1
                ON smtp_admission_entries_v1(mode,expires_at);",
        )?;
        let mut salt = [0u8; 32];
        rand::rngs::OsRng
            .try_fill_bytes(&mut salt)
            .context("admission salt generation failed")?;
        tx.execute(
            "INSERT OR IGNORE INTO smtp_admission_meta_v1(singleton,salt) VALUES(1,?1)",
            params![&salt[..]],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Call after validating MAIL/RCPT syntax and local recipient authorization,
    /// before accepting that RCPT. The peer MUST come from the accepted socket.
    /// Addresses are parsed paths without angle brackets; null MAIL FROM is "".
    /// `now` is a trusted nonnegative Unix timestamp, never a client timestamp.
    /// All state transitions and capacity checks commit in one IMMEDIATE tx.
    pub fn check(
        &self,
        db: &mut Connection,
        peer: SocketAddr,
        sender: &str,
        recipient: &str,
        now: i64,
    ) -> Result<Decision> {
        if !self.settings.enabled {
            return Ok(self.decision(Status::Disabled, false, None));
        }
        let eligible_at = deadline(now, self.settings.retry_delay_seconds)?;
        let pending_expiry = deadline(now, self.settings.retry_max_age_seconds)?;
        let passed_expiry = deadline(now, self.settings.retention_seconds)?;
        let sender = canonical_address(sender, true)?;
        let recipient = canonical_address(recipient, false)?;
        let peer = match normalize_peer_ip(peer.ip()) {
            IpAddr::V4(ip) => ip.octets().to_vec(),
            IpAddr::V6(ip) => ip.octets().to_vec(),
        };
        let mode = self.mode_id();
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let salt: Vec<u8> = tx.query_row(
            "SELECT salt FROM smtp_admission_meta_v1 WHERE singleton=1",
            [],
            |r| r.get(0),
        )?;
        ensure!(salt.len() == 32, "invalid admission salt");
        let sender_hash = address_hash(&salt, b"sender", &sender);
        let recipient_hash = address_hash(&salt, b"recipient", &recipient);
        prune_expired(&tx, now)?;
        // A targeted expiry also works when the bounded sweep has a backlog.
        tx.execute("DELETE FROM smtp_admission_entries_v1 WHERE mode=?1 AND peer=?2 AND sender_hash=?3 AND recipient_hash=?4 AND expires_at<=?5",
            params![mode, peer, &sender_hash[..], &recipient_hash[..], now])?;
        let row = tx
            .query_row(
                "SELECT id,first_seen,eligible_at,passed_at FROM smtp_admission_entries_v1
             WHERE mode=?1 AND peer=?2 AND sender_hash=?3 AND recipient_hash=?4",
                params![mode, peer, &sender_hash[..], &recipient_hash[..]],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, Option<i64>>(3)?,
                    ))
                },
            )
            .optional()?;
        let decision = if let Some((id, first_seen, eligible, passed)) = row {
            if now < first_seen || passed.is_some_and(|at| now < at) {
                self.decision(Status::ClockSkew, true, None)
            } else if passed.is_some() {
                self.decision(Status::Passed, false, None)
            } else if now < eligible {
                self.decision(Status::TooSoon, true, Some((eligible - now) as u64))
            } else {
                tx.execute(
                    "UPDATE smtp_admission_entries_v1 SET passed_at=?1,expires_at=?2 WHERE id=?3",
                    params![now, passed_expiry, id],
                )?;
                self.decision(Status::RetryPassed, false, None)
            }
        } else {
            let count: i64 = tx.query_row(
                "SELECT count(*) FROM smtp_admission_entries_v1 WHERE mode=?1",
                [mode],
                |r| r.get(0),
            )?;
            if count >= self.settings.max_entries as i64 {
                self.decision(Status::Capacity, false, None)
            } else {
                tx.execute("INSERT INTO smtp_admission_entries_v1(mode,peer,sender_hash,recipient_hash,first_seen,eligible_at,expires_at)
                    VALUES(?1,?2,?3,?4,?5,?6,?7)",
                    params![mode, peer, &sender_hash[..], &recipient_hash[..], now, eligible_at, pending_expiry])?;
                self.decision(
                    Status::FirstSeen,
                    true,
                    Some(self.settings.retry_delay_seconds),
                )
            }
        };
        tx.commit()?;
        Ok(decision)
    }

    /// Delete at most 256 expired rows per call, across both namespaces. Schedule
    /// periodically even when admission is disabled; no SMTP activity is needed.
    /// Does not initialize a database that has never enabled admission.
    pub fn prune(&self, db: &mut Connection, now: i64) -> Result<usize> {
        ensure!(now >= 0, "invalid admission clock");
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let exists: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='smtp_admission_entries_v1')", [], |r| r.get(0))?;
        let removed = if exists { prune_expired(&tx, now)? } else { 0 };
        tx.commit()?;
        Ok(removed)
    }

    /// Apply on DB/init/executor failure. Observe never changes SMTP behavior;
    /// explicit enforcement returns a temporary error, without tarpitting it.
    pub fn unavailable(&self) -> Decision {
        if self.settings.enabled {
            self.decision(Status::Unavailable, true, None)
        } else {
            self.decision(Status::Disabled, false, None)
        }
    }

    /// No queue for sleepers: saturation skips only the optional delay, never
    /// the 451. Dropping this future releases the permit; no task is detached.
    pub async fn delay(&self, decision: &Decision, budget: &mut DelayBudget) -> DelayOutcome {
        if !self.settings.enabled || decision.candidate_delay_ms == 0 {
            return DelayOutcome::NotNeeded;
        }
        if self.settings.mode == Mode::Observe || decision.mode == Mode::Observe {
            return DelayOutcome::Observe;
        }
        if decision.smtp_reply().is_none() {
            return DelayOutcome::NotNeeded;
        }
        let milliseconds = self
            .settings
            .tarpit_delay_ms
            .min(decision.candidate_delay_ms)
            .min(
                self.settings
                    .tarpit_session_budget_ms
                    .saturating_sub(budget.charged_ms),
            );
        if milliseconds == 0 {
            return DelayOutcome::BudgetExhausted;
        }
        let Ok(_permit) = self.sleepers.try_acquire() else {
            return DelayOutcome::Busy;
        };
        budget.charged_ms += milliseconds;
        tokio::time::sleep(Duration::from_millis(milliseconds)).await;
        DelayOutcome::Slept { milliseconds }
    }

    fn mode_id(&self) -> i64 {
        match self.settings.mode {
            Mode::Observe => 0,
            Mode::Enforce => 1,
        }
    }

    fn decision(
        &self,
        status: Status,
        would_defer: bool,
        retry_after_seconds: Option<u64>,
    ) -> Decision {
        Decision {
            version: VERSION,
            mode: self.settings.mode,
            status,
            would_defer,
            retry_after_seconds,
            candidate_delay_ms: if matches!(status, Status::FirstSeen | Status::TooSoon) {
                self.settings.tarpit_delay_ms
            } else {
                0
            },
            enforced: self.settings.enabled && self.settings.mode == Mode::Enforce && would_defer,
        }
    }
}

/// Map IPv4-mapped IPv6 to IPv4; otherwise retain the complete IP, never a CIDR
/// prefix. Text spelling, source port and IPv6 flow/scope metadata are not keys.
pub fn normalize_peer_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        _ => ip,
    }
}

fn deadline(now: i64, seconds: u64) -> Result<i64> {
    ensure!(now >= 0, "invalid admission clock");
    now.checked_add(i64::try_from(seconds)?)
        .context("admission clock overflow")
}

fn canonical_address(address: &str, allow_empty: bool) -> Result<String> {
    ensure!(
        address.len() <= 254
            && address.is_ascii()
            && !address.bytes().any(|b| b.is_ascii_control()),
        "invalid admission envelope identity"
    );
    if address.is_empty() && allow_empty {
        return Ok(String::new());
    }
    if !allow_empty && address.eq_ignore_ascii_case("postmaster") {
        return Ok("postmaster".into());
    }
    let (local, domain) = address
        .rsplit_once('@')
        .context("invalid admission envelope identity")?;
    ensure!(
        !local.is_empty() && !domain.is_empty(),
        "invalid admission envelope identity"
    );
    // Local parts can be case-sensitive. Do not merge aliases, plus addressing,
    // or recipients that share a delivery destination.
    Ok(format!("{local}@{}", domain.to_ascii_lowercase()))
}

fn address_hash(salt: &[u8], role: &[u8], address: &str) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"noisefence/smtp-admission/v1\0");
    hash.update(salt);
    hash.update(role);
    hash.update([0]);
    hash.update((address.len() as u64).to_be_bytes());
    hash.update(address.as_bytes());
    hash.finalize().into()
}

fn prune_expired(db: &Connection, now: i64) -> Result<usize> {
    Ok(db.execute("DELETE FROM smtp_admission_entries_v1 WHERE id IN
        (SELECT id FROM smtp_admission_entries_v1 WHERE expires_at<=?1 ORDER BY expires_at,id LIMIT ?2)", params![now, PRUNE_BATCH])?)
}
