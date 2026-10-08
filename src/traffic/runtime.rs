//! One bounded authority for all MX workers; coordination failures never create
//! divergent local buckets. SQLite transactions also deduplicate RPC retries.
use super::*;
use crate::{config::Config, store::Store};
use anyhow::Context;
use rusqlite::{OptionalExtension, params};
use std::{net::IpAddr, sync::OnceLock, time::Duration};

pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS traffic_buckets_v1 (key TEXT PRIMARY KEY, started INTEGER NOT NULL, count INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS traffic_buckets_expiry_v1 ON traffic_buckets_v1(started);
CREATE TABLE IF NOT EXISTS traffic_operations_v1 (id TEXT PRIMARY KEY, created INTEGER NOT NULL, result TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS traffic_operations_expiry_v1 ON traffic_operations_v1(created);
CREATE TABLE IF NOT EXISTS traffic_cache_size_v1 (id INTEGER PRIMARY KEY CHECK(id=1), bytes INTEGER NOT NULL);
INSERT OR IGNORE INTO traffic_cache_size_v1 SELECT 1,COALESCE(SUM(length(result)),0) FROM traffic_operations_v1;
CREATE TRIGGER IF NOT EXISTS traffic_cache_insert_v1 AFTER INSERT ON traffic_operations_v1 BEGIN UPDATE traffic_cache_size_v1 SET bytes=bytes+length(NEW.result) WHERE id=1; END;
CREATE TRIGGER IF NOT EXISTS traffic_cache_delete_v1 AFTER DELETE ON traffic_operations_v1 BEGIN UPDATE traffic_cache_size_v1 SET bytes=bytes-length(OLD.result) WHERE id=1; END;";
static CAPACITY: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(4);
static DB_CAPACITY: OnceLock<std::sync::Arc<tokio::sync::Semaphore>> = OnceLock::new();
fn db_permit() -> Result<tokio::sync::OwnedSemaphorePermit> {
    Ok(DB_CAPACITY
        .get_or_init(|| std::sync::Arc::new(tokio::sync::Semaphore::new(4)))
        .clone()
        .try_acquire_owned()?)
}
static HTTP: OnceLock<reqwest::Client> = OnceLock::new();
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub id: String,
    pub policy_hash: String,
    pub peer: IpAddr,
    pub sender: String,
    pub recipients: Vec<String>,
    pub fingerprint: String,
    pub authenticated: bool,
    pub verification_eligible: bool,
}
pub fn policy_hash(cfg: &Config) -> String {
    crate::message::digest(
        &serde_json::to_vec(&(settings(cfg), &cfg.preferences, cfg.filter.mode))
            .expect("typed traffic settings"),
    )
}
impl Request {
    pub fn validate(&self, cfg: &Config) -> Result<()> {
        ensure!(
            uuid::Uuid::parse_str(&self.id).is_ok(),
            "Invalid traffic transaction"
        );
        ensure!(
            self.policy_hash == policy_hash(cfg),
            "Traffic policy changed"
        );
        ensure!(
            !self.verification_eligible || (self.authenticated && !self.sender.is_empty()),
            "Unauthenticated verification request"
        );
        ensure!(
            self.sender.is_empty() || crate::config::valid_address(&self.sender),
            "Invalid traffic sender"
        );
        ensure!(
            !self.recipients.is_empty()
                && self.recipients.len() <= cfg.smtp.max_recipients
                && self.recipients.len() <= 1000,
            "Invalid traffic recipient count"
        );
        ensure!(
            self.recipients.iter().all(|r| cfg.recipient(r).is_some()),
            "Unknown traffic recipient"
        );
        ensure!(
            self.fingerprint.len() == 64 && self.fingerprint.bytes().all(|b| b.is_ascii_hexdigit()),
            "Invalid traffic fingerprint"
        );
        Ok(())
    }
}
pub type Reports = BTreeMap<String, Report>;

pub async fn rpc<T: Serialize, R: serde::de::DeserializeOwned>(
    cfg: &Config,
    path: &str,
    body: &T,
) -> Result<R> {
    let cluster = cfg.cluster.as_ref().context("Missing cluster")?;
    let credential_path = cluster
        .credential_file
        .clone()
        .context("Missing node identity")?;
    let key =
        tokio::task::spawn_blocking(move || crate::cluster::protocol::credential(&credential_path))
            .await??;
    let client = HTTP.get_or_init(|| {
        reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_millis(500))
            .timeout(Duration::from_secs(2))
            .build()
            .expect("traffic HTTP client")
    });
    let mut response = client
        .post(format!(
            "{}/api/v1/cluster/v1/traffic/{path}",
            cluster
                .coordinator_url
                .as_ref()
                .context("Missing coordinator")?
                .trim_end_matches('/')
        ))
        .header("x-noisefence-node", &cluster.node_id)
        .bearer_auth(key)
        .json(body)
        .send()
        .await?;
    ensure!(
        response.status().is_success(),
        "Traffic authority unavailable"
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            bytes.len() + chunk.len() <= 512 * 1024,
            "Traffic reply too large"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(serde_json::from_slice(&bytes)?)
}
pub async fn local(store: &Store, cfg: &Config, request: Request) -> Result<Reports> {
    request.validate(cfg)?;
    let cfg = cfg.clone();
    let permit = db_permit()?;
    store
        .run(move |db| {
            let _permit = permit;
            check(db, &cfg, &request, crate::now())
        })
        .await
}
pub async fn inspect(store: &Store, cfg: &Config, request: Request) -> Reports {
    let unavailable = || {
        request
            .recipients
            .iter()
            .map(|r| {
                (
                    r.clone(),
                    Report {
                        status: "unavailable".into(),
                        ..Default::default()
                    },
                )
            })
            .collect()
    };
    let Ok(_permit) = CAPACITY.try_acquire() else {
        return unavailable();
    };
    let operation = async {
        if crate::cluster::is_worker(cfg) {
            rpc(cfg, "check", &request).await
        } else {
            local(store, cfg, request.clone()).await
        }
    };
    match tokio::time::timeout(Duration::from_secs(3), operation).await {
        Ok(Ok(result)) => result,
        _ => {
            tracing::warn!("Traffic checks unavailable; content policy retained");
            unavailable()
        }
    }
}
fn bucket(tx: &rusqlite::Transaction<'_>, key: &str, window: u32, now: i64) -> Result<u32> {
    let old: Option<(i64, u32)> = tx
        .query_row(
            "SELECT started,count FROM traffic_buckets_v1 WHERE key=?1",
            [key],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let (start, count) = match old {
        Some((start, count)) if now >= start && now - start < window as i64 => {
            (start, count.saturating_add(1))
        }
        Some((start, _)) if now < start => anyhow::bail!("Traffic clock moved backwards"),
        _ => (now, 1),
    };
    tx.execute("INSERT INTO traffic_buckets_v1 VALUES(?1,?2,?3) ON CONFLICT(key) DO UPDATE SET started=excluded.started,count=excluded.count",params![key,start,count])?;
    Ok(count)
}
pub fn check(
    db: &mut rusqlite::Connection,
    cfg: &Config,
    request: &Request,
    now: i64,
) -> Result<Reports> {
    request.validate(cfg)?;
    ensure!(now >= 0, "Invalid clock");
    let Some(settings) = settings(cfg) else {
        return Ok(BTreeMap::new());
    };
    let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    if let Some(saved) = tx
        .query_row(
            "SELECT result FROM traffic_operations_v1 WHERE id=?1",
            [&request.id],
            |r| r.get::<_, String>(0),
        )
        .optional()?
    {
        return Ok(serde_json::from_str(&saved)?);
    }
    tx.execute("DELETE FROM traffic_operations_v1 WHERE id IN (SELECT id FROM traffic_operations_v1 WHERE created<?1 LIMIT 512)",[now-3600])?;
    tx.execute("DELETE FROM traffic_buckets_v1 WHERE key IN (SELECT key FROM traffic_buckets_v1 WHERE started<?1 LIMIT 512)",[now-3600])?;
    let entries:i64 = tx.query_row("SELECT (SELECT COUNT(*) FROM traffic_buckets_v1)+(SELECT COUNT(*) FROM traffic_operations_v1)",[],|r|r.get(0))?;
    ensure!(
        entries + (request.recipients.len() * 4 + 1) as i64 <= 100_000,
        "Traffic state capacity exhausted"
    );
    // Unauthenticated envelope addresses cannot poison a verified sender's bucket.
    let peer = match request.peer {
        IpAddr::V6(ip) => std::net::Ipv6Addr::from(u128::from(ip) & (u128::MAX << 64)).to_string(),
        ip => ip.to_string(),
    };
    let authority = if request.authenticated {
        "authenticated"
    } else {
        &peer
    };
    let sender = &request.sender;
    let domain = sender
        .rsplit_once('@')
        .map(|(_, d)| d.to_ascii_lowercase())
        .unwrap_or_default();
    let mut reports = BTreeMap::new();
    for recipient in &request.recipients {
        if reports.contains_key(recipient) {
            continue;
        }
        let policy = settings.policy_for(cfg, recipient);
        let trusted = request.authenticated && policy.trusted_senders.iter().any(|s| s == sender);
        let mut report = Report {
            status: "passed".into(),
            window_seconds: policy.window_seconds,
            ..Default::default()
        };
        for (name, identity, limit) in [
            (
                "sender",
                format!("{authority}:{sender}"),
                policy.sender_limit,
            ),
            (
                "domain",
                format!("{authority}:{domain}"),
                policy.domain_limit,
            ),
            ("recipient", String::new(), policy.recipient_limit),
            (
                "duplicate",
                request.fingerprint.clone(),
                policy.duplicate_limit,
            ),
        ] {
            if limit == 0 || (trusted && name != "recipient") {
                continue;
            }
            let key = crate::message::digest(&serde_json::to_vec(&(
                &request.policy_hash,
                recipient,
                name,
                identity,
            ))?);
            let count = bucket(&tx, &key, policy.window_seconds, now)?;
            report.counts.insert(name.into(), count);
            if count > limit {
                report.reasons.push(format!("{name}_limit"));
            }
        }
        if !report.reasons.is_empty() {
            report.status = "limited".into();
            report.action = policy.action;
            report.enforced =
                cfg.filter.mode != crate::config::Mode::Observe && policy.action != Action::Observe;
        }
        if !report.enforced
            && !trusted
            && policy.verify_new_senders
            && settings.verification.enabled
            && request.verification_eligible
            && cfg
                .provider_credentials
                .as_ref()
                .is_some_and(|s| s.get("turnstile").is_some())
            && cfg.filter.mode != crate::config::Mode::Observe
            && let Some(id) =
                verification::ticket(&tx, &settings.verification, sender, recipient, now)?
        {
            report.status = "verification_pending".into();
            report.verification_id = Some(id);
            report.enforced = true;
        }
        reports.insert(recipient.clone(), report);
    }
    let encoded = serde_json::to_string(&reports)?;
    let cache_bytes: i64 = tx.query_row(
        "SELECT bytes FROM traffic_cache_size_v1 WHERE id=1",
        [],
        |r| r.get(0),
    )?;
    ensure!(
        encoded.len() <= 128 * 1024 && cache_bytes + encoded.len() as i64 <= 16 * 1024 * 1024,
        "Traffic result cache capacity exhausted"
    );
    tx.execute(
        "INSERT INTO traffic_operations_v1 VALUES(?1,?2,?3)",
        params![request.id, now, encoded],
    )?;
    tx.commit()?;
    Ok(reports)
}

pub async fn prepare(
    store: &Store,
    cfg: &Config,
    raw: &[u8],
    scan: &mut crate::engine::Scan,
    context: (IpAddr, &str, &str, &[crate::config::Recipient]),
) {
    let (peer, sender, id, recipients) = context;
    if settings(cfg).is_none() || recipients.is_empty() {
        return;
    }
    let authenticated = scan.evidence.as_ref().is_some_and(|e| {
        e.source == crate::evidence::Source::SmtpSession
            && crate::evidence::eligibility::dmarc_pass(e)
            && crate::evidence::eligibility::authentication(
                e,
                crate::evidence::eligibility::AuthCheck::Spf,
            )
            .is_ok()
            && e.authentication.spf == Some(crate::evidence::AuthResult::Pass)
    });
    // Body fingerprints ignore transport headers added on each retry/hop.
    let body = crate::message::fields(raw)
        .map(|(_, body)| body)
        .unwrap_or(raw);
    let request = Request {
        id: id.into(),
        policy_hash: policy_hash(cfg),
        peer,
        sender: sender.into(),
        recipients: recipients.iter().map(|r| r.address.clone()).collect(),
        fingerprint: crate::message::digest(body),
        authenticated,
        verification_eligible: verification::eligible(raw, sender, scan, cfg),
    };
    let eligible = request.verification_eligible;
    scan.traffic_candidates = inspect(store, cfg, request).await;
    if !eligible {
        for report in scan.traffic_candidates.values_mut() {
            if report.verification_id.take().is_some() {
                report.status = "verification_ineligible".into();
                report.enforced = false;
            }
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Early {
    pub peer: IpAddr,
    pub sender: String,
    pub recipient: String,
    pub policy_hash: String,
}
pub async fn early_local(store: &Store, cfg: &Config, body: Early) -> Result<bool> {
    ensure!(
        body.policy_hash == policy_hash(cfg)
            && cfg.recipient(&body.recipient).is_some()
            && (body.sender.is_empty() || crate::config::valid_address(&body.sender)),
        "Invalid early traffic request"
    );
    let Some(s) = settings(cfg) else {
        return Ok(false);
    };
    let policy = s.policy_for(cfg, &body.recipient);
    if cfg.filter.mode == crate::config::Mode::Observe || policy.action != Action::Defer {
        return Ok(false);
    }
    store.run(move|db| {
        let peer=match body.peer {IpAddr::V6(ip)=>std::net::Ipv6Addr::from(u128::from(ip)&(u128::MAX<<64)).to_string(),ip=>ip.to_string()};
        let domain=body.sender.rsplit_once('@').map(|(_,d)|d.to_ascii_lowercase()).unwrap_or_default();
        for (name,identity,limit) in [("recipient",String::new(),policy.recipient_limit),("sender",format!("{peer}:{}",body.sender),policy.sender_limit),("domain",format!("{peer}:{domain}"),policy.domain_limit)] {
            if limit==0 {continue;}
            let key=crate::message::digest(&serde_json::to_vec(&(&body.policy_hash,&body.recipient,name,identity))?);
            let exceeds:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM traffic_buckets_v1 WHERE key=?1 AND started<=?2 AND started>?3 AND count>=?4)",params![key,crate::now(),crate::now()-i64::from(policy.window_seconds),limit],|r|r.get(0))?;
            if exceeds {return Ok(true);}
        }
        Ok(false)
    }).await
}
pub async fn early(store: &Store, cfg: &Config, body: Early) -> bool {
    if settings(cfg).is_none() || cfg.filter.mode == crate::config::Mode::Observe {
        return false;
    }
    let Ok(_permit) = CAPACITY.try_acquire() else {
        return false;
    };
    let work = async {
        if crate::cluster::is_worker(cfg) {
            rpc(cfg, "early", &body).await
        } else {
            early_local(store, cfg, body).await
        }
    };
    matches!(
        tokio::time::timeout(Duration::from_secs(2), work).await,
        Ok(Ok(true))
    )
}
