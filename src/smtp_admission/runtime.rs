//! Bounded pre-DATA admission, with one retry authority for all MX nodes.
use super::*;
use crate::{config::Config, store::Store};
use std::sync::OnceLock;

pub const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS smtp_admission_rates_v2 (
 mode INTEGER NOT NULL, peer TEXT NOT NULL, tokens REAL NOT NULL, updated INTEGER NOT NULL,
 PRIMARY KEY(mode,peer));
 CREATE INDEX IF NOT EXISTS smtp_admission_rates_expiry_v2 ON smtp_admission_rates_v2(updated);
 CREATE TABLE IF NOT EXISTS smtp_admission_counts_v2 (
 day INTEGER NOT NULL, mode TEXT NOT NULL, status TEXT NOT NULL, count INTEGER NOT NULL,
 PRIMARY KEY(day,mode,status));";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub peer: IpAddr,
    pub sender: String,
    pub recipient: String,
    pub listed_providers: usize,
    pub invalid_helo: bool,
    pub charge_rate: bool,
}
impl Request {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.listed_providers <= 8, "Invalid reputation count");
        ensure!(
            self.sender.is_empty() || crate::config::valid_address(&self.sender),
            "Invalid sender"
        );
        ensure!(
            crate::config::valid_address(&self.recipient),
            "Invalid recipient"
        );
        Ok(())
    }
}

pub struct Runtime {
    checks: Arc<tokio::sync::Semaphore>,
    admission: Admission,
    http: OnceLock<reqwest::Client>,
}
impl Runtime {
    pub fn new() -> Result<Self> {
        Ok(Self {
            checks: Arc::new(tokio::sync::Semaphore::new(4)),
            admission: Admission::new(Settings::default())?,
            http: OnceLock::new(),
        })
    }
    pub fn activate(&self, settings: Option<&Settings>) {
        if let Ok(admission) = self
            .admission
            .reconfigured(settings.cloned().unwrap_or_default())
        {
            admission.activate();
        }
    }
    /// Used by both local SMTP and authenticated coordinator RPC. The permit
    /// follows the blocking job even when the outer 500ms timeout expires.
    pub async fn local(&self, store: &Store, settings: Settings, request: Request) -> Decision {
        let Ok(admission) = self.admission.reconfigured(settings) else {
            return self.admission.unavailable();
        };
        let unavailable = admission.unavailable();
        let Ok(permit) = self.checks.clone().try_acquire_owned() else {
            return unavailable;
        };
        let task = store.run(move |db| {
            let _permit = permit;
            check(db, &admission, &request, crate::now())
        });
        match tokio::time::timeout(Duration::from_millis(500), task).await {
            Ok(Ok(result)) => result,
            _ => unavailable,
        }
    }
    pub async fn check(&self, store: &Store, cfg: &Config, request: Request) -> Decision {
        let settings = cfg.smtp_admission.clone().unwrap_or_default();
        let admission = self
            .admission
            .reconfigured(settings.clone())
            .expect("validated admission settings");
        if !settings.enabled {
            return admission.decision(Status::Disabled, false, None);
        }
        if !crate::cluster::is_worker(cfg) {
            return self.local(store, settings, request).await;
        }
        // A failed coordinator never starts a separate greylisting cycle on this
        // worker. Continue delivery and keep existing connection/size limits.
        let Ok(_permit) = self.checks.clone().try_acquire_owned() else {
            return admission.unavailable();
        };
        let cluster = cfg.cluster.as_ref().unwrap();
        let operation = async {
            if self.http.get().is_none() {
                let http = reqwest::Client::builder()
                    .no_proxy()
                    .redirect(reqwest::redirect::Policy::none())
                    .connect_timeout(Duration::from_millis(300))
                    .timeout(Duration::from_millis(700))
                    .build()?;
                let _ = self.http.set(http);
            }
            let path = cluster
                .credential_file
                .clone()
                .context("Missing node identity")?;
            let key =
                tokio::task::spawn_blocking(move || crate::cluster::protocol::credential(&path))
                    .await??;
            let mut response = self
                .http
                .get()
                .unwrap()
                .post(format!(
                    "{}/api/v1/cluster/v1/admission",
                    cluster
                        .coordinator_url
                        .as_ref()
                        .unwrap()
                        .trim_end_matches('/')
                ))
                .header("x-noisefence-node", &cluster.node_id)
                .bearer_auth(key)
                .json(&request)
                .send()
                .await?;
            ensure!(
                response.status().is_success(),
                "Admission coordinator unavailable"
            );
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await? {
                ensure!(
                    bytes.len() + chunk.len() <= 4096,
                    "Oversized admission reply"
                );
                bytes.extend_from_slice(&chunk);
            }
            let mut result: Decision = serde_json::from_slice(&bytes)?;
            ensure!(
                result.version == VERSION && result.reasons.len() <= 8,
                "Incompatible admission reply"
            );
            // An old/in-flight local observation policy cannot be upgraded remotely.
            if settings.mode == Mode::Observe {
                result.mode = Mode::Observe;
                result.enforced = false;
            }
            Ok::<_, anyhow::Error>(result)
        };
        match tokio::time::timeout(Duration::from_millis(750), operation).await {
            Ok(Ok(result)) => result,
            _ => admission.unavailable(),
        }
    }
    pub async fn delay(
        &self,
        settings: &Settings,
        decision: &Decision,
        budget: &mut DelayBudget,
    ) -> DelayOutcome {
        match self.admission.reconfigured(settings.clone()) {
            Ok(admission) => admission.delay(decision, budget).await,
            Err(_) => DelayOutcome::NotNeeded,
        }
    }
}

/// Parse exact CIDRs, never DNS names or a sender-provided header.
pub fn network(value: &str) -> Result<(IpAddr, u8)> {
    ensure!(value.len() <= 64, "Invalid admission network");
    let (ip, prefix) = value
        .split_once('/')
        .context("Use an explicit IP/CIDR exception")?;
    let ip: IpAddr = ip.parse()?;
    let prefix: u8 = prefix.parse()?;
    ensure!(
        prefix <= if ip.is_ipv4() { 32 } else { 128 },
        "Invalid network prefix"
    );
    // A catch-all disables reputation for the whole Internet; use the master switch.
    ensure!(
        prefix >= if ip.is_ipv4() { 8 } else { 16 },
        "Admission exception is too broad"
    );
    Ok((ip, prefix))
}
fn matches_network(ip: IpAddr, value: &str) -> bool {
    let Ok((net, prefix)) = network(value) else {
        return false;
    };
    match (ip, net) {
        (IpAddr::V4(ip), IpAddr::V4(net)) => {
            (u32::from(ip) >> (32 - prefix)) == (u32::from(net) >> (32 - prefix))
        }
        (IpAddr::V6(ip), IpAddr::V6(net)) => {
            (u128::from(ip) >> (128 - prefix)) == (u128::from(net) >> (128 - prefix))
        }
        _ => false,
    }
}
/// Retry grouping is only a greylisting exemption, never sender authentication.
fn retry_peer(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(ip) => std::net::Ipv4Addr::from(u32::from(ip) & 0xffffff00).into(),
        IpAddr::V6(ip) => std::net::Ipv6Addr::from(u128::from(ip) & (u128::MAX << 64)).into(),
    }
}
pub fn check(
    db: &mut Connection,
    admission: &Admission,
    request: &Request,
    now: i64,
) -> Result<Decision> {
    request.validate()?;
    let settings = &admission.settings;
    if !settings.enabled {
        return Ok(admission.decision(Status::Disabled, false, None));
    }
    let ip = normalize_peer_ip(request.peer);
    let mut reasons = Vec::new();
    let result = if ip.is_loopback()
        || settings
            .allow_networks
            .iter()
            .any(|n| matches_network(ip, n))
    {
        admission.decision(Status::Exempt, false, None)
    } else if request.charge_rate
        && settings.rate_per_minute > 0
        && limited(db, admission, ip, now)?
    {
        reasons.push("sender_rate_exceeded".into());
        admission.decision(
            Status::RateLimited,
            true,
            Some(60u64.div_ceil(settings.rate_per_minute as u64)),
        )
    } else if request.sender.is_empty()
        || request
            .recipient
            .split('@')
            .next()
            .is_some_and(|s| s.eq_ignore_ascii_case("postmaster"))
    {
        reasons.push("delivery_notification_or_postmaster".into());
        admission.decision(Status::Exempt, false, None)
    } else {
        if request.listed_providers > 0 {
            reasons.push("ip_reputation".into());
        }
        if request.invalid_helo {
            reasons.push("invalid_helo".into());
        }
        let signals = request.listed_providers + usize::from(request.invalid_helo);
        if !settings.greylisting
            || request.listed_providers == 0
            || signals < settings.minimum_providers
        {
            admission.decision(Status::NotSelected, false, None)
        } else {
            admission.check(
                db,
                SocketAddr::new(retry_peer(ip), 0),
                &request.sender,
                &request.recipient,
                now,
            )?
        }
    };
    let mut result = result;
    result.reasons = reasons;
    let status = serde_json::to_value(result.status)?
        .as_str()
        .unwrap()
        .to_owned();
    let mode = if settings.mode == Mode::Observe {
        "observe"
    } else {
        "enforce"
    };
    db.execute("INSERT INTO smtp_admission_counts_v2(day,mode,status,count) VALUES(?1,?2,?3,1) ON CONFLICT(day,mode,status) DO UPDATE SET count=count+1",params![now/86400,mode,status])?;
    Ok(result)
}
fn limited(db: &mut Connection, admission: &Admission, ip: IpAddr, now: i64) -> Result<bool> {
    ensure!(now >= 0, "Invalid admission clock");
    let settings = &admission.settings;
    let mode = admission.mode_id();
    // IPv6 rotation within /64 cannot create unlimited token buckets.
    let peer = if ip.is_ipv6() { retry_peer(ip) } else { ip }.to_string();
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    tx.execute("DELETE FROM smtp_admission_rates_v2 WHERE rowid IN (SELECT rowid FROM smtp_admission_rates_v2 WHERE updated<?1 ORDER BY updated LIMIT 256)",[now-86400])?;
    let previous = tx
        .query_row(
            "SELECT tokens,updated FROM smtp_admission_rates_v2 WHERE mode=?1 AND peer=?2",
            params![mode, peer],
            |r| Ok((r.get::<_, f64>(0)?, r.get::<_, i64>(1)?)),
        )
        .optional()?;
    if previous.is_none()
        && tx.query_row(
            "SELECT COUNT(*) FROM smtp_admission_rates_v2 WHERE mode=?1",
            [mode],
            |r| r.get::<_, usize>(0),
        )? >= settings.max_entries
    {
        return Ok(false);
    }
    let (tokens, updated) = previous.unwrap_or((settings.rate_burst as f64, now));
    // A backwards clock fails open and does not rewrite the bucket's timestamp.
    if now < updated {
        return Ok(false);
    }
    let tokens = (tokens + (now - updated) as f64 * settings.rate_per_minute as f64 / 60.0)
        .min(settings.rate_burst as f64);
    let limited = tokens < 1.0;
    tx.execute("INSERT INTO smtp_admission_rates_v2 VALUES(?1,?2,?3,?4) ON CONFLICT(mode,peer) DO UPDATE SET tokens=excluded.tokens,updated=excluded.updated",params![mode,peer,if limited {tokens} else {tokens-1.0},now])?;
    tx.commit()?;
    Ok(limited)
}
pub fn prune(db: &mut Connection, now: i64) -> Result<()> {
    Admission::new(Settings::default())?.prune(db, now)?;
    db.execute("DELETE FROM smtp_admission_rates_v2 WHERE rowid IN (SELECT rowid FROM smtp_admission_rates_v2 WHERE updated<?1 ORDER BY updated LIMIT 256)",[now-86400])?;
    db.execute(
        "DELETE FROM smtp_admission_counts_v2 WHERE day<?1",
        [now / 86400 - 29],
    )?;
    Ok(())
}
