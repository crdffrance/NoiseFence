//! IP DNSBL checks before DATA. No message headers, content or recipient data enter DNS.
use anyhow::{Result, ensure};
use mail_auth::{
    MessageAuthenticator,
    hickory_resolver::{
        net::{DnsError, NetError},
        proto::{
            op::ResponseCode,
            rr::{RData, RecordType},
        },
    },
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeSet, HashMap},
    future::Future,
    net::{IpAddr, Ipv4Addr},
    sync::Mutex,
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;

pub const VERSION: &str = "early-rbl-1";

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    #[default]
    Observe,
    Defer,
    Reject,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub action: Action,
    pub minimum_providers: usize,
    pub timeout_ms: u64,
    pub max_parallel: usize,
    pub cache_entries: usize,
    pub cache_ttl_seconds: u64,
    pub lists: Vec<List>,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            action: Action::Observe,
            minimum_providers: 2,
            timeout_ms: 800,
            max_parallel: 8,
            cache_entries: 4096,
            cache_ttl_seconds: 60,
            lists: Vec::new(),
        }
    }
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct List {
    pub id: String,
    /// Lists from the same operator count as one vote, even across several zones.
    pub provider: String,
    pub zone: String,
    pub key_env: Option<String>,
    pub listed_codes: Vec<Ipv4Addr>,
    #[serde(default)]
    pub observe_codes: Vec<Ipv4Addr>,
    #[serde(default)]
    pub ipv6: bool,
}
fn label(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 32
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}
impl Settings {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (1..=8).contains(&self.minimum_providers),
            "RBL minimum_providers must be 1..8"
        );
        ensure!(
            (10..=2000).contains(&self.timeout_ms),
            "RBL timeout must be 10..2000 ms"
        );
        ensure!(
            (1..=64).contains(&self.max_parallel),
            "RBL concurrency must be 1..64"
        );
        ensure!(
            (1..=16384).contains(&self.cache_entries),
            "RBL cache must be 1..16384 entries"
        );
        ensure!(
            (1..=3600).contains(&self.cache_ttl_seconds),
            "RBL TTL must be 1..3600 seconds"
        );
        ensure!(
            self.lists.len() <= 7,
            "at most seven custom RBLs plus Spamhaus ZEN"
        );
        let mut ids = BTreeSet::new();
        let mut zones = BTreeSet::new();
        for list in &self.lists {
            ensure!(
                label(&list.id) && label(&list.provider) && list.id != "spamhaus_zen",
                "invalid or reserved RBL identifier"
            );
            ensure!(
                ids.insert(&list.id) && zones.insert(list.zone.to_ascii_lowercase()),
                "duplicate RBL identifier or zone"
            );
            ensure!(
                crate::config::valid_domain(&list.zone) && list.zone.len() <= 120,
                "invalid RBL zone"
            );
            ensure!(
                !list.zone.to_ascii_lowercase().ends_with("spamhaus.net")
                    && !list.zone.to_ascii_lowercase().ends_with("spamhaus.org"),
                "use the built-in Spamhaus DQS connector"
            );
            if let Some(env) = &list.key_env {
                ensure!(
                    !env.is_empty()
                        && env.len() <= 128
                        && env.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'),
                    "invalid RBL key environment name"
                );
            }
            ensure!(
                !list.listed_codes.is_empty()
                    && list.listed_codes.len() + list.observe_codes.len() <= 32,
                "RBL needs explicit return codes (at most 32)"
            );
            let mut codes = BTreeSet::new();
            for code in list.listed_codes.iter().chain(&list.observe_codes) {
                let [a, b, c, _] = code.octets();
                ensure!(
                    a == 127 && !(b == 255 && c == 255) && codes.insert(*code),
                    "invalid, reserved or duplicate RBL return code"
                );
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    NotListed,
    Listed,
    Policy,
    Unavailable,
    Skipped,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Incident {
    Dns,
    Timeout,
    Busy,
    InvalidAnswer,
    UnsupportedIp,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Check {
    pub id: String,
    pub provider: String,
    pub status: Status,
    pub codes: Vec<Ipv4Addr>,
    pub incident: Option<Incident>,
    pub cached: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Report {
    pub version: String,
    pub elapsed_ms: u64,
    pub checks: Vec<Check>,
    pub listed_providers: usize,
    pub minimum_providers: usize,
    pub would_block: bool,
    pub requested_action: Action,
    pub effective_action: Action,
}
impl Report {
    pub fn smtp_reply(&self) -> Option<&'static str> {
        match self.effective_action {
            Action::Observe => None,
            Action::Defer => Some("451 4.7.1 Sender reputation policy; retry later\r\n"),
            Action::Reject => Some("550 5.7.1 Sender reputation policy\r\n"),
        }
    }
    pub fn attach(&self, scan: &mut crate::engine::Scan) {
        // Added after all classification stages: these checks are admission diagnostics.
        if !self.checks.is_empty() {
            scan.early_rbl = Some(self.clone());
        }
    }
}

#[derive(Clone)]
struct Answer {
    codes: std::result::Result<Vec<Ipv4Addr>, Incident>,
    ttl: Duration,
}
trait Resolver: Send + Sync {
    fn lookup(&self, name: &str) -> impl Future<Output = Answer> + Send;
}
pub struct SystemDns(MessageAuthenticator);
impl Resolver for SystemDns {
    async fn lookup(&self, name: &str) -> Answer {
        match self.0.0.lookup(name, RecordType::A).await {
            Ok(lookup) => {
                let codes: Vec<_> = lookup
                    .answers()
                    .iter()
                    .filter_map(|r| match &r.data {
                        RData::A(ip) => Some(ip.0),
                        _ => None,
                    })
                    .take(33)
                    .collect();
                Answer {
                    codes: if codes.is_empty() || codes.len() > 32 {
                        Err(Incident::InvalidAnswer)
                    } else {
                        Ok(codes)
                    },
                    ttl: lookup
                        .valid_until()
                        .saturating_duration_since(Instant::now()),
                }
            }
            Err(NetError::Dns(DnsError::NoRecordsFound(missing)))
                if missing.response_code == ResponseCode::NXDomain =>
            {
                Answer {
                    codes: Ok(Vec::new()),
                    ttl: Duration::from_secs(missing.negative_ttl.unwrap_or(0) as u64),
                }
            }
            // NODATA is not evidence of absence in a DNSBL. SERVFAIL/REFUSED stay unavailable.
            Err(_) => Answer {
                codes: Err(Incident::Dns),
                ttl: Duration::ZERO,
            },
        }
    }
}

struct Zone {
    list: List,
    suffix: String,
    dqs: bool,
}
pub struct Runtime<R = SystemDns> {
    settings: Settings,
    zones: Vec<Zone>,
    resolver: R,
    slots: Semaphore,
    cache: Mutex<HashMap<String, (Instant, Answer)>>,
}
impl Runtime {
    pub fn new(settings: Option<&Settings>, dqs_env: Option<&str>) -> Result<Self> {
        let settings = settings.cloned().unwrap_or_default();
        settings.validate()?;
        let mut zones = Vec::new();
        for list in &settings.lists {
            let suffix = match &list.key_env {
                Some(env) => format!("{}.{}", key(env)?, list.zone),
                None => list.zone.clone(),
            };
            zones.push(Zone {
                list: list.clone(),
                suffix,
                dqs: false,
            });
        }
        if let Some(env) = dqs_env {
            zones.push(Zone {
                list: List {
                    id: "spamhaus_zen".into(),
                    provider: "spamhaus".into(),
                    zone: "zen.dq.spamhaus.net".into(),
                    key_env: None,
                    listed_codes: Vec::new(),
                    observe_codes: Vec::new(),
                    ipv6: true,
                },
                suffix: format!("{}.zen.dq.spamhaus.net", key(env)?),
                dqs: true,
            });
        }
        Ok(Self {
            slots: Semaphore::new(settings.max_parallel),
            settings,
            zones,
            resolver: SystemDns(MessageAuthenticator::new_system_conf()?),
            cache: Mutex::new(HashMap::new()),
        })
    }
}
fn key(env: &str) -> Result<String> {
    let value = std::env::var(env)
        .map_err(|_| anyhow::anyhow!("RBL credential environment variable is missing"))?;
    ensure!(
        !value.is_empty() && value.len() <= 63 && value.bytes().all(|b| b.is_ascii_alphanumeric()),
        "invalid RBL credential"
    );
    Ok(value)
}
fn reverse(ip: IpAddr) -> String {
    match ip.to_canonical() {
        IpAddr::V4(ip) => ip
            .octets()
            .iter()
            .rev()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join("."),
        IpAddr::V6(ip) => hex::encode(ip.octets())
            .chars()
            .rev()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join("."),
    }
}
fn interpret(
    zone: &Zone,
    answer: &Answer,
) -> std::result::Result<(Status, Vec<Ipv4Addr>), Incident> {
    let mut codes = answer.codes.clone()?;
    if codes.is_empty() {
        return Ok((Status::NotListed, codes));
    }
    if codes.len() > 32 {
        return Err(Incident::InvalidAnswer);
    }
    let listed = if zone.dqs {
        crate::evidence::dqs_codes(&codes, crate::evidence::Dataset::Zen)
            .map_err(|_| Incident::InvalidAnswer)?;
        crate::evidence::malicious_ip(&codes)
    } else {
        if codes
            .iter()
            .any(|c| !zone.list.listed_codes.contains(c) && !zone.list.observe_codes.contains(c))
        {
            return Err(Incident::InvalidAnswer);
        }
        codes.iter().any(|c| zone.list.listed_codes.contains(c))
    };
    codes.sort();
    codes.dedup();
    Ok((
        if listed {
            Status::Listed
        } else {
            Status::Policy
        },
        codes,
    ))
}
#[allow(private_bounds)]
impl<R: Resolver> Runtime<R> {
    async fn query(&self, zone: &Zone, ip: IpAddr) -> Check {
        let mut check = Check {
            id: zone.list.id.clone(),
            provider: zone.list.provider.clone(),
            status: Status::Unavailable,
            codes: Vec::new(),
            incident: None,
            cached: false,
        };
        if !crate::protection::redirects::public_ip(ip) || (ip.is_ipv6() && !zone.list.ipv6) {
            check.status = Status::Skipped;
            check.incident = Some(Incident::UnsupportedIp);
            return check;
        }
        // Never log this name: it can contain a private query key.
        let name = format!("{}.{}.", reverse(ip), zone.suffix);
        let cached = self
            .cache
            .lock()
            .unwrap()
            .get(&name)
            .filter(|(end, _)| *end > Instant::now())
            .map(|(_, a)| a.clone());
        let answer = if let Some(answer) = cached {
            check.cached = true;
            answer
        } else {
            let Ok(_permit) = self.slots.try_acquire() else {
                check.incident = Some(Incident::Busy);
                return check;
            };
            let answer = self.resolver.lookup(&name).await;
            // Error answers are held for one second to avoid retry storms, as unavailable.
            let ttl = if interpret(zone, &answer).is_err() {
                Duration::from_secs(1)
            } else {
                answer
                    .ttl
                    .min(Duration::from_secs(self.settings.cache_ttl_seconds))
            };
            if !ttl.is_zero() {
                let mut cache = self.cache.lock().unwrap();
                if cache.len() >= self.settings.cache_entries {
                    cache.retain(|_, (end, _)| *end > Instant::now());
                    if cache.len() >= self.settings.cache_entries {
                        cache.clear();
                    }
                }
                cache.insert(name, (Instant::now() + ttl, answer.clone()));
            }
            answer
        };
        match interpret(zone, &answer) {
            Ok((status, codes)) => {
                check.status = status;
                check.codes = codes;
            }
            Err(incident) => check.incident = Some(incident),
        }
        check
    }
    pub async fn check(&self, ip: IpAddr, mode: crate::config::Mode, dqs_enabled: bool) -> Report {
        let start = Instant::now();
        let deadline =
            tokio::time::Instant::now() + Duration::from_millis(self.settings.timeout_ms);
        // A JoinSet would detach resolver work on cancellation. Poll these bounded futures inline.
        let mut work: Vec<_> = self
            .zones
            .iter()
            .filter(|z| !z.dqs || dqs_enabled)
            .map(|zone| {
                Box::pin(async move {
                    match tokio::time::timeout_at(deadline, self.query(zone, ip.to_canonical()))
                        .await
                    {
                        Ok(check) => check,
                        Err(_) => Check {
                            id: zone.list.id.clone(),
                            provider: zone.list.provider.clone(),
                            status: Status::Unavailable,
                            codes: Vec::new(),
                            incident: Some(Incident::Timeout),
                            cached: false,
                        },
                    }
                })
            })
            .collect();
        let mut completed: Vec<Option<Check>> = (0..work.len()).map(|_| None).collect();
        std::future::poll_fn(|cx| {
            for (i, future) in work.iter_mut().enumerate() {
                if completed[i].is_none()
                    && let std::task::Poll::Ready(check) = future.as_mut().poll(cx)
                {
                    completed[i] = Some(check);
                }
            }
            if completed.iter().all(Option::is_some) {
                std::task::Poll::Ready(())
            } else {
                std::task::Poll::Pending
            }
        })
        .await;
        let checks: Vec<_> = completed.into_iter().flatten().collect();
        let listed_providers = checks
            .iter()
            .filter(|c| c.status == Status::Listed)
            .map(|c| &c.provider)
            .collect::<BTreeSet<_>>()
            .len();
        // A partially unavailable set never enforces even when enough positive votes arrived.
        let would_block = listed_providers >= self.settings.minimum_providers
            && !checks.iter().any(|c| c.status == Status::Unavailable);
        let effective_action = if would_block && mode == crate::config::Mode::Enforce {
            self.settings.action
        } else {
            Action::Observe
        };
        Report {
            version: VERSION.into(),
            elapsed_ms: start.elapsed().as_millis() as u64,
            checks,
            listed_providers,
            minimum_providers: self.settings.minimum_providers,
            would_block,
            requested_action: self.settings.action,
            effective_action,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
