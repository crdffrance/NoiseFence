//! Weighted SMTP identity checks inspired by policyd-weight, implemented independently.
//! Inputs come from the socket and SMTP envelope, never from message trace headers.
#[cfg(test)]
mod tests;
use crate::capacity::Capacity;
use anyhow::{Result, ensure};
use mail_auth::{
    MessageAuthenticator,
    hickory_resolver::{
        net::{DnsError, NetError},
        proto::{
            op::ResponseCode,
            rr::{Name, RData, RecordType},
        },
    },
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    future::Future,
    net::IpAddr,
    sync::Mutex,
    time::{Duration, Instant},
};

pub const VERSION: &str = "smtp-policy-2";
const MAX_RECORDS: usize = 32;
const MAX_PTR: usize = 4;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct PolicyConfig {
    /// Collect evidence first; applying these experimental weights is explicit.
    pub contribute_to_score: bool,
    pub timeout_ms: u64,
    pub max_parallel: usize,
    pub cache_entries: usize,
    pub cache_ttl_seconds: u64,
}
impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            contribute_to_score: false,
            timeout_ms: 800,
            max_parallel: 8,
            cache_entries: 4096,
            cache_ttl_seconds: 300,
        }
    }
}
impl PolicyConfig {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (10..=2000).contains(&self.timeout_ms),
            "SMTP policy timeout must be 10..2000 ms"
        );
        ensure!(
            (1..=64).contains(&self.max_parallel),
            "SMTP policy concurrency must be 1..64"
        );
        ensure!(
            (1..=16384).contains(&self.cache_entries),
            "SMTP policy cache must be 1..16384 entries"
        );
        ensure!(
            (1..=3600).contains(&self.cache_ttl_seconds),
            "SMTP policy cache TTL must be 1..3600 seconds"
        );
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyStatus {
    #[default]
    Disabled,
    Complete,
    Unavailable,
    Busy,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CheckKind {
    Helo,
    Ptr,
    Sender,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PolicyResult {
    pub status: PolicyStatus,
    pub version: String,
    pub elapsed_ms: u64,
    /// Capped candidate logit contribution; not a probability.
    pub candidate_weight: f64,
    pub applied_weight: f64,
    pub scoring_enabled: bool,
    pub checks: Vec<crate::engine::Signal>,
    /// Explicit deadlines; historical narrative is never parsed to infer them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub timeouts: Vec<CheckKind>,
}
impl PolicyResult {
    pub fn apply(&self, scan: &mut crate::engine::Scan) {
        // Individual evidence stays visible without counting it a second time.
        scan.reasons
            .extend(self.checks.iter().cloned().map(|mut s| {
                s.weight = 0.0;
                s
            }));
        if self.status == PolicyStatus::Complete {
            scan.reasons.push(crate::engine::Signal {
                id: "smtp_policy_contribution".into(),
                detail: format!("SMTP/DNS consistency: capped contribution ({VERSION})"),
                weight: self.applied_weight,
            });
        } else if self.status != PolicyStatus::Disabled {
            scan.complete = false;
            scan.reasons.push(crate::engine::Signal {
                id: "smtp_policy_unavailable".into(),
                detail: "SMTP/DNS checks incomplete; no contribution, deliver without prefix"
                    .into(),
                weight: 0.0,
            });
        }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
enum Query {
    A(String),
    Aaaa(String),
    Ptr(IpAddr),
    Mx(String),
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum Record {
    Ip(IpAddr),
    Host(String),
    Mx(u16, String),
}
#[derive(Clone, Debug)]
struct Answer {
    records: std::result::Result<Vec<Record>, ()>,
    ttl: Duration,
}
impl Answer {
    fn unavailable() -> Self {
        Self {
            records: Err(()),
            ttl: Duration::from_secs(1),
        }
    }
}
trait Resolver: Send + Sync {
    fn lookup(&self, query: &Query) -> impl Future<Output = Answer> + Send;
}
pub struct SystemDns(MessageAuthenticator);
impl Resolver for SystemDns {
    async fn lookup(&self, query: &Query) -> Answer {
        let (name, kind) = match query {
            Query::A(n) => (format!("{n}."), RecordType::A),
            Query::Aaaa(n) => (format!("{n}."), RecordType::AAAA),
            Query::Mx(n) => (format!("{n}."), RecordType::MX),
            Query::Ptr(ip) => (Name::from(*ip).to_ascii(), RecordType::PTR),
        };
        match self.0.0.lookup(name, kind).await {
            Ok(lookup) => {
                let records: Vec<_> = lookup
                    .answers()
                    .iter()
                    .filter_map(|r| match &r.data {
                        RData::A(ip) if kind == RecordType::A => Some(Record::Ip(IpAddr::V4(ip.0))),
                        RData::AAAA(ip) if kind == RecordType::AAAA => {
                            Some(Record::Ip(IpAddr::V6(ip.0)))
                        }
                        RData::PTR(host) if kind == RecordType::PTR => {
                            Some(Record::Host(host.to_lowercase().to_ascii()))
                        }
                        RData::MX(mx) if kind == RecordType::MX => Some(Record::Mx(
                            mx.preference,
                            mx.exchange.to_lowercase().to_ascii(),
                        )),
                        _ => None,
                    })
                    .take(MAX_RECORDS + 1)
                    .collect();
                if records.len() > MAX_RECORDS {
                    return Answer::unavailable();
                }
                Answer {
                    records: Ok(records),
                    ttl: lookup
                        .valid_until()
                        .saturating_duration_since(Instant::now()),
                }
            }
            Err(NetError::Dns(DnsError::NoRecordsFound(missing)))
                if matches!(
                    missing.response_code,
                    ResponseCode::NoError | ResponseCode::NXDomain
                ) =>
            {
                Answer {
                    records: Ok(Vec::new()),
                    ttl: Duration::from_secs(missing.negative_ttl.unwrap_or(0) as u64),
                }
            }
            Err(_) => Answer::unavailable(),
        }
    }
}

pub struct Policy<R = SystemDns> {
    config: PolicyConfig,
    resolver: R,
    slots: std::sync::Arc<Capacity>,
    cache: Mutex<HashMap<Query, (Instant, Answer)>>,
}
impl Policy<SystemDns> {
    pub(crate) fn reconfigure(&self, config: PolicyConfig) -> Result<Self> {
        let mut next = Self::new(config)?;
        next.slots = self.slots.clone();
        Ok(next)
    }
    pub(crate) fn activate(&self) {
        self.slots.set_limit(self.config.max_parallel);
    }
    pub fn new(config: PolicyConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self::with_resolver(
            config,
            SystemDns(MessageAuthenticator::new_system_conf()?),
        ))
    }
}
// The resolver is private so callers cannot supply untrusted per-message DNS data.
#[allow(private_bounds)]
impl<R: Resolver> Policy<R> {
    fn with_resolver(config: PolicyConfig, resolver: R) -> Self {
        Self {
            slots: Capacity::new(config.max_parallel),
            config,
            resolver,
            cache: Mutex::new(HashMap::new()),
        }
    }
    async fn lookup(&self, query: Query) -> std::result::Result<Vec<Record>, ()> {
        if let Some((expires, answer)) = self.cache.lock().unwrap().get(&query)
            && *expires > Instant::now()
        {
            return answer.records.clone();
        }
        let answer = self.resolver.lookup(&query).await;
        let ttl = answer
            .ttl
            .min(Duration::from_secs(self.config.cache_ttl_seconds));
        let mut cache = self.cache.lock().unwrap();
        if cache.len() >= self.config.cache_entries {
            cache.retain(|_, (end, _)| *end > Instant::now());
            // Bound memory even under an attacker-controlled stream of unique names.
            if cache.len() >= self.config.cache_entries {
                cache.clear();
            }
        }
        if !ttl.is_zero() {
            cache.insert(query, (Instant::now() + ttl, answer.clone()));
        }
        answer.records
    }
    async fn peer_addresses(
        &self,
        name: &str,
        peer: IpAddr,
    ) -> std::result::Result<Vec<Record>, ()> {
        // Only the peer's address family can confirm its identity. A failing
        // AAAA lookup must not erase a verified IPv4 address (and vice versa).
        self.lookup(if peer.is_ipv4() {
            Query::A(name.into())
        } else {
            Query::Aaaa(name.into())
        })
        .await
    }
    async fn has_address(&self, name: &str) -> std::result::Result<bool, ()> {
        // Either family can prove that an implicit MX exists. An absent route
        // requires successful empty answers from both. Drop the other future
        // immediately on a positive answer; no background DNS work survives.
        let a = self.lookup(Query::A(name.into()));
        let aaaa = self.lookup(Query::Aaaa(name.into()));
        tokio::pin!(a, aaaa);
        let (first, second) = tokio::select! {
            first = &mut a => {
                if first.as_ref().is_ok_and(|r| !r.is_empty()) { return Ok(true); }
                (first, aaaa.await)
            }
            first = &mut aaaa => {
                if first.as_ref().is_ok_and(|r| !r.is_empty()) { return Ok(true); }
                (first, a.await)
            }
        };
        if second.as_ref().is_ok_and(|r| !r.is_empty()) {
            return Ok(true);
        }
        first?;
        second?;
        Ok(false)
    }
    pub async fn check(
        &self,
        ip: IpAddr,
        helo: &str,
        sender: &str,
        hostname: &str,
    ) -> PolicyResult {
        let started = Instant::now();
        let mut result = PolicyResult {
            version: VERSION.into(),
            scoring_enabled: self.config.contribute_to_score,
            ..Default::default()
        };
        let Ok(_slot) = self.slots.try_acquire() else {
            result.status = PolicyStatus::Busy;
            return result;
        };
        // Share one absolute deadline while retaining completed observations.
        // Missing checks remain explicitly unavailable, never adverse evidence.
        let deadline = tokio::time::Instant::now() + Duration::from_millis(self.config.timeout_ms);
        let (helo, reverse, sender) = tokio::join!(
            tokio::time::timeout_at(deadline, self.helo(ip.to_canonical(), helo, hostname)),
            tokio::time::timeout_at(deadline, self.reverse(ip.to_canonical())),
            tokio::time::timeout_at(deadline, self.sender(sender)),
        );
        result.status = PolicyStatus::Complete;
        for (name, kind, check) in [
            ("helo", CheckKind::Helo, helo),
            ("ptr", CheckKind::Ptr, reverse),
            ("sender", CheckKind::Sender, sender),
        ] {
            match check {
                Ok(Ok(signal)) => result.checks.push(signal),
                missing => {
                    result.status = PolicyStatus::Unavailable;
                    if missing.is_err() {
                        result.timeouts.push(kind);
                    }
                    result.checks.push(signal(
                        &format!("{name}_dns_unavailable"),
                        if missing.is_err() {
                            "SMTP identity check exceeded its DNS deadline"
                        } else {
                            "SMTP identity check has incomplete DNS evidence"
                        },
                        0.0,
                    ));
                }
            }
        }
        if result.status == PolicyStatus::Complete {
            let candidate: f64 = result.checks.iter().map(|s| s.weight).sum();
            // HELO and PTR are correlated. Verified DNS is only a small credit, never a bypass.
            result.candidate_weight = candidate.clamp(-0.25, 1.5);
            if self.config.contribute_to_score {
                result.applied_weight = result.candidate_weight;
            }
        } else {
            // Retain the successful facts without applying a partial score.
            for check in &mut result.checks {
                check.weight = 0.0;
            }
        }
        result.elapsed_ms = started.elapsed().as_millis() as u64;
        result
    }
    async fn helo(
        &self,
        ip: IpAddr,
        helo: &str,
        hostname: &str,
    ) -> std::result::Result<crate::engine::Signal, ()> {
        if let Some(literal) = literal(helo) {
            return Ok(if literal.to_canonical() == ip {
                signal(
                    "helo_literal_match",
                    "HELO IP literal matches the connection",
                    0.0,
                )
            } else {
                signal(
                    "helo_literal_mismatch",
                    "HELO IP literal differs from the connection",
                    0.5,
                )
            });
        }
        let Some(name) = host(helo) else {
            return Ok(signal(
                "helo_invalid",
                "HELO is not fully qualified or has unusual syntax",
                0.5,
            ));
        };
        if name == hostname.to_ascii_lowercase().trim_end_matches('.') {
            return Ok(signal(
                "helo_local_identity",
                "HELO claims this gateway’s identity",
                0.75,
            ));
        }
        let addresses = self.peer_addresses(&name, ip).await?;
        Ok(if addresses.contains(&Record::Ip(ip)) {
            signal(
                "helo_verified",
                "HELO DNS resolution matches the connecting IP",
                -0.15,
            )
        } else if addresses.is_empty() && !self.has_address(&name).await? {
            signal("helo_no_address", "HELO has no A/AAAA address", 0.5)
        } else {
            signal(
                "helo_address_mismatch",
                "HELO DNS resolution differs from the connecting IP",
                0.25,
            )
        })
    }
    async fn reverse(&self, ip: IpAddr) -> std::result::Result<crate::engine::Signal, ()> {
        let records = self.lookup(Query::Ptr(ip)).await?;
        if records.is_empty() {
            return Ok(signal("ptr_missing", "Reverse DNS has no PTR record", 0.25));
        }
        // Do not turn an incomplete search of a large RRset into a failed confirmation.
        if records.len() > MAX_PTR {
            return Err(());
        }
        let mut unknown = false;
        let mut names = Vec::new();
        for record in records {
            let Record::Host(name) = record else {
                return Err(());
            };
            let Some(name) = host(&name) else {
                unknown = true;
                continue;
            };
            if !names.contains(&name) {
                names.push(name);
            }
        }
        // At most MAX_PTR forward checks. A stale first PTR must not consume
        // the whole deadline before a second, valid PTR can be confirmed.
        let mut queries: Vec<_> = names
            .iter()
            .map(|name| Box::pin(self.peer_addresses(name, ip)))
            .collect();
        let confirmed = std::future::poll_fn(|cx| {
            use std::task::Poll;
            let mut confirmed = false;
            queries.retain_mut(|query| match query.as_mut().poll(cx) {
                Poll::Pending => true,
                Poll::Ready(Ok(ips)) => {
                    confirmed |= ips.contains(&Record::Ip(ip));
                    false
                }
                Poll::Ready(Err(())) => {
                    unknown = true;
                    false
                }
            });
            if confirmed {
                Poll::Ready(true)
            } else if queries.is_empty() {
                Poll::Ready(false)
            } else {
                Poll::Pending
            }
        })
        .await;
        if confirmed {
            return Ok(signal(
                "ptr_verified",
                "Reverse DNS PTR is confirmed by A/AAAA resolution",
                -0.15,
            ));
        }
        if unknown {
            return Err(());
        }
        Ok(signal(
            "ptr_unconfirmed",
            "No reverse DNS PTR resolves back to the connecting IP",
            0.5,
        ))
    }
    async fn sender(&self, sender: &str) -> std::result::Result<crate::engine::Signal, ()> {
        if sender.is_empty() {
            return Ok(signal(
                "sender_null",
                "Null envelope: delivery notification permitted",
                0.0,
            ));
        }
        let Some((_, domain)) = sender.rsplit_once('@') else {
            return Err(());
        };
        let Some(domain) = host(domain) else {
            return Err(());
        };
        let records = self.lookup(Query::Mx(domain.clone())).await?;
        if records.is_empty() {
            return Ok(if !self.has_address(&domain).await? {
                signal(
                    "sender_no_mail_route",
                    "Envelope domain has no MX or A/AAAA fallback",
                    0.75,
                )
            } else {
                signal(
                    "sender_implicit_mx",
                    "Envelope domain has a valid SMTP A/AAAA fallback without explicit MX",
                    0.0,
                )
            });
        }
        if records == [Record::Mx(0, ".".into())] {
            return Ok(signal(
                "sender_null_mx",
                "Envelope domain publishes Null MX: it declares that it does not receive mail",
                0.75,
            ));
        }
        if records
            .iter()
            .any(|r| !matches!(r, Record::Mx(_, name) if host(name).is_some()))
        {
            return Err(());
        }
        // Outbound SMTP servers need not be inbound MX servers. Do not compare their IPs.
        Ok(signal(
            "sender_mx_present",
            "Envelope domain has an explicit MX",
            0.0,
        ))
    }
}
fn signal(id: &str, detail: &str, weight: f64) -> crate::engine::Signal {
    crate::engine::Signal {
        id: id.into(),
        detail: detail.into(),
        weight,
    }
}
fn host(name: &str) -> Option<String> {
    let name = name.strip_suffix('.').unwrap_or(name);
    (crate::config::valid_domain(name) && name.contains('.') && name.parse::<IpAddr>().is_err())
        .then(|| name.to_ascii_lowercase())
}
fn literal(name: &str) -> Option<IpAddr> {
    let name = name.strip_prefix('[')?.strip_suffix(']')?;
    if name
        .get(..5)
        .is_some_and(|s| s.eq_ignore_ascii_case("IPv6:"))
    {
        name[5..].parse::<std::net::Ipv6Addr>().ok().map(IpAddr::V6)
    } else {
        name.parse::<std::net::Ipv4Addr>().ok().map(IpAddr::V4)
    }
}
