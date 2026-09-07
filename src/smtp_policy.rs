//! Weighted SMTP identity checks inspired by policyd-weight, implemented independently.
//! Inputs come from the socket and SMTP envelope, never from message trace headers.
#[cfg(test)]
mod tests;
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
use tokio::sync::Semaphore;

pub const VERSION: &str = "smtp-policy-1";
const MAX_RECORDS: usize = 32;
const MAX_PTR: usize = 4;

#[derive(Clone, Debug, Deserialize)]
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
                detail: format!("Cohérence SMTP/DNS : contribution plafonnée ({VERSION})"),
                weight: self.applied_weight,
            });
        } else if self.status != PolicyStatus::Disabled {
            scan.complete = false;
            scan.reasons.push(crate::engine::Signal {
                id: "smtp_policy_unavailable".into(),
                detail:
                    "Contrôles SMTP/DNS incomplets ; aucune contribution, livraison sans préfixe"
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
    slots: Semaphore,
    cache: Mutex<HashMap<Query, (Instant, Answer)>>,
}
impl Policy<SystemDns> {
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
            slots: Semaphore::new(config.max_parallel),
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
    async fn addresses(&self, name: &str) -> std::result::Result<Vec<IpAddr>, ()> {
        let (a, aaaa) = tokio::join!(
            self.lookup(Query::A(name.into())),
            self.lookup(Query::Aaaa(name.into()))
        );
        // An error in either family cannot prove an identity mismatch or missing route.
        Ok(a?
            .into_iter()
            .chain(aaaa?)
            .filter_map(|r| match r {
                Record::Ip(ip) => Some(ip.to_canonical()),
                _ => None,
            })
            .collect())
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
        // No queued background work survives this timeout or the enclosing engine deadline.
        let work = async {
            let (helo, reverse, sender) = tokio::join!(
                self.helo(ip.to_canonical(), helo, hostname),
                self.reverse(ip.to_canonical()),
                self.sender(sender),
            );
            let mut checks = vec![helo?, reverse?, sender?];
            let candidate: f64 = checks.iter().map(|s| s.weight).sum();
            // HELO and PTR are correlated. Verified DNS is only a small credit, never a bypass.
            let candidate = candidate.clamp(-0.25, 1.5);
            checks.retain(|s| !s.id.is_empty());
            Ok::<_, ()>((checks, candidate))
        };
        match tokio::time::timeout(Duration::from_millis(self.config.timeout_ms), work).await {
            Ok(Ok((checks, candidate))) => {
                result.status = PolicyStatus::Complete;
                result.checks = checks;
                result.candidate_weight = candidate;
                result.applied_weight = if self.config.contribute_to_score {
                    candidate
                } else {
                    0.0
                };
            }
            _ => result.status = PolicyStatus::Unavailable,
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
                    "HELO : adresse littérale conforme à la connexion",
                    0.0,
                )
            } else {
                signal(
                    "helo_literal_mismatch",
                    "HELO : adresse littérale différente de la connexion",
                    0.5,
                )
            });
        }
        let Some(name) = host(helo) else {
            return Ok(signal(
                "helo_invalid",
                "HELO : nom non pleinement qualifié ou syntaxe inhabituelle",
                0.5,
            ));
        };
        if name == hostname.to_ascii_lowercase().trim_end_matches('.') {
            return Ok(signal(
                "helo_local_identity",
                "HELO : le client annonce l’identité de cette passerelle",
                0.75,
            ));
        }
        let addresses = self.addresses(&name).await?;
        Ok(if addresses.contains(&ip) {
            signal(
                "helo_verified",
                "HELO : résolution DNS conforme à l’IP de connexion",
                -0.15,
            )
        } else if addresses.is_empty() {
            signal(
                "helo_no_address",
                "HELO : aucune adresse A/AAAA trouvée",
                0.5,
            )
        } else {
            signal(
                "helo_address_mismatch",
                "HELO : résolution différente de l’IP de connexion",
                0.25,
            )
        })
    }
    async fn reverse(&self, ip: IpAddr) -> std::result::Result<crate::engine::Signal, ()> {
        let records = self.lookup(Query::Ptr(ip)).await?;
        if records.is_empty() {
            return Ok(signal(
                "ptr_missing",
                "DNS inverse : aucun PTR trouvé",
                0.25,
            ));
        }
        // Do not turn an incomplete search of a large RRset into a failed confirmation.
        if records.len() > MAX_PTR {
            return Err(());
        }
        let mut unknown = false;
        for record in records {
            let Record::Host(name) = record else {
                return Err(());
            };
            let Some(name) = host(&name) else {
                unknown = true;
                continue;
            };
            match self.addresses(&name).await {
                Ok(ips) if ips.contains(&ip) => {
                    return Ok(signal(
                        "ptr_verified",
                        "DNS inverse : PTR confirmé par sa résolution A/AAAA",
                        -0.15,
                    ));
                }
                Ok(_) => (),
                Err(()) => unknown = true,
            }
        }
        if unknown {
            return Err(());
        }
        Ok(signal(
            "ptr_unconfirmed",
            "DNS inverse : aucun PTR ne revient à l’IP de connexion",
            0.5,
        ))
    }
    async fn sender(&self, sender: &str) -> std::result::Result<crate::engine::Signal, ()> {
        if sender.is_empty() {
            return Ok(signal(
                "sender_null",
                "Enveloppe vide : notification de livraison autorisée",
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
            return Ok(if self.addresses(&domain).await?.is_empty() {
                signal(
                    "sender_no_mail_route",
                    "Domaine d’enveloppe : aucun MX ni repli A/AAAA",
                    0.75,
                )
            } else {
                signal(
                    "sender_implicit_mx",
                    "Domaine d’enveloppe : repli SMTP A/AAAA valide sans MX explicite",
                    0.0,
                )
            });
        }
        if records == [Record::Mx(0, ".".into())] {
            return Ok(signal(
                "sender_null_mx",
                "Domaine d’enveloppe : Null MX, domaine déclarant ne pas recevoir de courrier",
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
            "Domaine d’enveloppe : MX explicite présent",
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
