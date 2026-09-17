//! Bounded, envelope-only recipient checks against administrator-configured routes.
//! A probe never sends DATA, never follows public MX records and never uses fallback.
use crate::{
    config::{Config, Recipient},
    relay::{response, unknown_recipient},
    smtp::{Wire, reply},
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{io::BufReader, net::TcpStream, sync::Semaphore};
use tokio_rustls::TlsConnector;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub timeout_ms: u64,
    pub positive_cache_seconds: u64,
    pub negative_cache_seconds: u64,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            timeout_ms: 8000,
            positive_cache_seconds: 60,
            negative_cache_seconds: 30,
        }
    }
}
impl Settings {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (100..=15000).contains(&self.timeout_ms),
            "Recipient verification timeout must be 100–15000 ms"
        );
        ensure!(
            self.positive_cache_seconds <= 300 && self.negative_cache_seconds <= 60,
            "Recipient verification caches exceed the permitted TTL"
        );
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Accepted,
    Unknown,
    Unavailable,
}
impl Verdict {
    pub fn smtp_reply(self) -> Option<&'static str> {
        match self {
            Self::Accepted => None,
            Self::Unknown => Some("550 5.1.1 Recipient does not exist at destination\r\n"),
            Self::Unavailable => {
                Some("451 4.4.3 Destination recipient verification unavailable; retry later\r\n")
            }
        }
    }
}
/// Policy belongs to the canonical destination, including for explicit aliases.
pub fn policy<'a>(cfg: &'a Config, recipient: &Recipient) -> Option<&'a Settings> {
    let (_, domain) = recipient.destination.rsplit_once('@')?;
    cfg.domains
        .iter()
        .find(|d| d.name.eq_ignore_ascii_case(domain))?
        .recipient_verification
        .as_ref()
}

pub struct Runtime {
    slots: Semaphore,
    cache: Mutex<HashMap<[u8; 32], (Instant, Verdict)>>,
}
impl Default for Runtime {
    fn default() -> Self {
        Self {
            slots: Semaphore::new(8),
            cache: Mutex::new(HashMap::new()),
        }
    }
}
impl Runtime {
    pub async fn check(&self, cfg: &Config, recipient: &Recipient, sender: &str) -> Verdict {
        let Some(settings) = policy(cfg, recipient) else {
            return Verdict::Accepted;
        };
        // Include the envelope and route/policy to isolate sender-dependent replies,
        // preserve local-part case and invalidate entries on configuration changes.
        let key: [u8; 32] = Sha256::digest(
            serde_json::to_vec(&(
                &cfg.hostname,
                &recipient.destination,
                sender,
                &recipient.hosts,
                cfg.relay.port,
                cfg.relay.require_tls,
                cfg.relay.allow_loopback_plaintext,
                settings,
            ))
            .expect("recipient cache key serializes"),
        )
        .into();
        {
            let mut cache = self.cache.lock().unwrap();
            if let Some((until, verdict)) = cache.get(&key) {
                if *until > Instant::now() {
                    return *verdict;
                }
                cache.remove(&key);
            }
        }
        let Ok(_permit) = self.slots.try_acquire() else {
            return Verdict::Unavailable;
        };
        let started = Instant::now();
        let verdict = tokio::time::timeout(Duration::from_millis(settings.timeout_ms), async {
            let mut all_unknown = !recipient.hosts.is_empty();
            let per_host =
                Duration::from_millis(settings.timeout_ms / recipient.hosts.len().max(1) as u64);
            for route in &recipient.hosts {
                let result = match tokio::time::timeout(
                    per_host,
                    probe(cfg, route, sender, &recipient.destination),
                )
                .await
                {
                    Ok(Ok(v)) => v,
                    _ => Verdict::Unavailable,
                };
                tracing::info!(route, verdict=?result, "SMTP destination recipient probe");
                if result == Verdict::Accepted {
                    return Verdict::Accepted;
                }
                all_unknown &= result == Verdict::Unknown;
            }
            if all_unknown {
                Verdict::Unknown
            } else {
                Verdict::Unavailable
            }
        })
        .await
        .unwrap_or(Verdict::Unavailable);
        tracing::info!(recipient_key=%hex::encode(&key[..8]), verdict=?verdict, elapsed_ms=started.elapsed().as_millis() as u64, "SMTP recipient verification");
        let ttl = match verdict {
            Verdict::Accepted => settings.positive_cache_seconds,
            Verdict::Unknown => settings.negative_cache_seconds,
            Verdict::Unavailable => 0,
        };
        if ttl > 0 {
            let mut cache = self.cache.lock().unwrap();
            if cache.len() >= 10000 {
                cache.retain(|_, (until, _)| *until > Instant::now());
            }
            if cache.len() < 10000 {
                cache.insert(key, (Instant::now() + Duration::from_secs(ttl), verdict));
            }
        }
        verdict
    }
}
async fn command(io: &mut Wire, value: &str) -> Result<crate::relay::Response> {
    reply(io, value).await?;
    response(io).await
}
async fn probe(cfg: &Config, route: &str, sender: &str, recipient: &str) -> Result<Verdict> {
    ensure!(
        (sender.is_empty() || crate::config::valid_address(sender))
            && crate::config::valid_address(recipient),
        "Invalid probe envelope"
    );
    let (host, port) = crate::config::endpoint(route, cfg.relay.port)
        .ok_or_else(|| anyhow::anyhow!("Invalid recipient route"))?;
    let dns_host = route.split_once(':').map_or(route, |(name, _)| name);
    let addresses = tokio::net::lookup_host((dns_host, port)).await?;
    let mut socket = None;
    for address in addresses.take(8) {
        let loopback_test = cfg.relay.allow_loopback_plaintext && address.ip().is_loopback();
        if !loopback_test && !crate::relay::safe_ip(address.ip()) {
            continue;
        }
        if let Ok(Ok(s)) =
            tokio::time::timeout(Duration::from_millis(750), TcpStream::connect(address)).await
        {
            socket = Some((s, loopback_test));
            break;
        }
    }
    let Some((socket, loopback_test)) = socket else {
        return Ok(Verdict::Unavailable);
    };
    let mut io: Wire = BufReader::new(Box::new(socket));
    if response(&mut io).await?.code != 220 {
        return Ok(Verdict::Unavailable);
    }
    let hello = format!("EHLO {}\r\n", cfg.hostname);
    let ehlo = command(&mut io, &hello).await?;
    if ehlo.code != 250 {
        return Ok(Verdict::Unavailable);
    }
    if ehlo
        .lines
        .iter()
        .any(|l| l.eq_ignore_ascii_case("STARTTLS"))
    {
        if command(&mut io, "STARTTLS\r\n").await?.code != 220 {
            return Ok(Verdict::Unavailable);
        }
        ensure!(
            io.buffer().is_empty(),
            "Unexpected plaintext after STARTTLS"
        );
        let roots =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let name = rustls::pki_types::ServerName::try_from(host.to_owned())?;
        let stream = TlsConnector::from(Arc::new(tls))
            .connect(name, io.into_inner())
            .await?;
        io = BufReader::new(Box::new(stream));
        if command(&mut io, &hello).await?.code != 250 {
            return Ok(Verdict::Unavailable);
        }
    } else if cfg.relay.require_tls || !loopback_test {
        return Ok(Verdict::Unavailable);
    }
    if command(&mut io, &format!("MAIL FROM:<{sender}>\r\n"))
        .await?
        .code
        != 250
    {
        return Ok(Verdict::Unavailable);
    }
    let rcpt = command(&mut io, &format!("RCPT TO:<{recipient}>\r\n")).await?;
    let verdict = if matches!(rcpt.code, 250 | 251) {
        Verdict::Accepted
    } else if unknown_recipient(&rcpt) {
        Verdict::Unknown
    } else {
        Verdict::Unavailable
    };
    // The RCPT result is authoritative even if cleanup fails. No DATA is sent.
    let _ = tokio::time::timeout(Duration::from_millis(100), async {
        let _ = command(&mut io, "RSET\r\n").await;
        let _ = reply(&mut io, "QUIT\r\n").await;
    })
    .await;
    Ok(verdict)
}
