//! Active, bounded URL inspection. Redirects are followed manually: each hop
//! resolves and validates every address before a new, DNS-pinned HTTP client is
//! created. Neither page content nor complete URLs enter the saved report.
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
use reqwest::{Url, header};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub timeout_ms: u64,
    pub max_urls: usize,
    pub max_redirects: usize,
    pub max_parallel: usize,
    /// Extra public addresses, e.g. a gateway's NAT/public management address.
    pub blocked_ips: Vec<IpAddr>,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            timeout_ms: 1200,
            max_urls: 4,
            max_redirects: 5,
            max_parallel: 2,
            blocked_ips: vec![],
        }
    }
}
impl Settings {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (100..=2000).contains(&self.timeout_ms)
                && (1..=8).contains(&self.max_urls)
                && (1..=8).contains(&self.max_redirects)
                && (1..=8).contains(&self.max_parallel)
                && self.blocked_ips.len() <= 128,
            "Invalid URL resolution limits"
        );
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Detail {
    UnsafeUrl,
    ForbiddenAddress,
    Dns,
    Network,
    HttpStatus,
    InvalidRedirect,
    Loop,
    HopLimit,
    BodyLimit,
    Encoding,
    ClientScript,
    Deadline,
    Busy,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Hop {
    pub url_sha256: String,
    /// Registrable public domain only: no subdomain identity, path or query.
    pub site: String,
    pub code: u16,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Chain {
    pub source_sha256: String,
    pub hops: Vec<Hop>,
    pub complete: bool,
    pub detail: Option<Detail>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Report {
    pub version: String,
    pub settings_sha256: String,
    pub chains: Vec<Chain>,
    pub omitted: usize,
    pub elapsed_ms: u64,
    /// Absent on historical rows. Keep interruption variants readable by old binaries.
    #[serde(default)]
    pub local_inventory_available: Option<bool>,
}
#[derive(Clone)]
pub struct Resolver {
    settings: Settings,
    dns: Arc<MessageAuthenticator>,
    slots: Arc<tokio::sync::Semaphore>,
    #[cfg(test)]
    test_dns: Arc<std::sync::Mutex<std::collections::HashMap<String, Vec<IpAddr>>>>,
    #[cfg(test)]
    test_peer: Option<SocketAddr>,
}
impl Resolver {
    pub fn new(settings: Settings) -> Result<Self> {
        settings.validate()?;
        let _ = rustls::crypto::ring::default_provider().install_default();
        Ok(Self {
            slots: Arc::new(tokio::sync::Semaphore::new(settings.max_parallel)),
            settings,
            dns: Arc::new(MessageAuthenticator::new_system_conf()?),
            #[cfg(test)]
            test_dns: Default::default(),
            #[cfg(test)]
            test_peer: None,
        })
    }
    async fn addresses(&self, host: &str) -> std::result::Result<Vec<IpAddr>, Detail> {
        if let Ok(ip) = host.trim_matches(['[', ']']).parse() {
            return Ok(vec![ip]);
        }
        #[cfg(test)]
        if self.test_peer.is_some() {
            return self
                .test_dns
                .lock()
                .unwrap()
                .get(host)
                .cloned()
                .ok_or(Detail::Dns);
        }
        let query = format!("{}.", host.trim_end_matches('.'));
        let lookup = async |kind| match self.dns.0.lookup(query.clone(), kind).await {
            Ok(answer) => {
                let ips: Vec<_> = answer
                    .answers()
                    .iter()
                    .filter_map(|r| match &r.data {
                        RData::A(ip) => Some(IpAddr::V4(ip.0)),
                        RData::AAAA(ip) => Some(IpAddr::V6(ip.0)),
                        _ => None,
                    })
                    .take(33)
                    .collect();
                if ips.len() > 32 {
                    Err(Detail::Dns)
                } else {
                    Ok(ips)
                }
            }
            Err(NetError::Dns(DnsError::NoRecordsFound(missing)))
                if matches!(
                    missing.response_code,
                    ResponseCode::NoError | ResponseCode::NXDomain
                ) =>
            {
                Ok(vec![])
            }
            Err(_) => Err(Detail::Dns),
        };
        // A temporary failure of either family cannot hide a private address.
        let (a, aaaa) = tokio::join!(lookup(RecordType::A), lookup(RecordType::AAAA));
        let mut ips = a?;
        ips.extend(aaaa?);
        ips.sort();
        ips.dedup();
        if ips.is_empty() || ips.len() > 32 {
            Err(Detail::Dns)
        } else {
            Ok(ips)
        }
    }
    async fn follow(
        &self,
        original: &str,
        chain: &mut Chain,
        visited: &mut BTreeSet<String>,
        own: &BTreeSet<IpAddr>,
    ) -> std::result::Result<(), Detail> {
        let mut url = safe_url(original)?;
        let mut seen = BTreeSet::new();
        for index in 0..=self.settings.max_redirects {
            if !seen.insert(url.to_string()) {
                return Err(Detail::Loop);
            }
            let host = url.host_str().ok_or(Detail::UnsafeUrl)?;
            let ips = self.addresses(host).await?;
            if ips.iter().any(|ip| {
                !public_ip(*ip) || own.contains(ip) || self.settings.blocked_ips.contains(ip)
            }) {
                return Err(Detail::ForbiddenAddress);
            }
            let peers: Vec<_> = ips.iter().map(|ip| SocketAddr::new(*ip, 0)).collect();
            #[cfg(test)]
            let peers = self.test_peer.map(|p| vec![p]).unwrap_or(peers);
            let http = reqwest::Client::builder()
                .no_proxy()
                .retry(reqwest::retry::never())
                .redirect(reqwest::redirect::Policy::none())
                .referer(false)
                .http1_only()
                .no_gzip()
                .no_brotli()
                .no_deflate()
                .no_zstd()
                .resolve_to_addrs(host, &peers)
                .connect_timeout(Duration::from_millis(500))
                .timeout(Duration::from_millis(self.settings.timeout_ms))
                .user_agent("NoiseFence/1 URL-check")
                .build()
                .map_err(network_error)?;
            // Never forward cookies, authorization, referrers or provider keys.
            let mut response = http
                .get(url.clone())
                .header(header::ACCEPT_ENCODING, "identity")
                .send()
                .await
                .map_err(network_error)?;
            if !response
                .remote_addr()
                .is_some_and(|p| peers.iter().any(|known| known.ip() == p.ip()))
            {
                return Err(Detail::Network);
            }
            let code = response.status().as_u16();
            visited.insert(url.to_string());
            chain.hops.push(Hop {
                url_sha256: crate::message::digest(url.as_str().as_bytes()),
                site: report_site(host),
                code,
            });
            let mut next = None;
            if matches!(code, 301 | 302 | 303 | 307 | 308) {
                let values: Vec<_> = response
                    .headers()
                    .get_all(header::LOCATION)
                    .iter()
                    .collect();
                if values.len() != 1 {
                    return Err(Detail::InvalidRedirect);
                }
                let location = values[0].to_str().map_err(|_| Detail::InvalidRedirect)?;
                next = Some(resolve_location(&url, location)?);
            } else if !(200..300).contains(&code) {
                return Err(Detail::HttpStatus);
            } else if let Some(refresh) = response.headers().get("refresh") {
                if response.headers().get_all("refresh").iter().count() != 1 {
                    return Err(Detail::InvalidRedirect);
                }
                next = Some(resolve_location(
                    &url,
                    refresh_target(refresh.to_str().map_err(|_| Detail::InvalidRedirect)?)?,
                )?);
            } else {
                let mime = response
                    .headers()
                    .get(header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if mime.starts_with("text/html") || mime.starts_with("application/xhtml+xml") {
                    if response
                        .headers()
                        .get(header::CONTENT_ENCODING)
                        .is_some_and(|e| e != "identity")
                    {
                        return Err(Detail::Encoding);
                    }
                    if response.content_length().is_some_and(|n| n > 65536) {
                        return Err(Detail::BodyLimit);
                    }
                    let mut body = Vec::new();
                    while let Some(chunk) = response.chunk().await.map_err(network_error)? {
                        if body.len() + chunk.len() > 65536 {
                            return Err(Detail::BodyLimit);
                        }
                        body.extend_from_slice(&chunk);
                    }
                    let text = std::str::from_utf8(&body).map_err(|_| Detail::Encoding)?;
                    next = html_next(&url, text)?;
                }
            }
            if let Some(destination) = next {
                if index == self.settings.max_redirects {
                    return Err(Detail::HopLimit);
                }
                url = destination;
            } else {
                chain.complete = true;
                return Ok(());
            }
        }
        Err(Detail::HopLimit)
    }
    pub async fn inspect(&self, urls: &[String], truncated: bool) -> (Report, BTreeSet<String>) {
        let start = Instant::now();
        let mut report = Report {
            version: "url-resolution-3".into(),
            settings_sha256: crate::message::digest(
                &serde_json::to_vec(&self.settings).expect("URL settings"),
            ),
            chains: vec![],
            omitted: urls.len().saturating_sub(self.settings.max_urls) + usize::from(truncated),
            elapsed_ms: 0,
            local_inventory_available: None,
        };
        let mut visited = BTreeSet::new();
        let own = local_addresses();
        report.local_inventory_available = Some(own.is_ok());
        let own = Arc::new(own);
        let deadline =
            tokio::time::Instant::now() + Duration::from_millis(self.settings.timeout_ms);
        let mut tasks = tokio::task::JoinSet::new();
        for (index, original) in urls.iter().take(self.settings.max_urls).enumerate() {
            let chain = Chain {
                source_sha256: crate::message::digest(original.as_bytes()),
                hops: vec![],
                complete: false,
                detail: Some(Detail::Network),
            };
            report.chains.push(chain.clone());
            let (resolver, own, original) = (self.clone(), own.clone(), original.clone());
            tasks.spawn(async move {
                let mut chain = chain;
                let mut visited = BTreeSet::new();
                chain.detail = match own.as_ref() {
                    Err(_) => Some(Detail::Network),
                    Ok(own) => {
                        match tokio::time::timeout_at(deadline, resolver.slots.acquire()).await {
                            Ok(Ok(_permit)) => match tokio::time::timeout_at(
                                deadline,
                                resolver.follow(&original, &mut chain, &mut visited, own),
                            )
                            .await
                            {
                                Ok(Ok(())) => None,
                                Ok(Err(detail)) => Some(detail),
                                Err(_) => Some(Detail::Deadline),
                            },
                            _ => Some(Detail::Busy),
                        }
                    }
                };
                (index, chain, visited)
            });
        }
        // One stalled chain cannot consume the other chains' whole budget. The
        // semaphore bounds active chains globally, and dropping this JoinSet
        // cancels every request if the SMTP analysis itself is cancelled.
        while let Some(result) = tasks.join_next().await {
            if let Ok((index, chain, seen)) = result {
                report.chains[index] = chain;
                visited.extend(seen);
            }
        }
        report.elapsed_ms = start.elapsed().as_millis() as u64;
        (report, visited)
    }
}

fn network_error(error: reqwest::Error) -> Detail {
    if error.is_timeout() {
        Detail::Deadline
    } else {
        Detail::Network
    }
}

fn report_site(host: &str) -> String {
    if host.trim_matches(['[', ']']).parse::<IpAddr>().is_ok() {
        "[adresse IP]".into()
    } else {
        psl::domain_str(host.trim_end_matches('.'))
            .unwrap_or("[domaine inconnu]")
            .into()
    }
}

fn safe_url(value: &str) -> std::result::Result<Url, Detail> {
    if value.is_empty()
        || value.len() > 4096
        || value.chars().any(char::is_control)
        || value.contains('\\')
    {
        return Err(Detail::UnsafeUrl);
    }
    let mut url = Url::parse(value).map_err(|_| Detail::UnsafeUrl)?;
    if !matches!(
        (url.scheme(), url.port_or_known_default()),
        ("http", Some(80)) | ("https", Some(443))
    ) || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(Detail::UnsafeUrl);
    }
    let host = url.host_str().ok_or(Detail::UnsafeUrl)?;
    if !super::local::public_domain(host)
        && host.trim_matches(['[', ']']).parse::<IpAddr>().is_err()
    {
        return Err(Detail::UnsafeUrl);
    }
    url.set_fragment(None);
    Ok(url)
}
fn resolve_location(base: &Url, location: &str) -> std::result::Result<Url, Detail> {
    if location.is_empty()
        || location.len() > 4096
        || location.chars().any(char::is_control)
        || location.contains('\\')
    {
        return Err(Detail::InvalidRedirect);
    }
    let url = base
        .join(location.trim())
        .map_err(|_| Detail::InvalidRedirect)?;
    safe_url(url.as_str())
}
fn refresh_target(value: &str) -> std::result::Result<&str, Detail> {
    let (delay, rest) = value.split_once(';').ok_or(Detail::InvalidRedirect)?;
    let delay: f64 = delay.trim().parse().map_err(|_| Detail::InvalidRedirect)?;
    if !delay.is_finite() || delay < 0.0 {
        return Err(Detail::InvalidRedirect);
    }
    let (name, target) = rest.trim().split_once('=').ok_or(Detail::InvalidRedirect)?;
    if !name.trim().eq_ignore_ascii_case("url") {
        return Err(Detail::InvalidRedirect);
    }
    Ok(target.trim().trim_matches(['\'', '"']))
}
fn html_next(base: &Url, body: &str) -> std::result::Result<Option<Url>, Detail> {
    let doc = scraper::Html::parse_document(body);
    let selector = scraper::Selector::parse("meta[http-equiv], base[href], script").unwrap();
    let mut destination = None;
    let mut base = base.clone();
    let mut base_seen = false;
    let mut script = false;
    for (index, element) in doc.select(&selector).take(1025).enumerate() {
        if index == 1024 {
            return Err(Detail::BodyLimit);
        }
        match element.value().name() {
            "base" if !base_seen => {
                base = resolve_location(&base, element.value().attr("href").unwrap())?;
                base_seen = true;
            }
            "script" => script = true,
            "meta"
                if element
                    .value()
                    .attr("http-equiv")
                    .unwrap()
                    .eq_ignore_ascii_case("refresh") =>
            {
                if destination.is_some() {
                    return Err(Detail::InvalidRedirect);
                }
                destination = Some(
                    element
                        .value()
                        .attr("content")
                        .ok_or(Detail::InvalidRedirect)?
                        .to_string(),
                );
            }
            _ => {}
        }
    }
    if let Some(destination) = destination {
        return Ok(Some(resolve_location(
            &base,
            refresh_target(&destination)?,
        )?));
    }
    if script {
        return Err(Detail::ClientScript);
    }
    Ok(None)
}

/// Conservative globally-routable policy: transition/translation IPv6 ranges
/// are excluded so an embedded IPv4 address cannot bypass the IPv4 boundary.
fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(a == 0
                || a == 10
                || a == 127
                || a >= 224
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && (b == 168 || b == 0 || (b == 88 && c == 99)))
                || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
                || (a == 203 && b == 0 && c == 113))
        }
        IpAddr::V6(ip) => {
            let s = ip.segments();
            (s[0] & 0xe000) == 0x2000
                && s[0] != 0x2002
                && !(s[0] == 0x2001 && (s[1] < 0x0200 || s[1] == 0x0db8))
                && !(s[0] == 0x3fff && s[1] < 0x1000)
        }
    }
}
fn local_addresses() -> std::result::Result<BTreeSet<IpAddr>, ()> {
    // getifaddrs owns the list until freeifaddrs; sockaddr casts are gated by
    // the OS-provided family and are valid on supported Linux/macOS targets.
    unsafe {
        let mut head = std::ptr::null_mut();
        if libc::getifaddrs(&mut head) != 0 {
            return Err(());
        }
        let mut next = head;
        let mut addresses = BTreeSet::new();
        while !next.is_null() {
            let address = (*next).ifa_addr;
            if !address.is_null() {
                match (*address).sa_family as i32 {
                    libc::AF_INET => {
                        let addr = &*(address as *const libc::sockaddr_in);
                        addresses.insert(IpAddr::V4(addr.sin_addr.s_addr.to_ne_bytes().into()));
                    }
                    libc::AF_INET6 => {
                        let addr = &*(address as *const libc::sockaddr_in6);
                        addresses.insert(IpAddr::V6(addr.sin6_addr.s6_addr.into()));
                    }
                    _ => {}
                }
            }
            next = (*next).ifa_next;
        }
        libc::freeifaddrs(head);
        Ok(addresses)
    }
}

#[cfg(test)]
mod tests;
