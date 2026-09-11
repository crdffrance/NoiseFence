use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub hostname: String,
    pub data_dir: PathBuf,
    pub smtp: Smtp,
    pub web: Web,
    pub filter: Filter,
    pub actions: Option<crate::actions::Policy>,
    pub custom_filtering: Option<crate::custom_filtering::Policy>,
    pub fusion: Option<crate::fusion::runtime::Settings>,
    pub smtp_policy: Option<crate::smtp_policy::PolicyConfig>,
    pub antivirus: Option<crate::antivirus::AntivirusConfig>,
    pub signatures: Option<crate::antivirus::AntivirusConfig>,
    pub llm: Option<crate::llm::LlmConfig>,
    pub vision: Option<crate::vision::Settings>,
    pub protection: Option<crate::protection::Settings>,
    pub mailing: Option<crate::mailing::Settings>,
    pub quality: Option<crate::quality::Settings>,
    pub native_filter: Option<crate::native_filter::Settings>,
    pub relay: Relay,
    pub domains: Vec<Domain>,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Smtp {
    pub listen: SocketAddr,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    #[serde(default = "default_size")]
    pub max_message_bytes: usize,
    #[serde(default = "default_connections")]
    pub max_connections: usize,
    #[serde(default = "default_per_ip")]
    pub max_connections_per_ip: usize,
    /// Concurrent DATA uploads, analyses and durable commits; excess senders retry.
    #[serde(default = "default_processing")]
    pub max_processing: usize,
    #[serde(default = "default_timeout")]
    pub command_timeout_seconds: u64,
    #[serde(default = "default_rcpts")]
    pub max_recipients: usize,
    #[serde(default = "default_free")]
    pub minimum_free_bytes: u64,
}
fn default_size() -> usize {
    25 * 1024 * 1024
}
fn default_connections() -> usize {
    128
}
fn default_per_ip() -> usize {
    8
}
fn default_processing() -> usize {
    4
}
fn default_timeout() -> u64 {
    300
}
fn default_rcpts() -> usize {
    100
}
fn default_free() -> u64 {
    1024 * 1024 * 1024
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Web {
    pub listen: SocketAddr,
    pub public_origin: String,
    pub static_dir: PathBuf,
    #[serde(default = "yes")]
    pub secure_cookies: bool,
}
fn yes() -> bool {
    true
}
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Observe,
    Tag,
    Enforce,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Filter {
    #[serde(default)]
    pub rule_weights: BTreeMap<String, f64>,
    #[serde(default)]
    pub mode: Mode,
    #[serde(default = "threshold")]
    pub threshold: f64,
    #[serde(default)]
    pub require_corroboration: bool,
    pub model: Option<PathBuf>,
    pub semantic: Option<SemanticFilter>,
    #[serde(default = "yes")]
    pub authentication: bool,
    pub spamhaus_key_env: Option<String>,
    pub arc_key: Option<PathBuf>,
    pub arc_domain: Option<String>,
    pub arc_selector: Option<String>,
    pub proton_report: Option<PathBuf>,
    #[serde(default = "analysis_limit")]
    pub max_analysis_bytes: usize,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticFilter {
    pub encoder_dir: PathBuf,
    pub combination: PathBuf,
    #[serde(default = "semantic_parallel")]
    pub max_parallel: usize,
    #[serde(default = "semantic_timeout")]
    pub timeout_ms: u64,
}
fn semantic_parallel() -> usize {
    1
}
fn semantic_timeout() -> u64 {
    500
}
fn threshold() -> f64 {
    95.0
}
fn analysis_limit() -> usize {
    2 * 1024 * 1024
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Relay {
    #[serde(default = "workers")]
    pub workers: usize,
    #[serde(default = "yes")]
    pub require_tls: bool,
    // Only for an isolated loopback integration test sink, never an internet relay.
    #[serde(default)]
    pub allow_loopback_plaintext: bool,
    #[serde(default = "port")]
    pub port: u16,
    #[serde(default = "max_age")]
    pub max_queue_age_seconds: i64,
    pub postmaster: String,
}
fn workers() -> usize {
    8
}
fn port() -> u16 {
    25
}
fn max_age() -> i64 {
    5 * 86400
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Domain {
    pub name: String,
    /// Routes belong to canonical destinations; alias-only domains may omit them.
    #[serde(default)]
    pub next_hops: Vec<String>,
    /// Accept every valid mailbox in this exact domain, preserving its local part.
    #[serde(default)]
    pub accept_all_recipients: bool,
    #[serde(default)]
    pub recipients: Vec<String>,
    #[serde(default)]
    pub aliases: BTreeMap<String, String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Recipient {
    pub address: String,
    pub destination: String,
    pub hosts: Vec<String>,
}

/// An explicit route may carry a port; bare names keep the legacy relay port.
/// Accept one DNS root dot and return the canonical host for TLS and loop checks.
/// IPv6 literals and credentials are intentionally not accepted here.
pub fn endpoint(value: &str, default_port: u16) -> Option<(&str, u16)> {
    let (host, port) = match value.split_once(':') {
        Some((host, port)) => (host, port.parse::<u16>().ok()?),
        None => (value, default_port),
    };
    let host = host.strip_suffix('.').unwrap_or(host);
    (valid_domain(host) && port > 0).then_some((host, port))
}
pub fn valid_domain(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.is_ascii()
        && s.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
}
pub fn valid_address(s: &str) -> bool {
    let Some((local, domain)) = s.rsplit_once('@') else {
        return false;
    };
    let local_valid = if local.starts_with('"') && local.ends_with('"') && local.len() >= 2 {
        let mut escaped = false;
        let mut valid = true;
        for c in local.as_bytes()[1..local.len() - 1].iter().copied() {
            if escaped {
                valid &= (32..=126).contains(&c);
                escaped = false;
            } else if c == b'\\' {
                escaped = true;
            } else {
                valid &= (32..=126).contains(&c) && c != b'"';
            }
        }
        valid && !escaped
    } else {
        !local.starts_with('.')
            && !local.ends_with('.')
            && !local.contains("..")
            && local
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"!#$%&'*+-/=?^_`{|}~.".contains(&c))
    };
    !local.is_empty() && local.len() <= 64 && s.len() <= 254 && valid_domain(domain) && local_valid
}
impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let value: Self =
            toml::from_str(&std::fs::read_to_string(path).context("read configuration")?)?;
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<()> {
        if let Some(native) = &self.native_filter {
            native.validate()?;
        }
        if let Some(protection) = &self.protection {
            protection.validate()?;
        }
        ensure!(valid_domain(&self.hostname), "invalid hostname");
        if let Some(vision) = &self.vision {
            vision.validate()?;
        }
        if let Some(fusion) = &self.fusion {
            fusion.validate()?;
        }
        if let Some(policy) = &self.smtp_policy {
            policy.validate()?;
        }
        if let Some(llm) = &self.llm {
            llm.validate()?;
        }
        if let Some(antivirus) = &self.antivirus {
            antivirus.validate()?;
            ensure!(
                antivirus.max_bytes >= self.smtp.max_message_bytes,
                "ClamAV stream limit must cover the SMTP message size limit"
            );
        }
        if let Some(signatures) = &self.signatures {
            signatures.validate()?;
            ensure!(
                signatures.max_bytes >= self.smtp.max_message_bytes,
                "signature stream limit must cover SMTP message size"
            );
            ensure!(
                signatures.trusted_unofficial_prefixes.is_empty(),
                "complementary signatures must remain advisory"
            );
            ensure!(
                self.antivirus
                    .as_ref()
                    .is_none_or(|av| av.socket != signatures.socket),
                "official and complementary signatures require separate scanner sockets"
            );
        }
        ensure!(
            self.smtp.max_connections > 0
                && self.smtp.max_connections <= 4096
                && self.smtp.max_connections_per_ip > 0,
            "invalid connection limits"
        );
        ensure!(
            (1..=64).contains(&self.smtp.max_processing)
                && self.smtp.max_processing <= self.smtp.max_connections,
            "max_processing must be 1..64 and no greater than max_connections"
        );
        ensure!(
            self.smtp.max_message_bytes >= 1024 && self.smtp.max_message_bytes <= 100 * 1024 * 1024,
            "message size must be 1 KiB..100 MiB"
        );
        ensure!(
            self.smtp.max_recipients > 0 && self.smtp.max_recipients <= 1000,
            "invalid recipient limit"
        );
        ensure!(self.smtp.command_timeout_seconds > 0, "invalid timeout");
        ensure!(
            self.smtp.tls_cert.is_some() == self.smtp.tls_key.is_some(),
            "TLS requires both certificate and key"
        );
        ensure!(
            self.smtp.listen.ip().is_loopback() || self.smtp.tls_cert.is_some(),
            "public SMTP requires a STARTTLS certificate"
        );
        ensure!(
            self.web.listen.ip().is_loopback(),
            "bind web API to loopback behind the HTTPS proxy"
        );
        ensure!(
            !self.web.public_origin.ends_with('/')
                && !self.web.public_origin.contains(['\r', '\n']),
            "invalid public_origin"
        );
        ensure!(
            self.web.public_origin.starts_with("https://")
                || (!self.web.secure_cookies
                    && self.web.public_origin.starts_with("http://127.0.0.1:")),
            "HTTPS origin required outside loopback development"
        );
        ensure!(
            !self.web.public_origin.starts_with("https://") || self.web.secure_cookies,
            "HTTPS production requires Secure session cookies"
        );
        ensure!(
            self.filter.threshold.is_finite() && (0.0..=100.0).contains(&self.filter.threshold),
            "invalid threshold"
        );
        ensure!(
            (1024..=10 * 1024 * 1024).contains(&self.filter.max_analysis_bytes),
            "invalid analysis budget"
        );
        if let Some(semantic) = &self.filter.semantic {
            ensure!(
                cfg!(feature = "semantic"),
                "semantic configuration requires a binary built with --features semantic"
            );
            ensure!(
                self.filter.model.is_some(),
                "semantic combination requires its calibrated lexical model"
            );
            ensure!(
                (1..=2).contains(&semantic.max_parallel)
                    && (50..=5000).contains(&semantic.timeout_ms),
                "invalid semantic resource limits"
            );
        }
        ensure!(
            self.relay.workers > 0
                && self.relay.workers <= 128
                && self.relay.max_queue_age_seconds >= 60,
            "invalid relay limits"
        );
        ensure!(
            self.relay.require_tls || self.relay.allow_loopback_plaintext,
            "plaintext relay only allowed in isolated loopback tests"
        );
        ensure!(
            valid_address(&self.relay.postmaster),
            "invalid postmaster address"
        );
        ensure!(!self.domains.is_empty(), "configure at least one domain");
        let mut names = std::collections::HashSet::new();
        let mut canonical = std::collections::HashSet::new();
        for d in &self.domains {
            ensure!(
                valid_domain(&d.name) && names.insert(d.name.to_lowercase()),
                "invalid or duplicate domain"
            );
            ensure!(
                (d.recipients.is_empty() && !d.accept_all_recipients) || !d.next_hops.is_empty(),
                "missing next hops for canonical recipients"
            );
            for h in &d.next_hops {
                ensure!(
                    endpoint(h, self.relay.port).is_some_and(|(host, _)| !host
                        .eq_ignore_ascii_case(&self.hostname)
                        && !self
                            .domains
                            .iter()
                            .any(|domain| host.eq_ignore_ascii_case(&domain.name))),
                    "unsafe or looping next hop"
                );
            }
            for r in &d.recipients {
                ensure!(
                    valid_address(r) && r.rsplit_once('@').unwrap().1.eq_ignore_ascii_case(&d.name),
                    "recipient outside domain: {r}"
                );
                let (local, domain) = r.rsplit_once('@').unwrap();
                ensure!(
                    canonical.insert(format!("{local}@{}", domain.to_ascii_lowercase())),
                    "duplicate canonical recipient: {r}"
                );
            }
        }
        let mut aliases = std::collections::HashSet::new();
        for d in &self.domains {
            for (alias, dest) in &d.aliases {
                ensure!(
                    valid_address(alias)
                        && alias
                            .rsplit_once('@')
                            .unwrap()
                            .1
                            .eq_ignore_ascii_case(&d.name)
                        && self.canonical_destination(dest).is_some(),
                    "invalid alias {alias}"
                );
                let (local, domain) = alias.rsplit_once('@').unwrap();
                let key = format!("{local}@{}", domain.to_ascii_lowercase());
                ensure!(
                    !canonical.contains(&key) && aliases.insert(key),
                    "duplicate or shadowed alias: {alias}"
                );
            }
        }
        let arc_count = [
            self.filter.arc_key.is_some(),
            self.filter.arc_domain.is_some(),
            self.filter.arc_selector.is_some(),
        ]
        .iter()
        .filter(|v| **v)
        .count();
        ensure!(
            arc_count == 0 || arc_count == 3,
            "ARC needs key, domain and selector"
        );
        if let Some(d) = &self.filter.arc_domain {
            ensure!(valid_domain(d), "invalid ARC domain");
        }
        if let Some(s) = &self.filter.arc_selector {
            ensure!(valid_domain(s), "invalid ARC selector");
        }
        crate::rules::validate(&self.filter.rule_weights)?;
        let actions = crate::actions::Policy::from_config(self);
        actions.validate()?;
        if let Some(p) = &self.custom_filtering {
            p.validate(self)?;
        }
        let custom_tags = self
            .custom_filtering
            .as_ref()
            .map(|p| p.tags())
            .unwrap_or_default();
        let spam_tag = actions.spam_tag() || custom_tags.0;
        let pub_tag = ((self.mailing.is_some() || self.custom_filtering.is_some())
            && actions.publicity == crate::actions::Action::Tag)
            || custom_tags.1;
        ensure!(
            self.filter.mode == Mode::Observe || !pub_tag || self.mailing.is_some(),
            "PUB tagging requires a validated mailing configuration"
        );
        if self.filter.mode != Mode::Observe && (spam_tag || pub_tag) {
            ensure!(
                arc_count == 3 && self.filter.authentication,
                "tag mode requires authentication and ARC sealing"
            );
            if spam_tag {
                let report = self
                    .filter
                    .proton_report
                    .as_ref()
                    .context("tag mode requires a Proton compatibility report")?;
                let report: CompatibilityReport = serde_json::from_slice(&std::fs::read(report)?)?;
                report.validate(self)?;
            }
            if let Some(mailing) = &self.mailing
                && pub_tag
            {
                let path = mailing
                    .proton_report
                    .as_ref()
                    .context("[PUB] tagging requires its own Proton compatibility report")?;
                let report: CompatibilityReport = serde_json::from_slice(&std::fs::read(path)?)?;
                report.validate_prefix(self, "[PUB]")?;
            }
        }
        Ok(())
    }
    fn canonical_destination(&self, address: &str) -> Option<(String, &Domain)> {
        if !valid_address(address) {
            return None;
        }
        let (local, domain) = address.rsplit_once('@')?;
        let d = self
            .domains
            .iter()
            .find(|d| d.name.eq_ignore_ascii_case(domain))?;
        // An alias never becomes a canonical target through domain-wide acceptance:
        // explicit aliases keep precedence and chains/cycles remain invalid.
        if d.aliases.keys().any(|alias| same_mailbox(alias, address)) {
            return None;
        }
        if let Some(configured) = d
            .recipients
            .iter()
            .find(|configured| same_mailbox(configured, address))
        {
            return Some((configured.clone(), d));
        }
        d.accept_all_recipients
            .then(|| (format!("{local}@{}", d.name.to_ascii_lowercase()), d))
    }
    pub fn recipient(&self, address: &str) -> Option<Recipient> {
        if let Some((canonical, owner)) = self.canonical_destination(address) {
            return Some(Recipient {
                address: canonical.clone(),
                destination: canonical,
                hosts: owner.next_hops.clone(),
            });
        }
        let (_, domain) = address.rsplit_once('@')?;
        let incoming = self
            .domains
            .iter()
            .find(|d| d.name.eq_ignore_ascii_case(domain))?;
        let (alias, target) = incoming
            .aliases
            .iter()
            .find(|(alias, _)| same_mailbox(alias, address))?;
        // A single explicit hop to an authorized mailbox, never another alias.
        // Transport and ACLs use that mailbox's canonical spelling and route.
        let (canonical, owner) = self.canonical_destination(target)?;
        Some(Recipient {
            address: alias.clone(),
            destination: canonical,
            hosts: owner.next_hops.clone(),
        })
    }
}
fn same_mailbox(left: &str, right: &str) -> bool {
    match (left.rsplit_once('@'), right.rsplit_once('@')) {
        (Some((ll, ld)), Some((rl, rd))) => ll == rl && ld.eq_ignore_ascii_case(rd),
        _ => false,
    }
}
pub const PROTON_CASES: &[&str] = &[
    "dkim",
    "spf_only",
    "dmarc_reject",
    "mailing_list",
    "forwarded",
    "international_subject",
    "bypass",
    "proton_internal",
];
#[derive(Debug, Serialize, Deserialize)]
pub struct CompatibilityReport {
    pub hostname: String,
    pub domains: Vec<String>,
    pub tested_at: i64,
    pub prefix: String,
    pub cases: BTreeMap<String, CompatibilityCase>,
    pub bypass_limit_accepted: bool,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct CompatibilityCase {
    pub passed: bool,
    pub evidence: String,
}
impl CompatibilityReport {
    pub fn validate(&self, config: &Config) -> Result<()> {
        self.validate_prefix(config, "[SPAM]")
    }
    pub fn validate_prefix(&self, config: &Config, prefix: &str) -> Result<()> {
        ensure!(
            self.hostname == config.hostname && self.prefix == prefix,
            "report does not match deployment"
        );
        ensure!(
            self.tested_at <= crate::now() && crate::now() - self.tested_at < 30 * 86400,
            "report must be less than 30 days old"
        );
        ensure!(
            config
                .domains
                .iter()
                .all(|d| self.domains.contains(&d.name)),
            "report missing a configured domain"
        );
        for case in PROTON_CASES {
            match self.cases.get(*case) {
                Some(c) if c.passed && c.evidence.trim().len() >= 20 => {}
                _ => bail!("Proton case {case} has not been validated with evidence"),
            }
        }
        ensure!(
            self.bypass_limit_accepted,
            "document and accept the Proton direct/internal delivery coverage limitation"
        );
        Ok(())
    }
}
