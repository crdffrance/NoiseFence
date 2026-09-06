use crate::{
    config::{Config, Mode},
    message,
};
use anyhow::{Context, Result, ensure};
use mail_auth::{
    AuthenticatedMessage, AuthenticationResults, DkimResult, DmarcResult, MessageAuthenticator,
    SpfResult,
    arc::ArcSealer,
    common::{
        crypto::{RsaKey, Sha256},
        headers::HeaderWriter,
    },
    dmarc::verify::DmarcParameters,
    spf::verify::SpfParameters,
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    net::IpAddr,
    path::Path,
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

pub const FEATURE_COUNT: usize = 16_384;
fn rsa_key(pem: &str) -> Result<RsaKey<Sha256>> {
    let der = rustls_pemfile::private_key(&mut std::io::BufReader::new(pem.as_bytes()))?
        .context("missing ARC RSA key")?;
    Ok(RsaKey::from_key_der(der)?)
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signal {
    pub id: String,
    pub detail: String,
    pub weight: f64,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SemanticStatus {
    #[default]
    Disabled,
    Complete,
    Busy,
    Unavailable,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SemanticResult {
    pub status: SemanticStatus,
    pub model: String,
    pub encoder: String,
    pub elapsed_ms: u64,
    pub logit: Option<f64>,
    pub contribution: Option<f64>,
    /// Retained as model features under the same 30-day metadata policy.
    #[serde(default)]
    pub features: Vec<f32>,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Scan {
    #[serde(default = "legacy_feature_version")]
    pub feature_version: u32,
    pub score: f64,
    pub tagged: bool,
    pub complete: bool,
    pub model: String,
    pub reasons: Vec<Signal>,
    pub features: Vec<(usize, f64)>,
    pub subject: String,
    pub sender: String,
    pub fingerprint: String,
    pub elapsed_ms: u64,
    #[serde(default)]
    pub antivirus: crate::antivirus::AntivirusResult,
    #[serde(default)]
    pub signatures: crate::antivirus::AntivirusResult,
    #[serde(default)]
    pub llm: crate::llm::LlmResult,
    #[serde(default)]
    pub semantic: SemanticResult,
}
pub fn legacy_feature_version() -> u32 {
    1
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum Algorithm {
    #[default]
    Logistic,
    BernoulliNb,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Model {
    pub version: String,
    #[serde(default)]
    pub algorithm: Algorithm,
    pub feature_version: u32,
    pub bias: f64,
    pub weights: Vec<f64>,
    #[serde(default)]
    pub idf: Vec<f64>,
    pub trained_at: i64,
    pub examples: usize,
}
impl Model {
    pub fn load(path: &Path) -> Result<Self> {
        let m: Self = serde_json::from_slice(&std::fs::read(path)?)?;
        ensure!(
            (((m.feature_version == 1 || m.feature_version == crate::features::VERSION)
                && m.algorithm == Algorithm::Logistic)
                || (m.feature_version == 2 && m.algorithm == Algorithm::BernoulliNb))
                && m.weights.len()
                    == if m.feature_version == crate::features::VERSION {
                        crate::features::DIMENSION
                    } else {
                        FEATURE_COUNT
                    }
                && m.weights.iter().all(|v| v.is_finite())
                && (m.idf.is_empty()
                    || (m.idf.len() == m.weights.len()
                        && m.idf.iter().all(|x| x.is_finite() && *x > 0.0)))
                && m.bias.is_finite(),
            "invalid model"
        );
        ensure!(
            m.algorithm != Algorithm::BernoulliNb || m.idf.is_empty(),
            "Bernoulli model must use binary presence features"
        );
        ensure!(
            m.feature_version != crate::features::VERSION
                || m.idf.len() == crate::features::DIMENSION,
            "feature schema 3 requires its fitted TF-IDF transform"
        );
        ensure!(
            !m.version.is_empty()
                && m.version
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c)),
            "invalid model version"
        );
        Ok(m)
    }
    pub fn logit(&self, f: &[(usize, f64)]) -> f64 {
        if self.algorithm == Algorithm::BernoulliNb {
            return self.bias
                + f.iter()
                    .filter(|(_, value)| *value != 0.0)
                    .map(|(index, _)| self.weights[*index])
                    .sum::<f64>();
        }
        if self.idf.is_empty() {
            return self.bias + f.iter().map(|(i, x)| self.weights[*i] * x).sum::<f64>();
        }
        let norm = f
            .iter()
            .map(|(i, x)| (x * self.idf[*i]).powi(2))
            .sum::<f64>()
            .sqrt()
            .max(1e-12);
        self.bias
            + f.iter()
                .map(|(i, x)| self.weights[*i] * x * self.idf[*i] / norm)
                .sum::<f64>()
    }
}
pub fn sigmoid(x: f64) -> f64 {
    1.0 / (1.0 + (-x.clamp(-40.0, 40.0)).exp())
}
fn regex(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).unwrap())
}
static WORDS: OnceLock<Regex> = OnceLock::new();
static URLS: OnceLock<Regex> = OnceLock::new();
static HTML: OnceLock<Regex> = OnceLock::new();
static DIGITS: OnceLock<Regex> = OnceLock::new();
fn hash_token(s: &str) -> usize {
    // Stable FNV-1a, independent of process hash seeds and platform word size.
    let mut hash = 14695981039346656037u64;
    for b in s.bytes() {
        hash ^= b as u64;
        hash = hash.wrapping_mul(1099511628211);
    }
    (hash % FEATURE_COUNT as u64) as usize
}
pub fn extract(raw: &[u8], max_bytes: usize) -> Scan {
    let mut scan = Scan {
        feature_version: 1,
        complete: true,
        model: "rules-1".into(),
        ..Scan::default()
    };
    if raw.len() > max_bytes {
        scan.complete = false;
        scan.reasons.push(Signal {
            id: "analysis_budget".into(),
            detail: "Message supérieur au budget d’analyse locale".into(),
            weight: 0.0,
        });
        if let Some(m) = mail_parser::MessageParser::default().parse_headers(raw) {
            scan.subject = m.subject().unwrap_or("").chars().take(500).collect();
        }
        return scan;
    }
    let Some(m) = mail_parser::MessageParser::default().parse(raw) else {
        scan.complete = false;
        return scan;
    };
    scan.subject = m.subject().unwrap_or("").chars().take(500).collect();
    scan.sender = m
        .from()
        .and_then(|a| a.first())
        .and_then(|a| a.address())
        .unwrap_or("")
        .to_string();
    if m.parts.len() > 200 {
        scan.complete = false;
        return scan;
    }
    let mut text = String::new();
    text.push_str(&scan.subject);
    // Attachment bytes, upstream spam headers, and transport metadata never enter training.
    for i in 0..m.text_body_count().min(20) {
        if let Some(body) = m.body_text(i) {
            text.push(' ');
            text.extend(body.chars().take(100_000usize.saturating_sub(text.len())));
        }
    }
    let html = m.body_html(0).unwrap_or_default();
    if m.text_body_count() == 0 {
        text.push_str(
            &regex(&HTML, r"(?s)<[^>]{0,4096}>")
                .replace_all(&html, " ")
                .chars()
                .take(100_000)
                .collect::<String>(),
        );
    }
    let lower = text.to_lowercase();
    let mut counts = BTreeMap::new();
    let tokens: Vec<&str> = regex(&WORDS, r"[\p{L}\p{N}]{2,40}")
        .find_iter(&lower)
        .take(20_000)
        .map(|m| m.as_str())
        .collect();
    for t in &tokens {
        *counts.entry(hash_token(t)).or_insert(0.0f64) += 1.0;
    }
    for pair in tokens.windows(2) {
        *counts
            .entry(hash_token(&format!("{} {}", pair[0], pair[1])))
            .or_insert(0.0) += 0.5;
    }
    for x in counts.values_mut() {
        *x = (1.0 + *x).ln();
    }
    let normalized = regex(&DIGITS, r"\d+").replace_all(&lower, "#");
    let normalized = normalized.split_whitespace().collect::<Vec<_>>().join(" ");
    scan.fingerprint = message::digest(normalized.as_bytes());
    let mut signal = |id: &str, detail: &str, weight: f64| {
        scan.reasons.push(Signal {
            id: id.into(),
            detail: detail.into(),
            weight,
        })
    };
    if ["urgent", "immediately", "immédiatement"]
        .iter()
        .any(|s| lower.contains(s))
    {
        signal("urgency", "Vocabulaire d’urgence", 0.5);
    }
    if [
        "verify your account",
        "confirmez votre compte",
        "password expires",
        "mot de passe expire",
    ]
    .iter()
    .any(|s| lower.contains(s))
    {
        signal("credential_request", "Demande liée aux identifiants", 1.5);
    }
    if [
        "lottery",
        "loterie",
        "million dollars",
        "guaranteed profit",
        "profit garanti",
    ]
    .iter()
    .any(|s| lower.contains(s))
    {
        signal("financial_lure", "Promesse financière suspecte", 1.5);
    }
    if html.to_lowercase().contains("<form") {
        signal("html_form", "Formulaire intégré au message", 1.5);
    }
    let urls = domains_in_text(&format!("{text} {html}"));
    if urls
        .iter()
        .any(|s| s.starts_with("xn--") || s.contains(".xn--"))
    {
        signal("idn_url", "Lien vers un domaine internationalisé", 0.4);
    }
    if urls.iter().any(|s| s.parse::<IpAddr>().is_ok()) {
        signal("ip_url", "Lien utilisant une adresse IP", 1.5);
    }
    if scan
        .sender
        .rsplit_once('@')
        .map(|x| x.1)
        .is_some_and(|from| {
            m.reply_to()
                .and_then(|a| a.first())
                .and_then(|a| a.address())
                .and_then(|a| a.rsplit_once('@'))
                .is_some_and(|(_, d)| !d.eq_ignore_ascii_case(from))
        })
    {
        signal(
            "reply_to",
            "Domaine de réponse différent de l’expéditeur",
            0.5,
        );
    }
    let capitals = scan.subject.chars().filter(|c| c.is_uppercase()).count();
    let letters = scan.subject.chars().filter(|c| c.is_alphabetic()).count();
    if letters > 15 && capitals as f64 / letters as f64 > 0.8 {
        signal("caps_subject", "Objet majoritairement en majuscules", 0.5);
    }
    // Structural features share the same train/inference extraction path. Never
    // include old filter decisions, transport headers or attachment content.
    for token in [
        format!("__mime_parts_{}", m.parts.len().min(8)),
        format!("__html_{}", !html.is_empty()),
        format!("__links_{}", urls.len().min(5)),
        format!("__attachments_{}", m.attachments.len().min(5)),
    ] {
        *counts.entry(hash_token(&token)).or_insert(0.0) += 1.0;
    }
    for reason in &scan.reasons {
        *counts
            .entry(hash_token(&format!("__signal_{}", reason.id)))
            .or_insert(0.0) += 1.0;
    }
    let norm = counts.values().map(|x| x * x).sum::<f64>().sqrt().max(1.0);
    scan.features = counts.into_iter().map(|(i, x)| (i, x / norm)).collect();
    scan
}
pub fn domains_in_text(text: &str) -> Vec<String> {
    let mut domains: Vec<_> = regex(&URLS, r"(?i)https?://([a-z0-9][a-z0-9.-]{0,252})")
        .captures_iter(text)
        .take(100)
        .map(|c| c[1].trim_end_matches('.').to_lowercase())
        .filter(|d| crate::config::valid_domain(d))
        .collect();
    domains.sort();
    domains.dedup();
    domains.truncate(12);
    domains
}

/// Reputation sees decoded MIME bodies, not transport/filter headers or raw encodings.
pub fn domains_in_message(raw: &[u8]) -> Vec<String> {
    let Some(message) = mail_parser::MessageParser::default().parse(raw) else {
        return Vec::new();
    };
    if message.parts.len() > 200 {
        return Vec::new();
    }
    let mut domains = Vec::new();
    for body in (0..message.text_body_count().min(20))
        .filter_map(|i| message.body_text(i))
        .chain((0..message.html_body_count().min(20)).filter_map(|i| message.body_html(i)))
    {
        let bounded: String = body.chars().take(100_000).collect();
        domains.extend(domains_in_text(&bounded));
    }
    domains.sort_unstable();
    domains.dedup();
    domains.truncate(12);
    domains
}
pub struct Engine {
    config: Arc<Config>,
    pub authenticator: MessageAuthenticator,
    model: Option<Model>,
    arc_key: Option<String>,
    dqs_key: Option<String>,
    dqs_cache: Mutex<HashMap<String, (Instant, bool)>>,
    llm: Option<crate::llm::Client>,
    #[cfg(feature = "semantic")]
    semantic: Option<Arc<crate::semantic::Hybrid>>,
}
impl Engine {
    pub fn new(config: Arc<Config>) -> Result<Self> {
        let llm = config
            .llm
            .as_ref()
            .filter(|c| c.monthly_budget_micro_eur > 0)
            .map(|c| crate::llm::Client::new(c.clone(), &config.data_dir))
            .transpose()?;
        let model = config
            .filter
            .model
            .as_ref()
            .map(|p| Model::load(p))
            .transpose()?;
        #[cfg(feature = "semantic")]
        let semantic = config
            .filter
            .semantic
            .as_ref()
            .map(|settings| {
                ensure!(
                    model
                        .as_ref()
                        .is_some_and(|m| m.feature_version == crate::features::VERSION),
                    "semantic combination requires lexical feature schema 3"
                );
                crate::semantic::Hybrid::load(
                    settings,
                    config.filter.model.as_ref().unwrap(),
                    config.filter.threshold,
                )
                .map(Arc::new)
            })
            .transpose()?;
        #[cfg(not(feature = "semantic"))]
        ensure!(
            config.filter.semantic.is_none(),
            "semantic support is not compiled in this binary"
        );
        let arc_key = config
            .filter
            .arc_key
            .as_ref()
            .map(std::fs::read_to_string)
            .transpose()?;
        if let Some(key) = &arc_key {
            rsa_key(key).context("ARC key must be an RSA PEM key")?;
        }
        let dqs_key = config
            .filter
            .spamhaus_key_env
            .as_ref()
            .map(|name| {
                std::env::var(name).with_context(|| format!("missing environment variable {name}"))
            })
            .transpose()?;
        if let Some(key) = &dqs_key {
            ensure!(
                !key.is_empty() && key.bytes().all(|b| b.is_ascii_alphanumeric()),
                "invalid DQS key"
            );
        }
        Ok(Self {
            config,
            authenticator: MessageAuthenticator::new_system_conf()?,
            model,
            arc_key,
            dqs_key,
            dqs_cache: Mutex::new(HashMap::new()),
            llm,
            #[cfg(feature = "semantic")]
            semantic,
        })
    }
    pub fn offline(&self, raw: &[u8]) -> Scan {
        let mut scan = self.extract(raw);
        #[cfg(feature = "semantic")]
        if scan.complete
            && let Some(model) = &self.semantic
        {
            scan.semantic = model.offline(raw);
            Self::check_semantic(&mut scan);
        }
        self.score(&mut scan);
        scan
    }
    #[cfg(feature = "semantic")]
    fn check_semantic(scan: &mut Scan) {
        if matches!(
            scan.semantic.status,
            SemanticStatus::Busy | SemanticStatus::Unavailable
        ) {
            scan.complete = false;
            scan.reasons.push(Signal {
                id: "semantic_unavailable".into(),
                detail: "Analyse multilingue incomplète ; résultat lexical conservé sans préfixe"
                    .into(),
                weight: 0.0,
            });
        }
    }
    fn extract(&self, raw: &[u8]) -> Scan {
        if self
            .model
            .as_ref()
            .is_some_and(|m| m.feature_version == crate::features::VERSION)
        {
            crate::features::extract(raw, self.config.filter.max_analysis_bytes)
        } else {
            extract(raw, self.config.filter.max_analysis_bytes)
        }
    }
    fn score(&self, scan: &mut Scan) {
        scan.reasons.retain(|r| r.id != "model_contribution");
        let mut content = self
            .model
            .as_ref()
            .map(|m| {
                scan.model = m.version.clone();
                m.logit(&scan.features)
            })
            .unwrap_or(-5.0);
        if scan.semantic.status == SemanticStatus::Complete {
            content += scan.semantic.contribution.unwrap_or(0.0);
            scan.model = scan.semantic.model.clone();
        }
        let rules = scan.reasons.iter().map(|r| r.weight).sum::<f64>();
        let score = sigmoid(content + rules) * 100.0;
        scan.score = if scan.feature_version == crate::features::VERSION {
            // Round only for display. Rounding here shifts a calibrated cutoff
            // and can classify a legitimate 94.99 as spam at a threshold of 95.
            score
        } else {
            (score * 10.0).round() / 10.0
        };
        if self.model.is_some() {
            scan.reasons.push(Signal {
                id: "model_contribution".into(),
                detail: "Contribution du modèle local : texte et structure".into(),
                weight: content,
            });
        }
    }
    async fn listed(&self, query: &str) -> Result<bool> {
        if let Some((expires, value)) = self.dqs_cache.lock().unwrap().get(query)
            && *expires > Instant::now()
        {
            return Ok(*value);
        }
        let result = self.authenticator.ipv4_lookup_raw(query).await;
        let value = match result {
            Ok(records) => dqs_answer(&records.entry)?,
            Err(mail_auth::Error::Dns(mail_auth::DnsError::RecordNotFound(
                mail_auth::hickory_resolver::proto::op::ResponseCode::NXDomain,
            ))) => false,
            Err(_) => anyhow::bail!("reputation lookup unavailable"),
        };
        let mut cache = self.dqs_cache.lock().unwrap();
        if cache.len() >= 10_000 {
            cache.retain(|_, (end, _)| *end > Instant::now());
            if cache.len() >= 10_000 {
                cache.clear();
            }
        }
        cache.insert(
            query.into(),
            (Instant::now() + Duration::from_secs(60), value),
        );
        Ok(value)
    }
    async fn reputation(&self, ip: IpAddr, raw: &[u8], scan: &mut Scan) -> Result<()> {
        let Some(key) = &self.dqs_key else {
            return Ok(());
        };
        let prefix = match ip {
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
        };
        if self
            .listed(&format!("{prefix}.{key}.zen.dq.spamhaus.net."))
            .await?
        {
            scan.reasons.push(Signal {
                id: "ip_reputation".into(),
                detail: "IP signalée par la source de réputation".into(),
                weight: 4.0,
            });
        }
        let mut domains = domains_in_message(raw);
        if let Some((_, d)) = scan.sender.rsplit_once('@')
            && crate::config::valid_domain(d)
        {
            domains.push(d.into());
        }
        domains.sort();
        domains.dedup();
        for domain in domains.into_iter().take(12) {
            if domain.parse::<IpAddr>().is_ok() {
                continue;
            }
            if self
                .listed(&format!("{domain}.{key}.dbl.dq.spamhaus.net."))
                .await?
            {
                scan.reasons.push(Signal {
                    id: "domain_reputation".into(),
                    detail: "Domaine signalé par la source de réputation".into(),
                    weight: 4.0,
                });
                break;
            }
        }
        Ok(())
    }
    pub async fn process(
        &self,
        raw: &[u8],
        ip: IpAddr,
        helo: &str,
        sender: &str,
        id: &str,
    ) -> Result<(Scan, Vec<u8>)> {
        let started = Instant::now();
        let mut scan = self.extract(raw);
        let headers = message::fields(raw)?.0;
        #[cfg(feature = "semantic")]
        if scan.complete
            && let Some(model) = &self.semantic
        {
            scan.semantic = model.analyze(raw.to_vec()).await;
            Self::check_semantic(&mut scan);
        }
        let (antivirus, signatures) = tokio::join!(
            async {
                match &self.config.antivirus {
                    Some(config) => crate::antivirus::scan(config, raw).await,
                    None => Default::default(),
                }
            },
            async {
                match &self.config.signatures {
                    Some(config) => crate::antivirus::scan(config, raw).await,
                    None => Default::default(),
                }
            }
        );
        scan.antivirus = antivirus;
        scan.signatures = signatures;
        if self.config.antivirus.is_some() {
            use crate::antivirus::AntivirusStatus;
            let (detail, weight) = match scan.antivirus.status {
                AntivirusStatus::Disabled | AntivirusStatus::Clean => (None, 0.0),
                AntivirusStatus::Malware => {
                    (Some("Détection antivirus de fichier malveillant"), 0.0)
                }
                AntivirusStatus::Suspicious => (Some("Signature antivirus consultative"), 1.0),
                AntivirusStatus::Unscannable => {
                    scan.complete = false;
                    (Some("Analyse antivirus limitée ou contenu chiffré"), 0.0)
                }
                AntivirusStatus::Unavailable => {
                    scan.complete = false;
                    (Some("Service antivirus indisponible ou délai dépassé"), 0.0)
                }
            };
            if let Some(detail) = detail {
                scan.reasons.push(Signal {
                    id: "antivirus".into(),
                    detail: match &scan.antivirus.signature {
                        Some(signature) => format!("{detail} : {signature}"),
                        None => detail.into(),
                    },
                    weight,
                });
            }
        }
        if self.config.signatures.is_some() {
            use crate::antivirus::AntivirusStatus;
            // This separate daemon is an advisory source, regardless of its signature label.
            if scan.signatures.status == AntivirusStatus::Malware {
                scan.signatures.status = AntivirusStatus::Suspicious;
            }
            match scan.signatures.status {
                AntivirusStatus::Suspicious => scan.reasons.push(Signal {
                    id: "complementary_signature".into(),
                    detail: format!(
                        "Signature complémentaire consultative : {}",
                        scan.signatures.signature.as_deref().unwrap_or("inconnue")
                    ),
                    weight: 1.0,
                }),
                AntivirusStatus::Unscannable | AntivirusStatus::Unavailable => {
                    scan.complete = false;
                    scan.reasons.push(Signal {
                        id: "complementary_signature_unavailable".into(),
                        detail: "Analyse des signatures complémentaires indisponible ou limitée"
                            .into(),
                        weight: 0.0,
                    });
                }
                _ => {}
            }
        }
        if headers
            .iter()
            .filter(|h| message::name(h) == "dkim-signature")
            .count()
            > 16
            || headers
                .iter()
                .filter(|h| message::name(h).starts_with("arc-"))
                .count()
                > 150
        {
            scan.complete = false;
            scan.reasons.push(Signal {
                id: "signature_budget".into(),
                detail: "Nombre de signatures supérieur au budget de vérification".into(),
                weight: 0.0,
            });
        }
        if !scan.complete {
            return self.finish_unchecked(raw, scan, ip, id, started);
        }
        let work = async {
            let authenticated =
                AuthenticatedMessage::parse(raw).context("authentication parsing failed")?;
            let mut results = AuthenticationResults::new(&self.config.hostname);
            let arc = self.authenticator.verify_arc(&authenticated).await;
            if self.config.filter.authentication {
                let (dkim, spf) = tokio::join!(
                    self.authenticator.verify_dkim(&authenticated),
                    self.authenticator
                        .verify_spf(SpfParameters::verify_mail_from(
                            ip,
                            helo,
                            &self.config.hostname,
                            sender
                        ))
                );
                let domain = sender.rsplit_once('@').map(|x| x.1).unwrap_or(helo);
                let dmarc = self
                    .authenticator
                    .verify_dmarc(DmarcParameters::new(&authenticated, &dkim, domain, &spf))
                    .await;
                if spf.result() == SpfResult::TempError
                    || dkim
                        .iter()
                        .any(|d| matches!(d.result(), DkimResult::TempError(_)))
                    || matches!(dmarc.spf_result(), DmarcResult::TempError(_))
                    || matches!(dmarc.dkim_result(), DmarcResult::TempError(_))
                {
                    anyhow::bail!("authentication temporary error");
                }
                if spf.result() == SpfResult::Fail {
                    scan.reasons.push(Signal {
                        id: "spf_fail".into(),
                        detail: "SPF ne valide pas cet expéditeur".into(),
                        weight: 1.0,
                    });
                }
                let pass = *dmarc.dkim_result() == DmarcResult::Pass
                    || *dmarc.spf_result() == DmarcResult::Pass;
                if !pass
                    && (matches!(dmarc.spf_result(), DmarcResult::Fail(_))
                        || matches!(dmarc.dkim_result(), DmarcResult::Fail(_)))
                {
                    scan.reasons.push(Signal {
                        id: "dmarc_fail".into(),
                        detail: "Alignement DMARC non validé".into(),
                        weight: 2.0,
                    });
                }
                results = results
                    .with_dkim_results(&dkim, &scan.sender)
                    .with_spf_mailfrom_result(&spf, ip, sender, helo)
                    .with_dmarc_result(&dmarc)
                    .with_arc_result(&arc, ip);
            }
            self.reputation(ip, raw, &mut scan).await?;
            self.score(&mut scan);
            if scan.complete
                && let Some(llm) = &self.llm
                && scan.antivirus.status != crate::antivirus::AntivirusStatus::Malware
            {
                // Preserve an attempted-check marker if the enclosing DNS/LLM deadline cancels it.
                scan.llm.status = crate::llm::LlmStatus::Unavailable;
                scan.llm.prompt_version = crate::llm::PROMPT_VERSION.into();
                scan.llm.model = self.config.llm.as_ref().unwrap().model.clone();
                scan.llm = llm.classify(raw, scan.score).await;
                if let Some(verdict) = &scan.llm.verdict {
                    let weight = match verdict.category {
                        crate::llm::Category::Spam | crate::llm::Category::Phishing
                            if verdict.confidence >= 0.9 && verdict.spam_probability >= 0.9 =>
                        {
                            1.5
                        }
                        crate::llm::Category::Legitimate
                            if verdict.confidence >= 0.95 && verdict.spam_probability <= 0.1 =>
                        {
                            -0.5
                        }
                        _ => 0.0,
                    };
                    scan.reasons.push(Signal {
                        id: "llm_advisory".into(),
                        detail: format!("Analyse LLM consultative : {}", verdict.explanation),
                        weight,
                    });
                    self.score(&mut scan);
                } else if matches!(scan.llm.status, crate::llm::LlmStatus::Unavailable) {
                    scan.complete = false;
                    scan.reasons.push(Signal {
                        id: "llm_unavailable".into(),
                        detail: "Analyse LLM indisponible ; résultat local conservé sans préfixe"
                            .into(),
                        weight: 0.0,
                    });
                }
            }
            let tag = scan.complete
                && self.config.filter.mode == Mode::Tag
                && scan.score >= self.config.filter.threshold;
            // If the chain cannot be extended, preserve the signed subject and fail open.
            if tag && !arc.can_be_sealed() {
                anyhow::bail!("ARC chain cannot be extended");
            }
            scan.tagged = tag;
            let mut bytes = message::rewrite(
                raw,
                tag,
                &format!("{}{}", self.headers(ip, id, &scan), results.to_header()),
            )?;
            if let Some(key) = &self.arc_key
                && arc.can_be_sealed()
            {
                let changed =
                    AuthenticatedMessage::parse(&bytes).context("modified message parse")?;
                let signature = ArcSealer::from_key(rsa_key(key)?)
                    .domain(self.config.filter.arc_domain.as_deref().unwrap())
                    .selector(self.config.filter.arc_selector.as_deref().unwrap())
                    .headers([
                        "From",
                        "To",
                        "Subject",
                        "Date",
                        "Message-ID",
                        "MIME-Version",
                        "Content-Type",
                        "Content-Transfer-Encoding",
                        "DKIM-Signature",
                        "X-NoiseFence-Score",
                        "X-NoiseFence-Status",
                    ])
                    .seal(&changed, &results, &arc)?;
                bytes = [signature.to_header().as_bytes(), &bytes].concat();
            }
            Ok::<_, anyhow::Error>(bytes)
        };
        match tokio::time::timeout(Duration::from_secs(5), work).await {
            Ok(Ok(bytes)) => {
                scan.elapsed_ms = started.elapsed().as_millis() as u64;
                Ok((scan, bytes))
            }
            _ => {
                scan.complete = false;
                scan.tagged = false;
                scan.reasons.push(Signal {
                    id: "checks_unavailable".into(),
                    detail: "Vérifications incomplètes ou délai dépassé".into(),
                    weight: 0.0,
                });
                self.finish_unchecked(raw, scan, ip, id, started)
            }
        }
    }
    fn headers(&self, ip: IpAddr, id: &str, scan: &Scan) -> String {
        format!(
            "Received: from [{}] by {} with ESMTP id {};\r\n\t{}\r\nX-NoiseFence-Id: {}\r\nX-NoiseFence-Score: {:.1}\r\nX-NoiseFence-Status: {}\r\n",
            ip,
            self.config.hostname,
            id,
            mail_parser::DateTime::from_timestamp(crate::now()).to_rfc822(),
            id,
            scan.score,
            if !scan.complete {
                "incomplete"
            } else if scan.tagged {
                "spam"
            } else {
                "observed"
            }
        )
    }
    fn finish_unchecked(
        &self,
        raw: &[u8],
        mut scan: Scan,
        ip: IpAddr,
        id: &str,
        started: Instant,
    ) -> Result<(Scan, Vec<u8>)> {
        self.score(&mut scan);
        scan.tagged = false;
        scan.elapsed_ms = started.elapsed().as_millis() as u64;
        let bytes = message::rewrite(raw, false, &self.headers(ip, id, &scan))?;
        Ok((scan, bytes))
    }
}
pub fn dqs_answer(records: &[std::net::Ipv4Addr]) -> Result<bool> {
    let mut listed = false;
    for ip in records {
        let o = ip.octets();
        ensure!(
            o[0] == 127 && !(o[1] == 255 && o[2] == 255) && o[3] != 255,
            "DNSBL provider error"
        );
        if o[1] == 0 {
            listed = true;
        } else {
            anyhow::bail!("unexpected DNSBL response");
        }
    }
    Ok(listed)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "semantic")]
    #[test]
    fn semantic_score_is_added_once_and_failure_preserves_lexical_fallback() {
        let config = Config::load(Path::new("config/development.toml")).unwrap();
        let engine = Engine::new(Arc::new(config)).unwrap();
        let mut scan = extract(
            b"From: sender@example.org\r\nSubject: Meeting\r\n\r\nMeeting tomorrow.",
            2048,
        );
        scan.feature_version = crate::features::VERSION;
        engine.score(&mut scan);
        let fallback = scan.score;
        scan.semantic = SemanticResult {
            status: SemanticStatus::Complete,
            model: "hybrid-fixture".into(),
            contribution: Some(8.0),
            ..Default::default()
        };
        engine.score(&mut scan);
        let combined = scan.score;
        assert!((combined - sigmoid(3.0) * 100.0).abs() < 1e-9);
        engine.score(&mut scan);
        assert_eq!(scan.score, combined);
        scan.semantic.status = SemanticStatus::Busy;
        Engine::check_semantic(&mut scan);
        engine.score(&mut scan);
        assert!(!scan.complete);
        assert_eq!(scan.score, fallback);
        assert!(
            scan.reasons
                .iter()
                .any(|reason| reason.id == "semantic_unavailable")
        );
    }
    #[test]
    fn reputation_decodes_mime_links_and_ignores_filter_headers_and_attachments() {
        let encoded = b"From: sender@example.org\r\nX-Old-Filter: https://ignore.example/result\r\nContent-Type: multipart/mixed; boundary=test\r\n\r\n--test\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\naHR0cHM6Ly9oaWRkZW4uZXhhbXBsZS9sb2dpbg==\r\n--test\r\nContent-Type: text/html\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n<a href=3D\"https://split.exa=\r\nmple/login\">Open</a>\r\n--test\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename=notes.txt\r\n\r\nhttps://attachment.example/document\r\n--test--\r\n";
        assert_eq!(
            domains_in_message(encoded),
            ["hidden.example", "split.example"]
        );
    }
    #[test]
    fn dnsbl_errors_not_spam() {
        for s in ["127.255.255.250", "127.0.1.255", "8.8.8.8"] {
            assert!(dqs_answer(&[s.parse().unwrap()]).is_err());
        }
        assert!(dqs_answer(&["127.0.0.2".parse().unwrap()]).unwrap());
    }
    #[test]
    fn features_ignore_old_filter_headers() {
        let a = b"From: a@example.org\r\nSubject: Bonjour\r\n\r\nUn message legitime\r\n";
        let b = [b"X-Spam-Status: Yes\r\n".as_slice(), a].concat();
        assert_eq!(extract(a, 10000).features, extract(&b, 10000).features);
    }
}
