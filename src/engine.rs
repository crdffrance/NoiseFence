use crate::{config::Config, message};
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
    /// Missing on older rows: their encoder revision must never be inferred.
    #[serde(default)]
    pub protocol: Option<crate::learning::SemanticProtocol>,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Scan {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery_classification: Option<crate::mailing::Category>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
    /// Exact decision settings at analysis time; absent on historical messages.
    #[serde(default)]
    pub analysis_policy: Option<crate::diagnostics::AnalysisPolicy>,
    #[serde(default)]
    pub action: Option<crate::actions::Applied>,
    #[serde(default = "legacy_feature_version")]
    pub feature_version: u32,
    pub score: f64,
    pub tagged: bool,
    /// Actual [PUB] wire marking; the legacy `tagged` flag continues to mean [SPAM].
    #[serde(default)]
    pub pub_tagged: bool,
    pub complete: bool,
    /// Local extraction result, before DNS/scanners/LLM can fail. Older rows lack it.
    #[serde(default)]
    pub features_complete: Option<bool>,
    pub model: String,
    pub reasons: Vec<Signal>,
    pub features: Vec<(usize, f64)>,
    pub subject: String,
    pub sender: String,
    pub fingerprint: String,
    /// Exact original octets, even when content extraction is limited. This is
    /// distinct from the normalized campaign fingerprint and never a feature.
    #[serde(default)]
    pub raw_sha256: Option<String>,
    #[serde(default)]
    pub campaign_simhash: Option<String>,
    pub elapsed_ms: u64,
    #[serde(default)]
    pub antivirus: crate::antivirus::AntivirusResult,
    #[serde(default)]
    pub signatures: crate::antivirus::AntivirusResult,
    #[serde(default)]
    pub llm: crate::llm::LlmResult,
    #[serde(default)]
    pub semantic: SemanticResult,
    #[serde(default)]
    pub smtp_policy: crate::smtp_policy::PolicyResult,
    /// Socket-IP checks before DATA; diagnostic only, never counted again in scoring.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub early_rbl: Option<crate::rbl::Report>,
    #[serde(default)]
    pub vision: crate::vision::Summary,
    #[serde(default)]
    pub protection: Option<crate::protection::Report>,
    #[serde(default)]
    pub mailing: Option<crate::mailing::Report>,
    /// Absent on historical rows: never infer checks from their missing reasons.
    #[serde(default)]
    pub evidence: Option<crate::evidence::Evidence>,
    /// Canonical decision. Historical rows use their original legacy score.
    #[serde(default)]
    pub decision: Option<crate::fusion::runtime::Decision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arbitration: Option<crate::decision::Arbitration>,
    #[serde(default)]
    pub fusion: crate::fusion::runtime::Observation,
    #[serde(default)]
    pub quality: Option<crate::quality::Report>,
    #[serde(default)]
    pub sender_history: Option<crate::quality::history::Report>,
    #[serde(default)]
    pub native_filter: Option<crate::native_filter::Observation>,
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
        Self::from_bytes(&std::fs::read(path)?)
    }
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let m: Self = serde_json::from_slice(bytes)?;
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
        raw_sha256: Some(message::digest(raw)),
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
struct ReputationTarget {
    domain: String,
    roles: Vec<crate::evidence::DomainRole>,
}
fn reputation_targets(
    raw: &[u8],
    from: &str,
    helo: &str,
    sender: &str,
    visual_domains: &[String],
) -> Vec<ReputationTarget> {
    use crate::evidence::DomainRole;
    // Envelope identities take priority over attacker-controlled body links.
    let mut targets: Vec<ReputationTarget> = Vec::new();
    for (domain, role) in [
        (
            sender.rsplit_once('@').map(|(_, d)| d),
            DomainRole::EnvelopeFrom,
        ),
        (Some(helo), DomainRole::Helo),
        (
            from.rsplit_once('@').map(|(_, d)| d),
            DomainRole::HeaderFrom,
        ),
    ]
    .into_iter()
    .filter_map(|(domain, role)| domain.map(|d| (d.to_owned(), role)))
    .chain(
        visual_domains
            .iter()
            .cloned()
            .chain(domains_in_message(raw))
            .map(|d| (d, DomainRole::Body)),
    ) {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        if crate::config::valid_domain(&domain)
            && domain.contains('.')
            && domain.parse::<IpAddr>().is_err()
        {
            if let Some(target) = targets.iter_mut().find(|t| t.domain == domain) {
                if !target.roles.contains(&role) {
                    target.roles.push(role);
                }
            } else if targets.len() < 12 {
                targets.push(ReputationTarget {
                    domain,
                    roles: vec![role],
                });
            }
        }
    }
    targets
}
#[cfg(test)]
fn reputation_domains(raw: &[u8], from: &str, helo: &str, sender: &str) -> Vec<String> {
    reputation_targets(raw, from, helo, sender, &[])
        .into_iter()
        .map(|t| t.domain)
        .collect()
}
pub struct Engine {
    config: Arc<Config>,
    pub authenticator: MessageAuthenticator,
    model: Option<Model>,
    evidence_artifacts: crate::evidence::Artifacts,
    fusion: Option<crate::fusion::runtime::Runtime>,
    quality: Option<crate::quality::Model>,
    quality_policy: String,
    arc_key: Option<String>,
    dqs_key: Option<String>,
    smtp_policy: Option<crate::smtp_policy::Policy>,
    dqs_cache: Mutex<HashMap<String, (Instant, Vec<std::net::Ipv4Addr>)>>,
    llm: Option<Arc<crate::llm::Client>>,
    vision: Option<Arc<crate::vision::Client>>,
    protection: Option<Arc<crate::protection::Runtime>>,
    native_filter: Option<Arc<crate::native_filter::Runtime>>,
    #[cfg(feature = "semantic")]
    semantic: Option<Arc<crate::semantic::Hybrid>>,
}
impl Engine {
    pub fn new(config: Arc<Config>) -> Result<Self> {
        Self::build(config, None)
    }
    /// Reuse loaded models and capacity gates across atomic console revisions.
    /// The controller only changes supported flags and routing, never model paths.
    pub(crate) fn reconfigure(&self, config: Arc<Config>) -> Result<Self> {
        Self::build(config, Some(self))
    }
    fn build(config: Arc<Config>, template: Option<&Self>) -> Result<Self> {
        let native_filter = config
            .native_filter
            .as_ref()
            .map(|settings| {
                if let Some(runtime) = template.and_then(|t| t.native_filter.as_ref()) {
                    ensure!(
                        &runtime.settings == settings,
                        "Changing native filter settings requires a restart"
                    );
                    Ok(runtime.clone())
                } else {
                    crate::native_filter::Runtime::new(settings.clone())
                }
            })
            .transpose()?;
        let quality = config
            .quality
            .as_ref()
            .and_then(|q| q.candidate.as_deref())
            .map(crate::quality::Model::load)
            .transpose()?;
        let quality_policy = crate::quality::policy_hash(&config);
        let llm = config
            .llm
            .as_ref()
            .filter(|c| c.monthly_budget_micro_eur > 0)
            .map(|c| match template.and_then(|t| t.llm.clone()) {
                Some(client) => Ok(client),
                None => crate::llm::Client::new(c.clone(), &config.data_dir).map(Arc::new),
            })
            .transpose()?;
        let (model, model_hash) = if let Some(template) = template {
            ensure!(
                config.filter.model == template.config.filter.model,
                "Changing model paths requires a restart"
            );
            // Keep the exact lexical bytes paired with the resident semantic encoder.
            // A file replacement on disk must not silently bypass their calibration binding.
            (
                template.model.clone(),
                template.evidence_artifacts.lexical_model_sha256.clone(),
            )
        } else {
            let bytes = config
                .filter
                .model
                .as_ref()
                .map(std::fs::read)
                .transpose()?;
            (
                bytes.as_deref().map(Model::from_bytes).transpose()?,
                bytes.as_deref().map(message::digest),
            )
        };
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
                if let Some(template) = template {
                    ensure!(
                        config.filter.threshold == template.config.filter.threshold,
                        "Le seuil du modèle multilingue est lié à sa calibration."
                    );
                    if let Some(model) = &template.semantic {
                        return Ok(model.clone());
                    }
                }
                crate::semantic::Hybrid::load_bound(
                    settings,
                    model_hash.as_deref().unwrap(),
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
        let smtp_policy = config
            .smtp_policy
            .clone()
            .map(crate::smtp_policy::Policy::new)
            .transpose()?;
        let protection = config
            .protection
            .as_ref()
            .map(
                |settings| match template.and_then(|t| t.protection.clone()) {
                    Some(runtime) => Ok(runtime),
                    None => {
                        crate::protection::Runtime::new(settings, &config.data_dir).map(Arc::new)
                    }
                },
            )
            .transpose()?;
        let vision = config
            .vision
            .clone()
            .map(|settings| match template.and_then(|t| t.vision.clone()) {
                Some(client) => Ok(client),
                None => crate::vision::Client::new(settings).map(Arc::new),
            })
            .transpose()?;
        #[cfg(feature = "semantic")]
        let semantic_hash = semantic.as_ref().map(|s| s.sha256().to_owned());
        #[cfg(not(feature = "semantic"))]
        let semantic_hash = None;
        let evidence_artifacts =
            crate::evidence::Artifacts::new(&config, model_hash, semantic_hash, llm.is_some());
        let fusion = config
            .fusion
            .as_ref()
            .map(|s| crate::fusion::runtime::Runtime::load(s, &evidence_artifacts))
            .transpose()?;
        Ok(Self {
            native_filter,
            quality,
            quality_policy,
            fusion,
            smtp_policy,
            config,
            authenticator: MessageAuthenticator::new_system_conf()?,
            model,
            evidence_artifacts,
            arc_key,
            dqs_key,
            dqs_cache: Mutex::new(HashMap::new()),
            llm,
            vision,
            protection,
            #[cfg(feature = "semantic")]
            semantic,
        })
    }
    pub fn offline(&self, raw: &[u8]) -> Scan {
        let mut scan = self.extract(raw);
        scan.native_filter = self
            .native_filter
            .as_ref()
            .map(|runtime| runtime.offline(raw, &[]));
        if let Some(settings) = &self.config.mailing {
            scan.mailing = Some(crate::mailing::inspect(
                raw,
                &settings.policy,
                self.config.filter.max_analysis_bytes,
            ));
        }
        self.start_evidence(&mut scan, crate::evidence::Source::ContentOnly);
        #[cfg(feature = "semantic")]
        if scan.complete
            && let Some(model) = &self.semantic
        {
            scan.semantic = model.offline(raw);
            Self::check_semantic(&mut scan);
        }
        if let Some(runtime) = &self.protection {
            scan.protection = Some(runtime.local(raw, "", &self.config).0);
        }
        self.score(&mut scan);
        self.decide(&mut scan);
        scan
    }
    fn start_evidence(&self, scan: &mut Scan, source: crate::evidence::Source) {
        let mut evidence = crate::evidence::Evidence::new(
            &self.config,
            self.evidence_artifacts.clone(),
            self.llm.is_some(),
        );
        evidence.source = source;
        scan.evidence = Some(evidence);
    }
    fn refresh_evidence(scan: &mut Scan) {
        if let Some(mut evidence) = scan.evidence.take() {
            evidence.refresh(scan);
            scan.evidence = Some(evidence);
        }
    }
    fn decide(&self, scan: &mut Scan) {
        scan.analysis_policy = Some(crate::diagnostics::AnalysisPolicy::capture(&self.config));
        // The historical score remains available for the LLM selection policy,
        // evidence export and comparisons. Fusion never feeds itself on a retry.
        scan.reasons.retain(|r| {
            r.id != crate::confirmation::REVIEW_REASON
                && r.id != crate::decision::MALWARE_REASON
                && r.id != crate::decision::REVIEW_REASON
        });
        scan.arbitration = None;
        Self::refresh_evidence(scan);
        scan.decision = Some(crate::fusion::runtime::Decision::legacy(
            scan,
            self.config.filter.threshold,
        ));
        if let Some(fusion) = &self.fusion {
            fusion.apply(scan);
        }
        crate::decision::apply(scan, self.config.filter.require_corroboration);
        if let (Some(runtime), Some(mut observation)) =
            (&self.native_filter, scan.native_filter.take())
        {
            runtime.finish(&mut observation, scan);
            scan.native_filter = Some(observation);
        }
        scan.quality = Some(crate::quality::snapshot_bound(
            scan,
            self.quality.as_ref(),
            Some(&self.quality_policy),
        ));
    }
    pub(crate) fn check_llm(scan: &mut Scan) {
        if matches!(
            scan.llm.status,
            crate::llm::LlmStatus::Unavailable | crate::llm::LlmStatus::Busy
        ) {
            scan.complete = false;
            scan.reasons.push(Signal {
                id: "llm_unavailable".into(),
                detail: "Analyse LLM indisponible ou saturée ; transmission sans préfixe".into(),
                weight: 0.0,
            });
        }
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
        crate::rules::apply(scan, &self.config.filter.rule_weights);
        scan.reasons.retain(|r| r.id != "model_contribution");
        let mut content = self
            .model
            .as_ref()
            .map(|m| {
                scan.model = m.version.clone();
                m.logit(&scan.features)
            })
            .unwrap_or(-5.0);
        if self.model.is_some()
            && let Some(evidence) = &mut scan.evidence
        {
            evidence.lexical_logit = Some(content);
            evidence.lexical_state = if scan.features_complete.unwrap_or(scan.complete) {
                crate::evidence::State::Complete
            } else {
                crate::evidence::State::Limited
            };
        }
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
    async fn reputation_lookup(
        &self,
        query: &str,
        dataset: crate::evidence::Dataset,
    ) -> Result<Vec<std::net::Ipv4Addr>> {
        if let Some((expires, value)) = self.dqs_cache.lock().unwrap().get(query)
            && *expires > Instant::now()
        {
            return Ok(value.clone());
        }
        let result = self.authenticator.ipv4_lookup_raw(query).await;
        let (value, expires) = match result {
            Ok(records) => (
                crate::evidence::dqs_codes(&records.entry, dataset)?,
                records.expires,
            ),
            Err(mail_auth::Error::Dns(mail_auth::DnsError::RecordNotFound(
                mail_auth::hickory_resolver::proto::op::ResponseCode::NXDomain,
            ))) => return Ok(Vec::new()),
            Err(_) => anyhow::bail!("reputation lookup unavailable"),
        };
        // The underlying resolver owns negative caching and its SOA TTL. The
        // positive cache never extends a record's authoritative lifetime.
        if expires <= Instant::now() {
            return Ok(value);
        }
        let mut cache = self.dqs_cache.lock().unwrap();
        if cache.len() >= 10_000 {
            cache.retain(|_, (end, _)| *end > Instant::now());
            if cache.len() >= 10_000 {
                cache.clear();
            }
        }
        cache.insert(
            query.into(),
            (
                expires.min(Instant::now() + Duration::from_secs(60)),
                value.clone(),
            ),
        );
        Ok(value)
    }
    async fn reputation(
        &self,
        ip: IpAddr,
        raw: &[u8],
        helo: &str,
        sender: &str,
        scan: &mut Scan,
        visual_domains: &[String],
    ) -> Result<()> {
        use crate::evidence::{Dataset, DomainQuery, DomainRole, Query, State};
        let Some(key) = &self.dqs_key else {
            return Ok(());
        };
        let targets = reputation_targets(raw, &scan.sender, helo, sender, visual_domains);
        let evidence = &mut scan
            .evidence
            .as_mut()
            .context("missing reputation evidence")?
            .reputation;
        evidence.state = State::Unavailable;
        evidence.ip.state = State::Unavailable;
        evidence.domains = targets
            .iter()
            .map(|t| DomainQuery {
                roles: t.roles.clone(),
                result: Query::new(State::NotRun),
            })
            .collect();
        let ip = ip.to_canonical();
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
        let codes = self
            .reputation_lookup(
                &format!("{prefix}.{key}.zen.dq.spamhaus.net."),
                Dataset::Zen,
            )
            .await?;
        let ip_positive = crate::evidence::malicious_ip(&codes);
        let ip_policy = !codes.is_empty() && !ip_positive;
        scan.evidence.as_mut().unwrap().reputation.ip = Query {
            state: State::Complete,
            codes,
        };
        if ip_positive {
            scan.reasons.push(Signal {
                id: "ip_reputation".into(),
                detail: "IP signalée par la source de réputation".into(),
                weight: 4.0,
            });
        } else if ip_policy {
            scan.reasons.push(Signal {
                id: "ip_reputation_policy".into(),
                detail: "IP présente dans une liste PBL ou BCL ; observation conservée sans poids de réputation malveillante".into(),
                weight: 0.0,
            });
        }
        for (index, target) in targets.iter().enumerate() {
            scan.evidence.as_mut().unwrap().reputation.domains[index]
                .result
                .state = State::Unavailable;
            let codes = self
                .reputation_lookup(
                    &format!("{}.{key}.dbl.dq.spamhaus.net.", target.domain),
                    Dataset::Dbl,
                )
                .await?;
            let positive = crate::evidence::malicious_domain(&codes);
            let abused = codes.iter().any(|c| c.octets()[3] >= 100);
            scan.evidence.as_mut().unwrap().reputation.domains[index].result = Query {
                state: State::Complete,
                codes,
            };
            if positive {
                scan.reasons.push(Signal {
                    id: "domain_reputation".into(),
                    detail: "Domaine signalé par la source de réputation".into(),
                    weight: 4.0,
                });
                scan.evidence
                    .as_mut()
                    .unwrap()
                    .reputation
                    .stopped_after_positive = index + 1 < targets.len();
                break;
            } else if abused && target.roles.contains(&DomainRole::Body) {
                // Abused legitimate domains are distinct from malicious domains.
                // Retain the body signal for calibration without the legacy +4.
                if !scan.reasons.iter().any(|r| r.id == "abused_domain_body") {
                    scan.reasons.push(Signal {
                        id: "abused_domain_body".into(),
                        detail: "Domaine légitime signalé comme compromis dans un lien ; observation à calibrer".into(),
                        weight: 0.0,
                    });
                }
            }
        }
        scan.evidence.as_mut().unwrap().reputation.state = State::Complete;
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
        let mut variants = self
            .process_with_source(
                raw,
                ip,
                helo,
                sender,
                id,
                (crate::evidence::Source::SuppliedEnvelope, &[], &[], None),
            )
            .await?;
        let variant = variants.remove(0);
        Ok((variant.scan, variant.raw))
    }
    pub(crate) async fn process_smtp(
        &self,
        raw: &[u8],
        ip: IpAddr,
        helo: &str,
        sender: &str,
        id: &str,
        context: (&[crate::config::Recipient], &crate::rbl::Report),
    ) -> Result<Vec<crate::store::QueueVariant>> {
        let (recipients, early_rbl) = context;
        let scopes: Vec<_> = recipients
            .iter()
            .filter_map(|r| {
                r.destination
                    .rsplit_once('@')
                    .map(|(_, d)| d.to_ascii_lowercase())
            })
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        self.process_with_source(
            raw,
            ip,
            helo,
            sender,
            id,
            (
                crate::evidence::Source::SmtpSession,
                &scopes,
                recipients,
                Some(early_rbl),
            ),
        )
        .await
    }
    async fn process_with_source(
        &self,
        raw: &[u8],
        ip: IpAddr,
        helo: &str,
        sender: &str,
        id: &str,
        context: (
            crate::evidence::Source,
            &[String],
            &[crate::config::Recipient],
            Option<&crate::rbl::Report>,
        ),
    ) -> Result<Vec<crate::store::QueueVariant>> {
        let started = Instant::now();
        let mut scan = self.extract(raw);
        scan.features_complete.get_or_insert(scan.complete);
        if let Some(settings) = &self.config.mailing {
            scan.mailing = Some(crate::mailing::inspect(
                raw,
                &settings.policy,
                self.config.filter.max_analysis_bytes,
            ));
        }
        self.start_evidence(&mut scan, context.0);
        let headers = message::fields(raw)?.0;
        let (semantic, antivirus, signatures, vision, native_filter) = tokio::join!(
            async {
                #[cfg(feature = "semantic")]
                if scan.complete
                    && let Some(model) = &self.semantic
                {
                    return model.analyze(raw.to_vec()).await;
                }
                SemanticResult::default()
            },
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
            },
            async {
                match &self.vision {
                    Some(client) => Some(client.inspect(raw).await),
                    None => None,
                }
            },
            async {
                match &self.native_filter {
                    Some(runtime) => Some(runtime.inspect(raw, context.1).await),
                    None => None,
                }
            }
        );
        scan.native_filter = native_filter;
        scan.semantic = semantic;
        #[cfg(feature = "semantic")]
        Self::check_semantic(&mut scan);
        let mut visual_domains = Vec::new();
        let mut visual_text = String::new();
        if let Some(mut inspection) = vision {
            visual_domains = inspection.domains();
            visual_text = inspection.text();
            if let Some(model) = &self.model
                && inspection.summary.status == crate::vision::Status::Complete
                && inspection.summary.text_chars > 0
            {
                // Independent observation: keep the trained mail feature schema intact.
                use base64::Engine as _;
                let text: String = inspection.text().chars().take(32_000).collect();
                let encoded = base64::engine::general_purpose::STANDARD.encode(text);
                let local = format!(
                    "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n{encoded}\r\n"
                );
                inspection.summary.lexical_logit =
                    Some(model.logit(&self.extract(local.as_bytes()).features));
            }
            inspection.apply(
                &mut scan,
                self.config
                    .vision
                    .as_ref()
                    .is_some_and(|c| c.contribute_to_score),
            );
        }
        let targets = if let Some(runtime) = &self.protection {
            let (report, targets) = runtime.local(raw, &visual_text, &self.config);
            scan.protection = Some(report);
            targets
        } else {
            Default::default()
        };
        scan.antivirus = antivirus;
        scan.signatures = signatures;
        if scan.signatures.status != crate::antivirus::AntivirusStatus::Disabled {
            // Keep the scanner result before the advisory-only delivery policy.
            scan.evidence.as_mut().unwrap().signatures = Some(scan.signatures.clone());
        }
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
        let excessive_signatures = headers
            .iter()
            .filter(|h| message::name(h) == "dkim-signature")
            .count()
            > 16
            || headers
                .iter()
                .filter(|h| message::name(h).starts_with("arc-"))
                .count()
                > 150;
        if excessive_signatures {
            scan.complete = false;
            scan.reasons.push(Signal {
                id: "signature_budget".into(),
                detail: "Nombre de signatures supérieur au budget de vérification".into(),
                weight: 0.0,
            });
        }
        // A limited OCR or scanner result must not skip safe authentication and
        // reputation checks. Keep completeness false and the delivery fallback.
        // Extraction and signature limits still bound parsing/authentication work.
        if !scan.features_complete.unwrap_or(scan.complete) || excessive_signatures {
            return self.finish_unchecked(
                raw,
                scan,
                ip,
                id,
                started,
                (sender, context.2, context.3),
            );
        }
        let work = async {
            let authenticated =
                AuthenticatedMessage::parse(raw).context("authentication parsing failed")?;
            if self.smtp_policy.is_some() {
                scan.smtp_policy.status = crate::smtp_policy::PolicyStatus::Unavailable;
                scan.smtp_policy.version = crate::smtp_policy::VERSION.into();
            }
            let policy_work = async {
                match &self.smtp_policy {
                    Some(policy) => policy.check(ip, helo, sender, &self.config.hostname).await,
                    None => Default::default(),
                }
            };
            let auth_work = async {
                let mut results = AuthenticationResults::new(&self.config.hostname);
                scan.evidence.as_mut().unwrap().authentication.arc_state =
                    crate::evidence::State::Unavailable;
                let arc = self.authenticator.verify_arc(&authenticated).await;
                {
                    let auth = &mut scan.evidence.as_mut().unwrap().authentication;
                    auth.arc = Some(arc.result().into());
                    auth.arc_can_seal = Some(arc.can_be_sealed());
                    if matches!(arc.result(), DkimResult::TempError(_)) {
                        anyhow::bail!("ARC verification temporary error");
                    }
                    auth.arc_state = crate::evidence::State::Complete;
                }
                if self.config.filter.authentication {
                    scan.evidence.as_mut().unwrap().authentication.state =
                        crate::evidence::State::Unavailable;
                    let (dkim, spf) = {
                        let crate::evidence::Authentication {
                            spf: observed_spf,
                            spf_state,
                            dkim: observed_dkim,
                            dkim_state,
                            ..
                        } = &mut scan.evidence.as_mut().unwrap().authentication;
                        tokio::join!(
                            async {
                                *dkim_state = crate::evidence::State::Unavailable;
                                let result = self.authenticator.verify_dkim(&authenticated).await;
                                *observed_dkim =
                                    Some(result.iter().map(|d| d.result().into()).collect());
                                if !result
                                    .iter()
                                    .any(|d| matches!(d.result(), DkimResult::TempError(_)))
                                {
                                    *dkim_state = crate::evidence::State::Complete;
                                }
                                result
                            },
                            async {
                                *spf_state = crate::evidence::State::Unavailable;
                                let result = self
                                    .authenticator
                                    .verify_spf(SpfParameters::verify_mail_from(
                                        ip,
                                        helo,
                                        &self.config.hostname,
                                        sender,
                                    ))
                                    .await;
                                *observed_spf = Some(result.result().into());
                                if result.result() != SpfResult::TempError {
                                    *spf_state = crate::evidence::State::Complete;
                                }
                                result
                            }
                        )
                    };
                    let domain = sender.rsplit_once('@').map(|x| x.1).unwrap_or(helo);
                    scan.evidence.as_mut().unwrap().authentication.dmarc_state =
                        crate::evidence::State::Unavailable;
                    let dmarc = self
                        .authenticator
                        .verify_dmarc(DmarcParameters::new(&authenticated, &dkim, domain, &spf))
                        .await;
                    {
                        let auth = &mut scan.evidence.as_mut().unwrap().authentication;
                        auth.dmarc_spf = Some(dmarc.spf_result().into());
                        auth.dmarc_dkim = Some(dmarc.dkim_result().into());
                        if !matches!(dmarc.spf_result(), DmarcResult::TempError(_))
                            && !matches!(dmarc.dkim_result(), DmarcResult::TempError(_))
                        {
                            auth.dmarc_state = crate::evidence::State::Complete;
                        }
                    }
                    if spf.result() == SpfResult::TempError
                        || dkim
                            .iter()
                            .any(|d| matches!(d.result(), DkimResult::TempError(_)))
                        || matches!(dmarc.spf_result(), DmarcResult::TempError(_))
                        || matches!(dmarc.dkim_result(), DmarcResult::TempError(_))
                    {
                        anyhow::bail!("authentication temporary error");
                    }
                    scan.evidence.as_mut().unwrap().authentication.state =
                        crate::evidence::State::Complete;
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
                Ok::<_, anyhow::Error>((arc, results))
            };
            let (auth_result, policy_result) = tokio::join!(auth_work, policy_work);
            policy_result.apply(&mut scan);
            scan.smtp_policy = policy_result;
            let (arc, results) = auth_result?;
            scan.sender_history = Some(
                crate::quality::history::inspect_with_context(
                    &self.config.data_dir,
                    raw,
                    &scan,
                    context.1,
                    context.2,
                    &targets,
                )
                .await,
            );
            if let (Some(runtime), Some(observation)) =
                (&self.native_filter, &mut scan.native_filter)
            {
                runtime
                    .remember(
                        &self.config.data_dir,
                        observation,
                        context.1,
                        scan.raw_sha256.as_deref().unwrap_or(""),
                    )
                    .await;
            }
            self.reputation(ip, raw, helo, sender, &mut scan, &visual_domains)
                .await?;
            self.score(&mut scan);
            let selection = self.config.llm.as_ref().map(|c| c.selection(&scan));
            let needs_llm = self.llm.is_some()
                && selection.is_some_and(|s| s != crate::llm::Selection::NotSelected);
            if self.llm.is_some() {
                scan.llm.selection = selection;
                scan.llm.status = crate::llm::LlmStatus::NotNeeded;
            }
            if needs_llm {
                // Preserve an attempted-check marker if the enclosing DNS/LLM deadline cancels it.
                scan.llm.status = crate::llm::LlmStatus::Unavailable;
                scan.llm.prompt_version = crate::llm::PROMPT_VERSION.into();
                scan.llm.model = self.config.llm.as_ref().unwrap().model.clone();
                scan.evidence.as_mut().unwrap().llm.requested_at_score = Some(scan.score);
                if selection == Some(crate::llm::Selection::UnconfirmedHigh) {
                    scan.reasons.push(Signal {
                        id: "llm_review_unconfirmed".into(),
                        detail: "Second avis demandé : score élevé sans confirmation suffisante."
                            .into(),
                        weight: 0.0,
                    });
                }
            }
            // Protection is advisory and does not change the LLM selection
            // score. Overlap these independent calls under the existing deadline.
            let (_, llm_result) = tokio::join!(
                async {
                    if let (Some(runtime), Some(settings)) =
                        (&self.protection, &self.config.protection)
                    {
                        runtime
                            .observe(&mut scan, targets, &settings.policy, context.1)
                            .await;
                    }
                },
                async {
                    if needs_llm {
                        Some(
                            self.llm
                                .as_ref()
                                .unwrap()
                                .classify_selected(raw, selection.unwrap())
                                .await,
                        )
                    } else {
                        None
                    }
                }
            );
            if let Some(result) = llm_result {
                scan.llm = result;
                if let Some(verdict) = &scan.llm.verdict {
                    let weight = scan.llm.advisory_weight();
                    scan.reasons.push(Signal {
                        id: "llm_advisory".into(),
                        detail: format!("Analyse LLM consultative : {}", verdict.explanation),
                        weight,
                    });
                    self.score(&mut scan);
                }
                Self::check_llm(&mut scan);
            }
            self.decide(&mut scan);
            // Header timing is the completed analysis, before wire rendering/ARC.
            // The stored elapsed time below additionally includes these operations.
            scan.elapsed_ms = started.elapsed().as_millis() as u64;
            self.variants(raw, &scan, sender, id, context.2, |scan, variant_id| {
                let subject_tag = if scan
                    .action
                    .as_ref()
                    .is_some_and(|a| a.effective == crate::actions::Action::Tag)
                {
                    match crate::mailing::category(scan, self.config.filter.threshold) {
                        crate::mailing::Category::Spam => Some(message::SubjectTag::Spam),
                        crate::mailing::Category::Publicity => Some(message::SubjectTag::Publicity),
                        _ => None,
                    }
                } else {
                    None
                };
                let tag = subject_tag == Some(message::SubjectTag::Spam);
                let pub_tag = subject_tag == Some(message::SubjectTag::Publicity);
                // If the chain cannot be extended, preserve the signed subject and fail open.
                if (tag || pub_tag) && !arc.can_be_sealed() {
                    anyhow::bail!("ARC chain cannot be extended");
                }
                scan.tagged = tag;
                scan.pub_tagged = pub_tag;
                let mut bytes = message::rewrite_with_tag(
                    raw,
                    subject_tag,
                    &format!(
                        "{}{}",
                        self.headers(ip, variant_id, scan, context.3),
                        results.to_header()
                    ),
                )?;
                if let Some(key) = &self.arc_key
                    && arc.can_be_sealed()
                {
                    let changed =
                        AuthenticatedMessage::parse(&bytes).context("modified message parse")?;
                    let signature = ArcSealer::from_key(rsa_key(key)?)
                        .domain(self.config.filter.arc_domain.as_deref().unwrap())
                        .selector(self.config.filter.arc_selector.as_deref().unwrap())
                        .headers(crate::scan_headers::signed_fields())
                        .seal(&changed, &results, &arc)?;
                    bytes = [signature.to_header().as_bytes(), &bytes].concat();
                }
                Ok(bytes)
            })
        };
        match tokio::time::timeout(Duration::from_secs(5), work).await {
            Ok(Ok(mut variants)) => {
                for v in &mut variants {
                    v.scan.elapsed_ms = started.elapsed().as_millis() as u64;
                }
                // decide() already snapshotted detector availability. A fusion
                // profile failure must not rewrite those observations as failed checks.
                Ok(variants)
            }
            _ => {
                scan.complete = false;
                scan.tagged = false;
                scan.pub_tagged = false;
                scan.reasons.push(Signal {
                    id: "checks_unavailable".into(),
                    detail: "Vérifications incomplètes ou délai dépassé".into(),
                    weight: 0.0,
                });
                self.finish_unchecked(raw, scan, ip, id, started, (sender, context.2, context.3))
            }
        }
    }
    fn variants(
        &self,
        raw: &[u8],
        scan: &Scan,
        sender: &str,
        id: &str,
        recipients: &[crate::config::Recipient],
        mut render: impl FnMut(&mut Scan, &str) -> Result<Vec<u8>>,
    ) -> Result<Vec<crate::store::QueueVariant>> {
        use crate::{actions::Action, store::QueueVariant};
        let mut variants: Vec<QueueVariant> = Vec::new();
        let mut base = scan.clone();
        base.action = Some(crate::actions::evaluate(scan, &self.config));
        if let Some(policy) = &self.config.custom_filtering
            && !recipients.is_empty()
        {
            let facts = crate::custom_filtering::Facts::message(
                raw,
                sender,
                scan,
                self.config.filter.max_analysis_bytes,
            );
            let prepared = crate::custom_filtering::Prepared::new(policy, &facts);
            for recipient in recipients {
                let assessment = crate::custom_filtering::assess_prepared(
                    policy,
                    &self.config,
                    scan,
                    &prepared,
                    recipient,
                    crate::now(),
                );
                let category = assessment.category;
                let tag = assessment.action.effective == Action::Tag;
                if let Some(v) = variants.iter_mut().find(|v| {
                    v.scan.delivery_classification == Some(category)
                        && (v.scan.tagged || v.scan.pub_tagged) == tag
                }) {
                    v.recipients.push((recipient.clone(), Some(assessment)));
                    // Distinct per-recipient actions are shown on the delivery, not as a global assertion.
                    v.scan.action = None;
                } else {
                    let mut s = base.clone();
                    s.delivery_classification = Some(category);
                    s.transaction_id = Some(id.into());
                    s.action = Some(assessment.action.clone());
                    let variant_id = if variants.is_empty() {
                        id.to_owned()
                    } else {
                        uuid::Uuid::new_v4().to_string()
                    };
                    let wire = render(&mut s, &variant_id)?;
                    variants.push(QueueVariant {
                        id: variant_id,
                        scan: s,
                        raw: wire,
                        recipients: vec![(recipient.clone(), Some(assessment))],
                    });
                }
            }
        } else {
            let wire = render(&mut base, id)?;
            variants.push(QueueVariant {
                id: id.into(),
                scan: base,
                raw: wire,
                recipients: recipients.iter().cloned().map(|r| (r, None)).collect(),
            });
        }
        anyhow::ensure!(variants.len() <= 6, "too many policy wire variants");
        Ok(variants)
    }
    fn headers(
        &self,
        ip: IpAddr,
        id: &str,
        scan: &Scan,
        early_rbl: Option<&crate::rbl::Report>,
    ) -> String {
        crate::scan_headers::render(&self.config, ip, id, scan, early_rbl)
    }
    fn finish_unchecked(
        &self,
        raw: &[u8],
        mut scan: Scan,
        ip: IpAddr,
        id: &str,
        started: Instant,
        context: (
            &str,
            &[crate::config::Recipient],
            Option<&crate::rbl::Report>,
        ),
    ) -> Result<Vec<crate::store::QueueVariant>> {
        self.score(&mut scan);
        scan.tagged = false;
        scan.pub_tagged = false;
        self.decide(&mut scan);
        scan.action = Some(crate::actions::evaluate(&scan, &self.config));
        scan.elapsed_ms = started.elapsed().as_millis() as u64;
        self.variants(raw, &scan, context.0, id, context.1, |scan, variant_id| {
            message::rewrite(raw, false, &self.headers(ip, variant_id, scan, context.2))
        })
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
    #[test]
    fn visual_links_keep_a_reputation_slot_after_envelope_identities() {
        let raw = format!(
            "Subject: visual links\r\n\r\n{}",
            (0..12)
                .map(|i| format!("https://footer{i}.example.org/ "))
                .collect::<String>()
        );
        let visual = vec!["qr.example.invalid".into()];
        let targets = super::reputation_targets(
            raw.as_bytes(),
            "from@example.org",
            "mx.example.org",
            "sender@example.org",
            &visual,
        );
        assert_eq!(targets.len(), 12);
        assert_eq!(targets[0].domain, "example.org");
        assert_eq!(targets[1].domain, "mx.example.org");
        assert_eq!(targets[2].domain, "qr.example.invalid");
        assert_eq!(targets[2].roles, [crate::evidence::DomainRole::Body]);
    }
    use super::*;
    #[tokio::test]
    async fn reputation_categories_and_context_are_preserved_without_penalizing_abused_identities()
    {
        use crate::evidence::{Artifacts, DomainRole, Source, State};
        for (code, body, ip_code, expected_weight, expected_ip_weight) in [
            (102, false, None, 0.0, 0.0),
            (104, true, None, 0.0, 0.0),
            (4, false, None, 4.0, 0.0),
            (102, false, Some(2), 0.0, 4.0),
            (102, false, Some(10), 0.0, 0.0),
            (102, false, Some(11), 0.0, 0.0),
            (102, false, Some(30), 0.0, 0.0),
        ] {
            let mut config = Config::load(Path::new("config/development.toml")).unwrap();
            let mut engine = Engine::new(Arc::new(config.clone())).unwrap();
            // Local cached provider fixtures avoid environment mutation and paid DNS.
            config.filter.spamhaus_key_env = Some("FIXTURE_KEY_NAME".into());
            engine.config = Arc::new(config);
            engine.dqs_key = Some("provider-fixture-key".into());
            engine.evidence_artifacts = Artifacts::new(&engine.config, None, None, false);
            for (name, values) in [
                (
                    "1.2.0.192.provider-fixture-key.zen.dq.spamhaus.net.",
                    ip_code
                        .map(|c| std::net::Ipv4Addr::new(127, 0, 0, c))
                        .into_iter()
                        .collect(),
                ),
                (
                    "example.org.provider-fixture-key.dbl.dq.spamhaus.net.",
                    vec![std::net::Ipv4Addr::new(127, 0, 1, code)],
                ),
            ] {
                engine.dqs_cache.lock().unwrap().insert(
                    name.into(),
                    (Instant::now() + Duration::from_secs(60), values),
                );
            }
            let raw = if body {
                "From: from@example.org\r\nSubject: x\r\n\r\nhttps://example.org/\r\n"
            } else {
                "From: from@example.org\r\nSubject: x\r\n\r\nHello\r\n"
            };
            let mut scan = engine.extract(raw.as_bytes());
            engine.start_evidence(&mut scan, Source::SuppliedEnvelope);
            engine
                .reputation(
                    "::ffff:192.0.2.1".parse().unwrap(),
                    raw.as_bytes(),
                    "EXAMPLE.ORG.",
                    "sender@example.org",
                    &mut scan,
                    &[],
                )
                .await
                .unwrap();
            let observed = &scan.evidence.as_ref().unwrap().reputation;
            assert_eq!(observed.state, State::Complete);
            assert_eq!(observed.ip.state, State::Complete);
            assert_eq!(
                observed.ip.codes,
                ip_code
                    .map(|c| std::net::Ipv4Addr::new(127, 0, 0, c))
                    .into_iter()
                    .collect::<Vec<_>>()
            );
            assert_eq!(observed.domains.len(), 1);
            assert_eq!(observed.domains[0].roles.contains(&DomainRole::Body), body);
            assert_eq!(observed.domains[0].roles.len(), if body { 4 } else { 3 });
            assert_eq!(
                observed.domains[0].result.codes,
                [std::net::Ipv4Addr::new(127, 0, 1, code)]
            );
            assert_eq!(
                scan.reasons
                    .iter()
                    .filter(|r| r.id == "domain_reputation" || r.id == "abused_domain_body")
                    .map(|r| r.weight)
                    .sum::<f64>(),
                expected_weight
            );
            let text = serde_json::to_string(scan.evidence.as_ref().unwrap()).unwrap();
            assert!(!text.contains("provider-fixture-key") && !text.contains("example.org"));
            assert_eq!(
                scan.reasons
                    .iter()
                    .filter(|r| r.id == "ip_reputation" || r.id == "ip_reputation_policy")
                    .map(|r| r.weight)
                    .sum::<f64>(),
                expected_ip_weight
            );
            assert_eq!(
                scan.reasons.iter().any(|r| r.id == "ip_reputation_policy"),
                ip_code.is_some_and(|c| matches!(c, 10 | 11 | 30))
            );
        }
    }
    #[tokio::test]
    async fn reputation_short_circuit_keeps_later_queries_unexecuted() {
        use crate::evidence::{Artifacts, Source, State};
        let mut config = Config::load(Path::new("config/development.toml")).unwrap();
        let mut engine = Engine::new(Arc::new(config.clone())).unwrap();
        config.filter.spamhaus_key_env = Some("FIXTURE_KEY_NAME".into());
        engine.config = Arc::new(config);
        engine.dqs_key = Some("fixture".into());
        engine.evidence_artifacts = Artifacts::new(&engine.config, None, None, false);
        for (name, codes) in [
            ("1.2.0.192.fixture.zen.dq.spamhaus.net.", vec![]),
            (
                "example.org.fixture.dbl.dq.spamhaus.net.",
                vec!["127.0.1.4".parse().unwrap()],
            ),
        ] {
            engine.dqs_cache.lock().unwrap().insert(
                name.into(),
                (Instant::now() + Duration::from_secs(60), codes),
            );
        }
        let raw = b"From: from@example.org\r\nSubject: x\r\n\r\nhttps://other.example/\r\n";
        let mut scan = engine.extract(raw);
        engine.start_evidence(&mut scan, Source::SuppliedEnvelope);
        engine
            .reputation(
                "192.0.2.1".parse().unwrap(),
                raw,
                "example.org",
                "sender@example.org",
                &mut scan,
                &[],
            )
            .await
            .unwrap();
        let evidence = &scan.evidence.unwrap().reputation;
        assert!(evidence.stopped_after_positive);
        assert_eq!(evidence.domains.len(), 2);
        assert_eq!(evidence.domains[0].result.state, State::Complete);
        assert_eq!(evidence.domains[1].result.state, State::NotRun);
    }
    #[test]
    fn domain_reputation_prioritizes_envelope_and_helo_without_duplicate_weights() {
        let raw = format!(
            "From: from@example.org\r\nSubject: links\r\n\r\n{}",
            (0..20)
                .map(|n| format!("https://a{n}.example.net "))
                .collect::<String>()
        );
        let domains = reputation_domains(
            raw.as_bytes(),
            "from@example.org",
            "MX.EXAMPLE.ORG.",
            "bounce@sender.example.org",
        );
        assert_eq!(
            &domains[..3],
            &["sender.example.org", "mx.example.org", "example.org"]
        );
        assert_eq!(domains.len(), 12);
        assert_eq!(
            reputation_domains(
                b"Subject: x\r\n\r\n",
                "from@example.org",
                "EXAMPLE.ORG.",
                "sender@example.org"
            ),
            ["example.org"]
        );
        assert!(reputation_domains(b"Subject: x\r\n\r\n", "", "[IPv6:2001:db8::1]", "").is_empty());
    }
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
