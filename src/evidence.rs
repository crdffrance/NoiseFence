//! Trusted, bounded observations for learning a joint decision later.
//! No mail identity, message text, DNS name or provider secret is retained here.
use crate::{antivirus, engine, learning::SemanticProtocol, llm, smtp_policy};
use anyhow::{Result, ensure};
use mail_auth::{DkimResult, DmarcResult, SpfResult};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

pub const SCHEMA: &str = "noisefence-evidence-1";
pub const REPUTATION_VERSION: &str = "spamhaus-context-1";

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    ContentOnly,
    SuppliedEnvelope,
    SmtpSession,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Disabled,
    NotRun,
    Complete,
    Unavailable,
    Busy,
    Skipped,
    Limited,
}
impl State {
    pub fn configured(enabled: bool) -> Self {
        if enabled {
            Self::NotRun
        } else {
            Self::Disabled
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthResult {
    Pass,
    Fail,
    SoftFail,
    Neutral,
    None,
    TempError,
    PermError,
}
impl From<SpfResult> for AuthResult {
    fn from(result: SpfResult) -> Self {
        match result {
            SpfResult::Pass => Self::Pass,
            SpfResult::Fail => Self::Fail,
            SpfResult::SoftFail => Self::SoftFail,
            SpfResult::Neutral => Self::Neutral,
            SpfResult::None => Self::None,
            SpfResult::TempError => Self::TempError,
            SpfResult::PermError => Self::PermError,
        }
    }
}
impl From<&DkimResult> for AuthResult {
    fn from(result: &DkimResult) -> Self {
        match result {
            DkimResult::Pass => Self::Pass,
            DkimResult::Fail(_) => Self::Fail,
            DkimResult::Neutral(_) => Self::Neutral,
            DkimResult::None => Self::None,
            DkimResult::TempError(_) => Self::TempError,
            DkimResult::PermError(_) => Self::PermError,
        }
    }
}
impl From<&DmarcResult> for AuthResult {
    fn from(result: &DmarcResult) -> Self {
        match result {
            DmarcResult::Pass => Self::Pass,
            DmarcResult::Fail(_) => Self::Fail,
            DmarcResult::None => Self::None,
            DmarcResult::TempError(_) => Self::TempError,
            DmarcResult::PermError(_) => Self::PermError,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authentication {
    pub state: State,
    pub spf_state: State,
    pub spf: Option<AuthResult>,
    pub dkim_state: State,
    pub dkim: Option<Vec<AuthResult>>,
    pub dmarc_state: State,
    pub dmarc_spf: Option<AuthResult>,
    pub dmarc_dkim: Option<AuthResult>,
    /// ARC is checked independently even when SPF/DKIM/DMARC are disabled.
    pub arc_state: State,
    pub arc: Option<AuthResult>,
    pub arc_can_seal: Option<bool>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DomainRole {
    EnvelopeFrom,
    Helo,
    HeaderFrom,
    Body,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dataset {
    Zen,
    Dbl,
}

/// Unknown, mixed-zone and provider error codes never become a spam hit.
pub fn dqs_codes(records: &[Ipv4Addr], dataset: Dataset) -> Result<Vec<Ipv4Addr>> {
    ensure!(
        !records.is_empty() && records.len() <= 32,
        "invalid DQS answer size"
    );
    for address in records {
        let [a, b, c, d] = address.octets();
        let known = match dataset {
            Dataset::Zen => c == 0 && matches!(d, 2 | 3 | 4 | 9 | 10 | 11 | 30),
            Dataset::Dbl => c == 1 && matches!(d, 2 | 4 | 5 | 6 | 102 | 103 | 104 | 105 | 106),
        };
        ensure!(
            a == 127 && b == 0 && known,
            "DQS provider error or unsupported return code"
        );
    }
    let mut codes = records.to_vec();
    codes.sort_unstable();
    codes.dedup();
    Ok(codes)
}

pub fn malicious_domain(codes: &[Ipv4Addr]) -> bool {
    codes
        .iter()
        .any(|code| matches!(code.octets(), [127, 0, 1, 2 | 4 | 5 | 6]))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Query {
    pub state: State,
    /// Empty with Complete means a verified negative answer, not an error.
    pub codes: Vec<Ipv4Addr>,
}
impl Query {
    pub fn new(state: State) -> Self {
        Self {
            state,
            codes: Vec::new(),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainQuery {
    pub roles: Vec<DomainRole>,
    pub result: Query,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reputation {
    pub state: State,
    pub version: String,
    pub ip: Query,
    pub domains: Vec<DomainQuery>,
    /// Later domain queries explicitly remain NotRun after this short circuit.
    pub stopped_after_positive: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Artifacts {
    pub application: String,
    pub dependency_lock_sha256: String,
    pub policy_sha256: String,
    pub lexical_model_sha256: Option<String>,
    pub semantic_model_sha256: Option<String>,
    pub semantic_protocol: Option<SemanticProtocol>,
    pub llm_prompt_sha256: Option<String>,
    /// ClamD does not identify its exact loaded definition set per INSTREAM.
    /// Never fill these from a mutable on-disk directory or an unrelated VERSION.
    pub antivirus_database_sha256: Option<String>,
    pub signatures_database_sha256: Option<String>,
    /// The provider's mutable model name is not an immutable model revision.
    pub llm_model_revision: Option<String>,
}

impl Artifacts {
    pub fn new(
        config: &crate::config::Config,
        lexical: Option<String>,
        semantic: Option<String>,
        llm_enabled: bool,
    ) -> Self {
        // Only behavior-affecting settings. No keys, environment variable names,
        // filesystem paths, recipient identities or cloud account identifiers.
        let av = |value: &Option<antivirus::AntivirusConfig>| {
            value.as_ref().map(|c| {
                serde_json::json!({"timeout_ms":c.timeout_ms,"max_bytes":c.max_bytes,
                "trusted_prefixes":c.trusted_unofficial_prefixes})
            })
        };
        let policy = serde_json::json!({
            "application":env!("CARGO_PKG_VERSION"), "schema":SCHEMA,
            "rules":"legacy-rules-with-contextual-dqs-1", "semantic_compiled":cfg!(feature="semantic"),
            "max_analysis_bytes":config.filter.max_analysis_bytes, "threshold":config.filter.threshold,
            "authentication":config.filter.authentication,
            "reputation_enabled":config.filter.spamhaus_key_env.is_some(), "reputation":REPUTATION_VERSION,
            "antivirus":av(&config.antivirus),"signatures":av(&config.signatures),
            "vision":config.vision.as_ref().map(|c| serde_json::json!({
                "protocol":crate::vision::PROTOCOL,"worker":crate::vision::worker_sha256(),
                "backend":c.backend_sha256,"timeout_ms":c.timeout_ms,"max_parallel":c.max_parallel,
                "max_parts":c.max_parts,"max_part_bytes":c.max_part_bytes,"max_total_bytes":c.max_total_bytes,
                "max_pixels":c.max_pixels,"max_pages":c.max_pages,"max_text_chars":c.max_text_chars,
                "max_codes":c.max_codes,"contribute":c.contribute_to_score})),
            "semantic":config.filter.semantic.as_ref().map(|c| (c.max_parallel,c.timeout_ms)),
            "smtp_policy":config.smtp_policy.as_ref().map(|c| serde_json::json!({
                "version":smtp_policy::VERSION,"contribute":c.contribute_to_score,
                "timeout_ms":c.timeout_ms,"max_parallel":c.max_parallel,
                "cache_entries":c.cache_entries,"cache_ttl_seconds":c.cache_ttl_seconds})),
            "llm_enabled":llm_enabled,
            "llm":config.llm.as_ref().map(|c| serde_json::json!({
                "model":c.model,"prompt":llm::PROMPT_VERSION,"timeout_ms":c.timeout_ms,
                "max_text_bytes":c.max_text_bytes,"max_output_tokens":c.max_output_tokens,
                "score_low":c.score_low,"score_high":c.score_high,"max_parallel":c.max_parallel,
                "budget":c.monthly_budget_micro_eur,"pricing_checked_at":c.pricing_checked_at,
                "input_price":c.input_micro_eur_per_million,"output_price":c.output_micro_eur_per_million}))
        });
        Self {
            application: env!("CARGO_PKG_VERSION").into(),
            dependency_lock_sha256: crate::message::digest(include_bytes!("../Cargo.lock")),
            policy_sha256: crate::message::digest(policy.to_string().as_bytes()),
            lexical_model_sha256: lexical,
            semantic_protocol: semantic.as_ref().map(|_| SemanticProtocol::pinned()),
            semantic_model_sha256: semantic,
            llm_prompt_sha256: llm_enabled.then(llm::prompt_sha256),
            antivirus_database_sha256: None,
            signatures_database_sha256: None,
            llm_model_revision: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LlmObservation {
    pub state: State,
    pub outcome: Option<llm::LlmStatus>,
    pub model: String,
    pub prompt_version: String,
    pub requested_at_score: Option<f64>,
    pub category: Option<llm::Category>,
    /// Self-reported values; neither is a calibrated probability or a label.
    pub reported_probability: Option<f64>,
    pub reported_confidence: Option<f64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub schema: String,
    pub source: Source,
    pub analysis_complete: bool,
    /// Retrospective baseline only; never a ground-truth label or fusion input.
    pub legacy_score: Option<f64>,
    pub artifacts: Artifacts,
    pub authentication: Authentication,
    pub reputation: Reputation,
    pub lexical_state: State,
    pub lexical_logit: Option<f64>,
    pub semantic_state: State,
    pub semantic_logit: Option<f64>,
    pub antivirus_state: State,
    pub antivirus: Option<antivirus::AntivirusResult>,
    pub signatures_state: State,
    pub signatures: Option<antivirus::AntivirusResult>,
    pub smtp_policy_state: State,
    pub smtp_policy: Option<smtp_policy::PolicyResult>,
    /// Absent on historical rows and when the local vision check did not run.
    #[serde(default)]
    pub vision: Option<crate::vision::Summary>,
    pub llm: LlmObservation,
}

impl Evidence {
    pub fn new(config: &crate::config::Config, artifacts: Artifacts, llm_enabled: bool) -> Self {
        Self {
            schema: SCHEMA.into(),
            source: Source::ContentOnly,
            analysis_complete: false,
            legacy_score: None,
            lexical_state: State::configured(artifacts.lexical_model_sha256.is_some()),
            lexical_logit: None,
            semantic_state: State::configured(artifacts.semantic_model_sha256.is_some()),
            semantic_logit: None,
            artifacts,
            authentication: Authentication {
                state: State::configured(config.filter.authentication),
                spf_state: State::configured(config.filter.authentication),
                spf: None,
                dkim_state: State::configured(config.filter.authentication),
                dkim: None,
                dmarc_state: State::configured(config.filter.authentication),
                dmarc_spf: None,
                dmarc_dkim: None,
                arc_state: State::NotRun,
                arc: None,
                arc_can_seal: None,
            },
            reputation: Reputation {
                state: State::configured(config.filter.spamhaus_key_env.is_some()),
                version: REPUTATION_VERSION.into(),
                ip: Query::new(State::configured(config.filter.spamhaus_key_env.is_some())),
                domains: Vec::new(),
                stopped_after_positive: false,
            },
            antivirus_state: State::configured(config.antivirus.is_some()),
            antivirus: Default::default(),
            signatures_state: State::configured(config.signatures.is_some()),
            signatures: Default::default(),
            smtp_policy_state: State::configured(config.smtp_policy.is_some()),
            smtp_policy: Default::default(),
            vision: None,
            llm: LlmObservation {
                state: State::configured(llm_enabled),
                outcome: (!llm_enabled).then_some(llm::LlmStatus::Disabled),
                model: config
                    .llm
                    .as_ref()
                    .map(|c| c.model.clone())
                    .unwrap_or_default(),
                prompt_version: if llm_enabled {
                    llm::PROMPT_VERSION.into()
                } else {
                    String::new()
                },
                requested_at_score: None,
                category: None,
                reported_probability: None,
                reported_confidence: None,
            },
        }
    }

    pub fn refresh(&mut self, scan: &engine::Scan) {
        self.analysis_complete = scan.complete;
        if scan.vision.status != crate::vision::Status::Disabled {
            self.vision = Some(scan.vision.clone());
        }
        self.legacy_score = Some(scan.score);
        use antivirus::AntivirusStatus as Av;
        let av_state = |status: &Av, original| match status {
            Av::Disabled => original,
            Av::Clean | Av::Malware | Av::Suspicious => State::Complete,
            Av::Unavailable => State::Unavailable,
            Av::Unscannable => State::Limited,
        };
        self.antivirus_state = av_state(&scan.antivirus.status, self.antivirus_state);
        if scan.antivirus.status != Av::Disabled {
            self.antivirus = Some(scan.antivirus.clone());
        }
        self.signatures_state = av_state(&scan.signatures.status, self.signatures_state);
        if self.signatures.is_none() && scan.signatures.status != Av::Disabled {
            self.signatures = Some(scan.signatures.clone());
        }
        self.semantic_state = match scan.semantic.status {
            engine::SemanticStatus::Disabled => self.semantic_state,
            engine::SemanticStatus::Complete => State::Complete,
            engine::SemanticStatus::Unavailable => State::Unavailable,
            engine::SemanticStatus::Busy => State::Busy,
        };
        self.semantic_logit = scan.semantic.logit;
        self.smtp_policy_state = match scan.smtp_policy.status {
            smtp_policy::PolicyStatus::Disabled => self.smtp_policy_state,
            smtp_policy::PolicyStatus::Complete => State::Complete,
            smtp_policy::PolicyStatus::Unavailable => State::Unavailable,
            smtp_policy::PolicyStatus::Busy => State::Busy,
        };
        if scan.smtp_policy.status != smtp_policy::PolicyStatus::Disabled {
            self.smtp_policy = Some(scan.smtp_policy.clone());
        }
        self.llm.state = match scan.llm.status {
            llm::LlmStatus::Disabled => self.llm.state,
            llm::LlmStatus::Complete => State::Complete,
            llm::LlmStatus::Unavailable => State::Unavailable,
            llm::LlmStatus::Busy => State::Busy,
            llm::LlmStatus::NotNeeded
            | llm::LlmStatus::BudgetLimited
            | llm::LlmStatus::PricingExpired => State::Skipped,
        };
        if scan.llm.status != llm::LlmStatus::Disabled {
            self.llm.outcome = Some(scan.llm.status.clone());
        }
        if let Some(verdict) = &scan.llm.verdict {
            self.llm.category = Some(verdict.category.clone());
            self.llm.reported_probability = Some(verdict.spam_probability);
            self.llm.reported_confidence = Some(verdict.confidence);
        }
    }

    pub fn validate(&self) -> Result<()> {
        if let Some(vision) = &self.vision {
            vision.validate()?;
        }
        let hash = |value: &str| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        };
        ensure!(
            self.schema == SCHEMA
                && hash(&self.artifacts.dependency_lock_sha256)
                && hash(&self.artifacts.policy_sha256),
            "invalid evidence schema or policy hash"
        );
        for value in [
            &self.artifacts.lexical_model_sha256,
            &self.artifacts.semantic_model_sha256,
            &self.artifacts.llm_prompt_sha256,
            &self.artifacts.antivirus_database_sha256,
            &self.artifacts.signatures_database_sha256,
        ]
        .into_iter()
        .flatten()
        {
            ensure!(hash(value), "invalid evidence artifact hash");
        }
        ensure!(
            self.authentication
                .dkim
                .as_ref()
                .is_none_or(|d| d.len() <= 16)
                && self.reputation.domains.len() <= 12,
            "unbounded evidence input"
        );
        for value in [
            self.lexical_logit,
            self.semantic_logit,
            self.legacy_score,
            self.llm.requested_at_score,
            self.llm.reported_probability,
            self.llm.reported_confidence,
        ]
        .into_iter()
        .flatten()
        {
            ensure!(value.is_finite(), "non-finite evidence");
        }
        for value in [self.llm.reported_probability, self.llm.reported_confidence]
            .into_iter()
            .flatten()
        {
            ensure!((0.0..=1.0).contains(&value), "invalid reported confidence");
        }
        for value in [self.legacy_score, self.llm.requested_at_score]
            .into_iter()
            .flatten()
        {
            ensure!((0.0..=100.0).contains(&value), "invalid baseline score");
        }
        for (query, dataset) in std::iter::once((&self.reputation.ip, Dataset::Zen)).chain(
            self.reputation
                .domains
                .iter()
                .map(|d| (&d.result, Dataset::Dbl)),
        ) {
            if !query.codes.is_empty() {
                ensure!(
                    query.state == State::Complete
                        && dqs_codes(&query.codes, dataset)? == query.codes,
                    "inconsistent reputation evidence"
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn codes(values: &[&str]) -> Vec<Ipv4Addr> {
        values.iter().map(|s| s.parse().unwrap()).collect()
    }

    #[test]
    fn dns_reputation_retains_categories_and_rejects_errors_mixed_zones_and_unknown_codes() {
        assert_eq!(
            dqs_codes(
                &codes(&["127.0.0.11", "127.0.0.2", "127.0.0.2"]),
                Dataset::Zen
            )
            .unwrap(),
            codes(&["127.0.0.2", "127.0.0.11"])
        );
        assert_eq!(
            dqs_codes(&codes(&["127.0.1.4", "127.0.1.104"]), Dataset::Dbl).unwrap(),
            codes(&["127.0.1.4", "127.0.1.104"])
        );
        for value in [
            "127.255.255.250",
            "127.255.255.251",
            "127.255.255.252",
            "127.0.1.255",
            "127.0.1.99",
            "8.8.8.8",
            "127.0.2.4",
        ] {
            assert!(dqs_codes(&codes(&[value]), Dataset::Dbl).is_err());
            assert!(dqs_codes(&codes(&["127.0.1.4", value]), Dataset::Dbl).is_err());
        }
        assert!(dqs_codes(&codes(&["127.0.0.2"]), Dataset::Dbl).is_err());
        assert!(dqs_codes(&codes(&["127.0.1.2"]), Dataset::Zen).is_err());
        assert!(dqs_codes(&[], Dataset::Zen).is_err());
        assert!(dqs_codes(&["127.0.0.2".parse().unwrap(); 33], Dataset::Zen).is_err());
    }

    #[test]
    fn abused_legitimate_domains_are_not_malicious_domain_evidence() {
        for suffix in [102, 103, 104, 105, 106] {
            assert!(!malicious_domain(&[Ipv4Addr::new(127, 0, 1, suffix)]));
        }
        assert!(malicious_domain(&codes(&["127.0.1.103", "127.0.1.4"])));
        assert!(!malicious_domain(&codes(&["127.255.255.250"])));
    }

    #[test]
    fn configured_unexecuted_checks_and_legacy_absence_are_never_backfilled_as_clean() {
        let mut config =
            crate::config::Config::load(std::path::Path::new("config/development.toml")).unwrap();
        config.filter.authentication = true;
        config.smtp_policy = Some(Default::default());
        let mut evidence =
            Evidence::new(&config, Artifacts::new(&config, None, None, false), false);
        evidence.refresh(&engine::Scan::default());
        assert_eq!(evidence.authentication.state, State::NotRun);
        assert!(evidence.authentication.spf.is_none() && evidence.authentication.dkim.is_none());
        assert_eq!(evidence.smtp_policy_state, State::NotRun);
        assert!(evidence.smtp_policy.is_none());
        assert_eq!(evidence.reputation.state, State::Disabled);
        assert_eq!(evidence.reputation.ip.state, State::Disabled);
        assert!(evidence.artifacts.antivirus_database_sha256.is_none());
        assert!(evidence.artifacts.llm_model_revision.is_none());
        evidence.validate().unwrap();
        let mut old = serde_json::to_value(engine::Scan::default()).unwrap();
        old.as_object_mut().unwrap().remove("evidence");
        assert!(
            serde_json::from_value::<engine::Scan>(old)
                .unwrap()
                .evidence
                .is_none()
        );
    }

    #[test]
    fn invalid_confidence_and_unavailable_positive_results_cannot_be_exported() {
        let config =
            crate::config::Config::load(std::path::Path::new("config/development.toml")).unwrap();
        let evidence = Evidence::new(&config, Artifacts::new(&config, None, None, false), false);
        let mut invalid = evidence.clone();
        invalid.llm.reported_confidence = Some(2.);
        assert!(invalid.validate().is_err());
        let mut invalid = evidence.clone();
        invalid.legacy_score = Some(f64::NAN);
        assert!(invalid.validate().is_err());
        let mut invalid = evidence;
        invalid.reputation.ip.codes = codes(&["127.0.0.2"]);
        invalid.reputation.ip.state = State::Unavailable;
        assert!(invalid.validate().is_err());
    }
}
