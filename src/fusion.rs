//! Native, data-only learned decision contract. This module never delivers mail
//! or enables a candidate. Missing checks remain visible and cannot enable a tag.
use crate::{
    antivirus::{AntivirusResult, AntivirusStatus},
    evidence::{Artifacts, AuthResult, DomainRole, Evidence, Source, State},
    llm::{Category, LlmStatus},
    smtp_policy::PolicyStatus,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, io::Read, path::Path, sync::OnceLock};

pub const SCHEMA: &str = "noisefence-fusion-model-1";
pub const FEATURE_SCHEMA: &str = "noisefence-fusion-features-1";
pub mod io;
pub mod population;
pub mod runtime;
pub const PROTOCOL: &[u8] = include_bytes!("../research/fusion-protocol.json");
const STATES: [State; 7] = [
    State::Disabled,
    State::NotRun,
    State::Complete,
    State::Unavailable,
    State::Busy,
    State::Skipped,
    State::Limited,
];
const RESULTS: [AuthResult; 7] = [
    AuthResult::Pass,
    AuthResult::Fail,
    AuthResult::SoftFail,
    AuthResult::Neutral,
    AuthResult::None,
    AuthResult::TempError,
    AuthResult::PermError,
];
const POLICY_CHECKS: [&str; 15] = [
    "helo_literal_match",
    "helo_literal_mismatch",
    "helo_invalid",
    "helo_local_identity",
    "helo_verified",
    "helo_no_address",
    "helo_address_mismatch",
    "ptr_missing",
    "ptr_verified",
    "ptr_unconfirmed",
    "sender_null",
    "sender_no_mail_route",
    "sender_implicit_mx",
    "sender_null_mx",
    "sender_mx_present",
];

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Feature {
    pub name: String,
    pub family: String,
    pub minimum: f64,
    pub maximum: f64,
}
pub fn specs() -> &'static [Feature] {
    static SPECS: OnceLock<Vec<Feature>> = OnceLock::new();
    SPECS.get_or_init(|| {
        #[derive(Deserialize)]
        struct Protocol {
            features: Vec<Feature>,
        }
        serde_json::from_slice::<Protocol>(PROTOCOL)
            .expect("embedded fusion protocol")
            .features
    })
}
pub fn protocol_sha256() -> String {
    crate::message::digest(PROTOCOL)
}

pub fn availability_profile(e: &Evidence) -> String {
    let a = &e.authentication;
    let mut states: Vec<_> = [
        e.lexical_state,
        e.semantic_state,
        a.spf_state,
        a.dkim_state,
        a.dmarc_state,
        a.arc_state,
        e.reputation.state,
        e.antivirus_state,
        e.signatures_state,
        e.smtp_policy_state,
        e.llm.state,
    ]
    .iter()
    .map(name)
    .collect();
    states.push(
        e.llm
            .outcome
            .as_ref()
            .map(name)
            .unwrap_or_else(|| "not_run".into()),
    );
    states.join("/")
}

/// The existing SMTP completeness rule also requires an extendable ARC chain.
/// A configured LLM is intentionally not called after an official malware hit.
pub fn tag_eligible(e: &Evidence) -> bool {
    let done = |state| matches!(state, State::Complete | State::Disabled);
    e.source == Source::SmtpSession
        && e.analysis_complete
        && [
            e.lexical_state,
            e.semantic_state,
            e.authentication.spf_state,
            e.authentication.dkim_state,
            e.authentication.dmarc_state,
            e.reputation.state,
            e.antivirus_state,
            e.signatures_state,
            e.smtp_policy_state,
        ]
        .into_iter()
        .all(done)
        && e.authentication.arc_state == State::Complete
        && e.authentication.arc_can_seal == Some(true)
        && (matches!(
            e.llm.state,
            State::Complete | State::Disabled | State::Skipped
        ) || (e.llm.state == State::NotRun
            && e.antivirus
                .as_ref()
                .is_some_and(|a| a.status == AntivirusStatus::Malware)))
}

pub(crate) fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn validate_artifacts(a: &Artifacts) -> Result<()> {
    ensure!(
        !a.application.is_empty()
            && a.application.len() <= 128
            && a.application
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c)),
        "invalid application identity"
    );
    ensure!(
        valid_hash(&a.policy_sha256) && valid_hash(&a.dependency_lock_sha256),
        "invalid artifact binding"
    );
    for h in [
        &a.lexical_model_sha256,
        &a.semantic_model_sha256,
        &a.llm_prompt_sha256,
        &a.antivirus_database_sha256,
        &a.signatures_database_sha256,
    ]
    .into_iter()
    .flatten()
    {
        ensure!(valid_hash(h), "invalid model or detector artifact hash");
    }
    ensure!(
        a.llm_model_revision.as_ref().is_none_or(|r| !r.is_empty()
            && r.len() <= 128
            && r.bytes().all(|b| b.is_ascii_graphic())),
        "invalid LLM revision"
    );
    if let Some(protocol) = &a.semantic_protocol {
        ensure!(
            protocol == &crate::learning::SemanticProtocol::pinned(),
            "unsupported semantic protocol"
        );
    }
    ensure!(
        a.semantic_model_sha256.is_some() == a.semantic_protocol.is_some(),
        "semantic artifact/protocol mismatch"
    );
    Ok(())
}

fn flag(value: bool) -> f64 {
    if value { 1.0 } else { 0.0 }
}
fn name<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .expect("enum serialization")
        .as_str()
        .expect("string enum")
        .to_owned()
}
#[derive(Default)]
struct Vector(BTreeMap<String, f64>);
impl Vector {
    fn set(&mut self, key: impl Into<String>, value: f64) {
        assert!(
            self.0.insert(key.into(), value).is_none(),
            "duplicate embedded feature"
        );
    }
    fn states(&mut self, prefix: &str, state: State) {
        for candidate in STATES {
            self.set(
                format!("{prefix}.state.{}", name(&candidate)),
                flag(candidate == state),
            );
        }
    }
    fn results(&mut self, prefix: &str, results: &[AuthResult]) {
        for candidate in RESULTS {
            self.set(
                format!("{prefix}.{}", name(&candidate)),
                flag(results.contains(&candidate)),
            );
        }
    }
    fn finish(self) -> Result<Vec<f64>> {
        ensure!(
            self.0.len() == specs().len(),
            "fusion feature protocol mismatch"
        );
        specs()
            .iter()
            .map(|spec| {
                let value = *self
                    .0
                    .get(&spec.name)
                    .ok_or_else(|| anyhow::anyhow!("missing fusion feature"))?;
                ensure!(
                    value.is_finite() && value >= spec.minimum && value <= spec.maximum,
                    "invalid fusion feature"
                );
                Ok(value)
            })
            .collect()
    }
}
fn auth_state(state: State, results: Option<&[AuthResult]>) -> Result<()> {
    match state {
        State::Disabled | State::NotRun => ensure!(
            results.is_none(),
            "result for an unexecuted authentication check"
        ),
        State::Complete => ensure!(
            results.is_some_and(|r| !r.contains(&AuthResult::TempError)),
            "incomplete authentication marked complete"
        ),
        State::Unavailable => ensure!(
            results.is_none_or(|r| r.contains(&AuthResult::TempError)),
            "unavailable authentication has no temporary error"
        ),
        _ => anyhow::bail!("unsupported authentication state"),
    }
    Ok(())
}
fn scanner(
    v: &mut Vector,
    prefix: &str,
    state: State,
    result: Option<&AntivirusResult>,
) -> Result<()> {
    use AntivirusStatus as Av;
    if let Some(result) = result {
        let expected = match result.status {
            Av::Clean | Av::Malware | Av::Suspicious => State::Complete,
            Av::Unavailable => State::Unavailable,
            Av::Unscannable => State::Limited,
            Av::Disabled => anyhow::bail!("disabled scanner must have no result"),
        };
        ensure!(state == expected, "inconsistent scanner state");
    } else {
        ensure!(
            matches!(state, State::Disabled | State::NotRun),
            "missing scanner result"
        );
    }
    v.states(prefix, state);
    for candidate in [
        Av::Clean,
        Av::Malware,
        Av::Suspicious,
        Av::Unscannable,
        Av::Unavailable,
    ] {
        v.set(
            format!("{prefix}.{}", name(&candidate)),
            flag(result.is_some_and(|r| r.status == candidate)),
        );
    }
    Ok(())
}

/// Encodes observations only; scores, labels, text and timing cannot enter this vector.
pub fn features(e: &Evidence) -> Result<Vec<f64>> {
    e.validate()?;
    validate_artifacts(&e.artifacts)?;
    ensure!(
        e.source != Source::ContentOnly,
        "fusion needs an observed or explicitly supplied SMTP context"
    );
    let mut v = Vector::default();
    for (prefix, state, logit, artifact) in [
        (
            "lexical",
            e.lexical_state,
            e.lexical_logit,
            &e.artifacts.lexical_model_sha256,
        ),
        (
            "semantic",
            e.semantic_state,
            e.semantic_logit,
            &e.artifacts.semantic_model_sha256,
        ),
    ] {
        ensure!(
            (state == State::Disabled) == artifact.is_none(),
            "local model availability does not match its artifact"
        );
        ensure!(
            matches!(state, State::Complete | State::Limited) == logit.is_some(),
            "inconsistent local model result"
        );
        ensure!(
            !matches!(state, State::Skipped),
            "unsupported local model state"
        );
        v.states(prefix, state);
        v.set(
            format!("{prefix}.logit_clipped_32"),
            logit.unwrap_or(0.0).clamp(-32.0, 32.0) / 32.0,
        );
    }
    let a = &e.authentication;
    match a.state {
        State::Disabled | State::NotRun => ensure!(
            [a.spf_state, a.dkim_state, a.dmarc_state]
                .iter()
                .all(|s| *s == a.state),
            "authentication state mismatch"
        ),
        State::Complete => ensure!(
            [a.spf_state, a.dkim_state, a.dmarc_state]
                .iter()
                .all(|s| *s == State::Complete),
            "authentication is only partly complete"
        ),
        State::Unavailable => ensure!(
            [a.spf_state, a.dkim_state, a.dmarc_state]
                .iter()
                .any(|s| matches!(s, State::NotRun | State::Unavailable)),
            "unavailable authentication has only completed checks"
        ),
        _ => anyhow::bail!("unsupported overall authentication state"),
    }
    auth_state(a.spf_state, a.spf.as_ref().map(std::slice::from_ref))?;
    // Option::as_slice alone loses the distinction between None and Some([]).
    auth_state(a.dkim_state, a.dkim.as_deref())?;
    ensure!(
        a.dmarc_spf.is_some() == a.dmarc_dkim.is_some(),
        "partial DMARC result pair"
    );
    let dmarc = a.dmarc_spf.zip(a.dmarc_dkim).map(|(spf, dkim)| [spf, dkim]);
    auth_state(a.dmarc_state, dmarc.as_ref().map(|r| r.as_slice()))?;
    auth_state(a.arc_state, a.arc.as_ref().map(std::slice::from_ref))?;
    ensure!(
        a.dkim
            .as_ref()
            .is_none_or(|r| !r.contains(&AuthResult::SoftFail))
            && a.arc != Some(AuthResult::SoftFail),
        "unsupported DKIM/ARC result"
    );
    ensure!(
        [a.dmarc_spf, a.dmarc_dkim]
            .into_iter()
            .flatten()
            .all(|r| !matches!(r, AuthResult::SoftFail | AuthResult::Neutral)),
        "unsupported DMARC result"
    );
    ensure!(
        a.arc.is_some() == a.arc_can_seal.is_some(),
        "ARC sealing state without verification"
    );
    for (prefix, state) in [
        ("spf", a.spf_state),
        ("dkim", a.dkim_state),
        ("dmarc", a.dmarc_state),
        ("arc", a.arc_state),
    ] {
        v.states(&format!("auth.{prefix}"), state);
    }
    for (prefix, result) in [
        ("spf", a.spf),
        ("dmarc_spf", a.dmarc_spf),
        ("dmarc_dkim", a.dmarc_dkim),
        ("arc", a.arc),
    ] {
        v.results(&format!("auth.{prefix}"), result.as_slice());
    }
    v.results("auth.dkim", a.dkim.as_deref().unwrap_or_default());
    v.set(
        "auth.dkim.unsigned",
        flag(a.dkim.as_ref().is_some_and(Vec::is_empty)),
    );
    v.set("auth.arc.can_seal", flag(a.arc_can_seal == Some(true)));

    let r = &e.reputation;
    ensure!(
        r.version == crate::evidence::REPUTATION_VERSION,
        "unsupported reputation version"
    );
    for q in std::iter::once(&r.ip).chain(r.domains.iter().map(|d| &d.result)) {
        ensure!(
            matches!(
                q.state,
                State::Disabled | State::NotRun | State::Complete | State::Unavailable
            ),
            "unsupported DNS query state"
        );
    }
    match r.state {
        State::Disabled | State::NotRun => ensure!(
            r.ip.state == r.state && r.domains.is_empty() && !r.stopped_after_positive,
            "reputation result for an unexecuted check"
        ),
        State::Complete => {
            ensure!(r.ip.state == State::Complete, "incomplete IP reputation");
            ensure!(
                r.domains.iter().all(|d| d.result.state == State::Complete
                    || (r.stopped_after_positive && d.result.state == State::NotRun)),
                "incomplete domain reputation"
            );
        }
        State::Unavailable => ensure!(
            r.ip.state == State::Unavailable
                || r.domains
                    .iter()
                    .any(|d| d.result.state == State::Unavailable),
            "unavailable reputation without a failed query"
        ),
        _ => anyhow::bail!("unsupported reputation state"),
    }
    if r.stopped_after_positive {
        let first_skipped = r
            .domains
            .iter()
            .position(|d| d.result.state == State::NotRun);
        ensure!(
            first_skipped.is_some_and(|i| i > 0
                && crate::evidence::malicious_domain(&r.domains[i - 1].result.codes)
                && r.domains[..i]
                    .iter()
                    .all(|d| d.result.state != State::NotRun)
                && r.domains[i..]
                    .iter()
                    .all(|d| d.result.state == State::NotRun)),
            "invalid reputation short circuit"
        );
    }
    for domain in &r.domains {
        ensure!(
            !domain.roles.is_empty() && domain.roles.len() <= 4,
            "invalid domain roles"
        );
        ensure!(
            domain
                .roles
                .iter()
                .enumerate()
                .all(|(i, role)| !domain.roles[..i].contains(role)),
            "duplicate domain role"
        );
    }
    v.states("reputation", r.state);
    v.states("reputation.ip", r.ip.state);
    for code in [2, 3, 4, 9, 10, 11, 30] {
        v.set(
            format!("reputation.ip.code_{code}"),
            flag(r.ip.codes.iter().any(|ip| ip.octets() == [127, 0, 0, code])),
        );
    }
    v.set(
        "reputation.stopped_after_positive",
        flag(r.stopped_after_positive),
    );
    for role in [
        DomainRole::EnvelopeFrom,
        DomainRole::Helo,
        DomainRole::HeaderFrom,
        DomainRole::Body,
    ] {
        let domains: Vec<_> = r
            .domains
            .iter()
            .filter(|d| d.roles.contains(&role))
            .collect();
        for state in STATES {
            v.set(
                format!("reputation.{}.queries_{}_div12", name(&role), name(&state)),
                domains.iter().filter(|d| d.result.state == state).count() as f64 / 12.0,
            );
        }
        for code in [2, 4, 5, 6, 102, 103, 104, 105, 106] {
            if code >= 100 && role != DomainRole::Body {
                continue;
            }
            v.set(
                format!("reputation.{}.code_{code}", name(&role)),
                flag(domains.iter().any(|d| {
                    d.result
                        .codes
                        .iter()
                        .any(|ip| ip.octets() == [127, 0, 1, code])
                })),
            );
        }
    }

    v.states("smtp_policy", e.smtp_policy_state);
    if let Some(policy) = &e.smtp_policy {
        ensure!(
            policy.version == crate::smtp_policy::VERSION,
            "unsupported SMTP policy version"
        );
        let expected = match policy.status {
            PolicyStatus::Complete => State::Complete,
            PolicyStatus::Unavailable => State::Unavailable,
            PolicyStatus::Busy => State::Busy,
            PolicyStatus::Disabled => anyhow::bail!("disabled SMTP policy must have no result"),
        };
        ensure!(
            e.smtp_policy_state == expected,
            "inconsistent SMTP policy state"
        );
        ensure!(
            policy.checks.len() <= 3
                && policy
                    .checks
                    .iter()
                    .all(|s| POLICY_CHECKS.contains(&s.id.as_str())),
            "unknown SMTP policy check"
        );
        for prefix in ["helo_", "ptr_", "sender_"] {
            let count = policy
                .checks
                .iter()
                .filter(|s| s.id.starts_with(prefix))
                .count();
            ensure!(
                count == usize::from(policy.status == PolicyStatus::Complete),
                "incomplete or repeated SMTP identity check"
            );
        }
    } else {
        ensure!(
            matches!(e.smtp_policy_state, State::Disabled | State::NotRun),
            "missing SMTP policy result"
        );
    }
    for id in POLICY_CHECKS {
        v.set(
            format!("smtp_policy.{id}"),
            flag(
                e.smtp_policy
                    .as_ref()
                    .is_some_and(|p| p.checks.iter().any(|c| c.id == id)),
            ),
        );
    }
    scanner(&mut v, "antivirus", e.antivirus_state, e.antivirus.as_ref())?;
    scanner(
        &mut v,
        "signatures",
        e.signatures_state,
        e.signatures.as_ref(),
    )?;

    let l = &e.llm;
    ensure!(
        e.artifacts.llm_prompt_sha256.is_some() == (l.state != State::Disabled),
        "LLM artifact/availability mismatch"
    );
    let expected = match l.outcome {
        Some(LlmStatus::Disabled) => State::Disabled,
        Some(LlmStatus::Complete) => State::Complete,
        Some(LlmStatus::Unavailable) => State::Unavailable,
        Some(LlmStatus::Busy) => State::Busy,
        Some(LlmStatus::NotNeeded | LlmStatus::BudgetLimited | LlmStatus::PricingExpired) => {
            State::Skipped
        }
        None => State::NotRun,
    };
    ensure!(l.state == expected, "inconsistent LLM state");
    ensure!(
        l.requested_at_score.is_some() == !matches!(l.state, State::Disabled | State::NotRun),
        "LLM selection observation missing or spurious"
    );
    ensure!(
        (l.state == State::Complete)
            == (l.category.is_some()
                && l.reported_probability.is_some()
                && l.reported_confidence.is_some()),
        "incomplete LLM verdict"
    );
    if l.state != State::Complete {
        ensure!(
            l.category.is_none()
                && l.reported_probability.is_none()
                && l.reported_confidence.is_none(),
            "verdict from an unexecuted LLM"
        );
    }
    if l.state != State::Disabled {
        ensure!(
            e.artifacts.llm_prompt_sha256.is_some()
                && l.prompt_version == crate::llm::PROMPT_VERSION
                && !l.model.is_empty()
                && l.model.len() <= 128,
            "missing LLM identity"
        );
    }
    v.states("llm", l.state);
    for candidate in [
        LlmStatus::Disabled,
        LlmStatus::NotNeeded,
        LlmStatus::Busy,
        LlmStatus::BudgetLimited,
        LlmStatus::PricingExpired,
        LlmStatus::Unavailable,
        LlmStatus::Complete,
    ] {
        v.set(
            format!("llm.outcome.{}", name(&candidate)),
            flag(l.outcome.as_ref() == Some(&candidate)),
        );
    }
    for candidate in [
        Category::Legitimate,
        Category::Spam,
        Category::Phishing,
        Category::Ambiguous,
    ] {
        v.set(
            format!("llm.category.{}", name(&candidate)),
            flag(
                l.category
                    .as_ref()
                    .is_some_and(|c| name(c) == name(&candidate)),
            ),
        );
    }
    v.set(
        "llm.reported_probability",
        l.reported_probability.unwrap_or(0.0),
    );
    v.set(
        "llm.reported_confidence",
        l.reported_confidence.unwrap_or(0.0),
    );
    v.finish()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Calibration {
    pub slope: f64,
    pub intercept: f64,
    pub messages: usize,
    pub positive_fraction: f64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Model {
    pub schema: String,
    pub version: String,
    pub protocol_sha256: String,
    pub artifacts: Artifacts,
    pub weights: Vec<f64>,
    pub bias: f64,
    pub cutoff: f64,
    pub calibration: Calibration,
    pub supported_profiles: Vec<String>,
    pub manifest_sha256: String,
    /// Research artifacts have no production approval. Callers must not interpret
    /// a fitted probability or a hypothetical tag as activation permission.
    pub purpose: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Contribution {
    pub feature: String,
    pub value: f64,
    pub contribution: f64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Prediction {
    pub version: String,
    pub logit: f64,
    pub probability: f64,
    pub above_threshold: bool,
    pub profile_supported: bool,
    pub tag_eligible: bool,
    pub would_tag: bool,
    pub contributions: Vec<Contribution>,
}
impl Model {
    pub fn load(path: &Path) -> Result<Self> {
        Ok(Self::load_bound(path)?.0)
    }
    pub fn load_bound(path: &Path) -> Result<(Self, String)> {
        let mut bytes = Vec::new();
        std::fs::File::open(path)?
            .take(128 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 128 * 1024, "oversized fusion model");
        let result: Self = serde_json::from_slice(&bytes)?;
        result.validate()?;
        Ok((result, crate::message::digest(&bytes)))
    }
    pub fn validate(&self) -> Result<()> {
        validate_artifacts(&self.artifacts)?;
        ensure!(
            self.schema == SCHEMA
                && self.protocol_sha256 == protocol_sha256()
                && self.purpose == "research",
            "unsupported fusion contract or purpose"
        );
        ensure!(
            !self.version.is_empty()
                && self.version.len() <= 128
                && self
                    .version
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c)),
            "invalid fusion version"
        );
        ensure!(
            self.weights.len() == specs().len(),
            "fusion dimensions differ"
        );
        ensure!(
            self.weights
                .iter()
                .chain([
                    &self.bias,
                    &self.cutoff,
                    &self.calibration.slope,
                    &self.calibration.intercept
                ])
                .all(|x| x.is_finite() && x.abs() <= 1e6),
            "invalid fusion coefficients"
        );
        ensure!(
            self.calibration.slope >= 0.0
                && self.calibration.messages >= 2
                && self.calibration.messages <= 100_000
                && self.calibration.positive_fraction.is_finite()
                && (0.0..1.0).contains(&self.calibration.positive_fraction)
                && self.calibration.positive_fraction > 0.0,
            "invalid monotone calibration"
        );
        ensure!(
            self.manifest_sha256.len() == 64
                && self
                    .manifest_sha256
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
            "invalid training manifest hash"
        );
        ensure!(
            !self.supported_profiles.is_empty() && self.supported_profiles.len() <= 128,
            "invalid availability profile set"
        );
        ensure!(
            self.supported_profiles.iter().all(|p| !p.is_empty()
                && p.len() <= 256
                && p.bytes()
                    .all(|b| b.is_ascii_lowercase() || b"/_".contains(&b)))
                && self.supported_profiles.windows(2).all(|p| p[0] < p[1]),
            "invalid, duplicate or unsorted availability profile"
        );
        Ok(())
    }
    pub fn predict(&self, evidence: &Evidence) -> Result<Prediction> {
        self.validate()?;
        ensure!(
            self.artifacts.equivalent(&evidence.artifacts),
            "fusion detector artifacts do not match the observations"
        );
        let values = features(evidence)?;
        let logit = values
            .iter()
            .zip(&self.weights)
            .map(|(x, w)| x * w)
            .sum::<f64>()
            + self.bias;
        let calibrated = self.calibration.slope * logit + self.calibration.intercept;
        let probability = if calibrated >= 0.0 {
            1.0 / (1.0 + (-calibrated).exp())
        } else {
            let p = calibrated.exp();
            p / (1.0 + p)
        };
        let mut contributions: Vec<_> = specs()
            .iter()
            .zip(values)
            .zip(&self.weights)
            .filter(|((_, x), w)| *x * **w != 0.0)
            .map(|((spec, value), weight)| Contribution {
                feature: spec.name.clone(),
                value,
                contribution: value * weight,
            })
            .collect();
        contributions.sort_by(|a, b| {
            b.contribution
                .abs()
                .total_cmp(&a.contribution.abs())
                .then_with(|| a.feature.cmp(&b.feature))
        });
        contributions.truncate(6);
        let profile_supported = self
            .supported_profiles
            .binary_search(&availability_profile(evidence))
            .is_ok();
        let tag_eligible = tag_eligible(evidence);
        Ok(Prediction {
            version: self.version.clone(),
            logit,
            probability,
            above_threshold: logit >= self.cutoff,
            profile_supported,
            tag_eligible,
            would_tag: profile_supported && tag_eligible && logit >= self.cutoff,
            contributions,
        })
    }
}
