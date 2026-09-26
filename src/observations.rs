//! Receipt-time normalization of existing trusted detector outputs.
//! No new queries, message text, feature vectors, provider responses or votes.
use crate::{antivirus, engine, evidence, llm, protection, smtp_policy, vision};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const VERSION: u32 = 3;
const MAX_OBSERVATIONS: usize = 160;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Complete,
    Partial,
    Unavailable,
    Timeout,
    BudgetExceeded,
    Disabled,
    NotApplicable,
}

impl From<evidence::State> for State {
    fn from(value: evidence::State) -> Self {
        match value {
            evidence::State::Complete => Self::Complete,
            evidence::State::Limited => Self::Partial,
            evidence::State::Disabled => Self::Disabled,
            evidence::State::NotRun
            | evidence::State::Unavailable
            | evidence::State::Busy
            | evidence::State::Skipped => Self::Unavailable,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Family {
    Content,
    Authentication,
    SenderReputation,
    UrlThreat,
    FileThreat,
    Malware,
    Context,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    DecisionInput,
    Safety,
    Advisory,
    Comparison,
    Admission,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Unit {
    LogOdds,
    Points,
    ReportedProbability,
    Count,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Measurement {
    pub value: f64,
    pub unit: Unit,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Exclusion {
    NotObserved,
    MissingEnvelopeContext,
    UnsupportedClaims,
    InconsistentOpinion,
    InvalidResult,
    UnavailableResult,
    MissingCaptureTime,
    InvalidObservationTime,
    StaleResult,
    DuplicateTarget,
    ConflictingTarget,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReputationResult {
    Listed,
    NotListed,
    Policy,
    Malicious,
    Suspicious,
    Clean,
    Unknown,
    Stale,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ResultValue {
    Authentication(Vec<evidence::AuthResult>),
    Antivirus(antivirus::AntivirusStatus),
    Llm(llm::Category),
    Reputation(ReputationResult),
    MailKind(crate::mailing::Verdict),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Observation {
    pub id: String,
    pub family: Family,
    pub role: Role,
    pub state: State,
    /// Exact underlying scope: a domain/host-root lookup is not a page verdict.
    pub scope: String,
    pub version: Option<String>,
    pub artifact_sha256: Option<String>,
    pub elapsed_ms: Option<u64>,
    pub result: Option<ResultValue>,
    pub measurements: BTreeMap<String, Measurement>,
    /// References to retained structured evidence, never excerpts or URL tokens.
    pub evidence_refs: Vec<String>,
    pub exclusion: Option<Exclusion>,
    pub group: String,
    /// Target freshness, not the age of the entire provider request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queried_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_max_age_seconds: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub analysis_max_age_seconds: Option<u32>,
}
impl Observation {
    fn new(
        id: &str,
        family: Family,
        role: Role,
        state: State,
        scope: &str,
        group: &str,
        reference: &str,
    ) -> Self {
        Self {
            id: id.into(),
            family,
            role,
            state,
            scope: scope.into(),
            group: group.into(),
            version: None,
            artifact_sha256: None,
            elapsed_ms: None,
            result: None,
            measurements: BTreeMap::new(),
            evidence_refs: vec![reference.into()],
            exclusion: None,
            queried_at: None,
            cache_max_age_seconds: None,
            analysis_max_age_seconds: None,
        }
    }
    fn measured(&mut self, name: &str, value: Option<f64>, unit: Unit) {
        if matches!(self.state, State::Complete | State::Partial)
            && let Some(value) = value.filter(|v| v.is_finite())
            && (unit != Unit::ReportedProbability || (0.0..=1.0).contains(&value))
        {
            self.measurements
                .insert(name.into(), Measurement { value, unit });
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvidenceGroup {
    pub key: String,
    pub family: Family,
    pub observations: Vec<String>,
    /// Contradictory provider opinions remain visible, not averaged into safety.
    pub conflict: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Report {
    pub version: u32,
    pub provenance: Option<evidence::Source>,
    pub observations: Vec<Observation>,
    pub groups: Vec<EvidenceGroup>,
    pub omitted: usize,
}

fn token(value: &str) -> Option<String> {
    (!value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-/".contains(&b)))
    .then(|| value.into())
}
fn digest(value: Option<&str>) -> Option<String> {
    value
        .filter(|v| crate::compatibility::valid_hash(v))
        .map(str::to_owned)
}
fn missing_transport(scan: &engine::Scan) -> Option<Exclusion> {
    match &scan.evidence {
        Some(e) => evidence::eligibility::context(e)
            .err()
            .map(transport_exclusion),
        None => Some(Exclusion::MissingEnvelopeContext),
    }
}
fn transport_exclusion(reason: evidence::eligibility::Exclusion) -> Exclusion {
    use evidence::eligibility::Exclusion as E;
    match reason {
        E::MissingEnvelopeContext => Exclusion::MissingEnvelopeContext,
        E::UnsupportedSchema | E::InvalidResult => Exclusion::InvalidResult,
        E::InactiveParent | E::IncompleteCheck | E::TemporaryFailure => {
            Exclusion::UnavailableResult
        }
    }
}
fn disabled_state(original: Option<evidence::State>) -> State {
    match original {
        None | Some(evidence::State::Disabled) => State::Disabled,
        // A default disabled result cannot supply the result of a configured
        // or supposedly completed check. Preserve the missing observation.
        _ => State::Unavailable,
    }
}
fn av_state(status: &antivirus::AntivirusStatus, original: Option<evidence::State>) -> State {
    use antivirus::AntivirusStatus::*;
    match status {
        Clean | Malware | Suspicious => State::Complete,
        Unscannable => State::Partial,
        Unavailable => State::Unavailable,
        Disabled => disabled_state(original),
    }
}
fn provider_state(report: &protection::ProviderReport, status: &protection::Status) -> State {
    use protection::Status::*;
    match status {
        Disabled => State::Disabled,
        NotConfigured => State::NotApplicable,
        Quota => State::BudgetExceeded,
        Complete if report.omitted > 0 => State::Partial,
        Complete if report.checked == 0 && report.observations.is_empty() => State::NotApplicable,
        Complete => State::Complete,
        Limited => State::Partial,
        _ if report.failure == Some(protection::providers::Failure::Timeout) => State::Timeout,
        _ => State::Unavailable,
    }
}

impl Report {
    fn push(&mut self, observation: Observation) {
        if self.observations.len() >= MAX_OBSERVATIONS {
            self.omitted += 1;
            return;
        }
        self.observations.push(observation);
    }
    fn admission(&mut self, scan: &engine::Scan) {
        let Some(rbl) = &scan.early_rbl else {
            return;
        };
        self.omitted += rbl.checks.len().saturating_sub(32);
        for (i, check) in rbl.checks.iter().take(32).enumerate() {
            use crate::rbl::{Incident, Status};
            let state = match check.status {
                Status::Listed | Status::NotListed | Status::Policy => State::Complete,
                Status::Skipped if check.incident == Some(Incident::UnsupportedIp) => {
                    State::NotApplicable
                }
                _ if check.incident == Some(Incident::Timeout) => State::Timeout,
                _ => State::Unavailable,
            };
            let mut observation = Observation::new(
                &format!("rbl.{i}"),
                Family::SenderReputation,
                Role::Admission,
                state,
                "peer_ip",
                "sender.ip",
                &format!("/early_rbl/checks/{i}"),
            );
            observation.version = token(&rbl.version);
            if let Some(reason) = missing_transport(scan) {
                observation.state = State::Unavailable;
                observation.exclusion = Some(reason);
            } else if state == State::Complete && check.incident.is_none() {
                observation.result = Some(ResultValue::Reputation(match check.status {
                    Status::Listed => ReputationResult::Listed,
                    Status::Policy => ReputationResult::Policy,
                    _ => ReputationResult::NotListed,
                }));
            } else if state == State::Complete {
                observation.state = State::Unavailable;
                observation.exclusion = Some(Exclusion::InvalidResult);
            }
            self.push(observation);
        }
    }
    fn native(&mut self, scan: &engine::Scan) {
        let Some(native) = &scan.native_filter else {
            return;
        };
        let native = &native.report;
        use crate::native_filter::Status;
        let state = match native.status {
            Status::Complete => State::Complete,
            Status::Limited => State::Partial,
            _ => State::Unavailable,
        };
        let mut observation = Observation::new(
            "native",
            Family::Content,
            Role::Comparison,
            state,
            "message",
            "message.native",
            "/native_filter/report",
        );
        observation.version = token(&native.version);
        observation.elapsed_ms = Some(native.elapsed_ms);
        observation.artifact_sha256 = digest(Some(&native.policy_sha256));
        observation.measured(
            "capped_total",
            native.score.as_ref().map(|s| s.total),
            Unit::Points,
        );
        self.push(observation);
        if let Some(score) = &native.score {
            for (family, values) in &score.families {
                use crate::native_filter::rules::Family as F;
                let (id, normalized, group) = match family {
                    F::Lexical => ("lexical", Family::Content, "message.content"),
                    F::Semantic => ("semantic", Family::Content, "message.content"),
                    F::Content => ("content", Family::Content, "message.content"),
                    F::Authentication => (
                        "authentication",
                        Family::Authentication,
                        "authentication.native",
                    ),
                    F::Reputation => ("reputation", Family::SenderReputation, "reputation.native"),
                    F::Smtp => ("smtp", Family::SenderReputation, "smtp.identity"),
                    F::Llm => ("llm", Family::Content, "message.llm"),
                    F::Campaign => ("campaign", Family::Context, "message.campaign"),
                    F::Bayes => ("bayes", Family::Content, "message.content"),
                    F::Other => ("other", Family::Context, "message.native.other"),
                };
                let mut observation = Observation::new(
                    &format!("native.{id}"),
                    normalized,
                    Role::Comparison,
                    state,
                    "family_aggregate",
                    group,
                    &format!("/native_filter/report/score/families/{id}"),
                );
                observation.measured("raw", Some(values.raw), Unit::Points);
                observation.measured("retained", Some(values.effective), Unit::Points);
                self.push(observation);
            }
        }
    }
    fn redirects(&mut self, report: &protection::redirects::Report) {
        self.omitted += report.omitted + report.chains.len().saturating_sub(32);
        for (i, chain) in report.chains.iter().take(32).enumerate() {
            let Some(hash) = digest(Some(&chain.source_sha256)) else {
                self.omitted += 1;
                continue;
            };
            use protection::redirects::Detail;
            let state = match (&chain.detail, chain.complete) {
                (Some(Detail::Deadline), _) => State::Timeout,
                (None, true) => State::Complete,
                _ if !chain.hops.is_empty() => State::Partial,
                _ => State::Unavailable,
            };
            let mut observation = Observation::new(
                &format!("redirect.{i}"),
                Family::UrlThreat,
                Role::Advisory,
                state,
                "url_navigation",
                &format!("url:{hash}"),
                &format!("/protection/url_resolution/chains/{i}"),
            );
            observation.version = token(&report.version);
            observation.artifact_sha256 = digest(Some(&report.settings_sha256));
            observation.measured("hops", Some(chain.hops.len() as f64), Unit::Count);
            // Reaching an HTTP destination is not a threat-intelligence verdict.
            self.push(observation);
        }
    }
    fn providers(&mut self, report: &protection::Report) {
        for (name, kind, provider) in [
            ("crdf", protection::Provider::Crdf, &report.crdf),
            (
                "virustotal",
                protection::Provider::Virustotal,
                &report.virustotal,
            ),
        ] {
            let evaluated = protection::evidence::evaluate(kind, provider);
            let mut parent = Observation::new(
                name,
                Family::UrlThreat,
                Role::Advisory,
                provider_state(provider, &evaluated.status),
                "provider_request",
                name,
                &format!("/protection/{name}"),
            );
            parent.elapsed_ms = Some(provider.elapsed_ms);
            parent.version = token(&report.version);
            parent.measured("checked", Some(provider.checked as f64), Unit::Count);
            self.push(parent);
            self.omitted += evaluated.omitted;
            for entry in evaluated.targets {
                let index = entry.index;
                let target = entry.value;
                let (family, scope, group_scope) = match target.scope.as_str() {
                    "file" => (Family::FileThreat, "file", "file"),
                    "host_lookup" => (Family::UrlThreat, "host_lookup", "host"),
                    "domain" => (Family::UrlThreat, "domain", "host"),
                    _ => {
                        self.omitted += 1;
                        continue;
                    }
                };
                let Some(hash) = digest(Some(&target.indicator_sha256)) else {
                    self.omitted += 1;
                    continue;
                };
                let mut observation = Observation::new(
                    &format!("{name}.{index}"),
                    family,
                    Role::Advisory,
                    State::Unavailable,
                    scope,
                    &format!("{group_scope}:{hash}"),
                    &format!("/protection/{name}/observations/{index}"),
                );
                let result = match target.verdict.as_str() {
                    "malicious" => Some(ReputationResult::Malicious),
                    "suspicious" => Some(ReputationResult::Suspicious),
                    // NoHit is the actual provider protocol: not a clean verdict.
                    "no_hit" => Some(ReputationResult::NotListed),
                    "unknown" => Some(ReputationResult::Unknown),
                    "stale" => Some(ReputationResult::Stale),
                    _ => None,
                };
                observation.version = Some(protection::evidence::VERSION.into());
                observation.queried_at = (target.queried_at > 0).then_some(target.queried_at);
                observation.cache_max_age_seconds = Some(target.cache_max_age_seconds);
                observation.analysis_max_age_seconds = target.analysis_max_age_seconds;
                if entry.usable() {
                    observation.state = State::Complete;
                    observation.result = result.map(ResultValue::Reputation);
                } else {
                    use protection::evidence::Exclusion as E;
                    observation.exclusion = entry.exclusion.map(|reason| match reason {
                        E::InvalidTarget | E::InvalidResult => Exclusion::InvalidResult,
                        E::UnavailableProvider => Exclusion::UnavailableResult,
                        E::MissingCaptureTime => Exclusion::MissingCaptureTime,
                        E::InvalidObservationTime => Exclusion::InvalidObservationTime,
                        E::StaleResult => Exclusion::StaleResult,
                        E::DuplicateTarget => Exclusion::DuplicateTarget,
                        E::ConflictingTarget => Exclusion::ConflictingTarget,
                    });
                }
                self.push(observation);
            }
        }
    }
    fn group(&mut self) {
        let mut groups: BTreeMap<String, (EvidenceGroup, BTreeSet<bool>)> = BTreeMap::new();
        for observation in &self.observations {
            let (group, opinions) = groups.entry(observation.group.clone()).or_insert_with(|| {
                (
                    EvidenceGroup {
                        key: observation.group.clone(),
                        family: observation.family,
                        observations: Vec::new(),
                        conflict: false,
                    },
                    BTreeSet::new(),
                )
            });
            group.observations.push(observation.id.clone());
            if observation.state == State::Complete && observation.exclusion.is_none() {
                match observation.result {
                    Some(ResultValue::Reputation(
                        ReputationResult::Malicious | ReputationResult::Listed,
                    )) => {
                        opinions.insert(true);
                    }
                    Some(ResultValue::Reputation(ReputationResult::Clean)) => {
                        opinions.insert(false);
                    }
                    // "not listed" and "unknown" are not a safety opinion.
                    _ => {}
                }
            }
        }
        self.groups = groups
            .into_values()
            .map(|(mut group, opinions)| {
                group.conflict = opinions.len() > 1;
                group
            })
            .collect();
    }
}

/// Normalize retained facts only. Optional comparisons remain outside the
/// canonical detector decision and can never create a new confirmation vote.
pub fn capture(scan: &engine::Scan) -> Report {
    let e = scan.evidence.as_ref();
    let mut report = Report {
        version: VERSION,
        provenance: e.map(|e| e.source),
        observations: vec![],
        groups: vec![],
        omitted: 0,
    };
    let content_state = match scan.features_complete {
        Some(true) => State::Complete,
        Some(false) if scan.reasons.iter().any(|r| r.id == "analysis_budget") => {
            State::BudgetExceeded
        }
        Some(false) => State::Unavailable,
        None => State::Unavailable,
    };
    let mut content = Observation::new(
        "content",
        Family::Content,
        Role::DecisionInput,
        content_state,
        "message",
        "message.content",
        "/features_complete",
    );
    content.version = Some(format!("features-{}", scan.feature_version));
    if scan.features_complete.is_none() {
        content.exclusion = Some(Exclusion::NotObserved);
    }
    report.push(content);
    let mut lexical = Observation::new(
        "lexical",
        Family::Content,
        Role::DecisionInput,
        e.map_or(State::Unavailable, |e| e.lexical_state.into()),
        "message",
        "message.content",
        "/evidence/lexical_logit",
    );
    lexical.artifact_sha256 = digest(e.and_then(|e| e.artifacts.lexical_model_sha256.as_deref()));
    if scan.features_complete != Some(false) {
        lexical.measured("logit", e.and_then(|e| e.lexical_logit), Unit::LogOdds);
    }
    if lexical.state == State::Complete && !lexical.measurements.contains_key("logit") {
        lexical.state = State::Unavailable;
        lexical.exclusion = Some(Exclusion::InvalidResult);
    }
    report.push(lexical);
    let mut semantic = Observation::new(
        "semantic",
        Family::Content,
        Role::DecisionInput,
        match scan.semantic.status {
            engine::SemanticStatus::Complete => State::Complete,
            engine::SemanticStatus::Disabled => disabled_state(e.map(|e| e.semantic_state)),
            _ if scan.semantic.failure == Some(engine::SemanticFailure::Deadline) => State::Timeout,
            _ => State::Unavailable,
        },
        "message",
        "message.content",
        "/semantic",
    );
    semantic.version = token(&scan.semantic.model);
    semantic.artifact_sha256 = digest(e.and_then(|e| e.artifacts.semantic_model_sha256.as_deref()));
    semantic.elapsed_ms = Some(scan.semantic.elapsed_ms);
    semantic.measured("logit", scan.semantic.logit, Unit::LogOdds);
    semantic.measured("contribution", scan.semantic.contribution, Unit::LogOdds);
    if semantic.state == State::Complete
        && (!semantic.measurements.contains_key("logit")
            || !semantic.measurements.contains_key("contribution"))
    {
        semantic.state = State::Unavailable;
        semantic.exclusion = Some(Exclusion::InvalidResult);
        semantic.measurements.clear();
    }
    report.push(semantic);

    for (id, state, values) in [
        (
            "spf",
            e.map(|e| e.authentication.spf_state),
            e.and_then(|e| e.authentication.spf).into_iter().collect(),
        ),
        (
            "dkim",
            e.map(|e| e.authentication.dkim_state),
            e.and_then(|e| e.authentication.dkim.clone())
                .unwrap_or_default(),
        ),
        (
            "dmarc",
            e.map(|e| e.authentication.dmarc_state),
            e.map(|e| {
                [e.authentication.dmarc_spf, e.authentication.dmarc_dkim]
                    .into_iter()
                    .flatten()
                    .collect()
            })
            .unwrap_or_default(),
        ),
        (
            "arc",
            e.map(|e| e.authentication.arc_state),
            e.and_then(|e| e.authentication.arc).into_iter().collect(),
        ),
    ] {
        let mut observation = Observation::new(
            id,
            Family::Authentication,
            Role::DecisionInput,
            state.map_or(State::Unavailable, State::from),
            "smtp_authentication",
            &format!("authentication.{id}"),
            &format!("/evidence/authentication/{id}"),
        );
        observation.version = Some(evidence::eligibility::VERSION.into());
        let check = match id {
            "spf" => evidence::eligibility::AuthCheck::Spf,
            "dkim" => evidence::eligibility::AuthCheck::Dkim,
            "dmarc" => evidence::eligibility::AuthCheck::Dmarc,
            _ => evidence::eligibility::AuthCheck::Arc,
        };
        if let Some(e) = e {
            match evidence::eligibility::authentication(e, check) {
                Ok(()) => observation.result = Some(ResultValue::Authentication(values)),
                Err(reason) if observation.state != State::Disabled => {
                    observation.state = State::Unavailable;
                    observation.exclusion = Some(transport_exclusion(reason));
                }
                Err(_) => (),
            }
        }
        report.push(observation);
    }
    if let Some(e) = e {
        report.omitted += e.reputation.domains.len().saturating_sub(12);
        for (id, query, scope, group) in std::iter::once((
            "dqs.ip".into(),
            &e.reputation.ip,
            "peer_ip",
            "sender.ip".into(),
        ))
        .chain(
            e.reputation
                .domains
                .iter()
                .take(12)
                .enumerate()
                .map(|(i, q)| {
                    (
                        format!("dqs.domain.{i}"),
                        &q.result,
                        "domain_role",
                        digest(scan.reputation_target_hashes.get(i).map(String::as_str))
                            .map_or_else(
                                || format!("sender.domain.{i}"),
                                |hash| format!("host:{hash}"),
                            ),
                    )
                }),
        ) {
            let mut observation = Observation::new(
                &id,
                Family::SenderReputation,
                Role::DecisionInput,
                query.state.into(),
                scope,
                &group,
                "/evidence/reputation",
            );
            observation.version = token(&e.reputation.version);
            let dataset = if id == "dqs.ip" {
                evidence::Dataset::Zen
            } else {
                evidence::Dataset::Dbl
            };
            match evidence::eligibility::query(e, query, dataset) {
                Ok(()) => {
                    observation.result = Some(ResultValue::Reputation(if query.codes.is_empty() {
                        ReputationResult::NotListed
                    } else if evidence::eligibility::malicious_query(e, query, dataset) {
                        ReputationResult::Listed
                    } else {
                        ReputationResult::Policy
                    }))
                }
                Err(reason) if observation.state != State::Disabled => {
                    observation.state = State::Unavailable;
                    observation.exclusion = Some(transport_exclusion(reason));
                }
                Err(_) => (),
            }
            report.push(observation);
        }
    }
    for (id, av, original, role) in [
        (
            "antivirus",
            &scan.antivirus,
            e.map(|e| e.antivirus_state),
            Role::Safety,
        ),
        (
            "signatures",
            &scan.signatures,
            e.map(|e| e.signatures_state),
            Role::Advisory,
        ),
    ] {
        let mut observation = Observation::new(
            id,
            Family::Malware,
            role,
            av_state(&av.status, original),
            "message",
            id,
            &format!("/{id}"),
        );
        observation.elapsed_ms = Some(av.elapsed_ms);
        if matches!(observation.state, State::Complete | State::Partial) {
            observation.result = Some(ResultValue::Antivirus(av.status.clone()));
        }
        report.push(observation);
    }
    let mut smtp = Observation::new(
        "smtp_dns",
        Family::SenderReputation,
        Role::DecisionInput,
        match scan.smtp_policy.status {
            smtp_policy::PolicyStatus::Complete => State::Complete,
            smtp_policy::PolicyStatus::Disabled => disabled_state(e.map(|e| e.smtp_policy_state)),
            _ if !scan.smtp_policy.timeouts.is_empty() => State::Timeout,
            _ => State::Unavailable,
        },
        "smtp_session",
        "smtp.identity",
        "/smtp_policy",
    );
    smtp.elapsed_ms = Some(scan.smtp_policy.elapsed_ms);
    smtp.version = token(&scan.smtp_policy.version);
    smtp.measured(
        "applied_contribution",
        Some(scan.smtp_policy.applied_weight),
        Unit::LogOdds,
    );
    if let Some(reason) = missing_transport(scan)
        && smtp.state != State::Disabled
    {
        smtp.state = State::Unavailable;
        smtp.measurements.clear();
        smtp.exclusion = Some(reason);
    }
    report.push(smtp);

    let mut llm = Observation::new(
        "llm",
        Family::Content,
        Role::DecisionInput,
        match scan.llm.status {
            llm::LlmStatus::Complete => State::Complete,
            llm::LlmStatus::Disabled => disabled_state(e.map(|e| e.llm.state)),
            llm::LlmStatus::NotNeeded => State::NotApplicable,
            llm::LlmStatus::BudgetLimited => State::BudgetExceeded,
            _ if scan.llm.failure == Some(llm::Failure::Timeout) => State::Timeout,
            _ => State::Unavailable,
        },
        "message_excerpt",
        "message.llm",
        "/llm",
    );
    llm.elapsed_ms = Some(scan.llm.elapsed_ms);
    llm.version = token(&scan.llm.prompt_version);
    llm.artifact_sha256 = digest(e.and_then(|e| e.artifacts.llm_prompt_sha256.as_deref()));
    if llm.state == State::Complete {
        if let Some(verdict) = &scan.llm.verdict {
            llm.measured(
                "reported_probability",
                Some(verdict.spam_probability),
                Unit::ReportedProbability,
            );
            llm.measured(
                "reported_confidence",
                Some(verdict.confidence),
                Unit::ReportedProbability,
            );
            if scan.llm.grounding.as_ref().is_some_and(|g| !g.supported) {
                llm.exclusion = Some(Exclusion::UnsupportedClaims);
            } else if !verdict.coherent() {
                llm.exclusion = Some(Exclusion::InconsistentOpinion);
            } else {
                llm.result = Some(ResultValue::Llm(verdict.category.clone()));
            }
            llm.measured(
                "contribution",
                Some(scan.llm.advisory_weight()),
                Unit::LogOdds,
            );
        } else {
            llm.state = State::Unavailable;
            llm.exclusion = Some(Exclusion::InvalidResult);
        }
    }
    report.push(llm);
    let mut visual = Observation::new(
        "vision",
        Family::Content,
        Role::DecisionInput,
        match scan.vision.status {
            vision::Status::Disabled => State::Disabled,
            vision::Status::Complete if scan.vision.parts == 0 => State::NotApplicable,
            vision::Status::Complete => State::Complete,
            vision::Status::Limited => State::Partial,
            _ if scan.vision.errors.iter().any(|e| e == "timeout") => State::Timeout,
            _ => State::Unavailable,
        },
        "message_images",
        "message.visual",
        "/vision",
    );
    visual.version = token(&scan.vision.version);
    visual.artifact_sha256 = digest(scan.vision.backend_sha256.as_deref());
    visual.elapsed_ms = Some(scan.vision.elapsed_ms);
    visual.measured("qr_codes", Some(scan.vision.qr_codes as f64), Unit::Count);
    visual.measured(
        "text_characters",
        Some(scan.vision.text_chars as f64),
        Unit::Count,
    );
    report.push(visual);
    report.admission(scan);
    report.native(scan);
    if let Some(protection) = &scan.protection {
        report.providers(protection);
        if let Some(redirects) = &protection.url_resolution {
            report.redirects(redirects);
        }
    }
    if let Some(mailing) = &scan.mailing {
        let mut observation = Observation::new(
            "mail_kind",
            Family::Context,
            Role::DecisionInput,
            match mailing.status {
                crate::mailing::Status::Complete => State::Complete,
                crate::mailing::Status::Limited => State::Partial,
            },
            "message",
            "message.kind",
            "/mailing",
        );
        observation.version = token(&mailing.version);
        if observation.state == State::Complete {
            observation.result = Some(ResultValue::MailKind(mailing.verdict));
        }
        report.push(observation);
    }
    report.group();
    report
}
