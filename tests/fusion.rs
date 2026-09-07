use noisefence::{
    config::Config,
    evidence::{Artifacts, AuthResult, DomainQuery, DomainRole, Evidence, Query, Source, State},
    fusion::{self, Calibration, Model},
};

fn evidence() -> Evidence {
    let config: Config = toml::from_str(include_str!("../config/development.toml")).unwrap();
    let artifacts = Artifacts::new(&config, Some("1".repeat(64)), None, false);
    let mut e = Evidence::new(&config, artifacts, false);
    e.source = Source::SmtpSession;
    e.analysis_complete = true;
    e.lexical_state = State::Complete;
    e.lexical_logit = Some(16.0);
    e.authentication.arc_state = State::Complete;
    e.authentication.arc = Some(AuthResult::None);
    e.authentication.arc_can_seal = Some(true);
    e
}
fn value(e: &Evidence, key: &str) -> f64 {
    fusion::features(e).unwrap()[fusion::specs().iter().position(|f| f.name == key).unwrap()]
}
fn model(e: &Evidence) -> Model {
    let mut weights = vec![0.0; fusion::specs().len()];
    weights[fusion::specs()
        .iter()
        .position(|f| f.name == "lexical.logit_clipped_32")
        .unwrap()] = 2.0;
    Model {
        schema: fusion::SCHEMA.into(),
        version: "test-fusion-1".into(),
        protocol_sha256: fusion::protocol_sha256(),
        artifacts: e.artifacts.clone(),
        weights,
        bias: -0.25,
        cutoff: 0.75,
        calibration: Calibration {
            slope: 2.0,
            intercept: -1.0,
            messages: 100,
            positive_fraction: 0.2,
        },
        supported_profiles: vec![fusion::availability_profile(e)],
        manifest_sha256: "2".repeat(64),
        purpose: "research".into(),
    }
}

#[test]
fn observations_are_bounded_missing_is_not_negative_and_old_scores_are_excluded() {
    let mut e = evidence();
    assert_eq!(fusion::features(&e).unwrap().len(), 218);
    assert_eq!(value(&e, "lexical.logit_clipped_32"), 0.5);
    let before = fusion::features(&e).unwrap();
    e.legacy_score = Some(100.0);
    e.analysis_complete = false;
    assert_eq!(before, fusion::features(&e).unwrap());
    e.lexical_logit = Some(1000.0);
    assert_eq!(value(&e, "lexical.logit_clipped_32"), 1.0);
    e.lexical_state = State::Unavailable;
    assert!(fusion::features(&e).is_err());
    e.lexical_logit = None;
    assert_eq!(value(&e, "lexical.state.unavailable"), 1.0);
    assert_eq!(value(&e, "lexical.logit_clipped_32"), 0.0);
    e.source = Source::ContentOnly;
    assert!(fusion::features(&e).is_err());
}

#[test]
fn canonical_reputation_codes_and_roles_prevent_provider_errors_becoming_hits() {
    let mut e = evidence();
    e.reputation.state = State::Complete;
    e.reputation.ip.state = State::Complete;
    e.reputation.domains = vec![DomainQuery {
        roles: vec![DomainRole::HeaderFrom, DomainRole::Body],
        result: Query {
            state: State::Complete,
            codes: vec!["127.0.1.102".parse().unwrap()],
        },
    }];
    assert_eq!(value(&e, "reputation.body.code_102"), 1.0);
    assert!(
        !fusion::specs()
            .iter()
            .any(|f| f.name == "reputation.header_from.code_102")
    );
    e.reputation.domains[0].result.codes = vec!["127.255.255.254".parse().unwrap()];
    assert!(fusion::features(&e).is_err());
    e.reputation.domains[0].result.codes.clear();
    e.reputation.domains[0].result.state = State::Unavailable;
    assert!(fusion::features(&e).is_err());
    e.reputation.state = State::Unavailable;
    assert_eq!(
        value(&e, "reputation.body.queries_unavailable_div12"),
        1.0 / 12.0
    );
    assert!(!fusion::tag_eligible(&e));
    e.reputation.domains[0].roles.push(DomainRole::Body);
    assert!(fusion::features(&e).is_err());
}

#[test]
fn native_threshold_is_raw_and_failures_or_unknown_profiles_cannot_tag() {
    let e = evidence();
    let m = model(&e);
    let p = m.predict(&e).unwrap();
    assert_eq!(p.logit, 0.75);
    assert!(p.would_tag && p.above_threshold && p.profile_supported);
    assert!((p.probability - 1.0 / (1.0 + (-0.5_f64).exp())).abs() < 1e-15);
    assert_eq!(p.contributions[0].feature, "lexical.logit_clipped_32");
    for delta in [-1e-8, 1e-8] {
        let mut changed = e.clone();
        changed.lexical_logit = Some(16.0 + delta);
        assert_eq!(m.predict(&changed).unwrap().would_tag, delta > 0.0);
    }
    for state in [State::NotRun, State::Busy, State::Unavailable] {
        let mut changed = e.clone();
        changed.lexical_state = state;
        changed.lexical_logit = None;
        let mut m = model(&changed);
        m.bias = 100.0;
        let p = m.predict(&changed).unwrap();
        assert!(p.above_threshold && p.profile_supported);
        assert!(!p.tag_eligible && !p.would_tag);
    }
    let mut changed = e.clone();
    changed.authentication.arc_can_seal = Some(false);
    assert!(!m.predict(&changed).unwrap().would_tag);
    changed = e.clone();
    changed.source = Source::SuppliedEnvelope;
    assert!(!m.predict(&changed).unwrap().would_tag);
    changed = e.clone();
    changed.artifacts.policy_sha256 = "3".repeat(64);
    assert!(m.predict(&changed).is_err());
    let mut m = model(&e);
    m.supported_profiles = vec!["not_seen".into()];
    assert!(!m.predict(&e).unwrap().would_tag);
    m.calibration.slope = -1.0;
    assert!(m.validate().is_err());
}

fn row(e: Option<Evidence>, id: char) -> serde_json::Value {
    serde_json::json!({"schema":"noisefence-learning-1", "source":"local_human_feedback", "id":id.to_string().repeat(64),
        "observed_at":10,"labelled_at":11,"feature_version":3,"spam":false,"fingerprint":"a".repeat(64),
        "simhash":"1234567890abcdef","evidence":e,"features":"IGNORED PRIVATE CONTENT","attacker_label":"not a feature"})
}

#[test]
fn llm_self_report_and_manual_weights_remain_observations_and_busy_never_tags() {
    use noisefence::{
        antivirus::{AntivirusResult, AntivirusStatus},
        engine::Signal,
        llm::{Category, LlmStatus},
        smtp_policy::{PolicyResult, PolicyStatus},
    };
    let mut e = evidence();
    e.artifacts.llm_prompt_sha256 = Some(noisefence::llm::prompt_sha256());
    e.llm.model = "fixture-model".into();
    e.llm.prompt_version = noisefence::llm::PROMPT_VERSION.into();
    e.llm.state = State::Complete;
    e.llm.outcome = Some(LlmStatus::Complete);
    e.llm.requested_at_score = Some(85.0);
    e.llm.category = Some(Category::Phishing);
    e.llm.reported_probability = Some(0.9);
    e.llm.reported_confidence = Some(0.95);
    e.antivirus_state = State::Complete;
    e.antivirus = Some(AntivirusResult {
        status: AntivirusStatus::Clean,
        ..Default::default()
    });
    e.smtp_policy_state = State::Complete;
    e.smtp_policy = Some(PolicyResult {
        status: PolicyStatus::Complete,
        version: noisefence::smtp_policy::VERSION.into(),
        checks: ["helo_verified", "ptr_verified", "sender_mx_present"]
            .iter()
            .map(|id| Signal {
                id: (*id).into(),
                detail: "ignored narrative".into(),
                weight: 100.0,
            })
            .collect(),
        ..Default::default()
    });
    assert_eq!(value(&e, "llm.reported_probability"), 0.9);
    let before = fusion::features(&e).unwrap();
    e.llm.requested_at_score = Some(1.0);
    e.smtp_policy.as_mut().unwrap().checks[0].weight = -1000.0;
    e.smtp_policy.as_mut().unwrap().checks[0].detail = "label=legit".into();
    e.smtp_policy.as_mut().unwrap().applied_weight = 99.0;
    e.antivirus.as_mut().unwrap().signature = Some("label=spam".into());
    e.antivirus.as_mut().unwrap().elapsed_ms = 99999;
    assert_eq!(before, fusion::features(&e).unwrap());
    for (status, state) in [
        (LlmStatus::Unavailable, State::Unavailable),
        (LlmStatus::Busy, State::Busy),
        (LlmStatus::BudgetLimited, State::Skipped),
    ] {
        e.llm.state = state;
        e.llm.outcome = Some(status);
        e.llm.category = None;
        e.llm.reported_probability = None;
        e.llm.reported_confidence = None;
        let m = model(&e);
        let result = m.predict(&e).unwrap();
        assert_eq!(result.would_tag, state == State::Skipped);
    }
    e.llm.reported_probability = Some(0.0);
    assert!(fusion::features(&e).is_err());
}

#[test]
fn offline_export_is_atomic_private_bounded_to_one_cohort_and_omissions_visible() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input.jsonl");
    let output = dir.path().join("vectors.jsonl");
    let mut diagnostic = evidence();
    diagnostic.source = Source::SuppliedEnvelope;
    std::fs::write(
        &input,
        [
            row(Some(evidence()), '1'),
            row(None, '2'),
            row(Some(diagnostic), '3'),
        ]
        .iter()
        .map(|r| format!("{r}\n"))
        .collect::<String>(),
    )
    .unwrap();
    let report = fusion::io::convert(&input, &output, None).unwrap();
    assert_eq!(
        (
            report.exported,
            report.missing_evidence,
            report.non_smtp_evidence
        ),
        (1, 1, 1)
    );
    assert_eq!(
        std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let contents = std::fs::read_to_string(&output).unwrap();
    assert_eq!(contents.lines().count(), 3);
    assert!(!contents.contains("PRIVATE CONTENT") && !contents.contains("attacker_label"));
    assert!(fusion::io::convert(&input, &output, None).is_err());
    assert_eq!(contents, std::fs::read_to_string(&output).unwrap());
    let mut changed = evidence();
    changed.artifacts.policy_sha256 = "3".repeat(64);
    std::fs::write(
        &input,
        format!(
            "{}\n{}\n",
            row(Some(evidence()), '1'),
            row(Some(changed), '2')
        ),
    )
    .unwrap();
    let failed = dir.path().join("failed.jsonl");
    assert!(fusion::io::convert(&input, &failed, None).is_err());
    assert!(!failed.exists());
    assert!(!std::fs::read_dir(dir.path()).unwrap().any(|f| {
        f.unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".partial")
    }));
}
