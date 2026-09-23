mod common;
use noisefence::{
    decision_record,
    engine::Scan,
    evidence::{self, Artifacts, AuthResult, Evidence, Source},
    llm,
    observations::{
        self, Exclusion, Observation, Report, ReputationResult, ResultValue, Role, State, Unit,
    },
    protection::{self, ProviderObservation, ProviderReport},
};

fn scan() -> Scan {
    let dir = tempfile::tempdir().unwrap();
    let cfg = common::config(dir.path());
    let mut e = Evidence::new(
        &cfg,
        Artifacts::new(&cfg, Some("a".repeat(64)), None, true),
        true,
    );
    e.source = Source::SmtpSession;
    Scan {
        raw_sha256: Some(noisefence::message::digest(common::MESSAGE)),
        features_complete: Some(true),
        evidence: Some(e),
        ..Default::default()
    }
}

#[test]
fn admission_checks_and_native_comparison_keep_roles_units_and_do_not_change_the_score() {
    use noisefence::{native_filter as native, rbl};
    let mut s = scan();
    s.score = 42.;
    s.early_rbl = Some(rbl::Report {
        version: "rbl-1".into(),
        elapsed_ms: 7,
        listed_providers: 1,
        minimum_providers: 2,
        would_block: false,
        requested_action: rbl::Action::Observe,
        effective_action: rbl::Action::Observe,
        checks: vec![rbl::Check {
            id: "public-list".into(),
            provider: "private-zone-canary".into(),
            status: rbl::Status::Listed,
            codes: vec!["127.0.0.2".parse().unwrap()],
            incident: None,
            cached: false,
        }],
    });
    s.native_filter = Some(native::Observation {
        report: native::Report {
            version: "native-1".into(),
            policy_sha256: "b".repeat(64),
            mode: native::Mode::Observe,
            status: native::Status::Complete,
            elapsed_ms: 2,
            score: Some(native::rules::Score {
                total: 1.,
                symbols: vec![],
                families: [(
                    native::rules::Family::Llm,
                    native::rules::FamilyScore {
                        raw: 3.,
                        effective: 1.,
                        capped: true,
                    },
                )]
                .into_iter()
                .collect(),
            }),
            bayes: Default::default(),
            bayes_sha256: None,
            fuzzy: Default::default(),
            calibrated: false,
            affects_delivery: false,
            adaptive: None,
        },
        features: None,
        local_symbols: vec![],
        adaptive_vector: None,
    });
    let before = serde_json::to_value(&s).unwrap();
    let r = observations::capture(&s);
    assert_eq!(observation(&r, "rbl.0").role, Role::Admission);
    assert_eq!(
        observation(&r, "rbl.0").group,
        observation(&r, "dqs.ip").group
    );
    assert!(observation(&r, "rbl.0").measurements.is_empty());
    let n = observation(&r, "native.llm");
    assert_eq!(n.role, Role::Comparison);
    assert_eq!(n.group, observation(&r, "llm").group);
    assert_eq!(n.measurements["retained"].unit, Unit::Points);
    assert_eq!(n.measurements["retained"].value, 1.);
    assert_eq!(n.measurements["raw"].value, 3.);
    assert_eq!(serde_json::to_value(&s).unwrap(), before);
    assert!(
        !serde_json::to_string(&r)
            .unwrap()
            .contains("private-zone-canary")
    );
}

#[test]
fn http_navigation_completion_never_becomes_a_clean_threat_verdict() {
    use protection::redirects::{Chain, Detail, Hop, Report as Redirects};
    let mut s = scan();
    s.protection = Some(protection::Report {
        url_resolution: Some(Redirects {
            version: "redirects-1".into(),
            settings_sha256: "b".repeat(64),
            omitted: 0,
            elapsed_ms: 20,
            local_inventory_available: Some(true),
            chains: vec![Chain {
                source_sha256: "a".repeat(64),
                hops: vec![Hop {
                    url_sha256: "b".repeat(64),
                    site: "private-site-canary".into(),
                    code: 200,
                }],
                complete: true,
                reached_http_success: true,
                body_truncated: false,
                detail: None,
            }],
        }),
        ..Default::default()
    });
    let r = observations::capture(&s);
    let url = observation(&r, "redirect.0");
    assert_eq!(url.state, State::Complete);
    assert!(url.result.is_none());
    assert_eq!(url.measurements["hops"].value, 1.);
    assert!(
        !serde_json::to_string(&r)
            .unwrap()
            .contains("private-site-canary")
    );
    s.protection
        .as_mut()
        .unwrap()
        .url_resolution
        .as_mut()
        .unwrap()
        .chains[0]
        .detail = Some(Detail::Deadline);
    assert_eq!(
        observation(&observations::capture(&s), "redirect.0").state,
        State::Timeout
    );
}
fn observation<'a>(report: &'a Report, id: &str) -> &'a Observation {
    report.observations.iter().find(|o| o.id == id).unwrap()
}
fn target(verdict: &str, scope: &str) -> ProviderObservation {
    ProviderObservation {
        indicator_sha256: "a".repeat(64),
        scope: scope.into(),
        verdict: verdict.into(),
        queried_at: 1234,
        cached: true,
        cache_max_age_seconds: 1800,
        analysis_max_age_seconds: None,
    }
}
fn provider(verdict: &str, scope: &str) -> ProviderReport {
    ProviderReport {
        status: protection::Status::Complete,
        checked: 1,
        captured_at: Some(1234),
        observations: vec![target(verdict, scope)],
        ..Default::default()
    }
}

#[test]
fn unavailable_disabled_timeout_and_quota_are_different_facts() {
    let mut s = scan();
    s.llm.status = llm::LlmStatus::BudgetLimited;
    s.semantic.status = noisefence::engine::SemanticStatus::Unavailable;
    s.semantic.failure = Some(noisefence::engine::SemanticFailure::Deadline);
    s.smtp_policy.status = noisefence::smtp_policy::PolicyStatus::Unavailable;
    s.smtp_policy.timeouts = vec![noisefence::smtp_policy::CheckKind::Ptr];
    let r = observations::capture(&s);
    assert_eq!(observation(&r, "llm").state, State::BudgetExceeded);
    assert_eq!(observation(&r, "semantic").state, State::Timeout);
    assert_eq!(observation(&r, "smtp_dns").state, State::Timeout);
    assert_eq!(observation(&r, "vision").state, State::Disabled);
    assert!(
        r.observations
            .iter()
            .filter(|o| o.state != State::Complete && o.state != State::Partial)
            .all(|o| o.measurements.is_empty())
    );
    // An old diagnostic string is not authoritative typed timeout evidence.
    s.smtp_policy.timeouts.clear();
    s.smtp_policy.checks.push(noisefence::engine::Signal {
        id: "smtp_timeout".into(),
        detail: "SMTP identity check exceeded its DNS deadline".into(),
        weight: 0.,
    });
    assert_eq!(
        observation(&observations::capture(&s), "smtp_dns").state,
        State::Unavailable
    );
}

#[test]
fn authentication_requires_recorded_results_and_real_envelope_context() {
    let mut s = scan();
    let a = &mut s.evidence.as_mut().unwrap().authentication;
    a.spf_state = evidence::State::Complete;
    a.dkim_state = evidence::State::Complete;
    a.dkim = Some(vec![]); // Verified absence of signatures is a real result.
    let r = observations::capture(&s);
    assert_eq!(
        observation(&r, "spf").exclusion,
        Some(Exclusion::InvalidResult)
    );
    assert!(matches!(&observation(&r, "dkim").result,
        Some(ResultValue::Authentication(v)) if v.is_empty()));
    s.evidence.as_mut().unwrap().authentication.spf = Some(AuthResult::TempError);
    assert_eq!(
        observation(&observations::capture(&s), "spf").state,
        State::Unavailable
    );
    s.evidence.as_mut().unwrap().authentication.spf = Some(AuthResult::Pass);
    s.evidence.as_mut().unwrap().source = Source::ContentOnly;
    let r = observations::capture(&s);
    assert_eq!(
        observation(&r, "spf").exclusion,
        Some(Exclusion::MissingEnvelopeContext)
    );
    assert!(observation(&r, "spf").result.is_none());
}

#[test]
fn completion_flags_without_model_results_do_not_establish_measurements() {
    let mut s = scan();
    let e = s.evidence.as_mut().unwrap();
    e.lexical_state = evidence::State::Complete;
    e.lexical_logit = None;
    e.antivirus_state = evidence::State::Complete;
    e.llm.state = evidence::State::Complete;
    e.semantic_state = evidence::State::Complete;
    let r = observations::capture(&s);
    for id in ["lexical", "antivirus", "llm", "semantic"] {
        assert_eq!(observation(&r, id).state, State::Unavailable);
        assert!(observation(&r, id).result.is_none());
        assert!(observation(&r, id).measurements.is_empty());
    }
    s.semantic.status = noisefence::engine::SemanticStatus::Complete;
    s.semantic.logit = Some(f64::NAN);
    s.semantic.contribution = Some(1.);
    let r = observations::capture(&s);
    assert_eq!(
        observation(&r, "semantic").exclusion,
        Some(Exclusion::InvalidResult)
    );
    assert!(observation(&r, "semantic").measurements.is_empty());
    s.evidence.as_mut().unwrap().lexical_logit = Some(0.);
    let r = observations::capture(&s);
    assert_eq!(observation(&r, "lexical").state, State::Complete);
    assert_eq!(observation(&r, "lexical").measurements["logit"].value, 0.);
}

#[test]
fn completed_target_facts_survive_other_targets_failing_but_never_become_clean() {
    for (status, failure, state) in [
        (protection::Status::Quota, None, State::BudgetExceeded),
        (protection::Status::Busy, None, State::Unavailable),
        (
            protection::Status::Unavailable,
            Some(serde_json::from_str("\"timeout\"").unwrap()),
            State::Timeout,
        ),
    ] {
        let mut s = scan();
        let mut p = provider("malicious", "host_lookup");
        p.status = status;
        p.failure = failure;
        p.omitted = 1;
        s.protection = Some(protection::Report {
            crdf: p,
            ..Default::default()
        });
        let r = observations::capture(&s);
        assert_eq!(observation(&r, "crdf").state, state);
        let t = observation(&r, "crdf.0");
        assert_eq!(t.state, State::Complete);
        assert!(matches!(
            t.result,
            Some(ResultValue::Reputation(ReputationResult::Malicious))
        ));
        assert_eq!(t.queried_at, Some(1234));
        assert_eq!(t.cache_max_age_seconds, Some(1800));
        s.protection.as_mut().unwrap().crdf.observations[0].verdict = "no_hit".into();
        assert!(matches!(
            observation(&observations::capture(&s), "crdf.0").result,
            Some(ResultValue::Reputation(ReputationResult::NotListed))
        ));
        // NoHit is not an attestation that the target is clean.
        s.protection.as_mut().unwrap().crdf.observations[0].verdict = "clean".into();
        assert_eq!(
            observation(&observations::capture(&s), "crdf.0").exclusion,
            Some(Exclusion::InvalidResult)
        );
    }
}

#[test]
fn stale_and_disabled_provider_values_cannot_become_completed_detections() {
    let mut s = scan();
    s.protection = Some(protection::Report {
        crdf: provider("stale", "host_lookup"),
        ..Default::default()
    });
    let r = observations::capture(&s);
    assert_eq!(observation(&r, "crdf.0").state, State::Unavailable);
    let p = &mut s.protection.as_mut().unwrap().crdf;
    p.status = protection::Status::Disabled;
    p.observations[0].verdict = "malicious".into();
    let r = observations::capture(&s);
    assert_eq!(observation(&r, "crdf").state, State::Disabled);
    assert!(observation(&r, "crdf.0").result.is_none());
}

#[test]
fn shared_host_is_one_evidence_group_with_explicit_provider_scopes() {
    let mut s = scan();
    s.reputation_target_hashes = vec!["a".repeat(64)];
    s.evidence
        .as_mut()
        .unwrap()
        .reputation
        .domains
        .push(evidence::DomainQuery {
            roles: vec![evidence::DomainRole::Body],
            result: evidence::Query {
                state: evidence::State::Complete,
                codes: vec!["127.0.1.2".parse().unwrap()],
            },
        });
    s.protection = Some(protection::Report {
        crdf: provider("malicious", "host_lookup"),
        virustotal: provider("no_hit", "domain"),
        ..Default::default()
    });
    let r = observations::capture(&s);
    let group = r
        .groups
        .iter()
        .find(|g| g.key == format!("host:{}", "a".repeat(64)))
        .unwrap();
    assert_eq!(
        group.observations,
        ["dqs.domain.0", "crdf.0", "virustotal.0"]
    );
    assert!(
        !group.conflict,
        "not listed is not a clean verdict contradicting a listing"
    );
    assert_eq!(observation(&r, "crdf.0").scope, "host_lookup");
    assert_eq!(observation(&r, "virustotal.0").scope, "domain");
    assert_eq!(observation(&r, "crdf.0").role, Role::Advisory);
    // Historical domains without identity cannot be guessed from provider hits.
    s.reputation_target_hashes.clear();
    let r = observations::capture(&s);
    assert_ne!(
        observation(&r, "dqs.domain.0").group,
        observation(&r, "crdf.0").group
    );
}

#[test]
fn unsupported_llm_has_no_usable_verdict_or_weight_and_raw_units_are_explicit() {
    let mut s = scan();
    s.llm.status = llm::LlmStatus::Complete;
    s.llm.verdict = Some(llm::Verdict {
        category: llm::Category::Phishing,
        confidence: 0.99,
        spam_probability: 0.99,
        explanation: "private-content-canary".into(),
    });
    s.llm.grounding = Some(llm::grounding::Report {
        version: "test".into(),
        supported: false,
        mail_kind: noisefence::quality::Kind::Other,
        accepted_citations: 0,
        issues: vec![],
    });
    let r = observations::capture(&s);
    let llm = observation(&r, "llm");
    assert_eq!(
        llm.state,
        State::Complete,
        "execution completed even though claims are excluded"
    );
    assert_eq!(llm.exclusion, Some(Exclusion::UnsupportedClaims));
    assert!(llm.result.is_none());
    assert_eq!(llm.measurements["contribution"].value, 0.);
    assert_eq!(llm.measurements["contribution"].unit, Unit::LogOdds);
    assert_eq!(
        llm.measurements["reported_probability"].unit,
        Unit::ReportedProbability
    );
    assert!(
        !serde_json::to_string(&r)
            .unwrap()
            .contains("private-content-canary")
    );
    s.llm.status = llm::LlmStatus::Unavailable;
    let r = observations::capture(&s);
    assert!(observation(&r, "llm").result.is_none());
    assert!(observation(&r, "llm").measurements.is_empty());
}

#[test]
fn normalization_is_bounded_and_preserved_at_receipt_not_rebuilt_on_read() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = common::config(dir.path());
    let mut s = scan();
    s.protection = Some(protection::Report {
        crdf: ProviderReport {
            status: protection::Status::Complete,
            checked: 1000,
            observations: (0..1000).map(|_| target("no_hit", "host_lookup")).collect(),
            ..Default::default()
        },
        ..Default::default()
    });
    decision_record::record_analysis(&mut s, &cfg);
    let before = serde_json::to_value(&s.analysis_result.as_ref().unwrap().observations).unwrap();
    assert_eq!(before["omitted"], 952);
    assert!(before["observations"].as_array().unwrap().len() <= 160);
    let mut restored: Scan = serde_json::from_slice(&serde_json::to_vec(&s).unwrap()).unwrap();
    restored.protection = None;
    restored.llm.status = llm::LlmStatus::Complete;
    decision_record::record_analysis(&mut restored, &cfg);
    assert_eq!(
        serde_json::to_value(noisefence::diagnostics::Analysis::from(restored)).unwrap()["observations"],
        before
    );
    s.analysis_result = None;
    assert!(
        noisefence::diagnostics::Analysis::from(s)
            .observations
            .is_none(),
        "legacy read is never a retrospective reanalysis"
    );
}

#[test]
fn provider_duplicates_conflicts_and_missing_time_have_explicit_exclusions() {
    let mut s = scan();
    let mut p = provider("malicious", "host_lookup");
    p.observations.push(target("malicious", "host_lookup"));
    s.protection = Some(protection::Report {
        crdf: p,
        ..Default::default()
    });
    let r = observations::capture(&s);
    assert_eq!(r.version, observations::VERSION);
    assert_eq!(observation(&r, "crdf.0").state, State::Complete);
    assert_eq!(
        observation(&r, "crdf.1").exclusion,
        Some(Exclusion::DuplicateTarget)
    );
    s.protection.as_mut().unwrap().crdf.observations[1].verdict = "no_hit".into();
    let r = observations::capture(&s);
    assert_eq!(observation(&r, "crdf").state, State::Partial);
    for id in ["crdf.0", "crdf.1"] {
        assert_eq!(
            observation(&r, id).exclusion,
            Some(Exclusion::ConflictingTarget)
        );
        assert!(observation(&r, id).result.is_none());
    }
    s.protection.as_mut().unwrap().crdf.captured_at = None;
    let r = observations::capture(&s);
    assert_eq!(
        observation(&r, "crdf.0").exclusion,
        Some(Exclusion::MissingCaptureTime)
    );
}
