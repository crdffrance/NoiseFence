use noisefence::{
    config::Config,
    decision_record, detection_diagnostics, diagnostics,
    engine::{Scan, SemanticStatus, Signal},
    scoring::{self, Adjustment},
};
use std::path::Path;
#[path = "common/unavailable_score.rs"]
mod unavailable_score;

#[test]
fn unavailable_transport_requires_explicit_consistent_evidence() {
    let config: Config = toml::from_str(include_str!("../config/development.toml")).unwrap();
    let original = unavailable_score::scan(&config);
    scoring::validate_transport(&original).unwrap();
    let roundtrip: Scan = serde_json::from_str(&serde_json::to_string(&original).unwrap()).unwrap();
    scoring::validate_transport(&roundtrip).unwrap();
    assert_eq!(
        noisefence::assessment::historical(&roundtrip).score.value,
        None
    );
    let mutations: &[fn(&mut Scan)] = &[
        |s| s.score = -2.,
        |s| s.score = -0.5,
        |s| s.score = 100.01,
        |s| s.score = f64::NAN,
        |s| s.score = f64::INFINITY,
        |s| s.complete = true,
        |s| s.scoring = None,
        |s| s.scoring.as_mut().unwrap().version = "unknown".into(),
        |s| s.scoring.as_mut().unwrap().score = Some(0.),
        |s| s.scoring.as_mut().unwrap().total_logit = Some(0.),
        |s| s.reasons.retain(|r| r.id != "score_combination_invalid"),
        |s| s.analysis_result.as_mut().unwrap().scoring = None,
        |s| s.analysis_result.as_mut().unwrap().score.raw = Some(0.),
        |s| s.analysis_result.as_mut().unwrap().score.scale = 1,
        |s| {
            s.analysis_result.as_mut().unwrap().coverage =
                noisefence::decision_record::Coverage::Complete
        },
        |s| {
            s.analysis_result.as_mut().unwrap().score.source =
                noisefence::assessment::ScoreSource::Raw
        },
        |s| s.recipient_decision.as_mut().unwrap().assessment.complete = true,
        |s| {
            s.recipient_decision
                .as_mut()
                .unwrap()
                .assessment
                .score
                .value = Some(0.)
        },
        |s| s.decision.as_mut().unwrap().score = Some(-1.),
        |s| s.decision.as_mut().unwrap().score = Some(0.),
    ];
    for (index, mutate) in mutations.iter().enumerate() {
        let mut scan = original.clone();
        mutate(&mut scan);
        assert!(
            scoring::validate_transport(&scan).is_err(),
            "mutation {index}"
        );
    }
    // Pre-snapshot records remain supported when their ledger explicitly proves
    // unavailable content; an unrelated fusion decision may still have a score.
    let mut scan = original.clone();
    scan.analysis_result = None;
    scan.recipient_decision = None;
    scoring::validate_transport(&scan).unwrap();
    scan.decision = Some(noisefence::fusion::runtime::Decision {
        source: noisefence::fusion::runtime::DecisionSource::Fusion,
        outcome: noisefence::fusion::runtime::Outcome::Unwanted,
        score: Some(97.),
        model: "separate-fusion-fixture".into(),
    });
    decision_record::record_recipient(&mut scan, &config, None, noisefence::now());
    scoring::validate_transport(&scan).unwrap();
    assert_eq!(
        noisefence::assessment::historical(&scan).score.value,
        Some(97.)
    );
    assert_eq!(noisefence::assessment::historical(&scan).score.raw, None);
    for score in [0., 0.1, 100.] {
        let scan = Scan {
            score,
            ..Default::default()
        };
        scoring::validate_transport(&scan).unwrap();
    }
    assert!(
        scoring::validate_transport(&Scan {
            score: -1.,
            ..Default::default()
        })
        .is_err()
    );
}

fn signal(id: &str, weight: f64) -> Signal {
    Signal {
        id: id.into(),
        detail: "PRIVATE EMAIL AND PROVIDER TEXT".into(),
        weight,
    }
}
fn sample() -> Scan {
    use noisefence::evidence::{
        Artifacts, AuthResult, DomainQuery, DomainRole, Evidence, Query, Source, State,
    };
    let config = Config::load(Path::new("config/development.toml")).unwrap();
    let mut evidence = Evidence::new(&config, Artifacts::new(&config, None, None, false), false);
    evidence.source = Source::SmtpSession;
    evidence.authentication.state = State::Complete;
    evidence.authentication.spf_state = State::Complete;
    evidence.authentication.spf = Some(AuthResult::Fail);
    evidence.reputation.state = State::Complete;
    evidence.reputation.domains = vec![DomainQuery {
        roles: vec![DomainRole::Body],
        result: Query {
            state: State::Complete,
            codes: vec!["127.0.1.2".parse().unwrap()],
        },
    }];
    Scan {
        evidence: Some(evidence),
        complete: true,
        features_complete: Some(true),
        feature_version: noisefence::features::VERSION,
        reasons: vec![
            signal("urgency", 0.5),
            signal("spf_fail", 1.),
            signal("domain_reputation", 4.),
        ],
        ..Default::default()
    }
}

#[test]
fn dmarc_consumes_the_observed_spf_failure_once_without_erasing_other_findings() {
    use noisefence::evidence::{AuthResult as A, State};
    let mut scan = sample();
    scan.reasons.push(signal("dmarc_fail", 2.));
    let a = &mut scan.evidence.as_mut().unwrap().authentication;
    a.dmarc_state = State::Complete;
    a.dmarc_spf = Some(A::Fail);
    a.dmarc_dkim = Some(A::Fail);
    let report = scoring::combine(&scan, Some(-2.), false);
    assert_eq!(report.rules_total, Some(6.5)); // 4 reputation + 2 DMARC + 0.5 urgency
    let spf = report
        .contributions
        .iter()
        .find(|r| r.id == "spf_fail")
        .unwrap();
    assert_eq!(spf.proposed, Some(1.));
    assert_eq!(spf.retained, Some(0.));
    assert_eq!(spf.adjustment, Adjustment::SubsumedEvidence);
    assert_eq!(spf.subsumed_by.as_deref(), Some("dmarc_fail"));
    scan.reasons.extend(scan.reasons.clone());
    scan.reasons.reverse();
    assert_eq!(
        scoring::combine(&scan, Some(-2.), false).score,
        report.score
    );
    // Missing DMARC evidence must not consume the separately observed SPF fail.
    scan.evidence.as_mut().unwrap().authentication.dmarc_state = State::Unavailable;
    let partial = scoring::combine(&scan, Some(-2.), false);
    assert_eq!(partial.rules_total, Some(5.5));
    assert!(
        partial
            .contributions
            .iter()
            .all(|r| r.subsumed_by.is_none())
    );
    // Conflicting duplicate inputs remain invalid, even in a consumed rule.
    scan.reasons.push(signal("spf_fail", 3.));
    assert!(scoring::combine(&scan, Some(-2.), false).score.is_none());
}

#[test]
fn unobserved_or_incompatible_transport_findings_cannot_retain_weights() {
    use noisefence::evidence::{Source, State};
    let changes: &[fn(&mut Scan)] = &[
        |s| s.evidence = None,
        |s| s.evidence.as_mut().unwrap().source = Source::ContentOnly,
        |s| s.evidence.as_mut().unwrap().schema = "unknown".into(),
        |s| {
            let e = s.evidence.as_mut().unwrap();
            e.authentication.spf_state = State::Unavailable;
            e.reputation.state = State::Disabled;
        },
        |s| {
            let e = s.evidence.as_mut().unwrap();
            e.authentication.state = State::Disabled;
            e.reputation.state = State::Busy;
        },
    ];
    for change in changes {
        let mut scan = sample();
        change(&mut scan);
        let report = scoring::combine(&scan, Some(-2.), false);
        assert_eq!(report.rules_total, Some(0.5));
        for r in report.contributions.iter().filter(|r| r.id != "urgency") {
            assert_eq!(r.retained, Some(0.));
            assert_eq!(r.adjustment, Adjustment::UnavailableEvidence);
        }
    }
}

#[test]
fn completed_reputation_targets_survive_partial_outages_but_policy_and_error_codes_do_not() {
    use noisefence::evidence::{DomainQuery, DomainRole, Query, State};
    let mut scan = sample();
    scan.reasons = vec![signal("domain_reputation", 4.), signal("ip_reputation", 4.)];
    let e = &mut scan.evidence.as_mut().unwrap().reputation;
    e.state = State::Unavailable;
    e.ip = Query {
        state: State::Complete,
        codes: vec!["127.0.0.2".parse().unwrap()],
    };
    e.domains.push(DomainQuery {
        roles: vec![DomainRole::Helo],
        result: Query::new(State::Unavailable),
    });
    assert_eq!(scoring::combine(&scan, None, false).rules_total, Some(8.));
    for code in ["127.0.0.10", "127.0.0.30", "127.255.255.254", "192.0.2.1"] {
        scan.evidence.as_mut().unwrap().reputation.ip.codes = vec![code.parse().unwrap()];
        assert_eq!(scoring::combine(&scan, None, false).rules_total, Some(4.));
    }
    for code in ["127.0.1.102", "127.255.255.254", "127.0.0.2"] {
        scan.evidence.as_mut().unwrap().reputation.domains[0]
            .result
            .codes = vec![code.parse().unwrap()];
        assert_eq!(scoring::combine(&scan, None, false).rules_total, Some(0.));
    }
}

#[test]
fn smtp_contribution_uses_current_complete_bounded_policy_not_a_stale_signal() {
    use noisefence::smtp_policy::{self, PolicyStatus};
    let mut scan = sample();
    scan.reasons = vec![signal("smtp_policy_contribution", 1.5)];
    let p = &mut scan.smtp_policy;
    p.version = smtp_policy::VERSION.into();
    p.status = PolicyStatus::Complete;
    p.scoring_enabled = true;
    p.applied_weight = -0.25;
    assert_eq!(
        scoring::combine(&scan, None, false).rules_total,
        Some(-0.25)
    );
    scan.smtp_policy.scoring_enabled = false;
    assert_eq!(scoring::combine(&scan, None, false).rules_total, Some(0.));
    scan.smtp_policy.scoring_enabled = true;
    for status in [
        PolicyStatus::Unavailable,
        PolicyStatus::Busy,
        PolicyStatus::Disabled,
    ] {
        scan.smtp_policy.status = status;
        assert_eq!(scoring::combine(&scan, None, false).rules_total, Some(0.));
    }
    scan.smtp_policy.status = PolicyStatus::Complete;
    scan.smtp_policy.applied_weight = 8.;
    assert_eq!(scoring::combine(&scan, None, false).rules_total, Some(0.));
}

#[test]
fn old_unavailable_ledgers_remain_readable_without_acquiring_new_dependencies() {
    let config: Config = toml::from_str(include_str!("../config/development.toml")).unwrap();
    let mut scan = unavailable_score::scan(&config);
    let report = scan.scoring.as_mut().unwrap();
    report.version = scoring::LEGACY_VERSION.into();
    scan.analysis_result.as_mut().unwrap().scoring = Some(report.clone());
    let raw = serde_json::to_string(&scan).unwrap();
    assert!(!raw.contains("subsumed_by"));
    let restored: Scan = serde_json::from_str(&raw).unwrap();
    scoring::validate_transport(&restored).unwrap();
    assert_eq!(
        scoring::recorded(&restored).unwrap().version,
        scoring::LEGACY_VERSION
    );
}

#[test]
fn dmarc_success_temporary_errors_and_missing_branches_cannot_supply_a_failure_vote() {
    use noisefence::evidence::{AuthResult as A, State};
    for (spf, dkim) in [
        (Some(A::Fail), Some(A::Pass)),
        (Some(A::Pass), Some(A::Fail)),
        (Some(A::Fail), Some(A::TempError)),
        (Some(A::TempError), Some(A::Fail)),
        (Some(A::Fail), None),
        (None, Some(A::Fail)),
        (Some(A::None), Some(A::None)),
    ] {
        let mut scan = sample();
        scan.reasons = vec![signal("spf_fail", 1.), signal("dmarc_fail", 2.)];
        let a = &mut scan.evidence.as_mut().unwrap().authentication;
        a.dmarc_state = State::Complete;
        a.dmarc_spf = spf;
        a.dmarc_dkim = dkim;
        let report = scoring::combine(&scan, None, false);
        assert_eq!(report.rules_total, Some(1.));
        assert!(report.contributions.iter().all(|r| r.subsumed_by.is_none()));
    }
}

#[test]
fn a_shared_authentication_failure_cannot_cross_the_threshold_by_counting_spf_twice() {
    use noisefence::{
        decision,
        evidence::{AuthResult as A, State},
        fusion::runtime::{Decision, DecisionSource, Outcome},
    };
    let mut scan = sample();
    scan.reasons = vec![signal("spf_fail", 1.), signal("dmarc_fail", 2.)];
    let a = &mut scan.evidence.as_mut().unwrap().authentication;
    a.dmarc_state = State::Complete;
    a.dmarc_spf = Some(A::Fail);
    a.dmarc_dkim = Some(A::Fail);
    let report = scoring::combine(&scan, Some(0.), false);
    scan.score = report.score.unwrap();
    scan.scoring = Some(report);
    assert!(noisefence::engine::sigmoid(3.) * 100. >= 95.); // old additive policy
    assert!(scan.score < 95.);
    scan.decision = Some(Decision {
        source: DecisionSource::Legacy,
        outcome: Outcome::Undetermined,
        score: Some(scan.score),
        model: "synthetic-index".into(),
    });
    decision::resolve_by_score(&mut scan, true, 95.);
    assert_eq!(scan.decision.as_ref().unwrap().outcome, Outcome::Legitimate);
    assert_eq!(scan.score_resolution.as_ref().unwrap().threshold, 95.);
    // This fixture proves a policy boundary, not that failed authentication is
    // legitimate or that the chosen cutoff is calibrated on real traffic.
}

#[test]
fn actual_combination_is_order_independent_and_duplicate_invariant() {
    let mut scan = sample();
    let expected = scoring::combine(&scan, Some(-2.), false);
    assert_eq!(expected.total_logit, Some(3.5));
    assert_eq!(
        expected.score,
        Some(noisefence::engine::sigmoid(3.5) * 100.)
    );
    scan.reasons.extend(scan.reasons.clone());
    scan.reasons.reverse();
    // An old output and diagnostic-only unknown signals do not become inputs.
    scan.reasons.push(signal("model_contribution", 100.));
    scan.reasons.push(signal("PRIVATE SUBJECT CANARY", 0.));
    let report = scoring::combine(&scan, Some(-2.), false);
    assert_eq!(report.score, expected.score);
    assert_eq!(report.rules_total, expected.rules_total);
    assert_eq!(report.contributions.len(), 3);
    assert!(
        report
            .contributions
            .iter()
            .all(|e| e.occurrences == 2 && e.adjustment == Adjustment::Duplicate)
    );
    assert!(!serde_json::to_string(&report).unwrap().contains("PRIVATE"));
    scan.reasons.reverse();
    assert_eq!(report, scoring::combine(&scan, Some(-2.), false));
}

#[test]
fn conflicting_nonfinite_and_unrecognized_inputs_do_not_fabricate_a_score() {
    for extra in [
        signal("urgency", 3.),
        signal("spf_fail", f64::NAN),
        signal("PRIVATE UNRECOGNIZED", 1.),
    ] {
        let mut scan = sample();
        scan.reasons.push(extra);
        let report = scoring::combine(&scan, Some(-2.), false);
        assert_eq!(report.score, None);
        assert_eq!(report.total_logit, None);
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("PRIVATE"));
        assert_eq!(
            serde_json::from_str::<scoring::Report>(&json).unwrap(),
            report
        );
    }
    assert_eq!(
        scoring::combine(&sample(), Some(f64::INFINITY), false).score,
        None
    );
}

#[test]
fn unavailable_semantic_preserves_explicit_fallback_but_malformed_success_does_not() {
    let mut scan = sample();
    scan.semantic.contribution = Some(100.);
    scan.semantic.status = SemanticStatus::Unavailable;
    let report = scoring::combine(&scan, None, false);
    assert_eq!(report.baseline, Some(-5.));
    assert_eq!(report.lexical, None);
    assert_eq!(report.semantic, None);
    assert_eq!(report.total_logit, Some(0.5));
    scan.semantic.status = SemanticStatus::Complete;
    scan.semantic.contribution = None;
    assert_eq!(scoring::combine(&scan, Some(-2.), false).score, None);
    // Opaque bodies intentionally bypass content-model contributions.
    assert!(scoring::combine(&scan, None, true).score.is_some());
}

#[test]
fn stale_or_unsupported_llm_signal_cannot_resurrect_a_vote() {
    let mut scan = sample();
    scan.reasons
        .extend([signal("llm_advisory", 1.5), signal("llm_advisory", 1.5)]);
    let report = scoring::combine(&scan, Some(-2.), false);
    let llm = report
        .contributions
        .iter()
        .find(|e| e.id == "llm_advisory")
        .unwrap();
    assert_eq!(llm.retained, Some(0.));
    assert_eq!(llm.adjustment, Adjustment::DetectorPolicy);
    assert_eq!(report.total_logit, Some(3.5));
    scan.reasons.retain(|r| r.id == "llm_advisory");
    scan.evidence = None;
    assert!(!noisefence::confirmation::corroborated(&scan));
}

#[test]
fn recorded_accounting_survives_retry_observers_and_current_policy_changes() {
    let mut scan = sample();
    scan.reasons.push(signal("urgency", 0.5));
    let report = scoring::combine(&scan, Some(-2.), false);
    scan.score = report.score.unwrap();
    scan.scoring = Some(report.clone());
    let mut config = Config::load(Path::new("config/development.toml")).unwrap();
    decision_record::record_analysis(&mut scan, &config);
    let original = serde_json::to_string(&scan.analysis_result).unwrap();
    scan.reasons.clear();
    scan.scoring = None;
    scan.score = 1.;
    config.filter.threshold = 1.;
    decision_record::record_analysis(&mut scan, &config);
    assert_eq!(
        serde_json::to_string(&scan.analysis_result).unwrap(),
        original
    );
    let restored: Scan = serde_json::from_str(&serde_json::to_string(&scan).unwrap()).unwrap();
    let breakdown = detection_diagnostics::breakdown(&restored);
    assert_eq!(breakdown.reconstructed_score, report.score);
    assert!(breakdown.matches_recorded_score);
    assert_eq!(breakdown.families["heuristics"], Some(0.5));
    let view = diagnostics::Analysis::from(restored);
    assert_eq!(view.scoring, Some(report));
    assert_eq!(view.rule_weight_total, Some(5.5));
}

#[test]
fn legacy_receipts_do_not_acquire_accounting_from_a_new_evaluation() {
    let mut scan = sample();
    let config = Config::load(Path::new("config/development.toml")).unwrap();
    decision_record::record_analysis(&mut scan, &config);
    scan.scoring = Some(scoring::combine(&scan, None, false));
    assert!(scoring::recorded(&scan).is_none());
    assert!(diagnostics::Analysis::from(scan).scoring.is_none());
}

#[test]
fn usable_llm_is_bounded_once_and_never_an_independent_confirmation() {
    use noisefence::llm::{Category, LlmStatus, Verdict};
    let mut scan = Scan {
        feature_version: noisefence::features::VERSION,
        ..Default::default()
    };
    scan.llm.status = LlmStatus::Complete;
    scan.llm.verdict = Some(Verdict {
        category: Category::Phishing,
        spam_probability: 0.99,
        confidence: 0.99,
        explanation: "Synthetic fixture".into(),
    });
    scan.reasons = vec![signal("llm_advisory", 1.5), signal("llm_advisory", 1.5)];
    let report = scoring::combine(&scan, Some(2.), false);
    assert_eq!(report.rules_total, Some(1.5));
    assert_eq!(report.total_logit, Some(3.5));
    assert!(!noisefence::confirmation::corroborated(&scan));
    scan.llm.verdict.as_mut().unwrap().category = Category::Legitimate;
    let report = scoring::combine(&scan, Some(2.), false);
    assert_eq!(report.rules_total, Some(0.)); // contradictory opinion
    scan.llm.verdict.as_mut().unwrap().spam_probability = 0.01;
    let report = scoring::combine(&scan, Some(2.), false);
    assert_eq!(report.rules_total, Some(-0.5));
    assert_eq!(
        report.contributions[0].adjustment,
        Adjustment::DetectorPolicy
    );
    scan.llm.status = LlmStatus::Unavailable;
    assert_eq!(
        scoring::combine(&scan, Some(2.), false).rules_total,
        Some(0.)
    );
}

#[test]
fn modern_threshold_precision_and_conflicting_order_are_preserved() {
    let scan = Scan {
        feature_version: noisefence::features::VERSION,
        ..Default::default()
    };
    let p = 0.9499_f64;
    let report = scoring::combine(&scan, Some((p / (1. - p)).ln()), false);
    assert!(report.score.unwrap() < 95.);
    let mut scan = sample();
    scan.reasons.push(signal("urgency", 2.));
    let report = scoring::combine(&scan, Some(-2.), false);
    scan.reasons.reverse();
    assert_eq!(report, scoring::combine(&scan, Some(-2.), false));
}

#[test]
fn native_context_reuses_retained_weights_and_cannot_revive_excluded_symbols() {
    use noisefence::{
        evidence::{AuthResult as A, State},
        native_filter::rules,
    };
    let mut scan = sample();
    scan.reasons.extend([
        signal("dmarc_fail", 2.),
        signal("llm_advisory", 100.),
        signal("caps_subject", 0.),
    ]);
    let a = &mut scan.evidence.as_mut().unwrap().authentication;
    a.dmarc_state = State::Complete;
    a.dmarc_spf = Some(A::Fail);
    a.dmarc_dkim = Some(A::Fail);
    scan.scoring = Some(scoring::combine(&scan, Some(-2.), false));
    let before = serde_json::to_value(&scan).unwrap();
    let symbols = rules::context(&scan);
    assert_eq!(
        symbols
            .iter()
            .find(|s| s.id == "dmarc_fail")
            .unwrap()
            .weight,
        2.
    );
    assert_eq!(
        symbols
            .iter()
            .find(|s| s.id == "NF_LEXICAL")
            .unwrap()
            .weight,
        -2.
    );
    assert!(
        !symbols
            .iter()
            .any(|s| matches!(s.id.as_str(), "spf_fail" | "NF_LLM" | "caps_subject"))
    );
    assert_eq!(serde_json::to_value(&scan).unwrap(), before);
    // Raw reasons added after accounting cannot contaminate the observer.
    scan.reasons.push(signal("ip_url", 100.));
    assert!(!rules::context(&scan).iter().any(|s| s.id == "ip_url"));
    // Unsupported historical accounting is not reinterpreted on a read.
    scan.scoring.as_mut().unwrap().version = scoring::LEGACY_VERSION.into();
    assert!(rules::context(&scan).is_empty());
    scan.scoring = None;
    assert!(rules::context(&scan).is_empty());
}
