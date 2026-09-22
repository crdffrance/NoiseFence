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
    Scan {
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
