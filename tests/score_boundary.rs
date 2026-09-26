mod common;
#[path = "common/fusion.rs"]
mod fixture;
use noisefence::{
    assessment, decision_record,
    engine::Scan,
    fusion::runtime::{Decision, Mode, Runtime},
    score_boundary::Source,
};

#[test]
fn json_roundtrips_preserve_score_bits_and_comparison_boundaries() {
    for value in [
        1.522997951276035e-8,
        95.00000000000001,
        f64::from_bits(1),
        f64::MAX,
    ] {
        let original = value.to_bits();
        let mut stored = value;
        for _ in 0..20 {
            let wire = serde_json::to_vec(&serde_json::json!({"value": stored})).unwrap();
            let decoded: serde_json::Value = serde_json::from_slice(&wire).unwrap();
            stored = decoded["value"].as_f64().unwrap();
            assert_eq!(stored.to_bits(), original);
        }
    }
}

#[test]
fn fusion_operating_point_preserves_native_comparison_even_when_index_collapses() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = (*common::config(dir.path())).clone();
    for (slope, intercept) in [(1., -20.), (0., 0.), (1., 1000.)] {
        for logit in [0., 1., 2.] {
            let (mut model, _) = fixture::install(&mut cfg, Mode::Decision);
            model.bias = logit;
            model.calibration.slope = slope;
            model.calibration.intercept = intercept;
            let bytes = serde_json::to_vec(&model).unwrap();
            let hash = noisefence::message::digest(&bytes);
            let settings = cfg.fusion.as_ref().unwrap();
            std::fs::write(&settings.model, bytes).unwrap();
            std::fs::write(
                settings.validation_report.as_ref().unwrap(),
                serde_json::to_vec(&fixture::validation(&model, &hash)).unwrap(),
            )
            .unwrap();
            let runtime = Runtime::load(settings, &model.artifacts).unwrap();
            let (_, evidence) = fixture::fixture(&cfg);
            let mut scan = Scan {
                complete: true,
                features_complete: Some(true),
                score: 99.,
                model: "content-fixture".into(),
                evidence: Some(evidence),
                analysis_policy: Some(noisefence::diagnostics::AnalysisPolicy::capture(&cfg)),
                ..noisefence::engine::extract(common::MESSAGE, 10000)
            };
            runtime.apply(&mut scan);
            decision_record::record_recipient(&mut scan, &cfg, None, 42);
            let assessment = assessment::historical(&scan);
            let boundary = assessment.score_boundary.as_ref().unwrap();
            assert_eq!(boundary.source, Source::Fusion);
            assert_eq!(boundary.cutoff, 1.);
            assert_eq!(boundary.value, logit);
            assert_eq!(boundary.above, logit >= 1.);
            assert_eq!(boundary.model_sha256.as_deref(), Some(hash.as_str()));
            assert_eq!(assessment.content_threshold, Some(cfg.filter.threshold));
            assert_eq!(
                scan.analysis_result
                    .as_ref()
                    .unwrap()
                    .score_boundary
                    .as_ref(),
                Some(boundary)
            );
            if slope == 0. || intercept == 1000. {
                assert_eq!(assessment.score.value, Some(boundary.index_cutoff));
            }
            let mut roundtrip: Scan =
                serde_json::from_slice(&serde_json::to_vec(&scan).unwrap()).unwrap();
            noisefence::scoring::validate_transport(&roundtrip).unwrap();
            let before = serde_json::to_value(&assessment).unwrap();
            let mut changed = cfg.clone();
            changed.filter.threshold = 50.;
            roundtrip.fusion_boundary = None;
            decision_record::record_recipient(&mut roundtrip, &changed, None, 99);
            assert_eq!(
                serde_json::to_value(assessment::assess(&roundtrip, 50.)).unwrap(),
                before
            );
            // New readers cannot manufacture an operating point for old records.
            roundtrip
                .recipient_decision
                .as_mut()
                .unwrap()
                .assessment
                .score_boundary = None;
            assert!(assessment::historical(&roundtrip).score_boundary.is_none());
            let mut invalid = boundary.clone();
            invalid.above = !invalid.above;
            assert!(invalid.validate(&assessment.score).is_err());
            if slope == 1. && intercept == -20. {
                let mut adjacent = assessment.score.clone();
                adjacent.value = Some(f64::from_bits(adjacent.value.unwrap().to_bits() + 1));
                boundary.validate(&adjacent).unwrap();
                let mut mapped = boundary.clone();
                mapped.index_cutoff = f64::from_bits(mapped.index_cutoff.to_bits() + 1);
                mapped.validate(&assessment.score).unwrap();
                mapped.index_cutoff *= 1.01;
                assert!(mapped.validate(&assessment.score).is_err());
            }
        }
    }
}

#[test]
fn observer_boundary_never_replaces_content_threshold_and_failed_runs_clear_it() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = (*common::config(dir.path())).clone();
    let (model, _) = fixture::install(&mut cfg, Mode::Observe);
    let runtime = Runtime::load(cfg.fusion.as_ref().unwrap(), &model.artifacts).unwrap();
    let (_, evidence) = fixture::fixture(&cfg);
    let mut scan = Scan {
        score: 99.,
        complete: true,
        features_complete: Some(true),
        model: "content-fixture".into(),
        evidence: Some(evidence),
        ..Default::default()
    };
    scan.decision = Some(Decision::legacy(&scan, 95.));
    runtime.apply(&mut scan);
    assert!(scan.fusion_boundary.is_some());
    decision_record::record_recipient(&mut scan, &cfg, None, 42);
    let boundary = assessment::historical(&scan).score_boundary.unwrap();
    assert_eq!(boundary.source, Source::Content);
    assert_eq!(boundary.cutoff, cfg.filter.threshold);
    assert_eq!(boundary.value, 99.);
    scan.evidence = None;
    runtime.apply(&mut scan);
    assert!(scan.fusion_boundary.is_none());
    assert_eq!(assessment::historical(&scan).score_boundary, Some(boundary));
}

#[test]
fn absent_fusion_boundary_does_not_fall_back_to_content_configuration() {
    let scan = Scan {
        score: 99.,
        complete: true,
        decision: Some(Decision {
            source: noisefence::fusion::runtime::DecisionSource::Fusion,
            outcome: noisefence::fusion::runtime::Outcome::Unwanted,
            score: Some(7.),
            model: "old-fusion".into(),
        }),
        ..Default::default()
    };
    assert!(assessment::assess(&scan, 95.).score_boundary.is_none());
}
