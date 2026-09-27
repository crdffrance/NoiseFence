mod common;
#[path = "common/fusion.rs"]
mod fixture;
use noisefence::{
    engine::Scan,
    fusion::runtime::{Decision, DecisionSource, Mode, Outcome, Runtime, Status},
    message::digest,
};

#[test]
fn observation_and_decision_share_threshold_without_overwriting_detector_evidence() {
    let root = tempfile::tempdir().unwrap();
    let mut config = (*common::config(root.path())).clone();
    for mode in [Mode::Observe, Mode::Decision] {
        let (model, _) = fixture::install(&mut config, mode);
        let runtime = Runtime::load(config.fusion.as_ref().unwrap(), &model.artifacts).unwrap();
        let (_, mut evidence) = fixture::fixture(&config);
        evidence.legacy_score = Some(2.0);
        let mut scan = Scan {
            complete: true,
            score: 2.0,
            evidence: Some(evidence),
            ..noisefence::features::extract(common::MESSAGE, 10000)
        };
        scan.decision = Some(Decision::legacy(&scan, 95.0));
        runtime.apply(&mut scan);
        assert!(scan.complete);
        assert_eq!(scan.fusion.status, Status::Complete);
        assert_eq!(scan.score, 2.0);
        assert_eq!(scan.evidence.as_ref().unwrap().legacy_score, Some(2.0));
        let decision = scan.decision.as_ref().unwrap();
        if mode == Mode::Observe {
            assert_eq!(decision.source, DecisionSource::Legacy);
            assert_eq!(decision.outcome, Outcome::Legitimate);
        } else {
            assert_eq!(decision.source, DecisionSource::Fusion);
            assert_eq!(decision.outcome, Outcome::Unwanted);
            assert!(decision.score.unwrap() < 1.0);
        }
        scan.evidence.as_mut().unwrap().authentication.arc_can_seal = Some(false);
        runtime.apply(&mut scan);
        assert_eq!(scan.complete, mode == Mode::Observe);
        if mode == Mode::Decision {
            assert_eq!(
                scan.decision.as_ref().unwrap().outcome,
                Outcome::Undetermined
            );
            assert!(scan.decision.as_ref().unwrap().score.is_none());
        }
    }
}

#[test]
fn unknown_profile_and_expired_or_mismatched_validation_never_enable_decisions() {
    let root = tempfile::tempdir().unwrap();
    let mut config = (*common::config(root.path())).clone();
    let (model, validation) = fixture::install(&mut config, Mode::Decision);
    let settings = config.fusion.as_ref().unwrap();
    let runtime = Runtime::load(settings, &model.artifacts).unwrap();
    let (_, mut evidence) = fixture::fixture(&config);
    evidence.authentication.arc_state = noisefence::evidence::State::NotRun;
    evidence.authentication.arc = None;
    evidence.authentication.arc_can_seal = None;
    let mut scan = Scan {
        complete: true,
        evidence: Some(evidence),
        ..Default::default()
    };
    runtime.apply(&mut scan);
    assert_eq!(scan.fusion.status, Status::UnsupportedProfile);
    assert_eq!(scan.decision.unwrap().outcome, Outcome::Undetermined);
    assert!(!scan.complete);
    let sha = digest(&std::fs::read(&settings.model).unwrap());
    assert!(
        validation
            .validate(&model, &sha, noisefence::now() + 31 * 86400)
            .is_err()
    );
    let mut artifacts = model.artifacts.clone();
    artifacts.policy_sha256 = digest(b"changed detector configuration");
    assert!(Runtime::load(settings, &artifacts).is_err());
    for case in 0..9 {
        let mut invalid = validation.clone();
        match case {
            0 => invalid.model_sha256 = digest(b"another model"),
            1 => invalid.fp = 10, // empirical 0.1% alone is insufficient
            2 => invalid.tp = 1800,
            3 => invalid.tn = 100,
            4 => invalid.pipeline_p95_ms = 500.0,
            5 => invalid.sampling = "corrections".into(),
            6 => invalid.unaccounted_messages = 1,
            7 => invalid.reviewed_at -= 31 * 86400,
            _ => invalid.manifest_sha256 = digest(b"another manifest"),
        }
        std::fs::write(
            settings.validation_report.as_ref().unwrap(),
            serde_json::to_vec(&invalid).unwrap(),
        )
        .unwrap();
        assert!(
            Runtime::load(settings, &model.artifacts).is_err(),
            "case {case}"
        );
    }
    let old: Scan = serde_json::from_value(serde_json::json!({"score":99.0,"tagged":false,
        "complete":false,"elapsed_ms":0,"model":"old","reasons":[],"features":[],"subject":"x","sender":"","fingerprint":""})).unwrap();
    assert!(old.decision.is_none() && old.raw_sha256.is_none());
    assert_eq!(Decision::legacy(&old, 95.0).outcome, Outcome::Undetermined);
}

#[test]
fn promotion_v2_counts_abstentions_and_separates_local_and_external_latency() {
    use noisefence::fusion::runtime::OperationalEvidence;
    let root = tempfile::tempdir().unwrap();
    let cfg = common::config(root.path());
    let (model, _) = fixture::fixture(&cfg);
    let hash = digest(b"synthetic model");
    let mut v = fixture::validation(&model, &hash);
    v.schema = "noisefence-fusion-promotion-2".into();
    v.tp = 1980;
    v.fn_count = 20;
    v.pipeline_p95_ms = 3300.;
    assert!(v.validate(&model, &hash, noisefence::now()).is_err());
    v.operational = Some(OperationalEvidence {
        native_p95_ms: 120.,
        native_samples: 1000,
        max_message_bytes: 1024 * 1024,
        warm_caches: true,
        native_latency_report_sha256: digest(b"native benchmark"),
        pipeline_budget_ms: 5000,
        review_spam: 0,
        review_legitimate: 0,
    });
    v.validate(&model, &hash, noisefence::now()).unwrap();
    for case in 0..5 {
        let mut invalid = v.clone();
        let op = invalid.operational.as_mut().unwrap();
        match case {
            0 => op.native_p95_ms = 500.,
            1 => op.review_spam = 100,
            2 => op.review_legitimate = 1500,
            3 => op.pipeline_budget_ms = 6000,
            _ => op.native_latency_report_sha256.clear(),
        };
        assert!(invalid.validate(&model, &hash, noisefence::now()).is_err());
    }
}

#[test]
fn capped_runtime_requires_matching_configuration_and_new_qualification() {
    use noisefence::fusion::{
        self,
        combination::{Limit, Policy},
    };
    let root = tempfile::tempdir().unwrap();
    let mut config = (*common::config(root.path())).clone();
    let (mut model, _) = fixture::install(&mut config, Mode::Decision);
    let settings = config.fusion.as_mut().unwrap();
    model.schema = fusion::CAPPED_SCHEMA.into();
    model.combination = Some(Policy {
        schema: fusion::combination::SCHEMA.into(),
        families: fusion::combination::FAMILIES
            .into_iter()
            .map(|n| {
                (
                    n.into(),
                    Limit {
                        minimum: -0.25,
                        maximum: 0.25,
                    },
                )
            })
            .collect(),
    });
    let bytes = serde_json::to_vec(&model).unwrap();
    std::fs::write(&settings.model, &bytes).unwrap();
    assert!(
        Runtime::load(settings, &model.artifacts)
            .err()
            .unwrap()
            .to_string()
            .contains("family-cap setting")
    );
    settings.family_caps = true;
    assert!(Runtime::load(settings, &model.artifacts).is_err()); // old model hash proof
    let legacy_proof = fixture::validation(&model, &digest(&bytes));
    assert!(
        legacy_proof
            .validate(&model, &digest(&bytes), noisefence::now())
            .is_err()
    );
    let proof = fixture::validation_v2(&model, &digest(&bytes));
    std::fs::write(
        settings.validation_report.as_ref().unwrap(),
        serde_json::to_vec(&proof).unwrap(),
    )
    .unwrap();
    let runtime = Runtime::load(settings, &model.artifacts).unwrap();
    let (_, evidence) = fixture::fixture(&config);
    let mut scan = Scan {
        complete: true,
        features_complete: Some(true),
        evidence: Some(evidence),
        ..Default::default()
    };
    runtime.apply(&mut scan);
    assert!(scan.fusion_combination.is_some());
    noisefence::decision_record::record_analysis(&mut scan, &config);
    let original =
        serde_json::to_string(&scan.analysis_result.as_ref().unwrap().fusion_combination).unwrap();
    scan.fusion_combination = None;
    let restored: Scan = serde_json::from_str(&serde_json::to_string(&scan).unwrap()).unwrap();
    let api = noisefence::diagnostics::Analysis::from(restored);
    assert_eq!(
        serde_json::to_string(&api.fusion_combination).unwrap(),
        original
    );
    // Capped predictions remain within the existing strict legacy Prediction
    // shape; the additional ledger lives outside that rollback-sensitive type.
    let p = serde_json::to_value(&scan.fusion.prediction).unwrap();
    assert!(p.get("families").is_none());
}

#[test]
fn web_fusion_parameters_are_scoped_and_do_not_expose_or_replace_model_paths() {
    let root = tempfile::tempdir().unwrap();
    let mut config = (*common::config(root.path())).clone();
    fixture::install(&mut config, Mode::Observe);
    let mut editable = noisefence::management::Detection::from_config(&config);
    assert_eq!(
        editable.modules["fusion"],
        serde_json::json!({"mode":"observe","family_caps":false})
    );
    let path = config.fusion.as_ref().unwrap().model.clone();
    editable.modules.insert(
        "fusion".into(),
        serde_json::json!({"mode":"decision","family_caps":true}),
    );
    editable.apply(&mut config).unwrap();
    assert!(config.fusion.as_ref().unwrap().family_caps);
    assert_eq!(config.fusion.as_ref().unwrap().mode, Mode::Decision);
    assert_eq!(config.fusion.as_ref().unwrap().model, path);
    editable
        .modules
        .insert("fusion".into(), serde_json::json!({"model":"/etc/shadow"}));
    assert!(editable.apply(&mut config).is_err());
}
