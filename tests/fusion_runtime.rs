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
