#![allow(dead_code)]
//! Fabricated in temporary test directories, never an activation certificate.
use noisefence::{
    config::Config,
    evidence::{Artifacts, AuthResult, Evidence, Source, State},
    fusion::{
        self, Calibration, Model,
        runtime::{Mode, Settings, Validation},
    },
    message::digest,
};

pub fn fixture(config: &Config) -> (Model, Evidence) {
    let artifacts = Artifacts::new(config, None, None, false);
    let mut evidence = Evidence::new(config, artifacts.clone(), false);
    evidence.source = Source::SmtpSession;
    evidence.analysis_complete = true;
    evidence.authentication.arc_state = State::Complete;
    evidence.authentication.arc = Some(AuthResult::None);
    evidence.authentication.arc_can_seal = Some(true);
    let model = Model {
        combination: None,
        schema: fusion::SCHEMA.into(),
        version: "SOFTWARE-TEST-ONLY".into(),
        protocol_sha256: fusion::protocol_sha256(),
        artifacts,
        weights: vec![0.0; fusion::specs().len()],
        bias: 2.0,
        cutoff: 1.0,
        // Deliberately not 50%/95: verifies raw threshold rather than UI index.
        calibration: Calibration {
            slope: 1.0,
            intercept: -20.0,
            messages: 100,
            positive_fraction: 0.5,
        },
        supported_profiles: vec![fusion::availability_profile(&evidence)],
        manifest_sha256: digest(b"synthetic software test manifest"),
        purpose: "research".into(),
    };
    (model, evidence)
}

pub fn validation(model: &Model, sha: &str) -> Validation {
    Validation {
        schema: "noisefence-fusion-promotion-1".into(),
        model_sha256: sha.into(),
        manifest_sha256: model.manifest_sha256.clone(),
        test_report_sha256: digest(b"synthetic test report"),
        population_report_sha256: digest(b"synthetic population report"),
        latency_report_sha256: digest(b"synthetic latency report"),
        reviewed_at: noisefence::now(),
        observation_start: noisefence::now() - 86400,
        observation_end: noisefence::now() - 1,
        review_reference:
            "Fabricated software fixture; not a quality measurement or production approval".into(),
        sampling: "representative_smtp".into(),
        tp: 1900,
        fn_count: 100,
        tn: 10000,
        fp: 0,
        unaccounted_messages: 0,
        pipeline_p95_ms: 100.0,
        pipeline_samples: 1000,
        operational: None,
    }
}

pub fn install(config: &mut Config, mode: Mode) -> (Model, Validation) {
    let (model, _) = fixture(config);
    let path = config.data_dir.join("software-test-fusion.json");
    let bytes = serde_json::to_vec(&model).unwrap();
    let validation = validation(&model, &digest(&bytes));
    std::fs::write(&path, bytes).unwrap();
    let report = config.data_dir.join("software-test-validation.json");
    std::fs::write(&report, serde_json::to_vec(&validation).unwrap()).unwrap();
    config.fusion = Some(Settings {
        family_caps: false,
        model: path,
        mode,
        validation_report: Some(report),
    });
    (model, validation)
}

/// Fabricated v2 proof only for exercising guards; never production evidence.
pub fn validation_v2(model: &Model, sha: &str) -> Validation {
    let mut proof = validation(model, sha);
    proof.schema = "noisefence-fusion-promotion-2".into();
    proof.tp = 1990;
    proof.fn_count = 10;
    proof.operational = Some(noisefence::fusion::runtime::OperationalEvidence {
        native_p95_ms: 100.,
        native_samples: 1000,
        max_message_bytes: 1024 * 1024,
        warm_caches: true,
        native_latency_report_sha256: digest(b"synthetic native benchmark"),
        pipeline_budget_ms: 5000,
        review_spam: 0,
        review_legitimate: 0,
    });
    proof
}
