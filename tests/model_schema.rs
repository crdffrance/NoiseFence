mod common;
use noisefence::{
    engine::{Algorithm, Engine, Model},
    features,
};
use std::sync::Arc;

#[test]
fn native_model_keeps_the_calibrated_boundary_and_does_not_add_local_rules_twice() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("model.json");
    let model = Model {
        version: "boundary-fixture".into(),
        algorithm: Algorithm::Logistic,
        feature_version: features::VERSION,
        bias: (0.9499_f64 / (1.0 - 0.9499_f64)).ln(),
        weights: vec![0.0; features::DIMENSION],
        idf: vec![1.0; features::DIMENSION],
        trained_at: 0,
        examples: 1,
    };
    std::fs::write(&path, serde_json::to_vec(&model).unwrap()).unwrap();
    let mut config = (*common::config(root.path())).clone();
    config.filter.model = Some(path.clone());
    let engine = Engine::new(Arc::new(config)).unwrap();
    let scan = engine
        .offline(b"From: update@example.org\r\nSubject: Urgent\r\n\r\nPlease update immediately.");
    assert_eq!(scan.feature_version, features::VERSION);
    assert!((scan.score - 94.99).abs() < 1e-9);
    assert_eq!(scan.score, engine.offline(common::MESSAGE).score);
    assert!(scan.score < 95.0);
    assert!(
        scan.reasons
            .iter()
            .any(|reason| reason.id == "urgency" && reason.weight == 0.0)
    );
    let mut invalid = model;
    invalid.idf.clear();
    std::fs::write(path.clone(), serde_json::to_vec(&invalid).unwrap()).unwrap();
    assert!(Model::load(&path).is_err());
}

#[test]
fn feedback_feature_versions_cannot_be_silently_mixed_by_legacy_training() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("feedback.jsonl");
    std::fs::write(
        &input,
        serde_json::json!({"feature_version":3,"spam":true,
        "fingerprint":"a".repeat(64),"features":[[1,0.5]]})
        .to_string(),
    )
    .unwrap();
    assert!(noisefence::corpus::load_examples(&input).is_err());
}
