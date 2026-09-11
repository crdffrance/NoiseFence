use noisefence::{
    detection_diagnostics::{self, Audit},
    engine::{Scan, SemanticResult, SemanticStatus, Signal},
    fusion::runtime::Decision,
};
#[test]
fn score_accounting_separates_families_without_counting_the_model_twice() {
    let mut scan = Scan {
        complete: true,
        feature_version: 3,
        score: noisefence::engine::sigmoid(3.) * 100.,
        semantic: SemanticResult {
            status: SemanticStatus::Complete,
            contribution: Some(2.),
            ..Default::default()
        },
        reasons: vec![
            Signal {
                id: "model_contribution".into(),
                detail: "PRIVATE TOKEN".into(),
                weight: 5.,
            },
            Signal {
                id: "llm_advisory".into(),
                detail: "PRIVATE ADVICE".into(),
                weight: -2.,
            },
        ],
        ..Default::default()
    };
    scan.decision = Some(Decision::legacy(&scan, 95.));
    let report = detection_diagnostics::breakdown(&scan);
    assert_eq!(report.families["lexical"], Some(3.));
    assert_eq!(report.families["semantic"], Some(2.));
    assert_eq!(report.families["llm"], Some(-2.));
    assert!(report.matches_recorded_score);
    let mut audit = Audit::default();
    audit.add(&scan, false);
    let text = serde_json::to_string(&audit).unwrap();
    assert!(!text.contains("PRIVATE") && !text.contains("features"));
    assert_eq!(audit.slices["false_positive"].reconstructed, 1);
    scan.reasons.clear();
    let report = detection_diagnostics::breakdown(&scan);
    assert_eq!(report.reconstructed_score, None);
    assert!(!report.matches_recorded_score);
}
#[test]
fn missing_split_and_nonfinite_weights_never_become_zero_evidence() {
    let mut scan = Scan {
        score: 50.,
        semantic: SemanticResult {
            status: SemanticStatus::Unavailable,
            ..Default::default()
        },
        reasons: vec![Signal {
            id: "model_contribution".into(),
            detail: String::new(),
            weight: 0.,
        }],
        ..Default::default()
    };
    assert_eq!(
        detection_diagnostics::breakdown(&scan).families["content_unseparated"],
        Some(0.)
    );
    scan.reasons.push(Signal {
        id: "unknown".into(),
        detail: String::new(),
        weight: f64::NAN,
    });
    assert!(!detection_diagnostics::breakdown(&scan).matches_recorded_score);
}
