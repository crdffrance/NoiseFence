mod common;
#[path = "common/fusion.rs"]
mod fixture;
use noisefence::{evidence::Evidence, fusion, message::digest};

fn config(root: &std::path::Path) -> noisefence::config::Config {
    let mut c = (*common::config(root)).clone();
    c.heuristics = Some(noisefence::heuristics::Settings {
        rules: vec![noisefence::heuristics::Rule {
            id: "fixture".into(),
            label: "Software test".into(),
            family: "content".into(),
            scopes: vec![noisefence::heuristics::Scope::Subject],
            pattern: "Rendez-vous".into(),
            candidate_weight: 0.0,
        }],
        ..Default::default()
    });
    c.content_inspection = Some(Default::default());
    c
}

#[test]
fn protocol_v2_appends_only_the_native_local_contract_and_v1_remains_frozen() {
    let v1 = fusion::specs();
    let v2 = fusion::specs_for(2).unwrap();
    assert_eq!(v1.len(), 218);
    assert_eq!(v2.len(), 327);
    assert_eq!(
        serde_json::to_value(v1).unwrap(),
        serde_json::to_value(&v2[..218]).unwrap()
    );
    assert_eq!(
        serde_json::to_value(fusion::local::specs()).unwrap(),
        serde_json::to_value(&v2[218..]).unwrap()
    );
    assert!(fusion::specs_for(3).is_err());
    let root = tempfile::tempdir().unwrap();
    let c = config(root.path());
    let (v1model, old) = fixture::fixture(&c);
    let mut extended = old.clone();
    extended.local = fixture::local_evidence(&c, common::MESSAGE).local;
    assert_eq!(
        fusion::features(&old).unwrap(),
        fusion::features(&extended).unwrap()
    );
    assert_eq!(
        serde_json::to_value(v1model.predict(&old).unwrap()).unwrap(),
        serde_json::to_value(v1model.predict(&extended).unwrap()).unwrap()
    );
    assert!(
        !serde_json::to_value(&v1model)
            .unwrap()
            .as_object()
            .unwrap()
            .contains_key("local_binding")
    );
}

#[test]
fn v2_rejects_mixed_bindings_missing_data_and_invalid_protocols() {
    let root = tempfile::tempdir().unwrap();
    let c = config(root.path());
    let (model, evidence) = fixture::local_model(&c, common::MESSAGE);
    assert!(model.predict(&evidence).unwrap().tag_eligible);
    let mut missing = evidence.clone();
    missing.local = None;
    assert!(model.predict(&missing).is_err());
    let mut changed = c.clone();
    changed.heuristics.as_mut().unwrap().rules[0].pattern = "changed-pattern".into();
    let mut mismatch = evidence.clone();
    mismatch.local = fixture::local_evidence(&changed, common::MESSAGE).local;
    assert!(model.predict(&mismatch).is_err());
    let mut unsupported = model.clone();
    unsupported.schema = "noisefence-fusion-model-3".into();
    assert!(unsupported.validate().is_err());
    unsupported = model.clone();
    unsupported.protocol_sha256 = fusion::protocol_sha256();
    assert!(unsupported.validate().is_err());
    unsupported = model.clone();
    unsupported.local_binding = None;
    assert!(unsupported.validate().is_err());
    unsupported = model.clone();
    unsupported.weights.pop();
    assert!(unsupported.validate().is_err());
    let binding = model.local_binding.as_ref().unwrap();
    let busy_scan = noisefence::engine::Scan {
        research_execution: Some(noisefence::research_engines::Execution {
            version: noisefence::research_engines::VERSION.into(),
            status: noisefence::research_engines::Status::Busy,
            elapsed_ms: 0,
        }),
        ..Default::default()
    };
    let mut busy = evidence.clone();
    busy.local = Some(fusion::local::LocalEvidence::capture(binding, &busy_scan));
    let p = model.predict(&busy).unwrap();
    assert!(!p.tag_eligible && !p.would_tag);
}

fn row(e: &Evidence, index: u8) -> String {
    serde_json::json!({"schema":"noisefence-learning-1","source":"local_human_feedback",
        "id":digest(&[index]),"observed_at":1000,"labelled_at":1001,"feature_version":3,
        "spam":false,"fingerprint":digest(&[index,1]),"simhash":"1234567890abcdef","evidence":e})
    .to_string()
        + "\n"
}
#[test]
fn v2_exports_count_missing_history_and_reject_mixed_catalogues_atomically() {
    let root = tempfile::tempdir().unwrap();
    let c = config(root.path());
    let (model, e) = fixture::local_model(&c, common::MESSAGE);
    let mut old = e.clone();
    old.local = None;
    let input = root.path().join("learning.jsonl");
    let output = root.path().join("vectors.jsonl");
    std::fs::write(&input, row(&old, 0) + &row(&e, 1)).unwrap();
    let report = fusion::io::convert_version(&input, &output, None, 2).unwrap();
    assert_eq!(
        (report.considered, report.exported, report.missing_evidence),
        (2, 1, 1)
    );
    let lines: Vec<serde_json::Value> = std::fs::read_to_string(&output)
        .unwrap()
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect();
    assert_eq!(lines[0]["protocol_sha256"], model.protocol_sha256);
    assert_eq!(
        lines[0]["local_binding"],
        serde_json::to_value(model.local_binding).unwrap()
    );
    assert_eq!(lines[1]["values"].as_array().unwrap().len(), 327);
    let predictions = root.path().join("predictions.jsonl");
    let (model, _) = fixture::local_model(&c, common::MESSAGE);
    assert_eq!(
        fusion::io::convert(&input, &predictions, Some(&model))
            .unwrap()
            .exported,
        1
    );
    let mut other = c.clone();
    other.heuristics.as_mut().unwrap().rules[0].id = "different-slot".into();
    let mut mixed = e.clone();
    mixed.local = fixture::local_evidence(&other, common::MESSAGE).local;
    std::fs::write(&input, row(&e, 1) + &row(&mixed, 2)).unwrap();
    let rejected = root.path().join("rejected.jsonl");
    assert!(fusion::io::convert_version(&input, &rejected, None, 2).is_err());
    assert!(!rejected.exists());
}
