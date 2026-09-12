use super::*;
use crate::native_filter::{input, rules};
use std::collections::BTreeMap;
fn rows() -> Vec<data::Example> {
    let start = crate::now() - 10000;
    let mut out = Vec::new();
    for (fold, n) in [25, 7, 7].into_iter().enumerate() {
        for class in CLASSES {
            for index in 0..n {
                let id = crate::message::digest(
                    format!("synthetic-{fold}-{}-{index}", class.index()).as_bytes(),
                );
                let mut v = vec![0.; WIDTH];
                v[class.index()] = 1.;
                out.push(data::Example {
                    schema: SCHEMA.into(),
                    scope: "example.test".into(),
                    id: id.clone(),
                    observed_at: start + fold as i64 * 1000 + index,
                    labelled_at: start + fold as i64 * 1000 + index + 1,
                    class,
                    protocol_sha256: protocol(&rules::default_patterns()),
                    features: input::Features {
                        protocol: input::PROTOCOL.into(),
                        fingerprint: id,
                        osb: (0..10).map(|i| i + class.index() as u32 * 20).collect(),
                        text: vec![],
                        html: vec![],
                        text_shingles: 0,
                        html_shingles: 0,
                    },
                    vector: v,
                });
            }
        }
    }
    out
}
fn fitted() -> model::Model {
    let rows = rows();
    let (folds, _) = training::split(&rows, crate::now() - 9500, crate::now() - 8500).unwrap();
    training::fit(
        &folds[0],
        &folds[1],
        "synthetic-only",
        crate::message::digest(b"synthetic-only"),
    )
    .unwrap()
    .0
}
#[test]
fn neural_and_bayes_learn_all_classes_on_held_out_synthetic_features() {
    let model = fitted();
    for row in rows()
        .into_iter()
        .filter(|r| r.observed_at >= crate::now() - 8500)
    {
        let (b, n) = model.predict(&row.features, &row.vector).unwrap();
        assert_eq!(model::winner(&b).0, row.class.index());
        assert_eq!(model::winner(&n).0, row.class.index());
        assert_eq!(model.select(&b, &n, &BTreeMap::new()), Some(row.class));
    }
    let metrics = training::metrics(&model, &rows());
    assert_eq!(metrics["false_positives"], 0);
    assert!(metrics["false_positive_rate_ci95"][1].as_f64().unwrap() > 0.001);
}
#[test]
fn disagreement_policy_and_insufficient_features_abstain() {
    let m = fitted();
    let mut b = [0.; 5];
    b[3] = 1.;
    let mut n = [0.; 5];
    n[0] = 1.;
    assert_eq!(m.select(&b, &n, &BTreeMap::new()), None);
    n = b;
    let policies = [(
        Class::Phishing,
        Policy {
            min_strength: 1.0,
            ..Default::default()
        },
    )]
    .into();
    assert_eq!(m.select(&b, &n, &policies), None);
    let mut r = rows().remove(0);
    r.features.osb.clear();
    assert!(m.predict(&r.features, &r.vector).is_none());
    r.vector[0] = f64::NAN;
    assert!(r.validate().is_err());
}
#[test]
fn training_rejects_mixed_scope_protocol_duplicate_ids_and_missing_classes() {
    for change in 0..4 {
        let mut r = rows();
        match change {
            0 => r[0].scope = "another.test".into(),
            1 => r[0].protocol_sha256 = crate::message::digest(b"other"),
            2 => r[0].id = r[1].id.clone(),
            _ => r.retain(|r| r.class != Class::Scam),
        }
        assert!(training::split(&r, crate::now() - 9500, crate::now() - 8500).is_err());
    }
}
#[test]
fn exact_fuzzy_conflicting_and_late_campaigns_do_not_leak_between_folds() {
    let mut r = rows();
    let start = crate::now() - 10000;
    // More than the minimum in each fold permits checking exclusions precisely.
    r[125].features.fingerprint = r[0].features.fingerprint.clone();
    for i in [1, 126] {
        r[i].features.text = vec![77; 32];
        r[i].features.text_shingles = 30;
    }
    r[2].labelled_at = start + 700;
    r[3].features.fingerprint = r[25].features.fingerprint.clone();
    let (folds, excluded) = training::split(&r, start + 500, start + 1500).unwrap();
    assert_eq!(excluded, 7);
    for absent in [0, 125, 1, 126, 2, 3, 25] {
        assert!(!folds.iter().flatten().any(|x| x.id == r[absent].id));
    }
}
#[test]
fn bounded_model_validation_rejects_shape_counts_nan_and_expiry_provenance() {
    let original = fitted();
    for case in 0..5 {
        let mut m = original.clone();
        match case {
            0 => m.neural.input_weights.pop().map(|_| ()).unwrap(),
            1 => m.neural.output_bias[0] = f64::NAN,
            2 => m.counts[0].1[0] = u32::MAX,
            3 => m.expires = m.created + 31 * 86400,
            _ => m.classes[4] = 0,
        }
        assert!(m.validate().is_err());
    }
}
#[test]
fn collection_is_tenant_scoped_and_ignores_statistical_and_composite_votes() {
    let patterns = rules::default_patterns();
    let runtime = Runtime::new(
        Settings {
            domains: [("example.test".into(), Tenant::default())].into(),
        },
        &patterns,
    )
    .unwrap();
    let input = input::extract(
        b"Subject: Bonjour\r\n\r\nMerci pour cette reunion demain.",
        10000,
    )
    .unwrap();
    for scopes in [
        vec![],
        vec!["another.test".into()],
        vec!["example.test".into(), "another.test".into()],
    ] {
        let (report, v) = runtime.predict(&input, &[], &scopes);
        assert!(v.is_none());
        assert_eq!(report.status, "scope_unavailable");
        assert!(report.model.is_none());
    }
    let (report, v) = runtime.predict(&input, &[], &["example.test".into()]);
    assert_eq!(report.status, "untrained");
    assert!(!report.affects_delivery);
    assert!(valid_vector(&v.unwrap()));
    let statistical = rules::Symbol {
        id: "NF_BAYES".into(),
        label: "ignored".into(),
        family: rules::Family::Bayes,
        weight: 100.,
        absorbed_by: vec![],
    };
    assert_eq!(vector(&input, &[]), vector(&input, &[statistical]));
}
#[test]
fn frozen_artifacts_roundtrip_and_future_overlap_is_excluded() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("data.jsonl");
    let rows = rows();
    let mut data = String::new();
    for r in &rows {
        data.push_str(&serde_json::to_string(r).unwrap());
        data.push('\n');
    }
    std::fs::write(&path, data).unwrap();
    let output = dir.path().join("candidate");
    let report = training::train(
        &path,
        &output,
        "synthetic-only",
        crate::now() - 9500,
        crate::now() - 8500,
    )
    .unwrap();
    assert_eq!(report["may_activate"], false);
    let mut future = rows[0].clone();
    future.observed_at = crate::now() - 100;
    future.labelled_at = crate::now() - 50;
    future.id = crate::message::digest(b"future");
    let futurepath = dir.path().join("future.jsonl");
    std::fs::write(&futurepath, serde_json::to_vec(&future).unwrap()).unwrap();
    let eval = dir.path().join("evaluation.json");
    assert!(
        training::evaluate(
            &futurepath,
            &output.join("model.json"),
            &output.join("manifest.json"),
            &output.join("report.json"),
            &eval
        )
        .is_err()
    );
    future.features.fingerprint = future.id.clone();
    std::fs::write(&futurepath, serde_json::to_vec(&future).unwrap()).unwrap();
    assert_eq!(
        training::evaluate(
            &futurepath,
            &output.join("model.json"),
            &output.join("manifest.json"),
            &output.join("report.json"),
            &eval
        )
        .unwrap()["evaluated"],
        1
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(output.join("model.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}
