#[path = "common/fusion.rs"]
mod fixture;
use noisefence::{config::Config, evidence::Evidence, fusion, message::digest, population::Report};
use serde_json::{Value, json};
use std::{fs, os::unix::fs::PermissionsExt, path::Path};

fn row(index: usize, evidence: Option<Evidence>) -> Value {
    let id = digest(format!("synthetic-population-{index}").as_bytes());
    json!({"type":"row","id":id,"observed_at":100,
        "raw_sha256":null,"fingerprint":null,"simhash":null,"complete":true,
        "features_complete":null,"decision":null,"tagged":false,
        "label":{"status":"consensus","unwanted":true,"labelled_at":101,"authorized_votes":1,"ignored_votes":0},
        "evidence_status":if evidence.is_some(){"smtp"}else{"missing"},"evidence":evidence})
}
fn snapshot(path: &Path, rows: &[Value]) {
    let mut counts = Report {
        considered: rows.len(),
        exported: rows.len(),
        ..Report::default()
    };
    for row in rows {
        counts.incomplete += usize::from(row["complete"] == false);
        counts.missing_raw_hash += usize::from(row["raw_sha256"].is_null());
        counts.missing_campaign +=
            usize::from(row["fingerprint"].is_null() || row["simhash"].is_null());
        match row["label"]["status"].as_str().unwrap() {
            "consensus" => counts.labelled += 1,
            "conflicting" => counts.conflicting_labels += 1,
            "unlabelled" => counts.unlabelled += 1,
            _ => counts.invalid_labels += 1,
        }
        match row["evidence_status"].as_str().unwrap() {
            "smtp" => counts.smtp_evidence += 1,
            "non_smtp" => counts.non_smtp_evidence += 1,
            "invalid" => counts.invalid_evidence += 1,
            _ => counts.missing_evidence += 1,
        }
    }
    let mut records = vec![
        json!({"type":"header","schema":noisefence::population::SCHEMA,
        "since":100,"until":200,"captured_at":200,"scope":"retained_accepted_messages",
        "sampling":"unreviewed","contains_bodies":false}),
    ];
    records.extend_from_slice(rows);
    records.push(json!({"type":"footer","schema":noisefence::population::SCHEMA,"report":counts}));
    fs::write(
        path,
        records.iter().map(|r| format!("{r}\n")).collect::<String>(),
    )
    .unwrap();
}
#[test]
fn population_predictions_retain_unknowns_and_count_fail_open_without_reusing_old_decision() {
    let dir = tempfile::tempdir().unwrap();
    let config: Config = toml::from_str(include_str!("../config/development.toml")).unwrap();
    let (model, e) = fixture::fixture(&config);
    let model_path = dir.path().join("model.json");
    fs::write(&model_path, serde_json::to_vec(&model).unwrap()).unwrap();
    let mut old_undetermined = row(0, Some(e.clone()));
    old_undetermined["complete"] = json!(false);
    let mut incomplete = e.clone();
    incomplete.analysis_complete = false;
    let mut mismatch = e.clone();
    mismatch.artifacts.policy_sha256 = "b".repeat(64);
    let mut conflicting = row(4, Some(e));
    conflicting["label"]["status"] = json!("conflicting");
    conflicting["label"]["unwanted"] = Value::Null;
    conflicting["label"]["authorized_votes"] = json!(2);
    let input = dir.path().join("population.jsonl");
    snapshot(
        &input,
        &[
            old_undetermined,
            row(1, None),
            row(2, Some(incomplete)),
            row(3, Some(mismatch)),
            conflicting,
        ],
    );
    let output = dir.path().join("prediction.jsonl");
    let result = fusion::population::predict(&input, &model_path, &output).unwrap();
    assert_eq!(
        (result.rows, result.assessed, result.unassessable),
        (5, 3, 2)
    );
    assert_eq!(
        (
            result.artifact_mismatch,
            result.ineligible_to_tag,
            result.would_tag
        ),
        (1, 1, 2)
    );
    let data: Vec<Value> = fs::read_to_string(&output)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(data[1]["prediction"]["would_tag"], true);
    assert!(data[2]["prediction"].is_null());
    assert_eq!(data[3]["prediction"]["would_tag"], false);
    assert_eq!(data[4]["assessment"], "artifact_mismatch");
    assert!(data[5]["label"]["unwanted"].is_null());
    assert!(data[1]["raw_sha256"].is_null() && data[1]["simhash"].is_null());
    assert_eq!(
        data[0]["model_sha256"],
        digest(&fs::read(&model_path).unwrap())
    );
    assert_eq!(
        data[6]["population_sha256"],
        digest(&fs::read(&input).unwrap())
    );
    assert_eq!(
        fs::metadata(&output).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let before = fs::read(&output).unwrap();
    assert!(fusion::population::predict(&input, &model_path, &output).is_err());
    assert_eq!(before, fs::read(&output).unwrap());
}

#[test]
fn malformed_or_partial_populations_never_publish_a_result() {
    let dir = tempfile::tempdir().unwrap();
    let config: Config = toml::from_str(include_str!("../config/development.toml")).unwrap();
    let (model, e) = fixture::fixture(&config);
    let model_path = dir.path().join("model.json");
    fs::write(&model_path, serde_json::to_vec(&model).unwrap()).unwrap();
    let input = dir.path().join("population.jsonl");
    let output = dir.path().join("prediction.jsonl");
    snapshot(&input, &[row(0, Some(e))]);
    let valid = fs::read_to_string(&input).unwrap();
    let records: Vec<_> = valid.lines().collect();
    for invalid in [
        format!("{}\n{}\n", records[0], records[1]),
        format!(
            "{}\n{}\n{}\n{}\n",
            records[0], records[1], records[1], records[2]
        ),
        valid.replace("\"exported\":1", "\"exported\":2"),
        valid.replace("\"complete\":true", "\"complete\":true,\"complete\":false"),
        valid.replace("\"type\":\"row\"", "\"type\":\"row\",\"type\":\"row\""),
        valid.replace(
            "\"type\":\"row\"",
            "\"type\":\"row\",\"body\":\"hidden content\"",
        ),
        format!("{valid}{}\n", records[1]),
        valid.replace("\"status\":\"consensus\"", "\"status\":\"unlabelled\""),
    ] {
        assert_ne!(valid, invalid);
        fs::write(&input, invalid).unwrap();
        assert!(fusion::population::predict(&input, &model_path, &output).is_err());
        assert!(!output.exists());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
    }
}
