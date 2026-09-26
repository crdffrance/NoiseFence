use noisefence::{
    config::Config,
    engine::{Scan, Signal},
    evidence::{Artifacts, AuthResult, Evidence, Source, State},
    scoring::comparison::{INPUT_SCHEMA, Skip, compare},
};
use serde_json::{Value, json};
use std::{fs, os::unix::fs::PermissionsExt};

fn sample() -> Value {
    let config: Config = toml::from_str(include_str!("../config/development.toml")).unwrap();
    let mut evidence = Evidence::new(&config, Artifacts::new(&config, None, None, false), false);
    evidence.source = Source::SmtpSession;
    evidence.lexical_state = State::Complete;
    evidence.lexical_logit = Some(0.);
    evidence.authentication.state = State::Complete;
    evidence.authentication.spf_state = State::Complete;
    evidence.authentication.spf = Some(AuthResult::Fail);
    evidence.authentication.dmarc_state = State::Complete;
    evidence.authentication.dmarc_spf = Some(AuthResult::Fail);
    evidence.authentication.dmarc_dkim = Some(AuthResult::Fail);
    let scan = Scan {
        score: 99.,
        feature_version: noisefence::features::VERSION,
        evidence: Some(evidence),
        message_context: Some(Default::default()),
        subject: "PRIVATE SUBJECT".into(),
        sender: "private@example.test".into(),
        reasons: vec![
            Signal {
                id: "spf_fail".into(),
                weight: 1.,
                detail: "PRIVATE PROVIDER TEXT".into(),
            },
            Signal {
                id: "dmarc_fail".into(),
                weight: 2.,
                detail: "PRIVATE MESSAGE TEXT".into(),
            },
        ],
        ..Default::default()
    };
    json!({"schema": INPUT_SCHEMA, "id": "a".repeat(64), "scan": scan})
}

fn run(rows: &[Value]) -> (noisefence::scoring::comparison::Summary, Vec<Value>) {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("inputs.jsonl");
    let output = dir.path().join("output.jsonl");
    let original = rows.iter().map(|v| format!("{v}\n")).collect::<String>();
    fs::write(&input, &original).unwrap();
    let report = compare(&input, &output, 95.).unwrap();
    assert_eq!(fs::read_to_string(input).unwrap(), original);
    assert_eq!(
        report.input_sha256,
        noisefence::message::digest(original.as_bytes())
    );
    assert_eq!(
        fs::metadata(&output).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let text = fs::read_to_string(output).unwrap();
    assert!(!text.contains("PRIVATE"));
    assert!(!text.contains("private@example.test"));
    let values = text
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect();
    (report, values)
}

#[test]
fn controlled_comparison_is_not_historical_replay_or_accuracy() {
    let (counts, rows) = run(&[sample()]);
    assert_eq!(counts.counts.considered, 1);
    assert_eq!(counts.counts.compared, 1);
    assert_eq!(counts.counts.changed_rule_totals, 1);
    assert_eq!(counts.counts.threshold_comparable, 1);
    assert_eq!(counts.counts.crossed_down, 1);
    assert_eq!(rows[0]["accuracy_evaluation"], false);
    assert_eq!(rows[0]["historical_decisions_replayed"], false);
    let result = &rows[1]["result"];
    assert_eq!(result["historical_score"], 99.);
    assert_eq!(result["reference"]["rules_total"], 3.);
    assert_eq!(result["candidate"]["rules_total"], 2.);
    assert_eq!(
        result["candidate"]["contributions"][1]["subsumed_by"],
        "dmarc_fail"
    );
    assert_eq!(result["reference_reaches_threshold"], true);
    assert_eq!(result["candidate_reaches_threshold"], false);
    assert_eq!(rows.last().unwrap()["type"], "footer");
}

#[test]
fn missing_or_future_precision_never_creates_a_threshold_result() {
    for version in [Value::Null, json!(999), json!(1)] {
        let mut input = sample();
        input["scan"]["feature_version"] = version;
        let (counts, rows) = run(&[input]);
        assert_eq!(counts.counts.changed_rule_totals, 1);
        assert_eq!(counts.counts.threshold_comparable, 0);
        assert_eq!(counts.counts.unknown_score_precision, 1);
        assert_eq!(rows[1]["result"]["candidate"]["total_logit"], 2.);
        assert!(rows[1]["result"]["candidate"]["score"].is_null());
        assert!(rows[1]["result"]["reference_reaches_threshold"].is_null());
    }
}

#[test]
fn missing_content_output_never_becomes_rules_only_or_inverted_historical_score() {
    let mut input = sample();
    input["scan"]["evidence"]["lexical_logit"] = Value::Null;
    let (counts, rows) = run(&[input]);
    assert_eq!(counts.counts.skipped[&Skip::UnknownLexicalInput], 1);
    assert_eq!(rows[1]["type"], "skipped");
    assert_eq!(counts.counts.compared, 0);
}

#[test]
fn partial_extraction_keeps_its_explicit_logit_without_claiming_complete_coverage() {
    let mut input = sample();
    input["scan"]["features_complete"] = json!(false);
    input["scan"]["evidence"]["lexical_state"] = json!("limited");
    input["scan"]["evidence"]["lexical_logit"] = json!(-1.);
    let (counts, rows) = run(&[input]);
    assert_eq!(counts.counts.compared, 1);
    assert_eq!(counts.counts.partial_lexical, 1);
    assert_eq!(rows[1]["result"]["candidate"]["lexical"], -1.);
    assert_eq!(rows[1]["result"]["partial_lexical"], true);
}

#[test]
fn opaque_content_requires_explicit_consistent_provenance() {
    let mut input = sample();
    input["scan"]["message_context"]["encrypted"] = json!(true);
    let (counts, _) = run(&[input.clone()]);
    assert_eq!(counts.counts.skipped[&Skip::ContradictoryOpaqueInput], 1);
    input["scan"]["evidence"]["lexical_logit"] = Value::Null;
    input["scan"]["evidence"]["lexical_state"] = json!("limited");
    let (counts, rows) = run(&[input]);
    assert_eq!(counts.counts.compared, 1);
    assert_eq!(
        rows[1]["result"]["candidate"]["baseline"],
        noisefence::engine::RULES_BASELINE_LOGIT
    );
    assert!(rows[1]["result"]["candidate"]["lexical"].is_null());
}

#[test]
fn missing_inputs_and_supplied_envelopes_are_accounted_without_default_evidence() {
    for key in [
        "llm",
        "smtp_policy",
        "semantic",
        "reasons",
        "message_context",
    ] {
        let mut input = sample();
        input["scan"].as_object_mut().unwrap().remove(key);
        let (counts, _) = run(&[input]);
        assert_eq!(counts.counts.skipped[&Skip::MissingInputs], 1, "{key}");
    }
    let mut input = sample();
    input["scan"]["evidence"]["source"] = json!("supplied_envelope");
    let (counts, _) = run(&[input]);
    assert_eq!(counts.counts.skipped[&Skip::NonSmtpEvidence], 1);
}

#[test]
fn corrupted_inputs_remain_invalid_and_cohorts_stay_separate() {
    let first = sample();
    let mut second = sample();
    second["id"] = json!("b".repeat(64));
    second["scan"]["evidence"]["artifacts"]["policy_sha256"] = json!("c".repeat(64));
    second["scan"]["reasons"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id":"spf_fail","weight":5.}));
    let (counts, rows) = run(&[first, second]);
    assert_eq!(counts.cohorts.len(), 2);
    assert_eq!(counts.counts.invalid_combinations, 1);
    assert_eq!(counts.counts.threshold_comparable, 1);
    assert!(rows[2]["result"]["candidate"]["score"].is_null());
}

#[test]
fn duplicate_or_malformed_rows_abort_atomically_and_do_not_echo_private_values() {
    for bad in [
        format!("{}\n", sample()),
        "{\"schema\":\"PRIVATE MALFORMED".into(),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("input");
        let output = dir.path().join("output");
        fs::write(&input, format!("{}\n{bad}", sample())).unwrap();
        let error = compare(&input, &output, 95.).unwrap_err();
        assert!(!format!("{error:#}").contains("PRIVATE"));
        assert!(!output.exists());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}

#[test]
fn output_is_never_overwritten_and_threshold_must_be_finite() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input");
    let output = dir.path().join("output");
    fs::write(&input, format!("{}\n", sample())).unwrap();
    fs::write(&output, "existing report").unwrap();
    assert!(compare(&input, &output, 95.).is_err());
    assert_eq!(fs::read_to_string(&output).unwrap(), "existing report");
    fs::remove_file(&output).unwrap();
    for threshold in [f64::NAN, f64::INFINITY, -1., 101.] {
        assert!(compare(&input, &output, threshold).is_err());
        assert!(!output.exists());
    }
    std::os::unix::fs::symlink(&input, &output).unwrap();
    assert!(compare(&input, &output, 95.).is_err());
    assert!(
        fs::symlink_metadata(&output)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn command_runs_without_configuration_or_runtime_startup() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input");
    let output = dir.path().join("output");
    fs::write(&input, format!("{}\n", sample())).unwrap();
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_noisefence"))
        .arg("--config")
        .arg(dir.path().join("does-not-exist.toml"))
        .arg("scoring-compare")
        .arg(&input)
        .arg("--output")
        .arg(&output)
        .args(["--threshold", "95"])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let counts: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(counts["counts"]["crossed_down"], 1);
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
}

#[test]
fn oversized_row_is_rejected_before_deserialization_or_output_publication() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input");
    let output = dir.path().join("output");
    fs::write(&input, vec![b' '; 2 * 1024 * 1024 + 1]).unwrap();
    assert!(
        compare(&input, &output, 95.)
            .unwrap_err()
            .to_string()
            .contains("size limit")
    );
    assert!(!output.exists());
}
