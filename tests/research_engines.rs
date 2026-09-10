mod common;
use noisefence::{
    engine::Engine,
    research_engines::{self, Status},
};
use std::sync::Arc;

#[test]
fn optional_detectors_preserve_existing_decisions_and_do_not_export_message_text() {
    let root = tempfile::tempdir().unwrap();
    let config = common::config(root.path());
    let baseline = Engine::new(config.clone())
        .unwrap()
        .offline(common::MESSAGE);
    assert!(baseline.research_execution.is_none());
    let mut enabled = (*config).clone();
    enabled.heuristics = Some(Default::default());
    enabled.content_inspection = Some(Default::default());
    enabled.validate().unwrap();
    let engine = Engine::new(Arc::new(enabled)).unwrap();
    let mut observed = engine.offline(common::MESSAGE);
    assert_eq!(observed.score, baseline.score);
    assert_eq!(observed.tagged, baseline.tagged);
    assert_eq!(observed.complete, baseline.complete);
    assert_eq!(
        observed.research_execution.as_ref().unwrap().status,
        Status::Complete
    );
    assert!(observed.heuristics.is_some());
    assert!(observed.content_inspection.is_some());
    let serialized = serde_json::to_string(&observed).unwrap();
    observed = serde_json::from_str(&serialized).unwrap();
    let report = serde_json::to_string(&noisefence::diagnostics::Analysis::from(observed)).unwrap();
    assert!(!report.contains("rendez-vous est confirme"));
    assert!(!report.contains("sender@example.org"));
    assert!(!report.contains("\"features\":"));
    assert!(report.contains("content_inspection"));
}

#[tokio::test]
async fn concurrent_research_analyses_are_bounded_and_oversize_is_explicit() {
    let root = tempfile::tempdir().unwrap();
    let mut config = (*common::config(root.path())).clone();
    config.heuristics = Some(Default::default());
    config.content_inspection = Some(Default::default());
    config.smtp.max_processing = 1;
    let runtime = Arc::new(research_engines::Runtime::new(&config).unwrap());
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..32 {
        let runtime = runtime.clone();
        tasks.spawn(async move { runtime.inspect(common::MESSAGE).await.execution.status });
    }
    let mut complete = 0;
    while let Some(status) = tasks.join_next().await {
        match status.unwrap() {
            Status::Complete => complete += 1,
            Status::Busy => {}
            state => panic!("unexpected detector state: {state:?}"),
        }
    }
    assert!(complete > 0);
    let large = vec![b'a'; config.filter.max_analysis_bytes + 1];
    let report = runtime.inspect(&large).await;
    assert_eq!(report.execution.status, Status::Limited);
    assert!(report.content.is_none() && report.heuristics.is_none());
    assert_eq!(
        runtime.inspect(common::MESSAGE).await.execution.status,
        Status::Complete
    );
}

#[test]
fn incomplete_research_is_not_a_suspicious_verdict() {
    let root = tempfile::tempdir().unwrap();
    let config = common::config(root.path());
    let baseline = Engine::new(config.clone())
        .unwrap()
        .offline(common::MESSAGE);
    let mut limited = (*config).clone();
    let mut settings = noisefence::heuristics::Settings::default();
    settings.limits.max_raw_bytes = 1;
    limited.heuristics = Some(settings);
    limited.content_inspection = Some(noisefence::content_inspection::Settings {
        max_raw_bytes: 1,
        ..Default::default()
    });
    limited.validate().unwrap();
    let observed = Engine::new(Arc::new(limited))
        .unwrap()
        .offline(common::MESSAGE);
    assert_eq!(observed.score, baseline.score);
    assert_eq!(observed.heuristics.as_ref().unwrap().contribution, 0.0);
    assert_ne!(
        observed.content_inspection.as_ref().unwrap().status,
        noisefence::content_inspection::Status::Complete
    );
}

#[test]
fn development_export_never_opens_reserved_tests_or_overwrites_results() {
    use noisefence::research::export_detectors;
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let mut config = (*common::config(root.path())).clone();
    config.heuristics = Some(Default::default());
    config.content_inspection = Some(Default::default());
    let corpus = root.path().join("corpus");
    std::fs::create_dir(&corpus).unwrap();
    std::fs::write(corpus.join("sample.eml"), common::MESSAGE).unwrap();
    let records = [
        serde_json::json!({"path":"sample.eml","spam":false,"source":"synthetic","year":2026}),
        serde_json::json!({"path":"sample.eml","spam":false,"source":"synthetic","year":2026}),
        serde_json::json!({"path":"must-not-be-opened.eml","spam":true,"source":"reserved","external_test":true}),
    ];
    let manifest = root.path().join("manifest.jsonl");
    std::fs::write(
        &manifest,
        records.iter().map(|r| format!("{r}\n")).collect::<String>(),
    )
    .unwrap();
    let output = root.path().join("observations.jsonl");
    let result = export_detectors(&config, &manifest, &corpus, &output, 3).unwrap();
    assert_eq!(result["exported"], 1);
    assert_eq!(result["reserved_test_excluded"], 1);
    assert_eq!(result["exact_duplicates"], 1);
    assert_eq!(result["independent_quality_evaluation"], false);
    let bytes = std::fs::read(&output).unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    assert!(!text.contains("rendez-vous est confirme") && !text.contains("sender@example.org"));
    assert_eq!(
        std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(export_detectors(&config, &manifest, &corpus, &output, 3).is_err());
    assert_eq!(std::fs::read(&output).unwrap(), bytes);
    assert!(
        export_detectors(
            &config,
            &manifest,
            &corpus,
            &root.path().join("limited.jsonl"),
            1
        )
        .is_err()
    );
    assert!(!root.path().join("limited.jsonl").exists());
    assert!(!std::fs::read_dir(root.path()).unwrap().any(|e| {
        e.unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".detectors-")
    }));
}
