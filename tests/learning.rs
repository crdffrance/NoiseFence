mod common;
use noisefence::{
    engine::{Scan, SemanticResult, SemanticStatus},
    features,
    learning::{self, SemanticProtocol},
    store::Store,
};
use std::os::unix::fs::PermissionsExt;

fn scan() -> Scan {
    let mut result = features::extract(common::MESSAGE, 10000);
    let mut vector = vec![0.0; learning::DIMENSION];
    vector[0] = 1.0;
    result.semantic = SemanticResult {
        status: SemanticStatus::Complete,
        encoder: learning::ENCODER_ID.into(),
        protocol: Some(SemanticProtocol::pinned()),
        features: vector,
        ..Default::default()
    };
    result
}
async fn seed(store: &Store, id: &str, scan: Scan, labels: &[(&str, bool)]) {
    let id = id.to_owned();
    let labels: Vec<_> = labels.iter().map(|(u, b)| (u.to_string(), *b)).collect();
    store.run(move |db| {
        db.execute("INSERT INTO messages(id,created,sender,scan,raw_present) VALUES(?1,?2,'private-sender@example.org',?3,0)",
            rusqlite::params![id,noisefence::now(),serde_json::to_string(&scan)?])?;
        for (user, label) in labels {
            let recipient = format!("{user}@example.test");
            db.execute("INSERT OR IGNORE INTO users(username,password) VALUES(?1,'test-only')", [&user])?;
            db.execute("INSERT OR IGNORE INTO grants(username,address) VALUES(?1,?2)", rusqlite::params![user,recipient])?;
            db.execute("INSERT INTO deliveries(message_id,address,destination,hosts,status,next_attempt) VALUES(?1,?2,?2,'[]','sending',0)", rusqlite::params![id,recipient])?;
            db.execute("INSERT INTO feedback(username,message_id,spam,created) VALUES(?1,?2,?3,?4)", rusqlite::params![user,id,label,noisefence::now()])?;
        }
        Ok(())
    }).await.unwrap();
}

#[test]
fn persisted_protocol_matches_training_and_old_rows_are_not_backfilled() {
    let protocol: SemanticProtocol =
        serde_json::from_str(include_str!("../research/semantic-protocol.json")).unwrap();
    assert_eq!(protocol, SemanticProtocol::pinned());
    let mut row = serde_json::to_value(scan()).unwrap();
    row["semantic"].as_object_mut().unwrap().remove("protocol");
    row.as_object_mut().unwrap().remove("campaign_simhash");
    row.as_object_mut().unwrap().remove("features_complete");
    let old: Scan = serde_json::from_value(row).unwrap();
    assert!(old.semantic.protocol.is_none());
    assert!(old.campaign_simhash.is_none());
    assert!(old.features_complete.is_none());
}

#[tokio::test]
async fn external_failures_do_not_select_training_data_but_incomplete_vectors_stay_excluded() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let mut external = scan();
    external.complete = false;
    assert_eq!(external.features_complete, Some(true));
    seed(
        &store,
        "external-failure",
        external.clone(),
        &[("alice", true)],
    )
    .await;
    let mut unknown = external.clone();
    unknown.features_complete = None;
    seed(&store, "old-unknown", unknown, &[("alice", false)]).await;
    let mut invalid = external.clone();
    invalid.features_complete = Some(false);
    seed(&store, "incomplete-extraction", invalid, &[("alice", true)]).await;
    external.semantic.status = SemanticStatus::Busy;
    seed(&store, "missing-semantic", external, &[("alice", false)]).await;
    let output = dir.path().join("export");
    let report = learning::export(&store, &output, true).await.unwrap();
    assert_eq!(report.exported, 1);
    assert_eq!(report.exported_with_incomplete_checks, 1);
    assert_eq!(report.incomplete, 2);
    assert_eq!(report.missing_semantic_protocol, 1);
    let row: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(output).unwrap()).unwrap();
    assert_eq!(row["id"], noisefence::message::digest(b"external-failure"));
    let truncated = features::extract(common::MESSAGE, 1);
    assert_eq!(truncated.features_complete, Some(false));
    assert!(truncated.features.is_empty());
}

#[tokio::test]
async fn actual_scanner_outage_preserves_local_learning_without_enabling_tagging() {
    use noisefence::engine::{Algorithm, Engine, Model};
    let root = tempfile::tempdir().unwrap();
    let mut config = (*common::config(root.path())).clone();
    let model = Model {
        version: "learning-outage-fixture".into(),
        algorithm: Algorithm::Logistic,
        feature_version: features::VERSION,
        bias: 10.0,
        weights: vec![0.0; features::DIMENSION],
        idf: vec![1.0; features::DIMENSION],
        trained_at: 0,
        examples: 1,
    };
    let path = root.path().join("model.json");
    std::fs::write(&path, serde_json::to_vec(&model).unwrap()).unwrap();
    config.filter.model = Some(path);
    config.filter.mode = noisefence::config::Mode::Tag;
    config.antivirus = Some(noisefence::antivirus::AntivirusConfig {
        socket: root.path().join("absent.sock"),
        timeout_ms: 100,
        max_bytes: 10000,
        trusted_unofficial_prefixes: vec![],
    });
    let engine = Engine::new(std::sync::Arc::new(config)).unwrap();
    let (scan, raw) = engine
        .process(
            common::MESSAGE,
            "127.0.0.1".parse().unwrap(),
            "sender.example.test",
            "sender@example.test",
            "fixture",
        )
        .await
        .unwrap();
    assert!(!scan.complete);
    assert!(!scan.tagged);
    assert!(scan.score > 95.0);
    assert_eq!(scan.features_complete, Some(true));
    assert!(!String::from_utf8_lossy(&raw).contains("[SPAM]"));
    let store = Store::open(root.path()).unwrap();
    seed(&store, "actual-outage", scan, &[("alice", true)]).await;
    let report = learning::export(&store, &root.path().join("feedback"), false)
        .await
        .unwrap();
    assert_eq!(report.exported, 1);
    assert_eq!(report.exported_with_incomplete_checks, 1);
}

#[tokio::test]
async fn private_export_survives_body_deletion_without_disturbing_delivery_or_leaking_recipients() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&common::config(dir.path()).data_dir).unwrap();
    seed(
        &store,
        "sample",
        scan(),
        &[("alice", true), ("bcc-user", true)],
    )
    .await;
    let output = dir.path().join("feedback.jsonl");
    let report = learning::export(&store, &output, true).await.unwrap();
    assert_eq!(report.exported, 1);
    assert_eq!(report.semantic_exported, 1);
    let raw = std::fs::read_to_string(&output).unwrap();
    for forbidden in [
        "alice",
        "bcc-user",
        "private-sender",
        "Rendez-vous",
        "Bonjour",
        "destination",
        "subject",
        "username",
    ] {
        assert!(!raw.contains(forbidden), "export leaked {forbidden}");
    }
    let row: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(row["feature_version"], 3);
    assert_eq!(row["semantic"]["features"].as_array().unwrap().len(), 384);
    let visible = serde_json::to_string(
        &store
            .list("alice".into(), "".into(), "all".into(), 0, 95.0)
            .await
            .unwrap(),
    )
    .unwrap();
    for forbidden in ["features", "protocol", "fingerprint", "bcc-user"] {
        assert!(!visible.contains(forbidden), "console exposed {forbidden}");
    }
    assert_eq!(
        std::fs::metadata(output).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        store
            .run(|db| Ok(db.query_row(
                "SELECT COUNT(*) FROM deliveries WHERE status='sending'",
                [],
                |r| r.get::<_, i64>(0)
            )?))
            .await
            .unwrap(),
        2
    );
}

#[tokio::test]
async fn excludes_conflicts_old_metadata_and_revoked_authorizations() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    seed(
        &store,
        "conflict",
        scan(),
        &[("alice", true), ("bob", false)],
    )
    .await;
    seed(&store, "expired", scan(), &[("alice", true)]).await;
    seed(&store, "revoked", scan(), &[("former", true)]).await;
    seed(&store, "disabled", scan(), &[("disabled", true)]).await;
    store
        .run(|db| {
            db.execute("UPDATE messages SET created=0 WHERE id='expired'", [])?;
            db.execute("DELETE FROM grants WHERE username='former'", [])?;
            db.execute("UPDATE users SET disabled=1 WHERE username='disabled'", [])?;
            Ok(())
        })
        .await
        .unwrap();
    let report = learning::export(&store, &dir.path().join("export"), true)
        .await
        .unwrap();
    assert_eq!(report.considered, 1);
    assert_eq!(report.conflicting, 1);
    assert_eq!(report.exported, 0);
}

#[tokio::test]
async fn incompatible_protocols_are_counted_and_invalid_vectors_do_not_replace_previous_export() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let mut old = scan();
    old.semantic.protocol.as_mut().unwrap().revision = "other-encoder".into();
    seed(&store, "old", old, &[("alice", true)]).await;
    let output = dir.path().join("export");
    let report = learning::export(&store, &output, true).await.unwrap();
    assert_eq!(report.missing_semantic_protocol, 1);
    assert_eq!(report.exported, 0);
    let mut invalid = scan();
    invalid.semantic.features[0] = 0.5;
    seed(&store, "invalid", invalid, &[("alice", true)]).await;
    std::fs::write(&output, b"previous complete snapshot").unwrap();
    assert!(learning::export(&store, &output, true).await.is_err());
    assert_eq!(
        std::fs::read(&output).unwrap(),
        b"previous complete snapshot"
    );
    assert!(!std::fs::read_dir(dir.path()).unwrap().any(|e| {
        e.unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".partial")
    }));
}
