#[allow(dead_code)]
mod common;
use noisefence::{
    central::{
        binding::Binding,
        outbox,
        selection::{Selection, key_digest},
    },
    cluster::{
        Role,
        activation::{Acknowledgement, Journal, Progress},
        artifacts,
    },
    control::Settings,
    store::Store,
};
use std::{os::unix::fs::PermissionsExt, path::Path};

async fn prepare(
    source: &Path,
    data: &Path,
    config_dir: &Path,
    output: &Path,
) -> std::process::Output {
    tokio::process::Command::new(env!("CARGO_BIN_EXE_noisefence"))
        .args(["ha-console-config", "--source"])
        .arg(source)
        .arg("--data-directory")
        .arg(data)
        .arg("--config-directory")
        .arg(config_dir)
        .args([
            "--hostname",
            "mx2.example.test",
            "--public-origin",
            "https://mx2.example.test",
            "--listen",
            "127.0.0.1:18081",
            "--output",
        ])
        .arg(output)
        .kill_on_drop(true)
        .output()
        .await
        .unwrap()
}

#[tokio::test]
async fn selected_console_preparation_is_offline_and_preserves_authority_and_startup_fence() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().canonicalize().unwrap();
    let data = path.join("data");
    std::fs::create_dir(&data).unwrap();
    drop(Store::open(&data).unwrap());
    noisefence::mfa::Key::open(&data).unwrap();
    let mut config = (*common::config(&data)).clone();
    config.cluster = Some(toml::from_str("role='coordinator'\nnode_id='mx1'").unwrap());
    config.web.public_origin = "https://mx1.example.test".into();
    config.web.secure_cookies = true;
    let baseline = artifacts::bind_credentials(
        artifacts::capture(&config, Settings::from_config(&config), 0).unwrap(),
    )
    .unwrap();
    let mut publication = baseline.clone();
    publication.bundle.revision = 1;
    publication.bundle.digest = publication.bundle.hash().unwrap();
    artifacts::freeze(&data, &publication, 0).unwrap();
    let mut db = rusqlite::Connection::open(data.join("state.sqlite3")).unwrap();
    db.execute_batch("INSERT INTO cluster_state VALUES('role','coordinator'),('node_id','mx1')")
        .unwrap();
    let identity = outbox::initialize(&mut db, "mx1").unwrap();
    let tx = db.transaction().unwrap();
    Journal::initialize(&tx, "mx1", baseline.bundle).unwrap();
    let journal = Journal::begin(&tx, publication.bundle, vec!["mx1".into()], 1).unwrap();
    let epoch = journal.rollout().unwrap().epoch().clone();
    Journal::acknowledge(
        &tx,
        "mx1",
        &Acknowledgement {
            epoch: epoch.clone(),
            progress: Progress::Prepared,
        },
        2,
    )
    .unwrap();
    Journal::commit(&tx, &epoch, 3).unwrap();
    Journal::acknowledge(
        &tx,
        "mx1",
        &Acknowledgement {
            epoch: epoch.clone(),
            progress: Progress::Applied,
        },
        4,
    )
    .unwrap();
    let released = Journal::release(&tx, &epoch, 5).unwrap();
    let local = serde_json::json!({"version":1,"node":"mx1","authority":released,"installed":released.current(),"installed_epoch":epoch,"prepared":epoch});
    let selection = Selection::new(
        Binding {
            instance: uuid::Uuid::new_v4().to_string(),
            source_digest: "e".repeat(64),
        },
        identity,
        Role::Coordinator,
        epoch,
        Some(key_digest(&data).unwrap()),
    )
    .unwrap();
    let op = uuid::Uuid::new_v4().to_string();
    let pending = serde_json::json!({"protocol":"noisefence-management-recovery-1","operation":op,"created":noisefence::now()});
    for (key, value) in [
        ("activation_participant", local.to_string()),
        (
            "management_selection",
            serde_json::to_string(&selection).unwrap(),
        ),
        (
            "management_transport",
            noisefence::central::transport::PROTOCOL.into(),
        ),
        (
            "runtime_history_protocol",
            noisefence::runtime_history::PROTOCOL.into(),
        ),
        ("management_recovery_required", pending.to_string()),
    ] {
        tx.execute(
            "INSERT INTO cluster_state VALUES(?1,?2)",
            rusqlite::params![key, value],
        )
        .unwrap();
    }
    // Selected preparation must never consume or rewrite obsolete local management data.
    let obsolete = "{\"obsolete\":\"/original/noisefence/private\"}";
    tx.execute(
        "INSERT INTO console_revisions VALUES(1,1,'old',?1)",
        [obsolete],
    )
    .unwrap();
    tx.pragma_update(None, "user_version", 7).unwrap();
    tx.commit().unwrap();
    let receipt = serde_json::json!({"owner":"mx1","operation":op,"smtp_started":false,"central_management_recovery_required":true});
    let receipt_path = data.join("ha-recovery.json");
    noisefence::cluster::protocol::private_write(&receipt_path, receipt.to_string().as_bytes())
        .unwrap();
    config.management = Some(noisefence::central::bootstrap::Management::PostgreSql {
        connection: noisefence::central::Settings {
            host: "/nonexistent/noisefence-postgresql".into(),
            port: 5432,
            database: "recovery".into(),
            username: "noisefence".into(),
            password_file: None,
            ca_file: None,
            max_connections: 1,
            allow_loopback_plaintext: false,
        },
    });
    config.data_dir = "/original/noisefence".into();
    let source = path.join("source.toml");
    std::fs::write(&source, toml::to_string(&config).unwrap()).unwrap();
    let output = path.join("console.toml");
    let config_dir = path.join("config");
    std::fs::create_dir(&config_dir).unwrap();
    let result = prepare(&source, &data, &config_dir, &output).await;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["management_recovery"]["operation"], op);
    assert_eq!(
        report["management_recovery"]["central_management_recovery_required"],
        true
    );
    let console = noisefence::config::Config::load(&output).unwrap();
    assert_eq!(console.data_dir, data);
    assert!(console.management.is_some());
    assert_eq!(console.cluster.as_ref().unwrap().node_id, "mx1");
    assert_eq!(console.hostname, "mx2.example.test");
    assert_eq!(console.smtp.listen.port(), 0);
    assert!(console.replication.is_none());
    assert!(
        noisefence::central::bootstrap::open(
            &console,
            noisefence::central::bootstrap::Purpose::Runtime
        )
        .is_err()
    );
    assert_eq!(
        db.query_row("SELECT settings FROM console_revisions", [], |r| r
            .get::<_, String>(0))
            .unwrap(),
        obsolete
    );
    assert_eq!(Selection::read(&db).unwrap(), Some(selection));
    assert_eq!(
        db.query_row(
            "SELECT value FROM cluster_state WHERE key='management_recovery_required'",
            [],
            |r| r.get::<_, String>(0)
        )
        .unwrap(),
        pending.to_string()
    );
    assert_eq!(
        std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let saved = std::fs::read(&output).unwrap();
    // Refusals must not overwrite a previously prepared configuration.
    let held = noisefence::central::import::SourceLocks::acquire(&data).unwrap();
    assert!(
        !prepare(&source, &data, &config_dir, &output)
            .await
            .status
            .success()
    );
    drop(held);
    let mut wrong = receipt.clone();
    wrong["operation"] = serde_json::json!(uuid::Uuid::new_v4().to_string());
    noisefence::cluster::protocol::private_write(&receipt_path, wrong.to_string().as_bytes())
        .unwrap();
    assert!(
        !prepare(&source, &data, &config_dir, &output)
            .await
            .status
            .success()
    );
    noisefence::cluster::protocol::private_write(&receipt_path, receipt.to_string().as_bytes())
        .unwrap();
    let key = std::fs::read(data.join("mfa.key")).unwrap();
    std::fs::write(data.join("mfa.key"), [0u8; 32]).unwrap();
    assert!(
        !prepare(&source, &data, &config_dir, &output)
            .await
            .status
            .success()
    );
    std::fs::write(data.join("mfa.key"), key).unwrap();
    let credential = data.join("cluster/credentials").join(format!(
        "{}.json",
        released.current().credential_generation.as_ref().unwrap()
    ));
    std::fs::remove_file(credential).unwrap();
    assert!(
        !prepare(&source, &data, &config_dir, &output)
            .await
            .status
            .success()
    );
    assert_eq!(std::fs::read(output).unwrap(), saved);
}

#[tokio::test]
async fn legacy_console_preparation_still_remaps_its_local_revisions() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().canonicalize().unwrap();
    let data = path.join("data");
    std::fs::create_dir(&data).unwrap();
    drop(Store::open(&data).unwrap());
    noisefence::mfa::Key::open(&data).unwrap();
    let key = std::fs::read(data.join("mfa.key")).unwrap();
    let db = rusqlite::Connection::open(data.join("state.sqlite3")).unwrap();
    db.execute(
        "INSERT INTO console_revisions VALUES(1,1,'admin',?1)",
        ["{\"path\":\"/original/noisefence/model.json\"}"],
    )
    .unwrap();
    noisefence::cluster::protocol::private_write(&data.join("ha-recovery.json"), b"{}").unwrap();
    let mut config = (*common::config(&data)).clone();
    config.cluster = Some(toml::from_str("role='coordinator'\nnode_id='mx1'").unwrap());
    config.web.public_origin = "https://mx1.example.test".into();
    config.web.secure_cookies = true;
    config.data_dir = "/original/noisefence".into();
    let source = path.join("source.toml");
    std::fs::write(&source, toml::to_string(&config).unwrap()).unwrap();
    let output = path.join("console.toml");
    let config_dir = path.join("config");
    std::fs::create_dir(&config_dir).unwrap();
    let result = prepare(&source, &data, &config_dir, &output).await;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert!(report["management_recovery"].is_null());
    let stored: String = db
        .query_row("SELECT settings FROM console_revisions", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&stored).unwrap()["path"],
        data.join("model.json").to_string_lossy().as_ref()
    );
    assert_eq!(std::fs::read(data.join("mfa.key")).unwrap(), key);
    let output = noisefence::config::Config::load(&output).unwrap();
    assert!(output.management.is_none());
    assert_eq!(output.smtp.listen.port(), 0);
    assert_eq!(output.data_dir, data);
}
