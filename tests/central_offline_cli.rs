#[allow(dead_code)]
mod common;
#[path = "common/postgres.rs"]
mod postgres;
use noisefence::{
    central::outbox,
    cluster::{activation::Journal, artifacts},
    control::Settings,
    store::Store,
};
use std::path::Path;
async fn source(root: &Path) -> Store {
    let store = Store::open(root).unwrap();
    noisefence::mfa::Key::open(root).unwrap();
    let config = common::config(root);
    let publication = artifacts::capture(&config, Settings::from_config(&config), 0).unwrap();
    store.run(move|db| {
        db.execute_batch("INSERT INTO cluster_state VALUES('role','coordinator'),('node_id','mx1'); INSERT INTO users VALUES('admin','synthetic-hash',1,0); PRAGMA user_version=6;")?;
        let tx=db.transaction()?;Journal::initialize(&tx,"mx1",publication.bundle)?;tx.commit()?;Ok(())
    }).await.unwrap();
    store
}
fn plan(root: &Path, settings: &noisefence::central::Settings, extra: &str) -> std::path::PathBuf {
    let path = root.join("import.toml");
    let source = toml::Table::from_iter([
        ("node_id".into(), toml::Value::String("mx1".into())),
        ("role".into(), toml::Value::String("coordinator".into())),
        (
            "data_dir".into(),
            // macOS /var is a symlink; exercise SQLite NOFOLLOW with the real path.
            toml::Value::String(root.canonicalize().unwrap().display().to_string()),
        ),
    ]);
    std::fs::write(
        &path,
        format!(
            "[database]\n{}\n[[sources]]\n{}\n{}",
            toml::to_string(settings).unwrap(),
            toml::to_string(&source).unwrap(),
            extra
        ),
    )
    .unwrap();
    path
}
async fn execute(path: &Path) -> std::process::Output {
    tokio::time::timeout(
        std::time::Duration::from_secs(60),
        tokio::process::Command::new(env!("CARGO_BIN_EXE_noisefence"))
            .args([
                "--config",
                "/nonexistent-unused-config",
                "management-stage",
                "--plan",
            ])
            .arg(path)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap()
    .unwrap()
}
async fn verify(path: &Path, receipt: &serde_json::Value) -> std::process::Output {
    tokio::time::timeout(
        std::time::Duration::from_secs(60),
        tokio::process::Command::new(env!("CARGO_BIN_EXE_noisefence"))
            .arg("management-verify-sources")
            .arg("--plan")
            .arg(path)
            .arg("--instance")
            .arg(receipt["database"]["instance"].as_str().unwrap())
            .arg("--source-digest")
            .arg(receipt["database"]["source_digest"].as_str().unwrap())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap()
    .unwrap()
}
#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn operator_command_preserves_source_format_and_leaves_destination_inactive() {
    let f = postgres::Fixture::new().await;
    let pg = f.connect().await;
    let root = tempfile::tempdir().unwrap();
    let store = source(root.path()).await;
    let key = std::fs::read(root.path().join("mfa.key")).unwrap();
    let plan = plan(root.path(), &f.settings, "");
    let output = execute(&plan).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let receipt: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(uuid::Uuid::parse_str(receipt["database"]["instance"].as_str().unwrap()).is_ok());
    assert_eq!(receipt["reconciliation"]["sources"], 1);
    let sequence_before = store
        .read(|db| Ok(outbox::status(db)?.sequence))
        .await
        .unwrap();
    for _ in 0..2 {
        let output = verify(&plan, &receipt).await;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()["status"],
            "sources_match_inactive_import"
        );
    }
    assert_eq!(
        store
            .read(|db| Ok(outbox::status(db)?.sequence))
            .await
            .unwrap(),
        sequence_before
    );
    let mut wrong_receipt = receipt.clone();
    wrong_receipt["database"]["instance"] = serde_json::json!(uuid::Uuid::new_v4().to_string());
    assert!(!verify(&plan, &wrong_receipt).await.status.success());
    pg.batch_execute(
        "UPDATE noisefence.users SET password='destination-only-change' WHERE username='admin'",
    )
    .await
    .unwrap();
    let changed = verify(&plan, &receipt).await;
    assert!(!changed.status.success());
    assert!(String::from_utf8_lossy(&changed.stderr).contains("parity mismatch"));
    pg.batch_execute(
        "UPDATE noisefence.users SET password='synthetic-hash' WHERE username='admin'",
    )
    .await
    .unwrap();

    store
        .run(|db| {
            db.execute(
                "UPDATE users SET password='changed-after-import' WHERE username='admin'",
                [],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    let output = verify(&plan, &receipt).await;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("sources changed after import"));

    assert_eq!(
        pg.query_one(
            "SELECT count(*) FROM noisefence.users WHERE username='admin'",
            &[]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        1
    );
    let row = pg
        .query_one(
            "SELECT activated_at,report->>'phase' FROM noisefence.migration_state",
            &[],
        )
        .await
        .unwrap();
    assert!(row.get::<_, Option<i64>>(0).is_none());
    assert_eq!(row.get::<_, String>(1), "copied_not_activated");
    store
        .read(|db| {
            assert_eq!(
                db.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))?,
                6
            );
            assert_eq!(outbox::identity(db)?.node, "mx1");
            assert_eq!(
                db.query_row("SELECT count(*) FROM users", [], |r| r.get::<_, i64>(0))?,
                1
            );
            assert_eq!(
                db.query_row(
                    "SELECT count(*) FROM cluster_state WHERE key='management_selection'",
                    [],
                    |r| r.get::<_, i64>(0)
                )?,
                0
            );
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(key, std::fs::read(root.path().join("mfa.key")).unwrap());
    assert!(store.daemon_lock().is_ok());
    assert!(
        !execute(&plan).await.status.success(),
        "existing destination cannot be overwritten"
    );
    f.finish().await;
}
#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn running_sources_missing_keys_and_unknown_plan_fields_fail_before_journal_or_pg_writes() {
    let f = postgres::Fixture::new().await;
    let pg = f.connect().await;
    let root = tempfile::tempdir().unwrap();
    let store = source(root.path()).await;
    let file = plan(root.path(), &f.settings, "");
    let guard = store.daemon_lock().unwrap();
    let output = execute(&file).await;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Stop the source daemon"));
    drop(guard);
    std::fs::remove_file(root.path().join("mfa.key")).unwrap();
    assert!(!execute(&file).await.status.success());
    assert!(
        !root.path().join("mfa.key").exists(),
        "never generate replacement key"
    );
    let file = plan(root.path(), &f.settings, "unexpected='rejected'");
    assert!(!execute(&file).await.status.success());
    store
        .read(|db| {
            assert_eq!(
                db.query_row(
                    "SELECT count(*) FROM sqlite_master WHERE name='management_journal'",
                    [],
                    |r| r.get::<_, i64>(0)
                )?,
                0
            );
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(
        pg.query_one("SELECT count(*) FROM noisefence.migration_state", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    assert_eq!(
        pg.query_one("SELECT count(*) FROM noisefence.users", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn two_source_command_requires_all_locks_and_detects_worker_changes() {
    let f = postgres::Fixture::new().await;
    let root = tempfile::tempdir().unwrap();
    let worker_root = tempfile::tempdir().unwrap();
    let coordinator = source(root.path()).await;
    let worker = Store::open(worker_root.path()).unwrap();
    let scan = serde_json::to_string(
        &noisefence::engine::Engine::new(common::config(worker_root.path()))
            .unwrap()
            .offline(common::MESSAGE),
    )
    .unwrap();
    worker.run(move |db| {
        db.execute_batch("INSERT INTO cluster_state VALUES('node_id','mx2'),('role','worker'); PRAGMA user_version=6;")?;
        let id = uuid::Uuid::new_v4().to_string();
        db.execute("INSERT INTO messages(id,created,sender,scan) VALUES(?1,1,'sender@example.test',?2)",rusqlite::params![id,scan])?;
        db.execute("INSERT INTO deliveries(message_id,address,destination,hosts,next_attempt) VALUES(?1,'alice@example.test','alice@example.test','[]',0)",[id])?;
        let delivery=db.last_insert_rowid();
        let trace=serde_json::json!({"route":"mx.example.test","peer":null,"started":1,"elapsed_ms":1,"outcome":"delivered","events":[],"truncated":false});
        db.execute("INSERT INTO delivery_attempts(delivery_id,attempt,trace) VALUES(?1,1,?2)",rusqlite::params![delivery,trace.to_string()])?;

        Ok(())
    }).await.unwrap();
    coordinator.run(|db| {
        db.execute("INSERT INTO cluster_nodes(id,name,token_hash,enabled,created,version) VALUES('mx2','Worker',?1,1,1,1)",["a".repeat(64)])?;
        Ok(())
    }).await.unwrap();
    let extra = format!(
        "\n[[sources]]\nnode_id='mx2'\nrole='worker'\ndata_dir={}\n",
        toml::Value::String(
            worker_root
                .path()
                .canonicalize()
                .unwrap()
                .display()
                .to_string()
        )
    );
    let file = plan(root.path(), &f.settings, &extra);
    let busy = worker.daemon_lock().unwrap();
    assert!(!execute(&file).await.status.success());
    coordinator
        .read(|db| {
            assert_eq!(
                db.query_row(
                    "SELECT count(*) FROM sqlite_master WHERE name='management_journal'",
                    [],
                    |r| r.get::<_, i64>(0)
                )?,
                0
            );
            Ok(())
        })
        .await
        .unwrap();
    drop(busy);
    let output = execute(&file).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let receipt: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(receipt["reconciliation"]["sources"], 2);
    assert_eq!(receipt["reconciliation"]["owner_records"], 1);
    let output = verify(&file, &receipt).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let pg = f.connect().await;
    for (change, repair) in [
        (
            "UPDATE noisefence.delivery_logs SET attempt=attempt+1",
            "UPDATE noisefence.delivery_logs SET attempt=attempt-1",
        ),
        (
            "UPDATE noisefence.delivery_log_versions SET generation=generation+1",
            "UPDATE noisefence.delivery_log_versions SET generation=generation-1",
        ),
        (
            "UPDATE noisefence.messages SET sender='changed@example.test'",
            "UPDATE noisefence.messages SET sender='sender@example.test'",
        ),
        (
            "UPDATE noisefence.deliveries SET attempts=attempts+1",
            "UPDATE noisefence.deliveries SET attempts=attempts-1",
        ),
        (
            "UPDATE noisefence.message_versions SET generation=generation+1",
            "UPDATE noisefence.message_versions SET generation=generation-1",
        ),
        (
            "UPDATE noisefence.policy_head SET activated_at=1",
            "UPDATE noisefence.policy_head SET activated_at=0",
        ),
        (
            "SELECT setval('noisefence.deliveries_id_seq',1,false)",
            "SELECT setval('noisefence.deliveries_id_seq',1,true)",
        ),
    ] {
        pg.batch_execute(change).await.unwrap();
        let output = verify(&file, &receipt).await;
        assert!(
            !output.status.success(),
            "destination change must be detected: {change}"
        );
        pg.batch_execute(repair).await.unwrap();
        let output = verify(&file, &receipt).await;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let original_score: Option<f64> = pg
        .query_one("SELECT score FROM noisefence.messages", &[])
        .await
        .unwrap()
        .get(0);
    let altered = original_score.expect("fixture has a numeric score") + 1e-12;
    pg.execute("UPDATE noisefence.messages SET score=$1", &[&altered])
        .await
        .unwrap();
    let output = verify(&file, &receipt).await;
    assert!(
        !output.status.success(),
        "small real score changes cannot pass as JSON notation changes"
    );
    let diagnostic = String::from_utf8_lossy(&output.stderr);
    assert!(diagnostic.contains("messages (columns: score)"));
    assert!(!diagnostic.contains("alice@example.test"));
    pg.execute(
        "UPDATE noisefence.messages SET score=$1",
        &[&original_score],
    )
    .await
    .unwrap();
    assert!(verify(&file, &receipt).await.status.success());
    worker
        .run(|db| {
            db.execute("UPDATE deliveries SET status='delivered'", [])?;
            Ok(())
        })
        .await
        .unwrap();
    let output = verify(&file, &receipt).await;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("sources changed after import"));
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn installation_preflight_checks_frozen_files_without_selecting_backend() {
    use noisefence::cluster::activation::{Acknowledgement, Progress, participant::Local};
    let f = postgres::Fixture::new().await;
    let root = tempfile::tempdir().unwrap();
    let store = source(root.path()).await;
    let mut config = (*common::config(root.path())).clone();
    config.cluster = Some(toml::from_str("role='coordinator'\nnode_id='mx1'").unwrap());
    let model = root.path().join("synthetic-model.json");
    // This test verifies artifact identity only, not model inference.
    std::fs::write(&model, b"{\"synthetic\":true}").unwrap();
    config.filter.model = Some(model);
    let publication = artifacts::bind_credentials(
        artifacts::capture(&config, Settings::from_config(&config), 1).unwrap(),
    )
    .unwrap();
    artifacts::freeze(root.path(), &publication, 0).unwrap();
    let frozen = artifacts::directory(root.path(), &publication.bundle)
        .join(publication.bundle.files.keys().next().unwrap());
    let original = std::fs::read(&frozen).unwrap();
    let credential = root.path().join("cluster/credentials").join(format!(
        "{}.json",
        publication.bundle.credential_generation.as_ref().unwrap()
    ));
    let config_path = root.path().join("installation.toml");
    std::fs::write(&config_path, toml::to_string(&config).unwrap()).unwrap();
    store
        .run(move |db| {
            let tx = db.transaction()?;
            let settings = serde_json::to_string(&publication.bundle.settings)?;
            let journal = Journal::begin(&tx, publication.bundle, vec!["mx1".into()], 1)?;
            let epoch = journal.rollout().unwrap().epoch().clone();
            Journal::acknowledge(
                &tx,
                "mx1",
                &Acknowledgement {
                    epoch: epoch.clone(),
                    progress: Progress::Prepared,
                },
                2,
            )?;
            Journal::commit(&tx, &epoch, 3)?;
            Journal::acknowledge(
                &tx,
                "mx1",
                &Acknowledgement {
                    epoch: epoch.clone(),
                    progress: Progress::Applied,
                },
                4,
            )?;
            let released=Journal::release(&tx,&epoch,5)?;
            // Fixture models an already enrolled participant; mutation APIs stay private.
            let local=serde_json::json!({"version":1,"node":"mx1","authority":released,"installed":released.current(),"installed_epoch":epoch,"prepared":epoch});
            tx.execute("INSERT INTO cluster_state VALUES('activation_participant',?1)",[local.to_string()])?;
            assert!(Local::read(&tx)?.is_some());
            tx.execute(
                "INSERT INTO console_revisions VALUES(1,3,'admin',?1)",
                [settings],
            )?;
            tx.commit()?;
            Ok(())
        })
        .await
        .unwrap();
    let file = plan(
        root.path(),
        &f.settings,
        &format!(
            "config={}\n",
            toml::Value::String(config_path.display().to_string())
        ),
    );
    let staged = execute(&file).await;
    assert!(
        staged.status.success(),
        "{}",
        String::from_utf8_lossy(&staged.stderr)
    );
    let receipt: serde_json::Value = serde_json::from_slice(&staged.stdout).unwrap();
    async fn prepare(path: &Path, r: &serde_json::Value) -> std::process::Output {
        tokio::time::timeout(
            std::time::Duration::from_secs(60),
            tokio::process::Command::new(env!("CARGO_BIN_EXE_noisefence"))
                .arg("management-prepare-selections")
                .arg("--plan")
                .arg(path)
                .arg("--instance")
                .arg(r["database"]["instance"].as_str().unwrap())
                .arg("--source-digest")
                .arg(r["database"]["source_digest"].as_str().unwrap())
                .kill_on_drop(true)
                .output(),
        )
        .await
        .unwrap()
        .unwrap()
    }
    let checked = prepare(&file, &receipt).await;
    assert!(
        checked.status.success(),
        "{}",
        String::from_utf8_lossy(&checked.stderr)
    );
    let output: serde_json::Value = serde_json::from_slice(&checked.stdout).unwrap();
    assert_eq!(output["status"], "installation_checked_not_activated");
    assert_eq!(output["selections"][0]["database"], receipt["database"]);
    assert_eq!(
        output["selections"][0]["mfa_key_sha256"],
        noisefence::central::selection::key_digest(root.path()).unwrap()
    );
    std::fs::write(&frozen, b"changed").unwrap();
    assert!(!prepare(&file, &receipt).await.status.success());
    std::fs::write(&frozen, original).unwrap();
    let original_credential = std::fs::read(&credential).unwrap();
    std::fs::remove_file(&credential).unwrap();
    assert!(!prepare(&file, &receipt).await.status.success());
    assert!(!credential.exists(), "never regenerate missing credentials");
    store
        .read(|db| {
            assert_eq!(
                db.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))?,
                6
            );
            assert!(noisefence::central::selection::Selection::read(db)?.is_none());
            Ok(())
        })
        .await
        .unwrap();
    assert!(
        f.connect()
            .await
            .query_one(
                "SELECT activated_at IS NULL FROM noisefence.migration_state",
                &[]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    // Recover the same inactive import after a durable local commit. Source
    // format changes must not change the canonical imported management data.
    noisefence::cluster::protocol::private_write(&credential, &original_credential).unwrap();
    let selected: noisefence::central::selection::Selection =
        serde_json::from_value(output["selections"][0].clone()).unwrap();
    let mut local = rusqlite::Connection::open(root.path().join("state.sqlite3")).unwrap();
    let tx = local.transaction().unwrap();
    selected.install(&tx).unwrap();
    tx.commit().unwrap();
    let recovered = verify(&file, &receipt).await;
    assert!(
        recovered.status.success(),
        "{}",
        String::from_utf8_lossy(&recovered.stderr)
    );
    let recovered = prepare(&file, &receipt).await;
    assert!(
        recovered.status.success(),
        "{}",
        String::from_utf8_lossy(&recovered.stderr)
    );
    let recovered: serde_json::Value = serde_json::from_slice(&recovered.stdout).unwrap();
    assert_eq!(recovered["selections"], output["selections"]);
    local.execute("UPDATE users SET disabled=1", []).unwrap();
    assert!(
        !verify(&file, &receipt).await.status.success(),
        "selected format cannot hide source changes"
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn prepared_journals_preserve_identity_and_generations_without_silent_reseeding() {
    let f = postgres::Fixture::new().await;
    let root = tempfile::tempdir().unwrap();
    let store = source(root.path()).await;
    let file = plan(root.path(), &f.settings, "");
    async fn seeded(file: &Path) -> std::process::Output {
        tokio::process::Command::new(env!("CARGO_BIN_EXE_noisefence"))
            .arg("management-stage")
            .arg("--preserve-source-generations")
            .arg("--plan")
            .arg(file)
            .kill_on_drop(true)
            .output()
            .await
            .unwrap()
    }
    assert!(
        !seeded(&file).await.status.success(),
        "never invent missing source epochs"
    );
    let before=store.run(|db| {
        let scan=serde_json::to_string(&noisefence::engine::Scan{complete:true,..Default::default()})?;
        let id=uuid::Uuid::new_v4().to_string();
        db.execute("INSERT INTO messages(id,created,sender,scan) VALUES(?1,?2,'sender@example.test',?3)",rusqlite::params![id,noisefence::now(),scan])?;
        db.execute("INSERT INTO deliveries(message_id,address,destination,hosts,next_attempt) VALUES(?1,'alice@example.test','alice@example.test','[]',0)",[&id])?;
        let identity=outbox::initialize(db,"mx1")?;
        Ok((identity,outbox::pending(db,12)?))
    }).await.unwrap();
    let withheld = before.1[0].clone();
    store
        .run(|db| {
            db.execute("DELETE FROM management_outbox", [])?;
            Ok(())
        })
        .await
        .unwrap();
    assert!(
        !seeded(&file).await.status.success(),
        "missing owner records must fail instead of reseeding"
    );
    store
        .run(move |db| {
            db.execute(
                "INSERT INTO management_outbox VALUES(?1,?2,0)",
                rusqlite::params![withheld.id, withheld.generation],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    let output = seeded(&file).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let receipt: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(verify(&file, &receipt).await.status.success());
    let after = store
        .read(|db| Ok((outbox::identity(db)?, outbox::pending(db, 12)?)))
        .await
        .unwrap();
    assert_eq!(before, after);
    let pg = f.connect().await;
    let row = pg
        .query_one(
            "SELECT epoch,last_sequence FROM noisefence.sources WHERE node='mx1'",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), before.0.epoch);
    assert_eq!(row.get::<_, i64>(1), before.1[0].generation);
    assert!(
        pg.query_one(
            "SELECT activated_at FROM noisefence.migration_state WHERE id=1",
            &[]
        )
        .await
        .unwrap()
        .get::<_, Option<i64>>(0)
        .is_none()
    );
    f.finish().await;
}
