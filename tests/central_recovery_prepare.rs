#[allow(dead_code)]
mod common;
#[path = "common/postgres.rs"]
mod postgres;
use noisefence::{
    central::{
        Central,
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
use serde_json::json;

#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn prepares_all_recovery_sources_without_releasing_startup_fences() {
    exercise(false).await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn native_command_prepares_and_retries_with_explicit_source_fences() {
    exercise(true).await;
}

async fn command(plan: &std::path::Path) -> std::process::Output {
    command_mode(plan, false).await
}
async fn command_mode(plan: &std::path::Path, verify: bool) -> std::process::Output {
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_noisefence"));
    command
        .args(["management-recovery-prepare", "--plan"])
        .arg(plan);
    if verify {
        command.arg("--verify-worker-installation");
    }
    command.kill_on_drop(true).output().await.unwrap()
}
async fn attach_workers(plan: &std::path::Path) -> std::process::Output {
    tokio::process::Command::new(env!("CARGO_BIN_EXE_noisefence"))
        .args(["management-recovery-attach-workers", "--plan"])
        .arg(plan)
        .kill_on_drop(true)
        .output()
        .await
        .unwrap()
}
async fn renew_worker_keys(plan: &std::path::Path) -> std::process::Output {
    tokio::process::Command::new(env!("CARGO_BIN_EXE_noisefence"))
        .args(["management-recovery-renew-worker-keys", "--plan"])
        .arg(plan)
        .kill_on_drop(true)
        .output()
        .await
        .unwrap()
}
async fn release_workers(plan: &std::path::Path) -> std::process::Output {
    tokio::process::Command::new(env!("CARGO_BIN_EXE_noisefence"))
        .args(["management-recovery-release-workers", "--plan"])
        .arg(plan)
        .kill_on_drop(true)
        .output()
        .await
        .unwrap()
}
async fn activate(plan: &std::path::Path) -> std::process::Output {
    tokio::process::Command::new(env!("CARGO_BIN_EXE_noisefence"))
        .args([
            "management-recovery-prepare",
            "--activate-console",
            "--plan",
        ])
        .arg(plan)
        .kill_on_drop(true)
        .output()
        .await
        .unwrap()
}
async fn refused_start(config: &std::path::Path, command: &str) {
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::process::Command::new(env!("CARGO_BIN_EXE_noisefence"))
            .arg("--config")
            .arg(config)
            .arg(command)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("unauthorized service did not exit")
    .unwrap();
    assert!(!result.status.success(), "unexpected authorized startup");
}
async fn exercise(native: bool) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let f = postgres::Fixture::new().await;
    let pg = f.connect().await;
    let binding = Binding {
        instance: uuid::Uuid::new_v4().to_string(),
        source_digest: "d".repeat(64),
    };
    pg.execute(
        "INSERT INTO noisefence.migration_state VALUES(1,$1,100,101,$2)",
        &[
            &binding.source_digest,
            &json!({"instance":binding.instance}),
        ],
    )
    .await
    .unwrap();
    let central = Central::new_bound(&f.settings, &binding).unwrap();
    let roots = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
    let mut configs = Vec::new();
    let mut dbs = Vec::new();
    let mut identities = Vec::new();
    for (i, root) in roots.iter().enumerate() {
        let path = root.path().canonicalize().unwrap();
        drop(Store::open(&path).unwrap());
        let mut config = (*common::config(&path)).clone();
        let role = if i == 0 { "coordinator" } else { "worker" };
        let node = format!("mx{}", i + 1);
        config.cluster = Some(toml::from_str(&format!("role='{role}'\nnode_id='{node}'")).unwrap());
        if i == 1 {
            let cluster = config.cluster.as_mut().unwrap();
            cluster.coordinator_url = Some("https://mx1.example.test".into());
            cluster.credential_file = Some(path.join("worker.json"));
        }
        if native && i == 0 {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            config.web.listen = listener.local_addr().unwrap();
        }
        config.validate().unwrap();
        let mut db = rusqlite::Connection::open(path.join("state.sqlite3")).unwrap();
        db.execute(
            "INSERT INTO cluster_state VALUES('role',?1),('node_id',?2)",
            rusqlite::params![role, node],
        )
        .unwrap();
        let identity = outbox::initialize(&mut db, &node).unwrap();
        central.register_source(&identity).await.unwrap();
        identities.push(identity);
        configs.push(config);
        dbs.push(db);
    }
    noisefence::mfa::Key::open(&configs[0].data_dir).unwrap();
    let previous_worker_token = "1".repeat(64);
    let previous_worker_hash = noisefence::message::digest(previous_worker_token.as_bytes());
    let installed_worker_file = configs[1]
        .cluster
        .as_ref()
        .unwrap()
        .credential_file
        .as_ref()
        .unwrap()
        .clone();
    noisefence::cluster::protocol::private_write(
        &installed_worker_file,
        previous_worker_token.as_bytes(),
    )
    .unwrap();
    central
        .enroll_node(&identities[1], "Original worker", &previous_worker_hash)
        .await
        .unwrap();
    let publication = artifacts::bind_credentials(
        artifacts::capture(&configs[0], Settings::from_config(&configs[0]), 0).unwrap(),
    )
    .unwrap();
    for config in &configs {
        artifacts::freeze(&config.data_dir, &publication, 0).unwrap();
    }
    let baseline = publication.bundle;
    central
        .initialize_policy(&identities[0], baseline.clone())
        .await
        .unwrap();
    let mut candidate = baseline.clone();
    candidate.revision = 1;
    candidate.settings.filters.threshold = 90.0;
    candidate.digest = candidate.hash().unwrap();
    let tx = dbs[0].transaction().unwrap();
    Journal::initialize(&tx, "mx1", baseline).unwrap();
    let j = Journal::begin(&tx, candidate, vec!["mx1".into(), "mx2".into()], 1).unwrap();
    let epoch = j.rollout().unwrap().epoch().clone();
    for node in ["mx1", "mx2"] {
        Journal::acknowledge(
            &tx,
            node,
            &Acknowledgement {
                epoch: epoch.clone(),
                progress: Progress::Prepared,
            },
            2,
        )
        .unwrap();
    }
    Journal::commit(&tx, &epoch, 3).unwrap();
    for node in ["mx1", "mx2"] {
        Journal::acknowledge(
            &tx,
            node,
            &Acknowledgement {
                epoch: epoch.clone(),
                progress: Progress::Applied,
            },
            4,
        )
        .unwrap();
    }
    let released = Journal::release(&tx, &epoch, 5).unwrap();
    tx.commit().unwrap();
    let op = uuid::Uuid::new_v4().to_string();
    for (i, db) in dbs.iter_mut().enumerate() {
        let mut local = json!({"version":1,"node":identities[i].node,"authority":released,"installed":released.current(),"installed_epoch":epoch,"prepared":epoch});
        if i == 1 {
            // Real peers can persist a later final-ack timestamp for the same
            // released policy. Exercise every recovery phase with that skew.
            local["authority"]["rollout"]["updated"] = json!(7);
        }
        let selection = Selection::new(
            binding.clone(),
            identities[i].clone(),
            if i == 0 {
                Role::Coordinator
            } else {
                Role::Worker
            },
            epoch.clone(),
            if i == 0 {
                Some(key_digest(&configs[0].data_dir).unwrap())
            } else {
                None
            },
        )
        .unwrap();
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
            (
                "management_recovery_required",
                json!({"protocol":"noisefence-management-recovery-1","operation":op}).to_string(),
            ),
        ] {
            db.execute(
                "INSERT INTO cluster_state VALUES(?1,?2)",
                rusqlite::params![key, value],
            )
            .unwrap();
        }
        db.pragma_update(None, "user_version", 7).unwrap();
    }
    configs[0].management = Some(noisefence::central::bootstrap::Management::PostgreSql {
        connection: f.settings.clone(),
    });
    configs[1].management = Some(noisefence::central::bootstrap::Management::Coordinator {});
    let private = tempfile::tempdir().unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(private.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let credentials = private.path().canonicalize().unwrap().join("recovery.json");
    pg.execute(
        "INSERT INTO noisefence.users(username,password,admin) VALUES('old-admin','unused',true)",
        &[],
    )
    .await
    .unwrap();
    assert!(
        central
            .prepare_recovered_management(&configs[..1], &op, &credentials)
            .await
            .is_err()
    );
    assert!(!credentials.exists());
    let held = noisefence::central::import::SourceLocks::acquire(&configs[1].data_dir).unwrap();
    assert!(
        central
            .prepare_recovered_management(&configs, &op, &credentials)
            .await
            .is_err()
    );
    drop(held);
    assert!(!credentials.exists());
    assert!(
        !pg.query_one(
            "SELECT disabled FROM noisefence.users WHERE username='old-admin'",
            &[]
        )
        .await
        .unwrap()
        .get::<_, bool>(0)
    );
    // Invalid sealed MFA fails before revoking access or publishing credentials.
    pg.execute(
        "INSERT INTO noisefence.mfa_credentials VALUES('old-admin',decode('1234','hex'),true,0,10)",
        &[],
    )
    .await
    .unwrap();
    assert!(
        central
            .prepare_recovered_management(&configs, &op, &credentials)
            .await
            .is_err()
    );
    assert!(!credentials.exists());
    pg.execute("DELETE FROM noisefence.mfa_credentials", &[])
        .await
        .unwrap();
    let configs_paths: Vec<_> = configs
        .iter()
        .enumerate()
        .map(|(i, config)| {
            let path = private.path().join(format!("mx{i}.toml"));
            std::fs::write(&path, toml::to_string(config).unwrap()).unwrap();
            path
        })
        .collect();
    let plan_path = private.path().canonicalize().unwrap().join("prepare.json");
    let plan = json!({"protocol":"noisefence-management-recovery-plan-1", "operation":op,
        "database":binding, "source_configs":configs_paths, "credentials_file":credentials,
        "fences":identities.iter().map(|identity|json!({"source":identity,"method":"systemd-persistent-condition",
            "reference":"synthetic stopped writer", "created":noisefence::now(), "fenced":true})).collect::<Vec<_>>()});
    if native {
        let mut wrong = plan.clone();
        wrong["fences"][1]["source"]["epoch"] = json!(uuid::Uuid::new_v4().to_string());
        noisefence::cluster::protocol::private_write(
            &plan_path,
            &serde_json::to_vec(&wrong).unwrap(),
        )
        .unwrap();
        let refused = command(&plan_path).await;
        assert!(!refused.status.success());
        assert!(String::from_utf8_lossy(&refused.stderr).contains("Fencing attestation differs"));
        assert!(!credentials.exists());
    }
    noisefence::cluster::protocol::private_write(&plan_path, &serde_json::to_vec(&plan).unwrap())
        .unwrap();
    if native {
        // This source represents the original stopped worker, not a replaced queue.
        dbs[1]
            .execute(
                "DELETE FROM cluster_state WHERE key='management_recovery_required'",
                [],
            )
            .unwrap();
        let queue_receipt = json!({"operation":op,"owner":"mx1","central_management_recovery_required":true,"smtp_started":false});
        noisefence::cluster::protocol::private_write(
            &configs[0].data_dir.join("ha-recovery.json"),
            &serde_json::to_vec(&queue_receipt).unwrap(),
        )
        .unwrap();
        let scan = noisefence::engine::Engine::new(common::config(&configs[1].data_dir))
            .unwrap()
            .offline(common::MESSAGE);
        let message = uuid::Uuid::new_v4().to_string();
        dbs[1].execute("INSERT INTO messages(id,created,sender,scan,raw_present) VALUES(?1,?2,'sender@example.test',?3,1)",rusqlite::params![message,noisefence::now(),serde_json::to_string(&scan).unwrap()]).unwrap();
        dbs[1].execute("INSERT INTO deliveries(message_id,address,destination,hosts,next_attempt,status) VALUES(?1,'alice@example.test','alice@example.test','[]',0,'delivered'),(?1,'bob@example.test','bob@example.test','[]',0,'pending')",[&message]).unwrap();
        let body = configs[1]
            .data_dir
            .join("spool")
            .join(format!("{message}.eml"));
        std::fs::write(&body, common::MESSAGE).unwrap();
        let sequence = noisefence::central::outbox::status(&dbs[1])
            .unwrap()
            .sequence;
        let outbox = noisefence::central::outbox::pending(&dbs[1], 12).unwrap();
        let selected_before: String = dbs[1]
            .query_row(
                "SELECT value FROM cluster_state WHERE key='management_selection'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let held = noisefence::central::import::SourceLocks::acquire(&configs[1].data_dir).unwrap();
        assert!(!attach_workers(&plan_path).await.status.success());
        drop(held);
        assert!(!dbs[1].query_row("SELECT EXISTS(SELECT 1 FROM cluster_state WHERE key='management_recovery_required')",[],|r|r.get::<_,bool>(0)).unwrap());
        dbs[1].execute_batch("CREATE TRIGGER reject_worker_attach BEFORE INSERT ON cluster_state WHEN NEW.key='management_worker_recovery' BEGIN SELECT RAISE(ABORT,'synthetic attachment failure'); END;").unwrap();
        assert!(!attach_workers(&plan_path).await.status.success());
        assert!(!dbs[1].query_row("SELECT EXISTS(SELECT 1 FROM cluster_state WHERE key='management_recovery_required')",[],|r|r.get::<_,bool>(0)).unwrap());
        dbs[1]
            .execute_batch("DROP TRIGGER reject_worker_attach")
            .unwrap();
        let attached = attach_workers(&plan_path).await;
        assert!(
            attached.status.success(),
            "{}",
            String::from_utf8_lossy(&attached.stderr)
        );
        let attached: serde_json::Value = serde_json::from_slice(&attached.stdout).unwrap();
        assert_eq!(attached["status"], "workers_fenced_in_place");
        assert_eq!(attached["network_used"], false);
        assert_eq!(attached["queue_replaced"], false);
        let again = attach_workers(&plan_path).await;
        assert!(again.status.success());
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&again.stdout).unwrap(),
            attached
        );
        assert_eq!(
            noisefence::central::outbox::status(&dbs[1])
                .unwrap()
                .sequence,
            sequence
        );
        assert_eq!(
            noisefence::central::outbox::pending(&dbs[1], 12).unwrap(),
            outbox
        );
        assert_eq!(
            dbs[1]
                .query_row(
                    "SELECT value FROM cluster_state WHERE key='management_selection'",
                    [],
                    |r| r.get::<_, String>(0)
                )
                .unwrap(),
            selected_before
        );
        let statuses = dbs[1]
            .prepare("SELECT address,status FROM deliveries WHERE message_id=?1 ORDER BY address")
            .unwrap()
            .query_map([&message], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(
            statuses,
            vec![
                ("alice@example.test".into(), "delivered".into()),
                ("bob@example.test".into(), "pending".into())
            ]
        );
        assert_eq!(std::fs::read(&body).unwrap(), common::MESSAGE);
        assert!(
            noisefence::central::bootstrap::open(
                &configs[1],
                noisefence::central::bootstrap::Purpose::Runtime
            )
            .is_err()
        );
    }
    let blocker = f.connect().await;
    blocker
        .batch_execute(
            "BEGIN; SELECT username FROM noisefence.users WHERE username='old-admin' FOR UPDATE",
        )
        .await
        .unwrap();
    let report = {
        let preparing = async {
            if native {
                let output = command(&plan_path).await;
                assert!(
                    output.status.success(),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
                let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
                assert_eq!(report["status"], "prepared_not_activated");
                assert_eq!(
                    report["fencing_attestation_sha256"].as_str().unwrap().len(),
                    64
                );
                Ok(report)
            } else {
                central
                    .prepare_recovered_management(&configs, &op, &credentials)
                    .await
            }
        };
        tokio::pin!(preparing);
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        while !credentials.exists() {
            tokio::select! {
                result = &mut preparing => panic!("Preparation must wait for in-flight access: {result:?}"),
                _ = tokio::time::sleep(std::time::Duration::from_millis(10)) => {}
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "Credential publication timed out"
            );
        }
        for config in &configs {
            assert!(noisefence::central::import::SourceLocks::acquire(&config.data_dir).is_err());
        }
        blocker.batch_execute("ROLLBACK").await.unwrap();
        drop(blocker);
        preparing.await.unwrap()
    };
    assert_eq!(report["history"].as_array().unwrap().len(), 2);
    assert_eq!(report["mfa_verified"], true);
    assert_eq!(report["provider_budgets_held"], true);
    assert_eq!(report["central_management_recovery_required"], true);
    assert_eq!(report["console_started"], false);
    assert_eq!(report["smtp_started"], false);
    assert_eq!(
        report["worker_access"]["worker_installation_required"],
        true
    );
    let worker_file = report["worker_access"]["credentials_file"]
        .as_str()
        .unwrap();
    let worker_keys: serde_json::Value =
        serde_json::from_slice(&std::fs::read(worker_file).unwrap()).unwrap();
    let replacement = worker_keys["workers"]["mx2"]["token"].as_str().unwrap();
    let replacement_hash = noisefence::message::digest(replacement.as_bytes());
    assert!(!report.to_string().contains(replacement));
    assert_ne!(replacement, previous_worker_token);
    assert_eq!(
        std::fs::read_to_string(&installed_worker_file).unwrap(),
        previous_worker_token
    );
    assert!(
        central
            .authenticate_node("mx2", &previous_worker_hash)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        central
            .authenticate_node("mx2", &replacement_hash)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        std::fs::metadata(worker_file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    pg.execute(
        "UPDATE noisefence.cluster_nodes SET last_seen=42 WHERE node='mx2'",
        &[],
    )
    .await
    .unwrap();
    assert!(
        configs[0]
            .data_dir
            .join("ha-recovery-budget-hold")
            .is_file()
    );
    assert!(
        pg.query_one(
            "SELECT disabled FROM noisefence.users WHERE username='old-admin'",
            &[]
        )
        .await
        .unwrap()
        .get::<_, bool>(0)
    );
    let username = report["access"]["username"].as_str().unwrap();
    pg.execute(
        "INSERT INTO noisefence.sessions VALUES(repeat('a',64),$1,'csrf',9999999999,true)",
        &[&username],
    )
    .await
    .unwrap();
    let retry = if native {
        let output = command(&plan_path).await;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    } else {
        central
            .prepare_recovered_management(&configs, &op, &credentials)
            .await
            .unwrap()
    };
    assert_eq!(retry["access"]["access_changed"], false);
    assert_eq!(retry["policy"], report["policy"]);
    assert_eq!(retry["worker_access"], report["worker_access"]);
    let worker = pg
        .query_one(
            "SELECT version,last_seen FROM noisefence.cluster_nodes WHERE node='mx2'",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(worker.get::<_, i64>(0), 1);
    assert_eq!(worker.get::<_, i64>(1), 42);
    if native {
        // Old configured key cannot pass, even though the replacement exists centrally.
        let missing = command_mode(&plan_path, true).await;
        assert!(!missing.status.success());
        assert!(
            String::from_utf8_lossy(&missing.stderr)
                .contains("Worker credential installation does not match")
        );
        noisefence::cluster::protocol::private_write(
            &installed_worker_file,
            replacement.as_bytes(),
        )
        .unwrap();
        // Fault after writing the receipt must roll back the receipt and audit together.
        pg.batch_execute("CREATE FUNCTION noisefence.reject_install_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='verify_recovery_worker_installation' THEN RAISE EXCEPTION 'synthetic installation failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_install_audit BEFORE INSERT ON noisefence.audit FOR EACH ROW EXECUTE FUNCTION noisefence.reject_install_audit();").await.unwrap();
        assert!(!command_mode(&plan_path, true).await.status.success());
        assert!(
            !pg.query_one(
                "SELECT report ? 'worker_installation_recoveries' FROM noisefence.migration_state",
                &[]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
        );
        pg.batch_execute("DROP TRIGGER reject_install_audit ON noisefence.audit; DROP FUNCTION noisefence.reject_install_audit();").await.unwrap();
        let installed = command_mode(&plan_path, true).await;
        assert!(
            installed.status.success(),
            "{}",
            String::from_utf8_lossy(&installed.stderr)
        );
        let installed: serde_json::Value = serde_json::from_slice(&installed.stdout).unwrap();
        assert_eq!(
            installed["worker_installation"]["worker_credentials_verified"],
            true
        );
        assert_eq!(
            installed["worker_access"]["worker_installation_required"],
            false
        );
        assert_eq!(installed["central_management_recovery_required"], true);
        assert_eq!(installed["status"], "prepared_not_activated");
        assert!(!installed.to_string().contains(replacement));
        let repeated = command_mode(&plan_path, true).await;
        assert!(repeated.status.success());
        let repeated: serde_json::Value = serde_json::from_slice(&repeated.stdout).unwrap();
        assert_eq!(
            repeated["worker_installation"],
            installed["worker_installation"]
        );
        assert_eq!(pg.query_one("SELECT count(*) FROM noisefence.audit WHERE action='verify_recovery_worker_installation'",&[]).await.unwrap().get::<_,i64>(0),1);
        noisefence::cluster::protocol::private_write(
            &installed_worker_file,
            previous_worker_token.as_bytes(),
        )
        .unwrap();
        assert!(!command_mode(&plan_path, true).await.status.success());
        assert_eq!(
            std::fs::read_to_string(&installed_worker_file).unwrap(),
            previous_worker_token
        );
        noisefence::cluster::protocol::private_write(
            &installed_worker_file,
            replacement.as_bytes(),
        )
        .unwrap();
        std::fs::set_permissions(
            &installed_worker_file,
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(!command_mode(&plan_path, true).await.status.success());
        std::fs::set_permissions(
            &installed_worker_file,
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    // Never undo later revocation or silently accept a different token on retry.
    pg.execute(
        "UPDATE noisefence.cluster_nodes SET enabled=false WHERE node='mx2'",
        &[],
    )
    .await
    .unwrap();
    assert!(
        central
            .prepare_recovered_management(&configs, &op, &credentials)
            .await
            .is_err()
    );
    assert!(
        !pg.query_one(
            "SELECT enabled FROM noisefence.cluster_nodes WHERE node='mx2'",
            &[]
        )
        .await
        .unwrap()
        .get::<_, bool>(0)
    );
    pg.execute(
        "UPDATE noisefence.cluster_nodes SET enabled=true,token_hash=$1 WHERE node='mx2'",
        &[&previous_worker_hash],
    )
    .await
    .unwrap();
    assert!(
        central
            .prepare_recovered_management(&configs, &op, &credentials)
            .await
            .is_err()
    );
    assert_eq!(
        pg.query_one(
            "SELECT token_hash FROM noisefence.cluster_nodes WHERE node='mx2'",
            &[]
        )
        .await
        .unwrap()
        .get::<_, String>(0),
        previous_worker_hash
    );
    pg.execute(
        "UPDATE noisefence.cluster_nodes SET token_hash=$1 WHERE node='mx2'",
        &[&replacement_hash],
    )
    .await
    .unwrap();
    assert_eq!(
        pg.query_one("SELECT count(*) FROM noisefence.sessions", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    for config in &configs {
        assert!(
            noisefence::central::bootstrap::open(
                config,
                noisefence::central::bootstrap::Purpose::Runtime
            )
            .is_err()
        );
        let guard = noisefence::central::import::SourceLocks::acquire(&config.data_dir).unwrap();
        guard.verify().unwrap();
    }
    if native {
        use noisefence::central::bootstrap::{Purpose, open};
        let console_config = noisefence::config::Config::load(&configs_paths[0]).unwrap();
        let queue_receipt = json!({"operation":op,"owner":"mx1","central_management_recovery_required":true,"smtp_started":false});
        noisefence::cluster::protocol::private_write(
            &configs[0].data_dir.join("ha-recovery.json"),
            &serde_json::to_vec(&queue_receipt).unwrap(),
        )
        .unwrap();
        refused_start(&configs_paths[0], "serve-console").await;
        // PostgreSQL audit failure leaves neither side authorized.
        pg.batch_execute("CREATE FUNCTION noisefence.reject_console_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='authorize_recovery_console' THEN RAISE EXCEPTION 'synthetic console failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_console_audit BEFORE INSERT ON noisefence.audit FOR EACH ROW EXECUTE FUNCTION noisefence.reject_console_audit();").await.unwrap();
        assert!(!activate(&plan_path).await.status.success());
        assert!(
            !pg.query_one(
                "SELECT report ? 'console_recoveries' FROM noisefence.migration_state",
                &[]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
        );
        pg.batch_execute("DROP TRIGGER reject_console_audit ON noisefence.audit; DROP FUNCTION noisefence.reject_console_audit();").await.unwrap();
        // Simulate a failure between the PostgreSQL and local durable commits.
        dbs[0].execute_batch("CREATE TRIGGER reject_console_activation BEFORE INSERT ON cluster_state WHEN NEW.key='management_console_activation' BEGIN SELECT RAISE(ABORT,'synthetic local publication failure'); END;").unwrap();
        assert!(!activate(&plan_path).await.status.success());
        assert!(
            pg.query_one(
                "SELECT report ? 'console_recoveries' FROM noisefence.migration_state",
                &[]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
        );
        assert!(open(&console_config, Purpose::Console).is_err());
        refused_start(&configs_paths[0], "serve-console").await;
        dbs[0]
            .execute_batch("DROP TRIGGER reject_console_activation")
            .unwrap();
        let authorized = activate(&plan_path).await;
        assert!(
            authorized.status.success(),
            "{}",
            String::from_utf8_lossy(&authorized.stderr)
        );
        let authorized: serde_json::Value = serde_json::from_slice(&authorized.stdout).unwrap();
        assert_eq!(authorized["status"], "console_authorized_not_started");
        assert_eq!(authorized["console_activation"]["console_only"], true);
        assert!(open(&console_config, Purpose::Runtime).is_err());
        drop(open(&console_config, Purpose::Console).unwrap());
        refused_start(&configs_paths[0], "serve").await;
        let repeated = activate(&plan_path).await;
        assert!(repeated.status.success());
        let repeated: serde_json::Value = serde_json::from_slice(&repeated.stdout).unwrap();
        assert_eq!(
            repeated["console_activation"],
            authorized["console_activation"]
        );
        assert_eq!(
            pg.query_one(
                "SELECT count(*) FROM noisefence.audit WHERE action='authorize_recovery_console'",
                &[]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
            1
        );
        let mut changed = console_config.clone();
        changed.hostname = "different.example.test".into();
        assert!(open(&changed, Purpose::Console).is_err());
        central
            .require_recovered_console_activation(&console_config)
            .await
            .unwrap();
        let verified = noisefence::central::recovery::activation::check(&console_config)
            .await
            .unwrap();
        assert_eq!(verified["receipt"], authorized["console_activation"]);
        assert_eq!(verified["state_changed"], false);
        assert_eq!(verified["smtp_enabled"], false);
        let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_noisefence"))
            .arg("--config")
            .arg(&configs_paths[0])
            .arg("management-recovery-check-console")
            .output()
            .await
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let output: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(output, verified);
        assert!(
            noisefence::central::recovery::activation::check(&changed)
                .await
                .is_err()
        );
        // A copied local receipt is insufficient if its central counterpart is missing.
        let saved: serde_json::Value = pg
            .query_one("SELECT report FROM noisefence.migration_state", &[])
            .await
            .unwrap()
            .get(0);
        pg.execute(
            "UPDATE noisefence.migration_state SET report=report-'console_recoveries'",
            &[],
        )
        .await
        .unwrap();
        assert!(
            central
                .require_recovered_console_activation(&console_config)
                .await
                .is_err()
        );
        assert!(
            noisefence::central::recovery::activation::check(&console_config)
                .await
                .is_err()
        );
        refused_start(&configs_paths[0], "serve-console").await;
        pg.execute("UPDATE noisefence.migration_state SET report=$1", &[&saved])
            .await
            .unwrap();
        let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_noisefence"))
            .arg("--config")
            .arg(&configs_paths[0])
            .arg("serve-console")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let http = reqwest::Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_millis(500))
            .build()
            .unwrap();
        let url = format!("http://{}", console_config.web.listen);
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                let output = child.wait_with_output().await.unwrap();
                panic!(
                    "Console exited {status}: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            if let Ok(response) = http.get(format!("{url}/healthz")).send().await
                && response.status().is_success()
            {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "Recovered console readiness timed out"
            );
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        let admin: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&credentials).unwrap()).unwrap();
        let login = http
            .post(format!("{url}/api/v1/login"))
            // Password verification is deliberately expensive. Keep the short
            // readiness probe above, but allow authentication on shared CI CPUs.
            .timeout(std::time::Duration::from_secs(10))
            .header("Origin", &console_config.web.public_origin)
            .json(&json!({"username":admin["username"],"password":admin["password"]}))
            .send()
            .await
            .unwrap();
        assert!(
            login.status().is_success(),
            "Recovered console login failed: {}",
            login.status()
        );
        // Checkpoint authorization is read-only and works while the console holds
        // its daemon lock; it must not stop the running listener.
        assert_eq!(
            noisefence::central::recovery::activation::check(&console_config)
                .await
                .unwrap(),
            verified
        );
        assert!(child.try_wait().unwrap().is_none());
        child.kill().await.unwrap();
        child.wait().await.unwrap();
        assert!(open(&console_config, Purpose::Runtime).is_err());
        // The original worker cannot resume against its former console.
        assert!(!release_workers(&plan_path).await.status.success());
        let mut worker_config = noisefence::config::Config::load(&configs_paths[1]).unwrap();
        let cluster = worker_config.cluster.as_mut().unwrap();
        cluster.coordinator_url = Some(console_config.web.public_origin.clone());
        cluster.allow_loopback_http = true;
        std::fs::write(&configs_paths[1], toml::to_string(&worker_config).unwrap()).unwrap();
        assert!(open(&worker_config, Purpose::Runtime).is_err());
        pg.batch_execute("CREATE FUNCTION noisefence.reject_worker_release_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='authorize_recovery_workers' THEN RAISE EXCEPTION 'synthetic worker release failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_worker_release_audit BEFORE INSERT ON noisefence.audit FOR EACH ROW EXECUTE FUNCTION noisefence.reject_worker_release_audit();").await.unwrap();
        assert!(!release_workers(&plan_path).await.status.success());
        assert!(open(&worker_config, Purpose::Runtime).is_err());
        assert_eq!(
            pg.query_one(
                "SELECT count(*) FROM noisefence.audit WHERE action='authorize_recovery_workers'",
                &[]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
            0
        );
        pg.batch_execute("DROP TRIGGER reject_worker_release_audit ON noisefence.audit; DROP FUNCTION noisefence.reject_worker_release_audit();").await.unwrap();
        // Local publication may fail after PostgreSQL commits. The worker stays fenced.
        dbs[1].execute_batch("CREATE TRIGGER reject_worker_release BEFORE INSERT ON cluster_state WHEN NEW.key='management_worker_release' BEGIN SELECT RAISE(ABORT,'synthetic release failure'); END;").unwrap();
        assert!(!release_workers(&plan_path).await.status.success());
        assert!(open(&worker_config, Purpose::Runtime).is_err());
        assert_eq!(
            pg.query_one(
                "SELECT count(*) FROM noisefence.audit WHERE action='authorize_recovery_workers'",
                &[]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
            1
        );
        dbs[1]
            .execute_batch("DROP TRIGGER reject_worker_release")
            .unwrap();
        let result = release_workers(&plan_path).await;
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(open(&worker_config, Purpose::Runtime).is_ok());
        let result = release_workers(&plan_path).await;
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(
            pg.query_one(
                "SELECT count(*) FROM noisefence.audit WHERE action='authorize_recovery_workers'",
                &[]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
            1
        );
        let worker_key = worker_config
            .cluster
            .as_ref()
            .unwrap()
            .credential_file
            .as_ref()
            .unwrap();
        let installed_key = std::fs::read(worker_key).unwrap();
        std::fs::write(worker_key, "0".repeat(64)).unwrap();
        assert!(open(&worker_config, Purpose::Runtime).is_err());
        assert!(!renew_worker_keys(&plan_path).await.status.success());
        let rotated_hash = noisefence::message::digest("0".repeat(64).as_bytes());
        pg.execute(
            "UPDATE noisefence.cluster_nodes SET token_hash=$1,version=version+1 WHERE node='mx2'",
            &[&rotated_hash],
        )
        .await
        .unwrap();
        pg.batch_execute("CREATE FUNCTION noisefence.reject_renewal_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='renew_recovered_worker_keys' THEN RAISE EXCEPTION 'synthetic renewal failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_renewal_audit BEFORE INSERT ON noisefence.audit FOR EACH ROW EXECUTE FUNCTION noisefence.reject_renewal_audit();").await.unwrap();
        assert!(!renew_worker_keys(&plan_path).await.status.success());
        assert!(open(&worker_config, Purpose::Runtime).is_err());
        pg.batch_execute("DROP TRIGGER reject_renewal_audit ON noisefence.audit; DROP FUNCTION noisefence.reject_renewal_audit();").await.unwrap();
        dbs[1].execute_batch("CREATE TRIGGER reject_key_renewal BEFORE INSERT ON cluster_state WHEN NEW.key='management_worker_key_renewal' BEGIN SELECT RAISE(ABORT,'synthetic renewal publication failure'); END;").unwrap();
        assert!(!renew_worker_keys(&plan_path).await.status.success());
        assert!(open(&worker_config, Purpose::Runtime).is_err());
        dbs[1]
            .execute_batch("DROP TRIGGER reject_key_renewal")
            .unwrap();
        for _ in 0..2 {
            let renewed = renew_worker_keys(&plan_path).await;
            assert!(
                renewed.status.success(),
                "{}",
                String::from_utf8_lossy(&renewed.stderr)
            );
            assert!(open(&worker_config, Purpose::Runtime).is_ok());
        }
        assert_eq!(
            pg.query_one(
                "SELECT count(*) FROM noisefence.audit WHERE action='renew_recovered_worker_keys'",
                &[]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
            1
        );
        pg.execute(
            "UPDATE noisefence.cluster_nodes SET enabled=false WHERE node='mx2'",
            &[],
        )
        .await
        .unwrap();
        assert!(!renew_worker_keys(&plan_path).await.status.success());
        pg.execute(
            "UPDATE noisefence.cluster_nodes SET enabled=true WHERE node='mx2'",
            &[],
        )
        .await
        .unwrap();
        std::fs::write(worker_key, &installed_key).unwrap();
        assert!(open(&worker_config, Purpose::Runtime).is_err());
        assert!(!renew_worker_keys(&plan_path).await.status.success());
        std::fs::write(worker_key, "0".repeat(64)).unwrap();
        assert!(open(&worker_config, Purpose::Runtime).is_ok());
        worker_config.cluster.as_mut().unwrap().coordinator_url =
            Some("https://old.example.test".into());
        assert!(open(&worker_config, Purpose::Runtime).is_err());
        std::fs::write(&configs_paths[1], toml::to_string(&worker_config).unwrap()).unwrap();
        assert!(!renew_worker_keys(&plan_path).await.status.success());
        assert!(open(&console_config, Purpose::Runtime).is_err());
        // A second recovery archives only completed evidence and never replaces the queue.
        assert!(!attach_workers(&plan_path).await.status.success());
        let next_op = uuid::Uuid::new_v4().to_string();
        let mut next_plan = plan.clone();
        next_plan["operation"] = json!(next_op);
        let next_credentials = private
            .path()
            .canonicalize()
            .unwrap()
            .join("second-admin.json");
        next_plan["credentials_file"] = json!(next_credentials);
        noisefence::cluster::protocol::private_write(
            &plan_path,
            &serde_json::to_vec(&next_plan).unwrap(),
        )
        .unwrap();
        dbs[0].execute_batch("CREATE TRIGGER reject_console_refence BEFORE INSERT ON cluster_state WHEN NEW.key='management_recovery_required' BEGIN SELECT RAISE(ABORT,'synthetic console refence failure'); END;").unwrap();
        let tx = dbs[0].transaction().unwrap();
        assert!(
            noisefence::central::recovery::console::begin_queue_recovery(&tx, &next_op).is_err()
        );
        tx.rollback().unwrap();
        assert_eq!(
            dbs[0]
                .query_row(
                    "SELECT count(*) FROM cluster_state WHERE key=?1",
                    [format!("management_console_history_{op}")],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
        assert!(open(&console_config, Purpose::Console).is_ok());
        dbs[0]
            .execute_batch("DROP TRIGGER reject_console_refence")
            .unwrap();
        let tx = dbs[0].transaction().unwrap();
        noisefence::central::recovery::console::begin_queue_recovery(&tx, &next_op).unwrap();
        tx.commit().unwrap();
        let tx = dbs[0].transaction().unwrap();
        noisefence::central::recovery::console::begin_queue_recovery(&tx, &next_op).unwrap();
        assert!(noisefence::central::recovery::console::begin_queue_recovery(&tx, &op).is_err());
        assert!(
            noisefence::central::recovery::console::begin_queue_recovery(
                &tx,
                &uuid::Uuid::new_v4().to_string()
            )
            .is_err()
        );
        tx.commit().unwrap();
        assert!(open(&console_config, Purpose::Console).is_err());
        noisefence::cluster::protocol::private_write(&configs[0].data_dir.join("ha-recovery.json"), &serde_json::to_vec(&json!({"operation":next_op,"owner":"mx1","central_management_recovery_required":true,"smtp_started":false})).unwrap()).unwrap();
        dbs[1]
            .execute(
                "UPDATE deliveries SET attempts=attempts+1 WHERE address='bob@example.test'",
                [],
            )
            .unwrap();
        let status_before = serde_json::to_value(outbox::status(&dbs[1]).unwrap()).unwrap();
        let pending_before = outbox::pending(&dbs[1], 12).unwrap();
        assert!(!pending_before.is_empty());
        let selected_before = Selection::read(&dbs[1]).unwrap().unwrap();
        let old_replay: String = dbs[1]
            .query_row(
                "SELECT value FROM cluster_state WHERE key='management_recovery_outbox'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let deliveries_before = dbs[1]
            .prepare("SELECT message_id,address,status FROM deliveries ORDER BY message_id,address")
            .unwrap()
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        let body_path = configs[1]
            .data_dir
            .join("spool")
            .join(format!("{}.eml", deliveries_before[0].0));
        let body_before = std::fs::read(&body_path).unwrap();
        // Failure after archiving must roll back the archive, removals and new fence together.
        dbs[1].execute_batch("CREATE TRIGGER reject_second_attach BEFORE INSERT ON cluster_state WHEN NEW.key='management_worker_recovery' BEGIN SELECT RAISE(ABORT,'synthetic second attachment failure'); END;").unwrap();
        assert!(!attach_workers(&plan_path).await.status.success());
        assert_eq!(
            dbs[1]
                .query_row(
                    "SELECT count(*) FROM cluster_state WHERE key=?1",
                    [format!("management_worker_history_{op}")],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
        assert_eq!(
            dbs[1]
                .query_row(
                    "SELECT value FROM cluster_state WHERE key='management_recovery_outbox'",
                    [],
                    |r| r.get::<_, String>(0)
                )
                .unwrap(),
            old_replay
        );
        dbs[1]
            .execute_batch("DROP TRIGGER reject_second_attach")
            .unwrap();
        let attached = attach_workers(&plan_path).await;
        assert!(
            attached.status.success(),
            "{}",
            String::from_utf8_lossy(&attached.stderr)
        );
        let archive: String = dbs[1]
            .query_row(
                "SELECT value FROM cluster_state WHERE key=?1",
                [format!("management_worker_history_{op}")],
                |r| r.get(0),
            )
            .unwrap();
        let archive: serde_json::Value = serde_json::from_str(&archive).unwrap();
        assert_eq!(archive["next_operation"], next_op);
        assert_eq!(
            archive["replay"],
            serde_json::from_str::<serde_json::Value>(&old_replay).unwrap()
        );
        assert!(!archive["key_renewal"].is_null());
        assert_eq!(
            serde_json::to_value(outbox::status(&dbs[1]).unwrap()).unwrap(),
            status_before
        );
        assert_eq!(outbox::pending(&dbs[1], 12).unwrap(), pending_before);
        assert_eq!(
            Selection::read(&dbs[1]).unwrap().as_ref(),
            Some(&selected_before)
        );
        assert_eq!(std::fs::read(body_path).unwrap(), body_before);
        let deliveries_after = dbs[1]
            .prepare("SELECT message_id,address,status FROM deliveries ORDER BY message_id,address")
            .unwrap()
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(deliveries_after, deliveries_before);
        assert!(open(&worker_config, Purpose::Runtime).is_err());
        let prepared = command(&plan_path).await;
        assert!(
            prepared.status.success(),
            "{}",
            String::from_utf8_lossy(&prepared.stderr)
        );
        let replay: String = dbs[1]
            .query_row(
                "SELECT value FROM cluster_state WHERE key='management_recovery_outbox'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let replay: serde_json::Value = serde_json::from_str(&replay).unwrap();
        assert_eq!(replay["operation"], next_op);
        assert!(
            replay["first_generation"].as_i64().unwrap()
                > status_before["sequence"].as_i64().unwrap()
        );
        let attached = attach_workers(&plan_path).await;
        assert!(
            attached.status.success(),
            "{}",
            String::from_utf8_lossy(&attached.stderr)
        );
        let prepared = command(&plan_path).await;
        assert!(
            prepared.status.success(),
            "{}",
            String::from_utf8_lossy(&prepared.stderr)
        );
        let second_keys: serde_json::Value = serde_json::from_slice(
            &std::fs::read(private.path().join("second-admin.json.workers.json")).unwrap(),
        )
        .unwrap();
        let second_key = second_keys["workers"]["mx2"]["token"].as_str().unwrap();
        let path = worker_config
            .cluster
            .as_ref()
            .unwrap()
            .credential_file
            .as_ref()
            .unwrap();
        noisefence::cluster::protocol::private_write(path, second_key.as_bytes()).unwrap();
        worker_config.cluster.as_mut().unwrap().coordinator_url =
            Some(console_config.web.public_origin.clone());
        std::fs::write(&configs_paths[1], toml::to_string(&worker_config).unwrap()).unwrap();
        let activated = activate(&plan_path).await;
        assert!(
            activated.status.success(),
            "{}",
            String::from_utf8_lossy(&activated.stderr)
        );
        let released = release_workers(&plan_path).await;
        assert!(
            released.status.success(),
            "{}",
            String::from_utf8_lossy(&released.stderr)
        );
        assert!(open(&worker_config, Purpose::Runtime).is_ok());
        assert!(open(&console_config, Purpose::Console).is_ok());
        assert!(open(&console_config, Purpose::Runtime).is_err());
        assert_eq!(
            pg.query_one(
                "SELECT count(*) FROM noisefence.audit WHERE action='authorize_recovery_workers'",
                &[]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
            2
        );
    }
    // Later damage must be noticed even after every history outbox was acknowledged.
    pg.execute("UPDATE noisefence.policy_head SET activated_at=NULL", &[])
        .await
        .unwrap();
    assert!(
        central
            .prepare_recovered_management(&configs, &op, &credentials)
            .await
            .is_err()
    );
    assert!(
        configs[0]
            .data_dir
            .join("ha-recovery-budget-hold")
            .is_file()
    );
    for (index, db) in dbs.iter().enumerate() {
        assert_eq!(db.query_row("SELECT EXISTS(SELECT 1 FROM cluster_state WHERE key='management_recovery_required')",[],|r|r.get::<_,bool>(0)).unwrap(), !(native && index == 1));
    }
    drop(central);
    drop(pg);
    f.finish().await;
}
