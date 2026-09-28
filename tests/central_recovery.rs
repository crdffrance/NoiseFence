#[path = "common/postgres.rs"]
mod postgres;
use noisefence::central::{Central, binding::Binding};

#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn persisted_credentials_survive_database_failure_and_exact_retry() {
    use std::os::unix::fs::PermissionsExt;
    let f = postgres::Fixture::new().await;
    let pg = f.connect().await;
    let binding = Binding {
        instance: uuid::Uuid::new_v4().to_string(),
        source_digest: "c".repeat(64),
    };
    pg.execute(
        "INSERT INTO noisefence.migration_state VALUES(1,$1,100,NULL,$2)",
        &[
            &binding.source_digest,
            &serde_json::json!({"instance":binding.instance}),
        ],
    )
    .await
    .unwrap();
    let runtime = Central::new_bound(&f.settings, &binding).unwrap();
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = root.path().canonicalize().unwrap().join("access.json");
    let operation = uuid::Uuid::new_v4().to_string();
    let failure = runtime
        .recover_access_saved(&operation, &path)
        .await
        .unwrap_err();
    assert!(path.exists(), "Credentials were not prepared: {failure:#}");
    let saved = std::fs::read(&path).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&saved).unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        pg.query_one("SELECT count(*) FROM noisefence.users", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    pg.batch_execute("UPDATE noisefence.migration_state SET activated_at=101")
        .await
        .unwrap();
    let report = runtime
        .recover_access_saved(&operation, &path)
        .await
        .unwrap();
    assert_eq!(report["access_changed"], true);
    assert_eq!(report["central_management_recovery_required"], true);
    assert!(
        !report
            .to_string()
            .contains(value["password"].as_str().unwrap())
    );
    assert!(
        !report
            .to_string()
            .contains(value["password_hash"].as_str().unwrap())
    );
    let replay = runtime
        .recover_access_saved(&operation, &path)
        .await
        .unwrap();
    assert_eq!(replay["access_changed"], false);
    assert_eq!(report["username"], replay["username"]);
    assert_eq!(std::fs::read(&path).unwrap(), saved);
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        runtime
            .recover_access_saved(&operation, &path)
            .await
            .is_err()
    );
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        runtime
            .recover_access_saved(&uuid::Uuid::new_v4().to_string(), &path)
            .await
            .is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), saved);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(
        runtime
            .recover_access_saved(&operation, &path)
            .await
            .is_err()
    );
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let link = path.with_file_name("linked.json");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert!(
        runtime
            .recover_access_saved(&operation, &link)
            .await
            .is_err()
    );
    std::fs::write(&path, b"{incomplete").unwrap();
    assert!(
        runtime
            .recover_access_saved(&operation, &path)
            .await
            .is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"{incomplete");
    assert_eq!(
        pg.query_one("SELECT count(*) FROM noisefence.users", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    drop(runtime);
    drop(pg);
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn access_recovery_is_atomic_bound_and_replay_does_not_revoke_new_access() {
    let f = postgres::Fixture::new().await;
    let pg = f.connect().await;
    let binding = Binding {
        instance: uuid::Uuid::new_v4().to_string(),
        source_digest: "a".repeat(64),
    };
    pg.execute(
        "INSERT INTO noisefence.migration_state VALUES(1,$1,100,101,$2)",
        &[
            &binding.source_digest,
            &serde_json::json!({"instance":binding.instance,"original":"preserved"}),
        ],
    )
    .await
    .unwrap();
    let hash = noisefence::api::hash_password("synthetic-recovery-password").unwrap();
    let operation = uuid::Uuid::new_v4().to_string();
    let runtime = Central::new_bound(&f.settings, &binding).unwrap();
    pg.execute("INSERT INTO noisefence.users(username,password,admin,version) VALUES('admin',$1,true,4),('user',$1,false,8)", &[&hash]).await.unwrap();
    let source = noisefence::central::outbox::Identity {
        node: "mx1".into(),
        epoch: uuid::Uuid::new_v4().to_string(),
    };
    runtime.register_source(&source).await.unwrap();
    let versioned = uuid::Uuid::new_v4().to_string();
    pg.execute(
        "UPDATE noisefence.sources SET last_sequence=20 WHERE node=$1",
        &[&source.node],
    )
    .await
    .unwrap();
    pg.execute("INSERT INTO noisefence.message_versions(id,node,epoch,generation,deleted) VALUES($1,$2,$3,50,true)", &[&versioned,&source.node,&source.epoch]).await.unwrap();
    pg.execute("INSERT INTO noisefence.delivery_log_versions(node,epoch,local_id,message_id,generation,deleted) VALUES($1,$2,701,$3,80,true)", &[&source.node,&source.epoch,&versioned]).await.unwrap();
    assert!(
        runtime
            .recovery_replay_floor(&operation, &source)
            .await
            .is_err()
    );
    let command_id = uuid::Uuid::new_v4().to_string();
    pg.execute("INSERT INTO noisefence.queue_commands(id,node,node_epoch,message_id,recipient,command,username,session_hash,actor_version,created,expires) VALUES($1,$2,$3,$4,'alice@example.test','release','admin',repeat('a',64),4,1,9999999999)", &[&command_id,&source.node,&source.epoch,&uuid::Uuid::new_v4().to_string()]).await.unwrap();
    pg.batch_execute("INSERT INTO noisefence.sessions VALUES(repeat('a',64),'admin','csrf',9999999999,true);
        INSERT INTO noisefence.grants VALUES('user','user@example.test');
        INSERT INTO noisefence.mfa_credentials VALUES('admin',decode('1234','hex'),true,0,10);
        INSERT INTO noisefence.invitations(id,token_hash,username,admin,addresses,creator,creator_version,created,expires)
            VALUES('invite','synthetic-token','new-user',false,'[]','admin',4,1,9999999999);")
        .await.unwrap();
    assert!(
        f.central
            .recover_access(&operation, "recovery-test", &hash)
            .await
            .is_err()
    );
    assert!(
        runtime
            .recover_access("bad-id", "recovery-test", &hash)
            .await
            .is_err()
    );
    assert!(
        runtime
            .recover_access(&operation, "admin", &hash)
            .await
            .is_err()
    );
    assert!(
        runtime
            .recover_access(&operation, "recovery-test", "bad-hash")
            .await
            .is_err()
    );
    let login_in_flight = f.connect().await;
    login_in_flight
        .batch_execute(
            "BEGIN; SELECT username FROM noisefence.users WHERE username='admin' FOR UPDATE",
        )
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            runtime.recover_access(&operation, "recovery-test", &hash)
        )
        .await
        .unwrap()
        .is_err()
    );
    login_in_flight.batch_execute("ROLLBACK").await.unwrap();
    drop(login_in_flight);
    // Fault after account/session/invitation changes must roll back everything.
    pg.batch_execute("CREATE FUNCTION noisefence.reject_recovery_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic test failure'; END $$;
        CREATE TRIGGER reject_recovery_audit BEFORE INSERT ON noisefence.audit FOR EACH ROW EXECUTE FUNCTION noisefence.reject_recovery_audit();")
        .await.unwrap();
    assert!(
        runtime
            .recover_access(&operation, "recovery-test", &hash)
            .await
            .is_err()
    );
    let intact: bool = pg
        .query_one(
            "SELECT
        (SELECT count(*)=2 FROM noisefence.users WHERE NOT disabled) AND
        (SELECT count(*)=1 FROM noisefence.sessions) AND
        (SELECT revoked IS NULL FROM noisefence.invitations WHERE id='invite') AND
        (SELECT count(*)=1 FROM noisefence.queue_commands WHERE finished IS NULL) AND
        (SELECT NOT(report ? 'access_recoveries') FROM noisefence.migration_state)",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(intact);
    pg.batch_execute("DROP TRIGGER reject_recovery_audit ON noisefence.audit; DROP FUNCTION noisefence.reject_recovery_audit();").await.unwrap();
    assert!(
        runtime
            .recover_access(&operation, "recovery-test", &hash)
            .await
            .unwrap()
    );
    assert!(runtime.password_hash("admin").await.unwrap().is_none());
    assert!(runtime.session(&"a".repeat(64)).await.unwrap().is_none());
    assert_eq!(
        runtime.password_hash("recovery-test").await.unwrap(),
        Some(hash.clone())
    );
    let revoked: bool = pg
        .query_one(
            "SELECT
        (SELECT count(*)=2 FROM noisefence.users WHERE disabled) AND
        (SELECT count(*)=1 FROM noisefence.users WHERE admin AND NOT disabled) AND
        (SELECT version=5 FROM noisefence.users WHERE username='admin') AND
        (SELECT revoked IS NOT NULL AND version=2 FROM noisefence.invitations WHERE id='invite') AND
        (SELECT count(*)=1 FROM noisefence.mfa_credentials) AND
        (SELECT count(*)=1 FROM noisefence.grants) AND
        (SELECT report->>'original'='preserved' FROM noisefence.migration_state)",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(revoked);
    assert_eq!(
        runtime
            .recovery_replay_floor(&operation, &source)
            .await
            .unwrap(),
        80
    );
    pg.execute(
        "UPDATE noisefence.message_versions SET generation=120 WHERE id=$1",
        &[&versioned],
    )
    .await
    .unwrap();
    assert_eq!(
        runtime
            .recovery_replay_floor(&operation, &source)
            .await
            .unwrap(),
        80
    );
    assert_eq!(
        runtime
            .recovery_replay_bounds(&operation, &source)
            .await
            .unwrap()
            .log_id,
        701
    );
    pg.execute(
        "UPDATE noisefence.delivery_log_versions SET local_id=900 WHERE node=$1",
        &[&source.node],
    )
    .await
    .unwrap();
    assert_eq!(
        runtime
            .recovery_replay_bounds(&operation, &source)
            .await
            .unwrap()
            .log_id,
        701
    );
    let wrong_source = noisefence::central::outbox::Identity {
        node: source.node.clone(),
        epoch: uuid::Uuid::new_v4().to_string(),
    };
    assert!(
        runtime
            .recovery_replay_floor(&operation, &wrong_source)
            .await
            .is_err()
    );
    assert!(runtime.pending_commands(&source).await.unwrap().is_empty());
    assert_eq!(
        pg.query_one(
            "SELECT result FROM noisefence.queue_commands WHERE id=$1",
            &[&command_id]
        )
        .await
        .unwrap()
        .get::<_, String>(0),
        "revoked"
    );
    runtime
        .acknowledge_commands(
            &source,
            &[noisefence::cluster::history::CommandResult {
                id: command_id.clone(),
                result: "done".into(),
            }],
        )
        .await
        .unwrap();
    assert!(pg.query_one("SELECT result='revoked' AND execution_result='done' FROM noisefence.queue_commands WHERE id=$1", &[&command_id]).await.unwrap().get::<_,bool>(0));
    let key_root = tempfile::tempdir().unwrap();
    let key = noisefence::mfa::Key::open(key_root.path()).unwrap();
    let token = "b".repeat(64);
    let csrf = "c".repeat(64);
    for (username, allowed) in [("admin", false), ("recovery-test", true)] {
        assert_eq!(
            runtime
                .create_session(
                    noisefence::central::accounts::Login {
                        username,
                        verified_password_hash: &hash,
                        code: "",
                        token_hash: &token,
                        csrf: &csrf,
                        previous_token_hash: None,
                    },
                    &key
                )
                .await
                .unwrap(),
            allowed
        );
    }
    pg.batch_execute("DELETE FROM noisefence.audit")
        .await
        .unwrap();
    // Durable idempotency does not depend on expiring audit records.
    assert!(
        !runtime
            .recover_access(&operation, "recovery-test", &hash)
            .await
            .unwrap()
    );
    assert!(runtime.session(&"b".repeat(64)).await.unwrap().is_some());
    assert!(
        runtime
            .recover_access(&operation, "recovery-other", &hash)
            .await
            .is_err()
    );
    let different_hash = noisefence::api::hash_password("another-synthetic-password").unwrap();
    assert!(
        runtime
            .recover_access(&operation, "recovery-test", &different_hash)
            .await
            .is_err()
    );
    assert!(
        runtime
            .recover_access(&uuid::Uuid::new_v4().to_string(), "recovery-test", &hash)
            .await
            .is_err()
    );
    assert!(runtime.session(&"b".repeat(64)).await.unwrap().is_some());
    pg.execute(
        "UPDATE noisefence.migration_state SET activated_at=NULL",
        &[],
    )
    .await
    .unwrap();
    assert!(
        runtime
            .recover_access(&operation, "recovery-test", &hash)
            .await
            .is_err()
    );
    drop(runtime);
    drop(pg);
    f.finish().await;
}
