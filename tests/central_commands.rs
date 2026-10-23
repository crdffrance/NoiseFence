#[allow(dead_code)]
mod common;
#[path = "common/postgres.rs"]
mod postgres;
#[allow(dead_code)]
#[path = "common/web_auth.rs"]
mod web_auth;
use axum::http::StatusCode;
use noisefence::{
    central::{commands, outbox},
    engine::Engine,
    store::Store,
};
use serde_json::json;
use web_auth::call;

#[tokio::test]
#[ignore = "requires disposable PostgreSQL on 127.0.0.1:15432 and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn queue_commands_recheck_authority_execute_once_and_recover_lost_receipts() {
    let fixture = postgres::Fixture::new().await;
    let db = fixture.connect().await;
    let root = tempfile::tempdir().unwrap();
    let config = common::config(root.path());
    let store = Store::open(root.path()).unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    let insert_id = id.clone();
    let raw = serde_json::to_string(
        &Engine::new(config.clone())
            .unwrap()
            .offline(common::MESSAGE),
    )
    .unwrap();
    store.run(move |db| {
        let tx=db.transaction()?;
        tx.execute("INSERT INTO messages(id,created,sender,scan) VALUES(?1,?2,'sender@example.org',?3)",rusqlite::params![insert_id,noisefence::now(),raw])?;
        for recipient in ["alice@example.test","bob@example.test"] {
            tx.execute("INSERT INTO deliveries(message_id,address,destination,hosts,next_attempt,status) VALUES(?1,?2,?2,'[]',0,'quarantined')",rusqlite::params![insert_id,recipient])?;
            tx.execute("INSERT INTO delivery_policy(delivery_id,action,held_until) VALUES(?1,'quarantine',?2)",rusqlite::params![tx.last_insert_rowid(),noisefence::now()+3600])?;
        }
        tx.commit()?;Ok(())
    }).await.unwrap();
    let identity = store.run(|db| outbox::initialize(db, "mx1")).await.unwrap();
    fixture.central.register_source(&identity).await.unwrap();
    while fixture.central.synchronize_once(&store).await.unwrap() > 0 {}
    let csrf = "c".repeat(64);
    let alice_token = "a".repeat(64);
    let admin_token = "b".repeat(64);
    let bob_token = "d".repeat(64);
    for (name, token, admin) in [
        ("alice", &alice_token, false),
        ("admin", &admin_token, true),
        ("bob", &bob_token, false),
    ] {
        db.execute("INSERT INTO noisefence.users(username,password,admin) VALUES($1,'synthetic-not-a-login',$2)", &[&name,&admin]).await.unwrap();
        db.execute(
            "INSERT INTO noisefence.sessions(token_hash,username,csrf,expires) VALUES($1,$2,$3,$4)",
            &[
                &noisefence::message::digest(token.as_bytes()),
                &name,
                &csrf,
                &(noisefence::now() + 3600),
            ],
        )
        .await
        .unwrap();
        if !admin {
            db.execute(
                "INSERT INTO noisefence.grants VALUES($1,$2)",
                &[&name, &format!("{name}@example.test")],
            )
            .await
            .unwrap();
        }
    }
    let central_store = store
        .clone()
        .with_management(fixture.central.clone())
        .await
        .unwrap();
    let app = noisefence::api::router(config.clone(), central_store.clone()).unwrap();
    let alice_cookie = format!("noisefence_session={alice_token}");
    let admin_cookie = format!("noisefence_session={admin_token}");
    let route = format!("/messages/{id}/quarantine");
    let (status, _, _) = call(
        &app,
        &config.web.public_origin,
        &route,
        &alice_cookie,
        &csrf,
        Some(json!({"recipient":"bob@example.test","action":"release"})),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, reply, _) = call(
        &app,
        &config.web.public_origin,
        &route,
        &alice_cookie,
        &csrf,
        Some(json!({"recipient":"alice@example.test","action":"release"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(reply["status"], "queued");
    let pending = fixture.central.pending_commands(&identity).await.unwrap();
    assert_eq!(pending.len(), 1);
    let command_id = pending[0].id.clone();
    assert_eq!(
        store
            .read(|db| Ok(db.query_row(
                "SELECT status FROM deliveries WHERE address='alice@example.test'",
                [],
                |r| r.get::<_, String>(0)
            )?))
            .await
            .unwrap(),
        "quarantined"
    );
    let wrong = outbox::Identity {
        node: identity.node.clone(),
        epoch: uuid::Uuid::new_v4().to_string(),
    };
    assert!(
        commands::execute(&store, wrong, pending.clone())
            .await
            .is_err()
    );
    let receipts = commands::execute(&store, identity.clone(), pending.clone())
        .await
        .unwrap();
    assert_eq!(receipts[0].result, "done");
    store
        .run(|db| {
            db.execute(
                "UPDATE deliveries SET next_attempt=123456 WHERE address='alice@example.test'",
                [],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    let duplicate = commands::execute(&store, identity.clone(), pending.clone())
        .await
        .unwrap();
    assert_eq!(duplicate[0].result, "done");
    assert_eq!(
        store
            .read(|db| Ok(db.query_row(
                "SELECT next_attempt FROM deliveries WHERE address='alice@example.test'",
                [],
                |r| r.get::<_, i64>(0)
            )?))
            .await
            .unwrap(),
        123456
    );
    let mut changed = pending.clone();
    changed[0].recipient = "bob@example.test".into();
    assert!(
        commands::execute(&store, identity.clone(), changed)
            .await
            .is_err()
    );
    let binding = command_id.clone();
    store
        .run(move |db| {
            // Pending receipts outlive the normal retention window until central ack.
            db.execute(
                "UPDATE cluster_command_receipts SET created=?2 WHERE id=?1",
                rusqlite::params![binding, noisefence::now() - 31 * 86400],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    commands::execute(&store, identity.clone(), Vec::new())
        .await
        .unwrap();
    assert_eq!(
        commands::pending_receipts(&store, &identity)
            .await
            .unwrap()
            .len(),
        1
    );
    fixture.suspend().await;
    assert!(
        fixture
            .central
            .synchronize_commands_once(&store)
            .await
            .is_err()
    );
    drop(app);
    drop(central_store);
    drop(store);
    drop(db);
    fixture.resume().await;
    let db = fixture.connect().await;
    // Simulate authority expiry during a long disconnection. Keep the actual
    // later execution receipt even after private command details were retained out.
    db.execute(
        "UPDATE noisefence.queue_commands SET result='expired',finished=$2 WHERE id=$1",
        &[&command_id, &(noisefence::now() - 31 * 86400)],
    )
    .await
    .unwrap();
    fixture.central.pending_commands(&identity).await.unwrap();
    let store = Store::open(root.path()).unwrap();
    assert_eq!(
        fixture
            .central
            .synchronize_commands_once(&store)
            .await
            .unwrap(),
        1
    );
    assert!(
        commands::pending_receipts(&store, &identity)
            .await
            .unwrap()
            .is_empty()
    );
    let result: String = db
        .query_one(
            "SELECT execution_result FROM noisefence.command_tombstones WHERE id=$1",
            &[&command_id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(result, "done");
    while fixture.central.synchronize_once(&store).await.unwrap() > 0 {}
    let central_store = store
        .clone()
        .with_management(fixture.central.clone())
        .await
        .unwrap();
    let app = noisefence::api::router(config.clone(), central_store).unwrap();
    let (status, queue, _) = call(
        &app,
        &config.web.public_origin,
        "/admin/queue",
        &admin_cookie,
        &csrf,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(queue.as_array().unwrap().len(), 1);
    let delivery_id = queue[0]["id"].as_i64().unwrap();
    let (status, _, _) = call(
        &app,
        &config.web.public_origin,
        "/admin/queue/retry",
        &admin_cookie,
        &csrf,
        Some(json!({"id":delivery_id})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        fixture
            .central
            .synchronize_commands_once(&store)
            .await
            .unwrap(),
        1
    );
    let count: i64 = store
        .read(|db| {
            Ok(db.query_row(
                "SELECT count(*) FROM audit WHERE action='cluster_release'",
                [],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap();
    assert_eq!(count, 1);
    let bob_session = noisefence::message::digest(bob_token.as_bytes());
    let change = fixture
        .central
        .queue_quarantine(
            "bob",
            &bob_session,
            &id,
            "bob@example.test",
            noisefence::quarantine::Command::Delete,
        )
        .await
        .unwrap();
    let revoked_id = match change {
        noisefence::quarantine::Change::Queued(id) => id,
        _ => panic!("expected queued deletion"),
    };
    db.execute("DELETE FROM noisefence.grants WHERE username='bob'", &[])
        .await
        .unwrap();
    assert_eq!(
        fixture
            .central
            .synchronize_commands_once(&store)
            .await
            .unwrap(),
        0
    );
    let result: String = db
        .query_one(
            "SELECT result FROM noisefence.queue_commands WHERE id=$1",
            &[&revoked_id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(result, "revoked");
    assert_eq!(
        store
            .read(|db| Ok(db.query_row(
                "SELECT status FROM deliveries WHERE address='bob@example.test'",
                [],
                |r| r.get::<_, String>(0)
            )?))
            .await
            .unwrap(),
        "quarantined"
    );
    drop(app);
    drop(db);
    fixture.finish().await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL on 127.0.0.1:15432 and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn quarantine_history_separates_late_receipts_from_current_state_and_rechecks_recipient_access()
 {
    let fixture = postgres::Fixture::new().await;
    let db = fixture.connect().await;
    let root = tempfile::tempdir().unwrap();
    let config = common::config(root.path());
    let store = Store::open(root.path()).unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    let insert_id = id.clone();
    let scan = serde_json::to_string(
        &Engine::new(config.clone())
            .unwrap()
            .offline(common::MESSAGE),
    )
    .unwrap();
    store.run(move |db| {
        let tx=db.transaction()?;
        tx.execute("INSERT INTO messages(id,created,sender,scan) VALUES(?1,?2,'sender@example.org',?3)", rusqlite::params![insert_id,noisefence::now(),scan])?;
        for recipient in ["alice@example.test","bob@example.test"] {
            tx.execute("INSERT INTO deliveries(message_id,address,destination,hosts,next_attempt,status) VALUES(?1,?2,?2,'[]',0,'quarantined')",rusqlite::params![insert_id,recipient])?;
            tx.execute("INSERT INTO delivery_policy(delivery_id,action,held_until) VALUES(?1,'quarantine',?2)",rusqlite::params![tx.last_insert_rowid(),noisefence::now()+3600])?;
        }
        tx.commit()?;Ok(())
    }).await.unwrap();
    let identity = store.run(|db| outbox::initialize(db, "mx1")).await.unwrap();
    fixture.central.register_source(&identity).await.unwrap();
    while fixture.central.synchronize_once(&store).await.unwrap() > 0 {}
    let csrf = uuid::Uuid::new_v4().simple().to_string().repeat(2);
    let alice_token = uuid::Uuid::new_v4().simple().to_string().repeat(2);
    let bob_token = uuid::Uuid::new_v4().simple().to_string().repeat(2);
    for (name, token) in [("alice", &alice_token), ("bob", &bob_token)] {
        let unusable_password = uuid::Uuid::new_v4().to_string();
        db.execute(
            "INSERT INTO noisefence.users(username,password,admin) VALUES($1,$2,false)",
            &[&name, &unusable_password],
        )
        .await
        .unwrap();
        db.execute(
            "INSERT INTO noisefence.sessions(token_hash,username,csrf,expires) VALUES($1,$2,$3,$4)",
            &[
                &noisefence::message::digest(token.as_bytes()),
                &name,
                &csrf,
                &(noisefence::now() + 3600),
            ],
        )
        .await
        .unwrap();
        db.execute(
            "INSERT INTO noisefence.grants VALUES($1,$2)",
            &[&name, &format!("{name}@example.test")],
        )
        .await
        .unwrap();
    }
    let app = noisefence::api::router(
        config.clone(),
        store
            .clone()
            .with_management(fixture.central.clone())
            .await
            .unwrap(),
    )
    .unwrap();
    let alice_cookie = format!("noisefence_session={alice_token}");
    let bob_cookie = format!("noisefence_session={bob_token}");
    let path = format!("/messages/{id}/quarantine?recipient=alice%40example.test");
    let (code, view, _) = call(
        &app,
        &config.web.public_origin,
        &path,
        &alice_cookie,
        &csrf,
        None,
    )
    .await;
    assert_eq!(code, StatusCode::OK, "{view}");
    assert_eq!(view["source"], "central");
    assert_eq!(view["node"], "mx1");
    assert_eq!(view["status"], "quarantined");
    assert!(view["snapshot_at"].as_i64().is_some());
    assert_eq!(view["requests"], json!([]));
    assert_eq!(
        call(
            &app,
            &config.web.public_origin,
            &path,
            &bob_cookie,
            &csrf,
            None
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call(
            &app,
            &config.web.public_origin,
            &format!("/messages/{id}/quarantine"),
            &alice_cookie,
            &csrf,
            Some(json!({"recipient":"alice@example.test","action":"release"}))
        )
        .await
        .0,
        StatusCode::OK
    );
    let (_, pending, _) = call(
        &app,
        &config.web.public_origin,
        &path,
        &alice_cookie,
        &csrf,
        None,
    )
    .await;
    let commands = fixture.central.pending_commands(&identity).await.unwrap();
    assert_eq!(commands.len(), 1);
    let command_id = commands[0].id.clone();
    assert_eq!(pending["pending_command"], command_id);
    assert_eq!(pending["requests"][0]["result"], "pending");
    assert_eq!(pending["requests"][0]["execution_result"], json!(null));
    let receipts = commands::execute(&store, identity.clone(), commands.clone())
        .await
        .unwrap();
    assert_eq!(receipts[0].result, "done");
    assert_eq!(
        commands::execute(&store, identity.clone(), commands)
            .await
            .unwrap()[0]
            .result,
        "done"
    );
    assert_eq!(
        store
            .read(|db| Ok(db.query_row(
                "SELECT COUNT(*) FROM audit WHERE action='quarantine_release'",
                [],
                |r| r.get::<_, i64>(0)
            )?))
            .await
            .unwrap(),
        1
    );
    db.execute(
        "UPDATE noisefence.queue_commands SET result='expired',finished=$2 WHERE id=$1",
        &[&command_id, &noisefence::now()],
    )
    .await
    .unwrap();
    let (_, expired, _) = call(
        &app,
        &config.web.public_origin,
        &path,
        &alice_cookie,
        &csrf,
        None,
    )
    .await;
    assert_eq!(expired["pending_command"], json!(null));
    assert_eq!(expired["requests"][0]["result"], "expired");
    assert_eq!(expired["requests"][0]["execution_result"], json!(null));
    fixture
        .central
        .acknowledge_commands(&identity, &receipts)
        .await
        .unwrap();
    let (_, late, _) = call(
        &app,
        &config.web.public_origin,
        &path,
        &alice_cookie,
        &csrf,
        None,
    )
    .await;
    assert_eq!(
        late["status"], "quarantined",
        "a receipt does not fabricate a new catalog snapshot"
    );
    assert_eq!(late["requests"][0]["result"], "expired");
    assert_eq!(late["requests"][0]["execution_result"], "done");
    assert!(late["requests"][0]["acknowledged_at"].as_i64().is_some());
    assert_eq!(
        late["events"],
        json!([]),
        "local audit entries are not replicated"
    );
    assert!(!late.to_string().contains("bob@example.test"));
    while fixture.central.synchronize_once(&store).await.unwrap() > 0 {}
    let (_, current, _) = call(
        &app,
        &config.web.public_origin,
        &path,
        &alice_cookie,
        &csrf,
        None,
    )
    .await;
    assert_eq!(current["status"], "pending");
    assert!(current["released_at"].as_i64().is_some());
    // More than the bounded response: only this recipient, newest first.
    db.execute("INSERT INTO noisefence.queue_commands(id,node,node_epoch,message_id,recipient,command,username,session_hash,actor_version,created,expires,result,finished) SELECT 'fixture-'||n,node,node_epoch,message_id,recipient,command,username,session_hash,actor_version,created-n,expires-n,'revoked',finished FROM noisefence.queue_commands CROSS JOIN generate_series(1,55) AS n WHERE id=$1",&[&command_id]).await.unwrap();
    db.execute("UPDATE noisefence.queue_commands SET created=$1,username='retained-out-owner' WHERE id='fixture-55'",&[&(noisefence::now()-31*86400)]).await.unwrap();
    let (_, bounded, _) = call(
        &app,
        &config.web.public_origin,
        &path,
        &alice_cookie,
        &csrf,
        None,
    )
    .await;
    assert_eq!(bounded["requests"].as_array().unwrap().len(), 50);
    assert_eq!(bounded["requests_truncated"], true);
    assert!(!bounded.to_string().contains("retained-out-owner"));
    assert_eq!(bounded["requests"][0]["id"], command_id);
    assert!(!bounded.to_string().contains(&alice_token));
    db.execute("DELETE FROM noisefence.grants WHERE username='alice'", &[])
        .await
        .unwrap();
    assert_eq!(
        call(
            &app,
            &config.web.public_origin,
            &path,
            &alice_cookie,
            &csrf,
            None
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    db.execute(
        "UPDATE noisefence.users SET disabled=true WHERE username='bob'",
        &[],
    )
    .await
    .unwrap();
    let bob_path = format!("/messages/{id}/quarantine?recipient=bob%40example.test");
    assert_eq!(
        call(
            &app,
            &config.web.public_origin,
            &bob_path,
            &bob_cookie,
            &csrf,
            None
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    drop(app);
    drop(db);
    fixture.finish().await;
}
