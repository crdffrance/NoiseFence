//! Run explicitly against the disposable local PostgreSQL test database.
mod common;
#[path = "common/postgres.rs"]
mod postgres;
use noisefence::{
    central::{
        Central,
        history::Event,
        outbox::{Entry, Identity},
    },
    cluster::history::{Delivery, Record},
    engine::Engine,
};

fn event(engine: &Engine, id: &str, generation: i64) -> Event {
    Event {
        receipt: Entry {
            id: id.into(),
            generation,
            deleted: false,
        },
        record: Some(Record {
            id: id.into(),
            generation,
            created: 1,
            sender: "sender@example.org".into(),
            scan: engine.offline(common::MESSAGE),
            is_dsn: false,
            raw_present: true,
            deliveries: vec![Delivery {
                address: "alice@example.test".into(),
                destination: "alice@example.test".into(),
                status: "pending".into(),
                attempts: 0,
                next_attempt: 1,
                error: None,
                action: None,
                held_until: None,
                released_at: None,
                filtering: None,
                logs: vec![],
            }],
        }),
    }
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL on 127.0.0.1:15432 and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn durable_ingestion_fences_sources_retries_and_recipient_changes() {
    let fixture = postgres::Fixture::new().await;
    let settings = fixture.settings.clone();
    let central = fixture.central.clone();
    central.health().await.unwrap();
    central.migrate().await.unwrap();
    central.migrate().await.unwrap();
    let mut db = fixture.connect().await;
    let identity = Identity {
        node: uuid::Uuid::new_v4().simple().to_string(),
        epoch: uuid::Uuid::new_v4().to_string(),
    };
    let other = Identity {
        node: uuid::Uuid::new_v4().simple().to_string(),
        epoch: uuid::Uuid::new_v4().to_string(),
    };
    let root = tempfile::tempdir().unwrap();
    let engine = Engine::new(common::config(root.path())).unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    assert!(
        central
            .ingest(&identity, &mut [event(&engine, &id, 1)])
            .await
            .is_err()
    );
    central.register_source(&identity).await.unwrap();
    central.register_source(&identity).await.unwrap();
    central.register_source(&other).await.unwrap();
    let wrong_epoch = Identity {
        node: identity.node.clone(),
        epoch: uuid::Uuid::new_v4().to_string(),
    };
    assert!(central.register_source(&wrong_epoch).await.is_err());
    central
        .ingest(&identity, &mut [event(&engine, &id, 1)])
        .await
        .unwrap();
    // A lost acknowledgement leads to a retry, never duplicate deliveries.
    central
        .ingest(&identity, &mut [event(&engine, &id, 1)])
        .await
        .unwrap();
    let count: i64 = db
        .query_one(
            "SELECT count(*) FROM noisefence.deliveries WHERE message_id=$1",
            &[&id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 1);
    assert!(
        central
            .ingest(&other, &mut [event(&engine, &id, 2)])
            .await
            .is_err()
    );
    assert!(
        central
            .ingest(&wrong_epoch, &mut [event(&engine, &id, 2)])
            .await
            .is_err()
    );
    let mut delivered = event(&engine, &id, 3);
    delivered.record.as_mut().unwrap().deliveries[0].status = "delivered".into();
    central.ingest(&identity, &mut [delivered]).await.unwrap();
    central
        .ingest(&identity, &mut [event(&engine, &id, 2)])
        .await
        .unwrap();
    let status: String = db
        .query_one(
            "SELECT status FROM noisefence.deliveries WHERE message_id=$1",
            &[&id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(status, "delivered");
    // Reject the whole batch if one update attempts to rewrite an accepted recipient.
    let fresh_id = uuid::Uuid::new_v4().to_string();
    let mut changed = event(&engine, &id, 4);
    changed.record.as_mut().unwrap().deliveries[0].destination = "bob@example.test".into();
    assert!(
        central
            .ingest(&identity, &mut [event(&engine, &fresh_id, 5), changed])
            .await
            .is_err()
    );
    assert!(
        db.query_opt(
            "SELECT id FROM noisefence.message_versions WHERE id=$1",
            &[&fresh_id]
        )
        .await
        .unwrap()
        .is_none()
    );
    let generation: i64 = db
        .query_one(
            "SELECT generation FROM noisefence.message_versions WHERE id=$1",
            &[&id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(generation, 3);
    let tombstone = || Event {
        receipt: Entry {
            id: id.clone(),
            generation: 6,
            deleted: true,
        },
        record: None,
    };
    central.ingest(&identity, &mut [tombstone()]).await.unwrap();
    drop(central);
    let reopened = Central::new(&settings).unwrap();
    reopened
        .ingest(&identity, &mut [tombstone()])
        .await
        .unwrap();
    reopened
        .ingest(&identity, &mut [event(&engine, &id, 3)])
        .await
        .unwrap();
    assert!(
        reopened
            .ingest(&identity, &mut [event(&engine, &id, 7)])
            .await
            .is_err()
    );
    assert!(
        db.query_opt("SELECT id FROM noisefence.messages WHERE id=$1", &[&id])
            .await
            .unwrap()
            .is_none()
    );
    let count: i64 = db
        .query_one(
            "SELECT count(*) FROM noisefence.deliveries WHERE message_id=$1",
            &[&id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 0);
    db.execute(
        "UPDATE noisefence.sources SET enabled=false WHERE node=$1",
        &[&identity.node],
    )
    .await
    .unwrap();
    assert!(
        reopened
            .ingest(&identity, &mut [tombstone()])
            .await
            .is_err()
    );
    assert!(reopened.register_source(&identity).await.is_err());
    // A PostgreSQL lock timeout cannot erase local work or prevent a local write.
    let store = noisefence::store::Store::open(root.path()).unwrap();
    let source = store
        .run(|db| {
            noisefence::central::outbox::initialize(db, &uuid::Uuid::new_v4().simple().to_string())
        })
        .await
        .unwrap();
    reopened.register_source(&source).await.unwrap();
    let queued_id = uuid::Uuid::new_v4().to_string();
    let insert_id = queued_id.clone();
    let scan = serde_json::to_string(&engine.offline(common::MESSAGE)).unwrap();
    store.run(move |db| {
        let tx = db.transaction()?;
        tx.execute("INSERT INTO messages(id,created,sender,scan) VALUES(?1,1,'sender@example.org',?2)", rusqlite::params![insert_id, scan])?;
        tx.execute("INSERT INTO deliveries(message_id,address,destination,hosts,next_attempt) VALUES(?1,'alice@example.test','alice@example.test','[]',1)", [&insert_id])?;
        tx.commit()?;
        Ok(())
    }).await.unwrap();
    let blocked = db.transaction().await.unwrap();
    blocked
        .batch_execute("LOCK TABLE noisefence.messages IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let started = std::time::Instant::now();
    assert!(reopened.synchronize_once(&store).await.is_err());
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    let update_id = queued_id.clone();
    store
        .run(move |db| {
            assert_eq!(noisefence::central::outbox::status(db)?.pending, 1);
            db.execute(
                "UPDATE deliveries SET status='delivered' WHERE message_id=?1",
                [&update_id],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    blocked.rollback().await.unwrap();
    assert_eq!(reopened.synchronize_once(&store).await.unwrap(), 1);
    assert_eq!(reopened.synchronize_once(&store).await.unwrap(), 0);
    let status: String = db
        .query_one(
            "SELECT status FROM noisefence.deliveries WHERE message_id=$1",
            &[&queued_id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(status, "delivered");
    // Authorization follows individual recipients, including blind recipients.
    let alice = format!("alice-{}", uuid::Uuid::new_v4());
    let bob = format!("bob-{}", uuid::Uuid::new_v4());
    for name in [&alice, &bob] {
        db.execute(
            "INSERT INTO noisefence.users(username,password) VALUES($1,'synthetic-not-a-login')",
            &[name],
        )
        .await
        .unwrap();
    }
    db.execute(
        "INSERT INTO noisefence.grants VALUES($1,'alice@example.test'),($2,'bob@example.test')",
        &[&alice, &bob],
    )
    .await
    .unwrap();
    let allowed: bool = db.query_one("SELECT EXISTS(SELECT 1 FROM noisefence.console_access a JOIN noisefence.deliveries d ON d.id=a.delivery_id WHERE a.username=$1 AND d.message_id=$2)", &[&alice,&queued_id]).await.unwrap().get(0);
    let hidden: bool = db.query_one("SELECT EXISTS(SELECT 1 FROM noisefence.console_access a JOIN noisefence.deliveries d ON d.id=a.delivery_id WHERE a.username=$1 AND d.message_id=$2)", &[&bob,&queued_id]).await.unwrap().get(0);
    assert!(allowed);
    assert!(!hidden);
    db.execute(
        "UPDATE noisefence.users SET disabled=true WHERE username=$1",
        &[&alice],
    )
    .await
    .unwrap();
    let count: i64 = db
        .query_one(
            "SELECT count(*) FROM noisefence.console_access WHERE username=$1",
            &[&alice],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 0);
    // Password resets between Argon2 verification and session commit are fenced.
    let key = noisefence::mfa::Key::open(root.path()).unwrap();
    let token = "a".repeat(64);
    let csrf = "b".repeat(64);
    let login = |code| noisefence::central::accounts::Login {
        username: &bob,
        verified_password_hash: "synthetic-not-a-login",
        code,
        token_hash: &token,
        csrf: &csrf,
        previous_token_hash: None,
    };
    assert!(reopened.create_session(login(""), &key).await.unwrap());
    let session = reopened.session(&token).await.unwrap().unwrap();
    assert_eq!(session.addresses, vec!["bob@example.test"]);
    db.execute(
        "UPDATE noisefence.users SET password='changed-in-the-meantime' WHERE username=$1",
        &[&bob],
    )
    .await
    .unwrap();
    assert!(!reopened.create_session(login(""), &key).await.unwrap());
    db.execute(
        "UPDATE noisefence.users SET password='synthetic-not-a-login' WHERE username=$1",
        &[&bob],
    )
    .await
    .unwrap();
    let sealed = key.seal(&bob, &noisefence::mfa::secret()).unwrap();
    db.execute("INSERT INTO noisefence.mfa_credentials(username,secret,enabled,pending_until) VALUES($1,$2,true,0)", &[&bob,&sealed]).await.unwrap();
    // Enabling MFA invalidates an unverified session immediately.
    assert!(reopened.session(&token).await.unwrap().is_none());
    let recovery = "c".repeat(32);
    db.execute(
        "INSERT INTO noisefence.mfa_recovery VALUES($1,$2)",
        &[&bob, &noisefence::message::digest(recovery.as_bytes())],
    )
    .await
    .unwrap();
    let before: i32 = db
        .query_one(
            "SELECT attempts FROM noisefence.mfa_attempts WHERE username=$1",
            &[&bob],
        )
        .await
        .unwrap()
        .get(0);
    assert!(
        !reopened
            .create_session(login("incorrect"), &key)
            .await
            .unwrap()
    );
    let after: i32 = db
        .query_one(
            "SELECT attempts FROM noisefence.mfa_attempts WHERE username=$1",
            &[&bob],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(after, before + 1);
    assert!(
        reopened
            .create_session(login(&recovery), &key)
            .await
            .unwrap()
    );
    assert!(reopened.session(&token).await.unwrap().is_some());
    assert!(
        !reopened
            .create_session(login(&recovery), &key)
            .await
            .unwrap()
    );
    reopened.delete_session(&token).await.unwrap();
    assert!(reopened.session(&token).await.unwrap().is_none());
    drop(db);
    fixture.finish().await;
}
