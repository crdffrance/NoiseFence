#[allow(dead_code)]
mod common;
#[path = "common/postgres.rs"]
mod postgres;
use noisefence::{
    central::{logs, outbox},
    delivery_log::{Attempt, Event},
    engine::Engine,
    store::Store,
};

fn trace(detail: &str) -> Attempt {
    Attempt {
        route: "mx.example.test".into(),
        peer: Some("192.0.2.25".into()),
        started: 1,
        elapsed_ms: 42,
        outcome: "deferred".into(),
        truncated: false,
        events: vec![Event {
            phase: "rcpt".into(),
            elapsed_ms: 41,
            code: Some(450),
            enhanced_code: Some("4.2.0".into()),
            response: Some(detail.into()),
            detail: None,
        }],
    }
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL on 127.0.0.1:15432 and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn full_transcripts_are_durable_scoped_bounded_and_cannot_be_resurrected() {
    let fixture = postgres::Fixture::new().await;
    let db = fixture.connect().await;
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path()).unwrap();
    let scan = Engine::new(common::config(root.path()))
        .unwrap()
        .offline(common::MESSAGE);
    let id = uuid::Uuid::new_v4().to_string();
    let insert_id = id.clone();
    let raw = serde_json::to_string(&scan).unwrap();
    store.run(move |db| {
        let tx=db.transaction()?;
        tx.execute("INSERT INTO users(username,password,admin) VALUES('owner','none',1),('alice','none',0)",[])?;
        tx.execute("INSERT INTO grants VALUES('alice','alice@example.test')",[])?;
        tx.execute("INSERT INTO messages(id,created,sender,scan) VALUES(?1,?2,'sender@example.org',?3)",rusqlite::params![insert_id,noisefence::now(),raw])?;
        for recipient in ["alice@example.test","bob@example.test","hidden@example.test"] {
            tx.execute("INSERT INTO deliveries(message_id,address,destination,hosts,next_attempt,error) VALUES(?1,?2,?2,'[]',0,'recipient hidden@example.test unavailable')",rusqlite::params![insert_id,recipient])?;
            let delivery=tx.last_insert_rowid();
            for attempt in 1..=50 {
                tx.execute("INSERT INTO delivery_attempts(delivery_id,attempt,trace) VALUES(?1,?2,?3)",rusqlite::params![delivery,attempt,serde_json::to_string(&trace("hidden@example.test temporarily unavailable"))?])?;
            }
        }
        tx.commit()?;
        Ok(())
    }).await.unwrap();
    let identity = store.run(|db| outbox::initialize(db, "mx1")).await.unwrap();
    assert_eq!(
        store
            .read(|db| Ok(outbox::status(db)?.pending_logs))
            .await
            .unwrap(),
        150
    );
    fixture.central.register_source(&identity).await.unwrap();
    assert!(
        logs::export(&store).await.unwrap().1.is_empty(),
        "logs wait for durable message metadata"
    );
    assert_eq!(
        fixture
            .central
            .synchronize_metadata_once(&store)
            .await
            .unwrap(),
        1
    );
    let (_, mut events) = logs::export(&store).await.unwrap();
    assert_eq!(events.len(), 12);
    let saved = events[0].clone();
    let receipts = fixture
        .central
        .ingest_logs(&identity, &mut events)
        .await
        .unwrap();
    let changed_id = saved.receipt.local_id;
    store
        .run(move |db| {
            db.execute(
                "UPDATE delivery_attempts SET trace=?2 WHERE id=?1",
                rusqlite::params![
                    changed_id,
                    serde_json::to_string(&trace("new response after lost acknowledgement"))?
                ],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(
        logs::acknowledge(&store, identity.clone(), receipts)
            .await
            .unwrap(),
        11
    );
    while fixture.central.synchronize_once(&store).await.unwrap() > 0 {}
    db.execute("INSERT INTO noisefence.users(username,password,admin) VALUES('owner','none',true),('alice','none',false)",&[]).await.unwrap();
    db.execute(
        "INSERT INTO noisefence.grants VALUES('alice','alice@example.test')",
        &[],
    )
    .await
    .unwrap();
    let central_store = store
        .clone()
        .with_management(fixture.central.clone())
        .await
        .unwrap();
    for username in ["owner", "alice"] {
        let local = store
            .diagnostics(username.into(), id.clone())
            .await
            .unwrap()
            .unwrap();
        let central = central_store
            .diagnostics(username.into(), id.clone())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            serde_json::to_value(&central).unwrap(),
            serde_json::to_value(&local).unwrap()
        );
        let count: usize = central.recipients.iter().map(|r| r.logs.len()).sum();
        assert_eq!(count, if username == "owner" { 100 } else { 50 });
        assert_eq!(central.recipients[0].logs_available, 50);
        for recipient in central.recipients {
            let detail = central_store
                .diagnostics_for(username.into(), id.clone(), Some(recipient.delivery_id))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(detail.recipients.len(), 1);
            assert_eq!(detail.recipients[0].logs.len(), 50);
            let json = serde_json::to_string(&detail.recipients[0].logs).unwrap();
            assert!(!json.contains("hidden@example.test"));
        }
    }
    assert!(
        central_store
            .diagnostics_for("alice".into(), id.clone(), Some(2))
            .await
            .unwrap()
            .is_none()
    );
    // Reordered retries preserve the newer response, and cannot retarget a log.
    fixture
        .central
        .ingest_logs(&identity, &mut [saved.clone()])
        .await
        .unwrap();
    let response: String = db
        .query_one(
            "SELECT trace#>>'{events,0,response}' FROM noisefence.delivery_logs WHERE local_id=$1",
            &[&changed_id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(response, "new response after lost acknowledgement");
    let mut foreign = saved.clone();
    foreign.recipient = "bob@example.test".into();
    foreign.receipt.generation += 10000;
    assert!(
        fixture
            .central
            .ingest_logs(&identity, &mut [foreign])
            .await
            .is_err()
    );
    store
        .run(move |db| {
            db.execute("DELETE FROM delivery_attempts WHERE id=?1", [changed_id])?;
            Ok(())
        })
        .await
        .unwrap();
    drop(central_store);
    drop(store);
    let reopened = Store::open(root.path()).unwrap();
    assert_eq!(
        reopened
            .read(|db| Ok(outbox::status(db)?.log_tombstones))
            .await
            .unwrap(),
        1
    );
    while fixture.central.synchronize_once(&reopened).await.unwrap() > 0 {}
    fixture
        .central
        .ingest_logs(&identity, &mut [saved.clone()])
        .await
        .unwrap();
    let mut resurrected = saved.clone();
    resurrected.receipt.generation += 20000;
    assert!(
        fixture
            .central
            .ingest_logs(&identity, &mut [resurrected])
            .await
            .is_err()
    );
    let delete_id = id.clone();
    reopened
        .run(move |db| {
            db.execute("DELETE FROM messages WHERE id=?1", [delete_id])?;
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(
        reopened
            .read(|db| Ok(outbox::status(db)?.pending_logs))
            .await
            .unwrap(),
        0
    );
    while fixture.central.synchronize_once(&reopened).await.unwrap() > 0 {}
    fixture
        .central
        .ingest_logs(&identity, &mut [saved])
        .await
        .unwrap();
    let count: i64 = db
        .query_one("SELECT count(*) FROM noisefence.delivery_logs", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 0);
    assert!(
        fixture
            .central
            .diagnostics("owner", &id, None)
            .await
            .unwrap()
            .is_none()
    );
    drop(db);
    fixture.finish().await;
}
