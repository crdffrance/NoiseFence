#[allow(dead_code)]
mod common;
#[path = "common/postgres.rs"]
mod postgres;
use noisefence::{
    central::{
        import::{DeliveryIdentities, SpoolSnapshot},
        outbox,
    },
    engine::Engine,
    store::Store,
};

#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn complete_spool_capture_roundtrips_history_ids_and_all_smtp_attempts() {
    let fixture = postgres::Fixture::new().await;
    let pg = fixture.connect().await;
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path()).unwrap();
    let scan = Engine::new(common::config(root.path()))
        .unwrap()
        .offline(common::MESSAGE);
    let raw = serde_json::to_string(&scan).unwrap();
    let (mut snapshot,ids)=store.run(move |db| {
        for n in 0..13 {
            let id=uuid::Uuid::new_v4().to_string();
            db.execute("INSERT INTO messages(id,created,sender,scan,is_dsn,raw_present) VALUES(?1,?2,?3,?4,?5,0)",rusqlite::params![id,noisefence::now(),if n==0 {""} else {"sender@example.test"},raw,n==0])?;
            for address in ["alice@example.test","hidden@example.test"] {
                // Deliberately nonconsecutive IDs; old public links must survive.
                let delivery=100+n*10+if address.starts_with("alice") {0} else {1};
                db.execute("INSERT INTO deliveries(id,message_id,address,destination,hosts,status,attempts,next_attempt) VALUES(?1,?2,?3,?3,'[]','delivered',7,42)",rusqlite::params![delivery,id,address])?;
                for attempt in 1..=7 {
                    let trace=serde_json::json!({"route":"mx.example.test","peer":"192.0.2.10","started":1,"elapsed_ms":attempt,"outcome":if attempt<7 {"deferred"} else {"delivered"},"truncated":false,"events":[]});
                    db.execute("INSERT INTO delivery_attempts(delivery_id,attempt,trace) VALUES(?1,?2,?3)",rusqlite::params![delivery,attempt,trace.to_string()])?;
                }
                db.execute("INSERT INTO delivery_policy(delivery_id,action,held_until,released_at) VALUES(?1,'deliver',NULL,123)",[delivery])?;
            }
        }
        outbox::initialize(db,"mx1")?;
        db.execute_batch("DELETE FROM management_outbox; DELETE FROM management_log_outbox; PRAGMA user_version=6;")?;
        let mut tx=db.transaction()?;
        let snapshot=SpoolSnapshot::capture(&mut tx)?;
        let ids=DeliveryIdentities::capture(&tx)?;
        tx.commit()?;
        Ok((snapshot,ids))
    }).await.unwrap();
    assert!(snapshot.mirrors.is_empty());
    assert!(snapshot.mirror_logs.is_empty());
    fixture
        .central
        .register_source(&snapshot.identity)
        .await
        .unwrap();
    for events in snapshot.metadata.chunks_mut(12) {
        fixture
            .central
            .ingest(&snapshot.identity, events)
            .await
            .unwrap();
    }
    fixture
        .central
        .import_delivery_identities(&ids)
        .await
        .unwrap();
    for events in snapshot.logs.chunks_mut(12) {
        fixture
            .central
            .ingest_logs(&snapshot.identity, events)
            .await
            .unwrap();
    }
    assert_eq!(
        pg.query_one("SELECT count(*) FROM noisefence.messages", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        13
    );
    assert_eq!(
        pg.query_one("SELECT count(*) FROM noisefence.delivery_logs", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        182
    );
    for event in &snapshot.metadata {
        let record = event.record.as_ref().unwrap();
        let row=pg.query_one("SELECT created,sender,scan,is_dsn,raw_present FROM noisefence.messages WHERE id=$1",&[&record.id]).await.unwrap();
        assert_eq!(row.get::<_, i64>(0), record.created);
        assert_eq!(row.get::<_, String>(1), record.sender);
        assert_eq!(
            row.get::<_, serde_json::Value>(2),
            serde_json::to_value(&record.scan).unwrap()
        );
        assert_eq!(row.get::<_, bool>(3), record.is_dsn);
        assert_eq!(row.get::<_, bool>(4), record.raw_present);
        let rows=pg.query("SELECT id,address,destination,status,attempts,next_attempt,action,released_at FROM noisefence.deliveries WHERE message_id=$1 ORDER BY id",&[&record.id]).await.unwrap();
        assert_eq!(rows.len(), record.deliveries.len());
        for (row, expected) in rows.iter().zip(&record.deliveries) {
            let id = row.get::<_, i64>(0);
            assert!(id >= 100 && id % 10 <= 1);
            assert_eq!(row.get::<_, String>(1), expected.address);
            assert_eq!(row.get::<_, String>(2), expected.destination);
            assert_eq!(row.get::<_, String>(3), expected.status);
            assert_eq!(row.get::<_, i64>(4), i64::from(expected.attempts));
            assert_eq!(row.get::<_, i64>(5), expected.next_attempt);
            assert_eq!(row.get::<_, Option<String>>(6), expected.action);
            assert_eq!(row.get::<_, Option<i64>>(7), expected.released_at);
        }
    }
    for event in &snapshot.logs {
        let expected = event.log.as_ref().unwrap();
        let row=pg.query_one("SELECT l.attempt,l.trace,v.generation,d.address FROM noisefence.delivery_logs l JOIN noisefence.delivery_log_versions v USING(node,epoch,local_id) JOIN noisefence.deliveries d ON d.id=v.delivery_id WHERE l.node=$1 AND l.epoch=$2 AND l.local_id=$3",&[&snapshot.identity.node,&snapshot.identity.epoch,&event.receipt.local_id]).await.unwrap();
        assert_eq!(row.get::<_, i64>(0), i64::from(expected.attempt));
        assert_eq!(
            row.get::<_, serde_json::Value>(1),
            serde_json::to_value(&expected.trace).unwrap()
        );
        assert_eq!(row.get::<_, i64>(2), event.receipt.generation);
        assert_eq!(row.get::<_, String>(3), event.recipient);
    }
    // A lost response and a new client connection cannot duplicate retained logs.
    let restarted = noisefence::central::Central::new(&fixture.settings).unwrap();
    for events in snapshot.metadata.chunks_mut(12) {
        restarted.ingest(&snapshot.identity, events).await.unwrap();
    }
    for events in snapshot.logs.chunks_mut(12) {
        restarted
            .ingest_logs(&snapshot.identity, events)
            .await
            .unwrap();
    }
    assert_eq!(
        pg.query_one("SELECT count(*) FROM noisefence.delivery_logs", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        182
    );
    assert_eq!(
        pg.query_one("SELECT count(*) FROM noisefence.deliveries", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        26
    );
    assert!(
        pg.query_opt(
            "SELECT 1 FROM noisefence.migration_state WHERE activated_at IS NOT NULL",
            &[]
        )
        .await
        .unwrap()
        .is_none()
    );
    drop(restarted);
    fixture.finish().await;
}
