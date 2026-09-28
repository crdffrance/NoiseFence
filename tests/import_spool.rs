#[allow(dead_code)]
mod common;
use noisefence::{
    central::{import::SpoolSnapshot, outbox},
    engine::Engine,
    store::Store,
};

#[tokio::test]
async fn capture_includes_acknowledged_history_all_transcripts_and_explicit_mirrors() {
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path()).unwrap();
    let scan = Engine::new(common::config(root.path()))
        .unwrap()
        .offline(common::MESSAGE);
    let raw = serde_json::to_string(&scan).unwrap();
    let owned = uuid::Uuid::new_v4().to_string();
    let mirror = uuid::Uuid::new_v4().to_string();
    let deleted = uuid::Uuid::new_v4().to_string();
    let (own, copy, gone) = (owned.clone(), mirror.clone(), deleted.clone());
    let identity=store.run(move |db| {
        for id in [&own,&copy] {
            db.execute("INSERT INTO messages(id,created,sender,scan,raw_present) VALUES(?1,?2,'sender@example.test',?3,0)",rusqlite::params![id,noisefence::now(),raw])?;
            db.execute("INSERT INTO deliveries(message_id,address,destination,hosts,next_attempt) VALUES(?1,'alice@example.test','alice@example.test','[]',0)",[id])?;
            let delivery=db.last_insert_rowid();
            for attempt in 1..=7 {
                let trace=serde_json::json!({"route":"mx.example.test","peer":null,"started":1,"elapsed_ms":attempt,"outcome":"deferred","truncated":false,"events":[{"phase":"rcpt","elapsed_ms":0,"code":450,"enhanced_code":"4.2.0","response":"private@example.test unavailable","detail":null}]});
                db.execute("INSERT INTO delivery_attempts(delivery_id,attempt,trace) VALUES(?1,?2,?3)",rusqlite::params![delivery,attempt,trace.to_string()])?;
            }
        }
        db.execute("INSERT INTO cluster_origin VALUES(?1,'mx2',?1,123,1,9)",[copy])?;
        let identity=outbox::initialize(db,"mx1")?;
        // Simulate an old importer/consumer having acknowledged all retained rows.
        db.execute_batch("DELETE FROM management_outbox; DELETE FROM management_log_outbox; UPDATE management_journal SET sequence=100; PRAGMA user_version=6;")?;
        db.execute("INSERT INTO management_outbox VALUES(?1,99,1)",[gone])?;
        db.execute("INSERT INTO management_log_outbox VALUES(99,100,?1,'alice@example.test',1)",[own])?;
        Ok(identity)
    }).await.unwrap();
    let (snapshot, sequence) = store
        .run(|db| {
            let mut tx = db.transaction()?;
            let snapshot = SpoolSnapshot::capture(&mut tx)?;
            let sequence = outbox::status(&tx)?.sequence;
            tx.commit()?;
            Ok((snapshot, sequence))
        })
        .await
        .unwrap();
    assert_eq!(snapshot.identity, identity);
    assert_eq!(snapshot.metadata.len(), 2);
    assert_eq!(snapshot.logs.len(), 8);
    assert_eq!(snapshot.mirrors.len(), 1);
    assert_eq!(
        snapshot.mirror_logs.len(),
        7,
        "mirror history must not be capped at five"
    );
    assert_eq!(snapshot.mirrors[0].owner, "mx2");
    assert_eq!(snapshot.mirrors[0].updated, 123);
    assert_eq!(snapshot.mirrors[0].record.id, mirror);
    assert!(
        snapshot.mirrors[0].record.raw_present,
        "remote availability is distinct from a local body"
    );
    assert!(
        snapshot
            .metadata
            .iter()
            .any(|e| e.receipt.id == deleted && e.receipt.deleted && e.receipt.generation == 99)
    );
    assert!(
        snapshot
            .logs
            .iter()
            .any(|e| e.receipt.local_id == 99 && e.receipt.deleted && e.receipt.generation == 100)
    );
    assert_eq!(sequence, 108);
    for log in snapshot
        .logs
        .iter()
        .filter_map(|e| e.log.as_ref())
        .chain(snapshot.mirror_logs.iter().map(|e| &e.log))
    {
        assert!(
            !serde_json::to_string(log)
                .unwrap()
                .contains("private@example.test")
        );
    }
    // Old receipts must not erase changes recorded after capture.
    let receipts = snapshot
        .metadata
        .into_iter()
        .map(|e| e.receipt)
        .collect::<Vec<_>>();
    let id = owned.clone();
    store
        .run(move |db| {
            db.execute("UPDATE messages SET raw_present=1 WHERE id=?1", [id])?;
            assert_eq!(outbox::acknowledge(db, &identity, &receipts)?, 1);
            let current = outbox::pending(db, 12)?;
            assert_eq!(current.len(), 1);
            assert!(current[0].generation > sequence);
            Ok(())
        })
        .await
        .unwrap();
    store
        .run(|db| {
            let before = outbox::status(db)?.sequence;
            let tx = db.transaction()?;
            let mut tx = tx;
            let repeated = SpoolSnapshot::capture(&mut tx)?;
            assert_eq!(repeated.metadata.len(), 1);
            assert!(outbox::status(&tx)?.sequence > before);
            tx.rollback()?;
            assert_eq!(outbox::status(db)?.sequence, before);
            Ok(())
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn failed_capture_rolls_back_reseeding_even_if_caller_commits() {
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path()).unwrap();
    store.run(|db| {
        let identity=outbox::initialize(db,"mx1")?;
        let id=uuid::Uuid::new_v4().to_string();
        db.execute("INSERT INTO messages(id,created,sender,scan) VALUES(?1,1,'sender@example.test','{}')",[&id])?;
        db.execute("INSERT INTO deliveries(message_id,address,destination,hosts,next_attempt) VALUES(?1,'alice@example.test','alice@example.test','[]',0)",[&id])?;
        db.pragma_update(None,"user_version",6)?;
        let before=outbox::status(db)?.sequence;
        let pending=outbox::pending(db,12)?;
        let mut tx=db.transaction()?;
        assert!(SpoolSnapshot::capture(&mut tx).is_err()); // malformed scan, after reseed
        tx.commit()?;
        assert_eq!(outbox::status(db)?.sequence,before);
        assert_eq!(outbox::pending(db,12)?,pending);
        assert_eq!(outbox::identity(db)?,identity);
        db.execute("UPDATE messages SET scan=?1",["x".repeat(2097153)])?;
        let mut tx=db.transaction()?;
        assert!(SpoolSnapshot::capture(&mut tx).is_err());
        tx.rollback()?;
        db.pragma_update(None,"user_version",7)?;
        let mut tx=db.transaction()?;
        assert!(SpoolSnapshot::capture(&mut tx).is_err());
        tx.rollback()?;
        Ok(())
    }).await.unwrap();
}

#[tokio::test]
async fn seeded_verification_preserves_generations_and_rejects_missing_owner_entries() {
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path()).unwrap();
    let raw = serde_json::to_string(
        &Engine::new(common::config(root.path()))
            .unwrap()
            .offline(common::MESSAGE),
    )
    .unwrap();
    store.run(move |db| {
        outbox::initialize(db, "mx1")?;
        let id = uuid::Uuid::new_v4().to_string();
        db.execute("INSERT INTO messages(id,created,sender,scan) VALUES(?1,1,'sender@example.test',?2)", rusqlite::params![id,raw])?;
        db.execute("INSERT INTO deliveries(message_id,address,destination,hosts,next_attempt) VALUES(?1,'alice@example.test','alice@example.test','[]',0)", [&id])?;
        db.pragma_update(None,"user_version",6)?;
        let mut tx = db.transaction()?;
        let initial = SpoolSnapshot::capture(&mut tx)?;
        let sequence = outbox::status(&tx)?.sequence;
        let verified = SpoolSnapshot::read_seeded(&tx)?;
        assert_eq!(serde_json::to_value(&initial.metadata)?,serde_json::to_value(&verified.metadata)?);
        assert_eq!(outbox::status(&tx)?.sequence,sequence);
        tx.execute("DELETE FROM management_outbox WHERE message_id=?1",[&id])?;
        assert!(SpoolSnapshot::read_seeded(&tx).is_err());
        assert_eq!(outbox::status(&tx)?.sequence,sequence);
        tx.rollback()?;
        Ok(())
    }).await.unwrap();
}

#[tokio::test]
async fn legacy_dsn_capture_preserves_identity_and_refuses_non_notification_envelopes() {
    use noisefence::central::import::DeliveryIdentities;
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path()).unwrap();
    store.run(|db| {
        let scan=serde_json::to_string(&noisefence::engine::Scan{complete:true,subject:"Delivery failure".into(),model:"dsn".into(),..Default::default()})?;
        db.execute("INSERT INTO messages(id,created,sender,scan,is_dsn) VALUES('dsn-7',?1,'',?2,1)",rusqlite::params![noisefence::now(),scan])?;
        db.execute_batch("INSERT INTO deliveries(id,message_id,address,destination,hosts,next_attempt) VALUES(99,'dsn-7','alice@example.test','alice@example.test','[]',0); PRAGMA user_version=6;")?;
        outbox::initialize(db,"mx1")?;
        let mut tx=db.transaction()?;
        DeliveryIdentities::capture(&tx)?;
        let mut snapshot=SpoolSnapshot::capture(&mut tx)?;
        assert_eq!(snapshot.metadata[0].receipt.id,"dsn-7");
        let event=&mut snapshot.metadata[0];
        event.validate()?;
        event.record.as_mut().unwrap().is_dsn=false;
        assert!(event.validate().is_err());
        event.record.as_mut().unwrap().is_dsn=true;
        event.record.as_mut().unwrap().sender="sender@example.test".into();
        assert!(event.validate().is_err());
        tx.execute("UPDATE messages SET sender='sender@example.test'",[])?;
        assert!(DeliveryIdentities::capture(&tx).is_err());
        assert!(SpoolSnapshot::capture(&mut tx).is_err());
        tx.execute("UPDATE messages SET sender='',is_dsn=0",[])?;
        assert!(DeliveryIdentities::capture(&tx).is_err());
        assert!(SpoolSnapshot::capture(&mut tx).is_err());
        Ok(())
    }).await.unwrap();
}
