#[allow(dead_code)]
mod common;
#[path = "common/postgres.rs"]
mod postgres;
use noisefence::{
    central::{Central, binding::Binding, outbox, selection::Selection},
    store::Store,
};

#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn fenced_replay_drains_multiple_batches_and_detects_destination_loss_on_retry() {
    let f = postgres::Fixture::new().await;
    let pg = f.connect().await;
    let binding = Binding {
        instance: uuid::Uuid::new_v4().to_string(),
        source_digest: "c".repeat(64),
    };
    pg.execute(
        "INSERT INTO noisefence.migration_state VALUES(1,$1,100,101,$2)",
        &[
            &binding.source_digest,
            &serde_json::json!({"instance":binding.instance}),
        ],
    )
    .await
    .unwrap();
    let central = Central::new_bound(&f.settings, &binding).unwrap();
    let root = tempfile::tempdir().unwrap();
    let path = root.path().canonicalize().unwrap();
    let store = Store::open(&path).unwrap();
    let identity = store.run(|db| outbox::initialize(db, "mx2")).await.unwrap();
    central.register_source(&identity).await.unwrap();
    let retired = uuid::Uuid::new_v4().to_string();
    pg.execute("INSERT INTO noisefence.message_versions(id,node,epoch,generation,deleted) VALUES($1,$2,$3,10,true)",&[&retired,&identity.node,&identity.epoch]).await.unwrap();
    pg.execute("INSERT INTO noisefence.delivery_log_versions(node,epoch,local_id,message_id,generation,deleted) VALUES($1,$2,1000,$3,20,true)",&[&identity.node,&identity.epoch,&retired]).await.unwrap();
    let operation = uuid::Uuid::new_v4().to_string();
    central
        .recover_access(
            &operation,
            "recovery-replay",
            &noisefence::api::hash_password("synthetic-recovery-password").unwrap(),
        )
        .await
        .unwrap();
    let (epoch, participant) = participant_fixture(&path);
    let selection = Selection::new(
        binding,
        identity,
        noisefence::cluster::Role::Worker,
        epoch,
        None,
    )
    .unwrap();
    let scan = noisefence::engine::Engine::new(common::config(&path))
        .unwrap()
        .offline(common::MESSAGE);
    let message = uuid::Uuid::new_v4().to_string();
    let id = message.clone();
    let op = operation.clone();
    store.run(move |db| {
        let tx=db.transaction()?;
        // Synthetic storage fixture: migration itself is covered by the native
        // offline CLI tests. This test exercises recovery transport and parity.
        for (key,value) in [
            ("activation_participant",participant.to_string()),
            ("role","worker".to_owned()),("node_id","mx2".to_owned()),
            ("management_selection",serde_json::to_string(&selection)?),
            ("management_transport",noisefence::central::transport::PROTOCOL.to_owned()),
            ("runtime_history_protocol",noisefence::runtime_history::PROTOCOL.to_owned()),
            ("management_recovery_required",serde_json::json!({"protocol":"noisefence-management-recovery-1","operation":op}).to_string()),
        ] {tx.execute("INSERT OR REPLACE INTO cluster_state VALUES(?1,?2)",rusqlite::params![key,value])?;}
        tx.pragma_update(None,"user_version",7)?;
        tx.execute("INSERT INTO messages(id,created,sender,scan,raw_present) VALUES(?1,?2,'sender@example.test',?3,0)",rusqlite::params![id,noisefence::now(),serde_json::to_string(&scan)?])?;
        tx.execute("INSERT INTO deliveries(message_id,address,destination,hosts,next_attempt,status) VALUES(?1,'alice@example.test','alice@example.test','[]',0,'delivered')",[&id])?;
        let delivery=tx.last_insert_rowid();
        let trace=noisefence::delivery_log::Attempt {route:"mx.example.test".into(),peer:None,started:1,elapsed_ms:1,outcome:"delivered".into(),truncated:false,events:Vec::new()};
        for attempt in 1..=25 {
            tx.execute("INSERT INTO delivery_attempts(delivery_id,attempt,trace) VALUES(?1,?2,?3)",rusqlite::params![delivery,attempt,serde_json::to_string(&trace)?])?;
        }
        tx.commit()?;Ok(())
    }).await.unwrap();
    let held = store.daemon_lock().unwrap();
    assert!(
        central
            .replay_recovered_source(&path, &operation)
            .await
            .is_err()
    );
    drop(held);
    let report = central
        .replay_recovered_source(&path, &operation)
        .await
        .unwrap();
    assert_eq!(report["messages"], 1);
    assert_eq!(report["transcripts"], 25);
    assert!(report["batches"].as_u64().unwrap() >= 3);
    assert_eq!(report["central_management_recovery_required"], true);
    assert_eq!(
        pg.query_one(
            "SELECT status FROM noisefence.deliveries WHERE message_id=$1",
            &[&message]
        )
        .await
        .unwrap()
        .get::<_, String>(0),
        "delivered"
    );
    store.read(|db| {
        assert_eq!(outbox::status(db)?.pending,0);assert_eq!(outbox::status(db)?.pending_logs,0);
        assert_eq!(db.query_row("SELECT status FROM deliveries",[],|r|r.get::<_,String>(0))?,"delivered");
        assert!(db.query_row("SELECT EXISTS(SELECT 1 FROM cluster_state WHERE key='management_recovery_required')",[],|r|r.get::<_,bool>(0))?);
        Ok(())
    }).await.unwrap();
    assert_eq!(
        central
            .replay_recovered_source(&path, &operation)
            .await
            .unwrap()["batches"],
        0
    );
    store
        .run(|db| {
            let delivery: i64 = db.query_row("SELECT id FROM deliveries", [], |r| r.get(0))?;
            let trace = noisefence::delivery_log::Attempt {
                route: "mx.example.test".into(),
                peer: None,
                started: 2,
                elapsed_ms: 1,
                outcome: "delivered".into(),
                truncated: false,
                events: Vec::new(),
            };
            db.execute(
                "INSERT INTO delivery_attempts(delivery_id,attempt,trace) VALUES(?1,26,?2)",
                rusqlite::params![delivery, serde_json::to_string(&trace)?],
            )?;
            assert_eq!(db.last_insert_rowid(), 1001);
            Ok(())
        })
        .await
        .unwrap();
    let next = central
        .replay_recovered_source(&path, &operation)
        .await
        .unwrap();
    assert_eq!(next["transcripts"], 26);
    assert_eq!(next["batches"], 1);
    assert_eq!(
        pg.query_one(
            "SELECT count(*) FROM noisefence.delivery_logs WHERE local_id=1001",
            &[]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        1
    );
    // Identity and generation alone must not hide altered payloads on retry.
    pg.execute(
        "UPDATE noisefence.deliveries SET status='failed' WHERE message_id=$1",
        &[&message],
    )
    .await
    .unwrap();
    let error = central
        .replay_recovered_source(&path, &operation)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("message payload differs"));
    pg.execute(
        "UPDATE noisefence.deliveries SET status='delivered' WHERE message_id=$1",
        &[&message],
    )
    .await
    .unwrap();
    let original: serde_json::Value = pg
        .query_one(
            "SELECT trace FROM noisefence.delivery_logs WHERE local_id=1001",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    pg.execute("UPDATE noisefence.delivery_logs SET trace=jsonb_set(trace,'{outcome}','\"failed\"'::jsonb) WHERE local_id=1001", &[]).await.unwrap();
    let error = central
        .replay_recovered_source(&path, &operation)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("transcript payload differs"));
    pg.execute(
        "UPDATE noisefence.delivery_logs SET trace=$1 WHERE local_id=1001",
        &[&original],
    )
    .await
    .unwrap();
    central
        .replay_recovered_source(&path, &operation)
        .await
        .unwrap();
    pg.execute("DELETE FROM noisefence.messages WHERE id=$1", &[&message])
        .await
        .unwrap();
    let error = central
        .replay_recovered_source(&path, &operation)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("inventories differ"));
    drop(store);
    drop(central);
    drop(pg);
    f.finish().await;
}

// Build the same released authority journal used by the native activation tests.
fn participant_fixture(
    path: &std::path::Path,
) -> (noisefence::cluster::activation::Epoch, serde_json::Value) {
    use noisefence::cluster::{
        activation::{Acknowledgement, Journal, Progress},
        artifacts,
    };
    let authority = tempfile::tempdir().unwrap();
    drop(Store::open(authority.path()).unwrap());
    let mut db = rusqlite::Connection::open(authority.path().join("state.sqlite3")).unwrap();
    let tx = db.transaction().unwrap();
    tx.execute_batch("INSERT INTO cluster_state VALUES('role','coordinator'),('node_id','mx1')")
        .unwrap();
    let config = common::config(path);
    let baseline = artifacts::capture(
        &config,
        noisefence::control::Settings::from_config(&config),
        0,
    )
    .unwrap()
    .bundle;
    let mut candidate = baseline.clone();
    candidate.revision = 1;
    candidate.digest = candidate.hash().unwrap();
    Journal::initialize(&tx, "mx1", baseline).unwrap();
    let journal = Journal::begin(&tx, candidate, vec!["mx1".into(), "mx2".into()], 1).unwrap();
    let epoch = journal.rollout().unwrap().epoch().clone();
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
    let participant = serde_json::json!({"version":1,"node":"mx2","authority":released,"installed":released.current(),"installed_epoch":epoch,"prepared":epoch});
    (epoch, participant)
}
