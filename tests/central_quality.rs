#[path = "common/bulk_quality.rs"]
mod bulk_quality;
#[allow(dead_code)]
mod common;
#[path = "common/fusion.rs"]
mod fusion;
#[path = "common/postgres.rs"]
mod postgres;
use noisefence::{
    central::outbox,
    engine::Scan,
    message::digest,
    quality::{
        self,
        evaluation::{self, Risk},
    },
    store::Store,
};

#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn quality_annotations_scoping_and_exports_survive_management_migration() {
    let fixture = postgres::Fixture::new().await;
    let db = fixture.connect().await;
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path()).unwrap();
    let cfg = common::config(root.path());
    let identity = store.run(|db| outbox::initialize(db, "mx1")).await.unwrap();
    fixture.central.register_source(&identity).await.unwrap();
    for (name, grant) in [("alice", "alice@example.test"), ("bob", "bob@example.test")] {
        db.execute(
            "INSERT INTO noisefence.users(username,password) VALUES($1,'unused')",
            &[&name],
        )
        .await
        .unwrap();
        db.execute(
            "INSERT INTO noisefence.grants VALUES($1,$2)",
            &[&name, &grant],
        )
        .await
        .unwrap();
        store
            .run(move |db| {
                db.execute(
                    "INSERT INTO users(username,password) VALUES(?1,'unused')",
                    [name],
                )?;
                db.execute(
                    "INSERT INTO grants VALUES(?1,?2)",
                    rusqlite::params![name, grant],
                )?;
                Ok(())
            })
            .await
            .unwrap();
    }
    let mut ids = Vec::new();
    for n in 0..4 {
        let (_, evidence) = fusion::fixture(&cfg);
        let mut scan = Scan {
            complete: true,
            features_complete: Some(true),
            evidence: Some(evidence),
            fingerprint: digest(format!("campaign-{n}").as_bytes()),
            campaign_simhash: Some(format!("{n:016x}")),
            subject: "PRIVATE SUBJECT".into(),
            ..Default::default()
        };
        scan.quality = Some(quality::snapshot(&scan, None));
        let id = uuid::Uuid::new_v4().to_string();
        ids.push(id.clone());
        let scan = serde_json::to_string(&scan).unwrap();
        store.run(move |db| {
            db.execute("INSERT INTO messages(id,created,sender,scan) VALUES(?1,?2,'private@example.org',?3)", rusqlite::params![id,noisefence::now()-10,scan])?;
            let address = if n==3 {"bob@example.test"} else {"alice@example.test"};
            db.execute("INSERT INTO deliveries(message_id,address,destination,hosts,next_attempt) VALUES(?1,?2,?2,'[]',0)",rusqlite::params![id,address])?;
            Ok(())
        }).await.unwrap();
    }
    while fixture.central.synchronize_once(&store).await.unwrap() > 0 {}
    let central = store
        .clone()
        .with_management(fixture.central.clone())
        .await
        .unwrap();
    let batch = evaluation::sample(
        &central,
        "alice".into(),
        noisefence::now() - 60,
        noisefence::now(),
        10,
        String::new(),
    )
    .await
    .unwrap();
    let members = evaluation::members(&central, "alice".into(), batch.clone())
        .await
        .unwrap();
    assert_eq!(members.len(), 3);
    assert!(!members.iter().any(|r| r["id"] == ids[3]));
    assert!(
        evaluation::members(&central, "bob".into(), batch.clone())
            .await
            .is_err()
    );
    assert!(
        evaluation::label(&central, "alice".into(), ids[3].clone(), Risk::Spam, None)
            .await
            .is_err()
    );
    // Copy the frozen draw to the legacy store to compare both implementations.
    let row=db.query_one("SELECT created,since,until,seed,population,selected FROM noisefence.quality_batches WHERE id=$1", &[&batch]).await.unwrap();
    let (created, since, until, seed, population, selected): (i64, i64, i64, String, i64, i64) = (
        row.get(0),
        row.get(1),
        row.get(2),
        row.get(3),
        row.get(4),
        row.get(5),
    );
    let b = batch.clone();
    store.run(move |db| {
        db.execute("INSERT INTO quality_batches(id,username,created,since,until,domain,seed,population,selected) VALUES(?1,'alice',?2,?3,?4,'',?5,?6,?7)",rusqlite::params![b,created,since,until,seed,population,selected])?;
        for (rank,m) in members.iter().enumerate() {
            db.execute("INSERT INTO quality_members(batch_id,message_id,rank) VALUES(?1,?2,?3)",rusqlite::params![b,m["id"].as_str().unwrap(),rank])?;
        }
        Ok(())
    }).await.unwrap();
    for s in [&store, &central] {
        bulk_quality::check(s, &batch, &ids[..3], &ids[3]).await;
    }
    for (id, risk) in ids
        .iter()
        .zip([Risk::Legitimate, Risk::Spam, Risk::Uncertain])
    {
        for s in [&store, &central] {
            evaluation::label(s, "alice".into(), id.clone(), risk, None)
                .await
                .unwrap();
        }
    }
    assert_eq!(
        evaluation::batches(&store, "alice".into()).await.unwrap(),
        evaluation::batches(&central, "alice".into()).await.unwrap()
    );
    assert_eq!(
        evaluation::members(&store, "alice".into(), batch.clone())
            .await
            .unwrap(),
        evaluation::members(&central, "alice".into(), batch.clone())
            .await
            .unwrap()
    );
    assert_eq!(
        evaluation::readiness(&store, "alice".into(), batch.clone())
            .await
            .unwrap(),
        evaluation::readiness(&central, "alice".into(), batch.clone())
            .await
            .unwrap()
    );
    assert_eq!(
        quality::workflow::cohorts(&store, "alice".into())
            .await
            .unwrap(),
        quality::workflow::cohorts(&central, "alice".into())
            .await
            .unwrap()
    );
    assert_eq!(
        evaluation::observation_start(&store, "alice".into())
            .await
            .unwrap(),
        evaluation::observation_start(&central, "alice".into())
            .await
            .unwrap()
    );
    let legacy = quality::qualification::inspect(&store, "alice".into(), "current".into())
        .await
        .unwrap();
    let migrated = quality::qualification::inspect(&central, "alice".into(), "current".into())
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_value(legacy).unwrap(),
        serde_json::to_value(migrated).unwrap()
    );
    // Operational feedback cannot silently replace independent evaluation truth.
    db.execute("INSERT INTO noisefence.feedback(username,message_id,spam,created) VALUES('alice',$1,true,$2)", &[&ids[0], &noisefence::now()]).await.unwrap();
    db.execute("INSERT INTO noisefence.adaptive_labels(username,message_id,domain,class,created) VALUES('alice',$1,'example.test','spam',$2)", &[&ids[0], &noisefence::now()]).await.unwrap();
    db.execute(
        "UPDATE noisefence.feedback SET spam=false WHERE username='alice' AND message_id=$1",
        &[&ids[0]],
    )
    .await
    .unwrap();
    let counts=db.query_one("SELECT (SELECT count(*) FROM noisefence.adaptive_labels),(SELECT count(*) FROM noisefence.quality_labels),(SELECT count(*) FROM noisefence.training_feedback)", &[]).await.unwrap();
    assert_eq!(counts.get::<_, i64>(0), 0);
    assert_eq!(counts.get::<_, i64>(1), 3);
    assert_eq!(counts.get::<_, i64>(2), 0);
    let (first, second) = tokio::join!(
        fixture.central.quality_export_rows("alice", &batch, None),
        fixture.central.quality_export_rows("alice", &batch, None)
    );
    let outputs: Vec<_> = [first, second].into_iter().filter_map(Result::ok).collect();
    assert!(!outputs.is_empty());
    assert_eq!(
        outputs
            .iter()
            .filter(|rows| rows[0]["previously_examined"] == false)
            .count(),
        1
    );
    let rows = outputs
        .iter()
        .find(|rows| rows[0]["previously_examined"] == false)
        .unwrap();
    assert_eq!(rows[0]["previously_examined"], false);
    assert_eq!(rows.last().unwrap()["rows"], 3);
    let serialized = serde_json::to_string(&rows).unwrap();
    for private in [
        "PRIVATE SUBJECT",
        "private@example.org",
        "alice@example.test",
        "bob@example.test",
    ] {
        assert!(!serialized.contains(private));
    }
    let repeat = fixture
        .central
        .quality_export_rows("alice", &batch, None)
        .await
        .unwrap();
    assert_eq!(repeat[0]["previously_examined"], true);
    // An unwritable export is still exposure: it cannot become a fresh holdout later.
    let fresh = evaluation::sample(
        &central,
        "alice".into(),
        noisefence::now() - 60,
        noisefence::now(),
        2,
        String::new(),
    )
    .await
    .unwrap();
    assert!(
        evaluation::export(
            &central,
            "alice".into(),
            fresh.clone(),
            &root.path().join("missing/rows.jsonl")
        )
        .await
        .is_err()
    );
    let count: i64 = db
        .query_one(
            "SELECT count(*) FROM noisefence.quality_export_batches WHERE batch_id=$1",
            &[&fresh],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 1);
    db.execute("DELETE FROM noisefence.grants WHERE username='alice'", &[])
        .await
        .unwrap();
    assert!(
        evaluation::members(&central, "alice".into(), batch.clone())
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        evaluation::label(&central, "alice".into(), ids[0].clone(), Risk::Spam, None)
            .await
            .is_err()
    );
    db.execute(
        "UPDATE noisefence.users SET disabled=true WHERE username='alice'",
        &[],
    )
    .await
    .unwrap();
    assert!(evaluation::batches(&central, "alice".into()).await.is_err());
    fixture.suspend().await;
    assert!(
        evaluation::readiness(&central, "alice".into(), batch.clone())
            .await
            .is_err()
    );
    assert!(
        evaluation::readiness(&store, "alice".into(), batch)
            .await
            .is_ok()
    );
    fixture.resume().await;
    drop(db);
    fixture.finish().await;
}
