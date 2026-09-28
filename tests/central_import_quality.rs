#[allow(dead_code)]
mod common;
#[path = "common/postgres.rs"]
mod postgres;
use noisefence::{
    central::{
        import::{AccountsSnapshot, QualitySnapshot},
        outbox,
    },
    store::Store,
};

#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn import_preserves_holdouts_campaign_exposure_and_human_labels_atomically() {
    let f = postgres::Fixture::new().await;
    let pg = f.connect().await;
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path()).unwrap();
    noisefence::api::create_user(
        &store,
        "admin".into(),
        "synthetic-password-123".into(),
        vec![],
        true,
    )
    .await
    .unwrap();
    let accounts = store
        .run(|db| AccountsSnapshot::capture(&db.transaction()?, None))
        .await
        .unwrap();
    f.central.import_accounts(&accounts).await.unwrap();
    let ids: Vec<_> = (1..=5)
        .map(|n| uuid::Uuid::from_u128(n).to_string())
        .collect();
    let messages = ids.clone();
    let batch = uuid::Uuid::from_u128(100).to_string();
    let development = uuid::Uuid::from_u128(101).to_string();
    let holdout = uuid::Uuid::from_u128(102).to_string();
    let job = uuid::Uuid::from_u128(103).to_string();
    let (b, d, h, j) = (
        batch.clone(),
        development.clone(),
        holdout.clone(),
        job.clone(),
    );
    store.run(move |db| {
        let scan=serde_json::to_string(&noisefence::features::extract(common::MESSAGE,10000))?;
        for id in &messages {
            db.execute("INSERT INTO messages(id,created,sender,scan) VALUES(?1,?2,'sender@example.test',?3)",rusqlite::params![id,noisefence::now()-10,scan])?;
            db.execute("INSERT INTO deliveries(message_id,address,destination,hosts,next_attempt) VALUES(?1,'alice@example.test','alice@example.test','[]',0)",[id])?;
            db.execute("INSERT INTO feedback VALUES('admin',?1,1,100)",[id])?;
        }
        db.execute("INSERT INTO feedback_categories VALUES('admin',?1,'spam')",[&messages[0]])?;
        for name in [&b,&d,&h] {
            db.execute("INSERT INTO quality_batches VALUES(?1,'admin',100,1,100,'example.test','seed',5,1)",[name])?;
        }
        db.execute("INSERT INTO quality_purposes VALUES(?1,'development','dev-cohort'),(?2,'holdout','holdout-cohort')",rusqlite::params![d,h])?;
        db.execute("INSERT INTO quality_members VALUES(?1,?2,0),(?3,?4,0),(?5,?6,0)",rusqlite::params![b,messages[0],d,messages[4],h,messages[3]])?;
        db.execute("INSERT INTO quality_reference_sets VALUES(?1,'curated human references')",[b])?;
        db.execute("INSERT INTO quality_labels VALUES('admin',?1,'legitimate','notification',111)",[&messages[1]])?;
        db.execute("INSERT INTO quality_reserved VALUES(?1,112,'independent evaluation')",[&messages[2]])?;
        db.execute("INSERT INTO adaptive_labels VALUES('admin',?1,'example.test','phishing',113)",[&messages[4]])?;
        db.execute("INSERT INTO quality_jobs VALUES(?1,'admin',?2,'train',NULL,'complete',114,115,116,?3,?4)",rusqlite::params![j,d,serde_json::json!({"status":"complete","details":"x".repeat(300000)}).to_string(),"a".repeat(64)])?;
        db.execute_batch("UPDATE quality_exposure_state SET tracking_since=99;
            INSERT INTO quality_export_batches VALUES('deleted-old-batch',123);
            INSERT INTO quality_export_campaigns VALUES('fingerprint','simhash',124);")?;
        Ok(())
    }).await.unwrap();
    let snapshot = store
        .run(|db| QualitySnapshot::capture(&db.transaction()?))
        .await
        .unwrap();
    // Missing message identities must fail before any annotation can be committed.
    assert!(f.central.import_quality(&snapshot).await.is_err());
    assert_eq!(
        pg.query_one("SELECT count(*) FROM noisefence.feedback", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    let source = store.run(|db| outbox::initialize(db, "mx1")).await.unwrap();
    f.central.register_source(&source).await.unwrap();
    while f.central.synchronize_once(&store).await.unwrap() > 0 {}
    pg.batch_execute("CREATE FUNCTION noisefence.break_quality_import() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic'; END $$; CREATE TRIGGER break_quality_import BEFORE INSERT ON noisefence.quality_export_campaigns FOR EACH ROW EXECUTE FUNCTION noisefence.break_quality_import();").await.unwrap();
    assert!(f.central.import_quality(&snapshot).await.is_err());
    for table in [
        "feedback",
        "quality_batches",
        "quality_members",
        "quality_reference_sets",
        "quality_labels",
        "quality_reserved",
        "adaptive_labels",
        "quality_jobs",
        "quality_export_batches",
        "quality_export_campaigns",
    ] {
        assert_eq!(
            pg.query_one(&format!("SELECT count(*) FROM noisefence.{table}"), &[])
                .await
                .unwrap()
                .get::<_, i64>(0),
            0
        );
    }
    assert_eq!(
        pg.query_one(
            "SELECT generation FROM noisefence.quality_exposure_state WHERE id=1",
            &[]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        0
    );
    pg.batch_execute("DROP TRIGGER break_quality_import ON noisefence.quality_export_campaigns;")
        .await
        .unwrap();
    let held: bool = pg
        .query_one("SELECT pg_try_advisory_lock(719021428125::bigint)", &[])
        .await
        .unwrap()
        .get(0);
    assert!(held);
    assert!(
        f.central
            .import_quality(&snapshot)
            .await
            .unwrap_err()
            .to_string()
            .contains("research worker")
    );
    pg.query_one("SELECT pg_advisory_unlock(719021428125::bigint)", &[])
        .await
        .unwrap();
    f.central.import_quality(&snapshot).await.unwrap();
    assert_eq!(
        pg.query_one(
            "SELECT purpose FROM noisefence.quality_batches WHERE id=$1",
            &[&batch]
        )
        .await
        .unwrap()
        .get::<_, String>(0),
        "regression"
    );
    let eligible = pg
        .query(
            "SELECT message_id FROM noisefence.training_feedback ORDER BY message_id",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(eligible.len(), 1);
    assert_eq!(eligible[0].get::<_, String>(0), ids[4]);
    let local = store
        .read(|db| {
            Ok(
                db.query_row("SELECT message_id FROM training_feedback", [], |r| {
                    r.get::<_, String>(0)
                })?,
            )
        })
        .await
        .unwrap();
    assert_eq!(local, ids[4]);
    assert_eq!(
        pg.query_one("SELECT class FROM noisefence.adaptive_labels", &[])
            .await
            .unwrap()
            .get::<_, String>(0),
        "phishing"
    );
    assert_eq!(
        pg.query_one(
            "SELECT tracking_since FROM noisefence.quality_exposure_state",
            &[]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        99
    );
    assert_eq!(
        pg.query_one(
            "SELECT exposed_at FROM noisefence.quality_export_campaigns",
            &[]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        124
    );
    assert_eq!(
        pg.query_one(
            "SELECT model_sha256 FROM noisefence.quality_jobs WHERE id=$1",
            &[&job]
        )
        .await
        .unwrap()
        .get::<_, String>(0),
        "a".repeat(64)
    );
    assert!(f.central.import_quality(&snapshot).await.is_err());
    f.finish().await;
}
