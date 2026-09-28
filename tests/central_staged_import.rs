#[allow(dead_code)]
mod common;
#[path = "common/postgres.rs"]
mod postgres;
use noisefence::{
    central::{
        import::{
            AccountsSnapshot, DeliveryIdentities, PolicySnapshot, PreparedImport, QualitySnapshot,
            ReconciledSpools, SpoolSnapshot,
        },
        outbox,
    },
    cluster::{activation::Journal, artifacts},
    control::Settings,
    store::Store,
};
async fn prepared() -> PreparedImport {
    prepared_kind(false).await
}
async fn prepared_kind(legacy_dsn: bool) -> PreparedImport {
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path()).unwrap();
    let config = common::config(root.path());
    let scan = serde_json::to_string(&if legacy_dsn {
        noisefence::engine::Scan {
            complete: true,
            subject: "Delivery failure".into(),
            model: "dsn".into(),
            ..Default::default()
        }
    } else {
        noisefence::engine::Engine::new(config.clone())
            .unwrap()
            .offline(common::MESSAGE)
    })
    .unwrap();
    let baseline = artifacts::capture(&config, Settings::from_config(&config), 0)
        .unwrap()
        .bundle;
    store.run(move|db| {
        let identity=outbox::initialize(db,"mx1")?;
        db.execute_batch("INSERT INTO users VALUES('admin','synthetic-test-only',1,0); INSERT INTO cluster_state VALUES('node_id','mx1'),('role','coordinator'); PRAGMA user_version=6;")?;
        let id = if legacy_dsn {"dsn-42".into()} else {uuid::Uuid::new_v4().to_string()};
        db.execute("INSERT INTO messages(id,created,sender,scan,is_dsn) VALUES(?1,?2,?4,?3,?5)",rusqlite::params![id,noisefence::now(),scan,if legacy_dsn {""} else {"sender@example.test"},legacy_dsn])?;
        db.execute("INSERT INTO deliveries(id,message_id,address,destination,hosts,status,next_attempt) VALUES(42,?1,'alice@example.test','alice@example.test','[]','delivered',0)",[&id])?;
        db.execute("INSERT INTO feedback VALUES('admin',?1,1,100)",[&id])?;
        db.execute("INSERT INTO feedback_categories VALUES('admin',?1,'spam')",[&id])?;
        let trace=serde_json::json!({"route":"mx.example.test","peer":null,"started":1,"elapsed_ms":1,"outcome":"delivered","events":[],"truncated":false});
        db.execute("INSERT INTO delivery_attempts(delivery_id,attempt,trace) VALUES(42,1,?1)",[trace.to_string()])?;
        let mut tx=db.transaction()?;
        Journal::initialize(&tx,"mx1",baseline)?;
        let accounts=AccountsSnapshot::capture(&tx,None)?;
        let quality=QualitySnapshot::capture(&tx)?;
        let deliveries=DeliveryIdentities::capture(&tx)?;
        let policy=PolicySnapshot::capture(&tx,[(identity.node,identity.epoch)].into_iter().collect())?;
        let spool=SpoolSnapshot::capture(&mut tx)?;
        tx.commit()?;
        PreparedImport::new(accounts,deliveries,quality,policy,ReconciledSpools::verify(vec![spool])?)
    }).await.unwrap()
}
#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn ordered_import_records_identity_but_does_not_enable_runtime_or_overwrite_data() {
    let f = postgres::Fixture::new().await;
    let pg = f.connect().await;
    let receipt = f.central.stage_import(prepared().await).await.unwrap();
    receipt.database.validate().unwrap();
    let row = pg
        .query_one(
            "SELECT source_digest,activated_at,report FROM noisefence.migration_state WHERE id=1",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), receipt.database.source_digest);
    assert!(row.get::<_, Option<i64>>(1).is_none());
    let report: serde_json::Value = row.get(2);
    assert_eq!(report["instance"], receipt.database.instance);
    assert_eq!(report["phase"], "copied_not_activated");
    assert_eq!(
        pg.query_one("SELECT count(*) FROM noisefence.users", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    assert_eq!(
        pg.query_one("SELECT count(*) FROM noisefence.policy_authority", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    assert_eq!(
        pg.query_one(
            "SELECT count(*) FROM noisefence.policy_head WHERE revision=0",
            &[]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        1
    );
    assert_eq!(
        pg.query_one("SELECT count(*) FROM noisefence.messages", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    assert_eq!(
        pg.query_one("SELECT count(*) FROM noisefence.delivery_logs", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    assert_eq!(
        pg.query_one(
            "SELECT count(*) FROM noisefence.deliveries WHERE id=42",
            &[]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        1
    );
    assert_eq!(pg.query_one("SELECT count(*) FROM noisefence.feedback WHERE username='admin' AND spam AND category='spam'",&[]).await.unwrap().get::<_,i64>(0),1);
    let runtime = noisefence::central::Central::new_bound(&f.settings, &receipt.database).unwrap();
    assert!(
        runtime.health().await.is_err(),
        "copy receipt cannot authorize runtime"
    );
    assert!(f.central.stage_import(prepared().await).await.is_err());
    let unchanged: serde_json::Value = pg
        .query_one(
            "SELECT report FROM noisefence.migration_state WHERE id=1",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        unchanged, report,
        "failed second claim cannot overwrite original receipt"
    );
    drop(runtime);
    f.finish().await;
}
#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn late_failure_leaves_inactive_diagnostic_receipt_and_refuses_unsafe_retry() {
    let f = postgres::Fixture::new().await;
    let pg = f.connect().await;
    pg.batch_execute("CREATE FUNCTION noisefence.fail_import() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic failure'; END $$; CREATE TRIGGER fail_import BEFORE INSERT ON noisefence.policy_authority FOR EACH ROW EXECUTE FUNCTION noisefence.fail_import();").await.unwrap();
    assert!(f.central.stage_import(prepared().await).await.is_err());
    let row = pg
        .query_one(
            "SELECT activated_at,report->>'phase' FROM noisefence.migration_state WHERE id=1",
            &[],
        )
        .await
        .unwrap();
    assert!(row.get::<_, Option<i64>>(0).is_none());
    assert_eq!(row.get::<_, String>(1), "failed");
    assert_eq!(
        pg.query_one("SELECT count(*) FROM noisefence.users", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        1,
        "earlier completed phases remain diagnosable"
    );
    assert_eq!(
        pg.query_one("SELECT count(*) FROM noisefence.policy_revisions", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0,
        "failed final component rolled back"
    );
    assert!(
        f.central.stage_import(prepared().await).await.is_err(),
        "partial data is never automatically erased"
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn legacy_dsn_keeps_public_identity_transcripts_and_runtime_history() {
    let f = postgres::Fixture::new().await;
    f.central
        .stage_import(prepared_kind(true).await)
        .await
        .unwrap();
    let pg = f.connect().await;
    let row=pg.query_one("SELECT m.id,m.is_dsn,m.sender,d.id,l.message_id FROM noisefence.messages m JOIN noisefence.deliveries d ON d.message_id=m.id JOIN noisefence.delivery_log_versions v ON v.delivery_id=d.id JOIN noisefence.delivery_logs l ON (l.node,l.epoch,l.local_id)=(v.node,v.epoch,v.local_id)",&[]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "dsn-42");
    assert!(row.get::<_, bool>(1));
    assert_eq!(row.get::<_, String>(2), "");
    assert_eq!(row.get::<_, i64>(3), 42);
    assert_eq!(row.get::<_, String>(4), "dsn-42");
    let mut history = f.central.runtime_history(None).await.unwrap();
    assert_eq!(history.rows.len(), 1);
    assert_eq!(history.rows[0].id, "dsn-42");
    history.validate().unwrap();
    history.rows[0].is_dsn = false;
    assert!(
        history.validate().is_err(),
        "legacy IDs cannot describe ordinary mail"
    );
    f.finish().await;
}
