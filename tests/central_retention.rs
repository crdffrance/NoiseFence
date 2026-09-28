#[allow(dead_code)]
mod common;
#[path = "common/postgres.rs"]
mod postgres;
use noisefence::{central::outbox, store::Store};

#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn housekeeping_is_bounded_preserves_holdouts_jobs_and_unresolved_operations() {
    let f = postgres::Fixture::new().await;
    let pg = f.connect().await;
    let root = tempfile::tempdir().unwrap();
    let local = Store::open(root.path()).unwrap();
    let identity = local.run(|db| outbox::initialize(db, "mx1")).await.unwrap();
    f.central.register_source(&identity).await.unwrap();
    let ids: Vec<String> = (0..3).map(|_| uuid::Uuid::new_v4().to_string()).collect();
    let records = ids.clone();
    let scan = noisefence::features::extract(common::MESSAGE, 10000);
    local.run(move|db| {
        for id in records {
            db.execute("INSERT INTO messages(id,created,sender,scan) VALUES(?1,?2,'sender@example.org',?3)",rusqlite::params![id,noisefence::now(),serde_json::to_string(&scan)?])?;
            db.execute("INSERT INTO deliveries(message_id,address,destination,hosts,next_attempt) VALUES(?1,'alice@example.test','alice@example.test','[]',0)",[id])?;
        }Ok(())
    }).await.unwrap();
    while f.central.synchronize_once(&local).await.unwrap() > 0 {}
    let now = noisefence::now();
    let old = now - 31 * 86400;
    pg.batch_execute(
        "INSERT INTO noisefence.users(username,password,admin) VALUES('admin','unused',true)",
    )
    .await
    .unwrap();
    pg.execute("INSERT INTO noisefence.sessions SELECT lpad(n::text,64,'0'),'admin','synthetic',$1,false FROM generate_series(1,501) n", &[&(now-100)]).await.unwrap();
    pg.execute(
        "INSERT INTO noisefence.sessions VALUES($1,'admin','live',$2,false)",
        &[&"f".repeat(64), &(now + 3600)],
    )
    .await
    .unwrap();
    pg.execute(
        "INSERT INTO noisefence.mfa_attempts VALUES('admin',$1,3)",
        &[&(now - 100)],
    )
    .await
    .unwrap();
    pg.execute("INSERT INTO noisefence.invitations(id,token_hash,username,admin,addresses,creator,creator_version,created,expires) VALUES('expired','unused','new-user',false,'[]','admin',0,$1,$1)",&[&old]).await.unwrap();
    for (action, object, time) in [
        ("account", "expired", old),
        ("account", "recent", now),
        ("model_set_retain_started", "done", old),
        ("model_set_retain_completed", "done", old),
        ("model_set_remove_started", "unresolved", old),
        ("model_set_retain_started", "recent-outcome", old),
        ("model_set_retain_failed", "recent-outcome", now),
    ] {
        pg.execute("INSERT INTO noisefence.audit(created,username,action,object_id) VALUES($1,'admin',$2,$3)",&[&time,&action,&object]).await.unwrap();
    }
    for (n, id) in ids.iter().enumerate() {
        pg.execute("INSERT INTO noisefence.feedback(username,message_id,spam,created) VALUES('admin',$1,true,$2)",&[id,&now]).await.unwrap();
        if n == 0 {
            pg.execute(
                "INSERT INTO noisefence.quality_labels VALUES('admin',$1,'spam',NULL,$2)",
                &[id, &old],
            )
            .await
            .unwrap();
        }
    }
    for (id, purpose, time) in [
        ("holdout", "holdout", old - 1),
        ("busy", "development", old),
        ("bound", "development", old),
        ("done", "development", old),
        ("live", "development", now),
    ] {
        pg.execute("INSERT INTO noisefence.quality_batches(id,username,created,since,until,domain,seed,population,selected,purpose) VALUES($1,'admin',$2,$2,$3,'','synthetic',1,1,$4)",&[&id,&time,&now,&purpose]).await.unwrap();
    }
    pg.execute(
        "INSERT INTO noisefence.quality_members VALUES('holdout',$1,0)",
        &[&ids[1]],
    )
    .await
    .unwrap();
    pg.execute("INSERT INTO noisefence.quality_jobs(id,username,batch_id,operation,status,created,finished) VALUES('running','admin','busy','train','running',$1,NULL),('bound-job','admin','bound','train','complete',$1,$1),('done-job','admin','done','train','complete',$1,$1)",&[&old]).await.unwrap();
    pg.execute("INSERT INTO noisefence.policy_revisions(id,created,username,settings,sha256) VALUES(0,$1,'admin','{\"quality_candidate\":{\"job\":\"bound-job\"}}',$2)",&[&old,&"a".repeat(64)]).await.unwrap();
    pg.execute(
        "INSERT INTO noisefence.quality_export_campaigns VALUES('old','old',$1),('live','live',$2)",
        &[&old, &now],
    )
    .await
    .unwrap();
    pg.execute(
        "INSERT INTO noisefence.quality_export_batches VALUES('old',$1)",
        &[&old],
    )
    .await
    .unwrap();
    // A late failure rolls back the whole sweep, including early session expiry.
    pg.batch_execute("CREATE FUNCTION reject_retention() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic cleanup failure'; END $$; CREATE TRIGGER reject_retention BEFORE DELETE ON noisefence.quality_export_batches FOR EACH ROW EXECUTE FUNCTION reject_retention();").await.unwrap();
    assert!(f.central.cleanup_management().await.is_err());
    assert_eq!(
        pg.query_one("SELECT count(*) FROM noisefence.sessions", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        502
    );
    assert_eq!(
        pg.query_one("SELECT count(*) FROM noisefence.quality_reserved", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    pg.batch_execute("DROP TRIGGER reject_retention ON noisefence.quality_export_batches; DROP FUNCTION reject_retention();").await.unwrap();
    let counts = f.central.cleanup_management().await.unwrap();
    assert_eq!(counts["sessions"], 500);
    assert_eq!(counts["invitations"], 1);
    assert_eq!(counts["catalog_audit"], 2);
    assert_eq!(counts["audit"], 1);
    assert_eq!(counts["quality_labels"], 1);
    assert_eq!(counts["quality_jobs"], 1);
    assert_eq!(counts["quality_batches"], 1);
    assert_eq!(
        pg.query_one("SELECT count(*) FROM noisefence.training_feedback", &[])
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
        3
    );
    assert_eq!(
        pg.query_one("SELECT count(*) FROM noisefence.message_versions", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        3
    );
    assert_eq!(pg.query_one("SELECT count(*) FROM noisefence.audit WHERE object_id IN ('unresolved','recent-outcome')",&[]).await.unwrap().get::<_,i64>(0),3);
    assert_eq!(
        pg.query_one(
            "SELECT generation FROM noisefence.quality_exposure_state WHERE id=1",
            &[]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        1
    );
    let next = f.central.cleanup_management().await.unwrap();
    assert_eq!(next["sessions"], 1);
    assert_eq!(
        pg.query_one("SELECT count(*) FROM noisefence.sessions", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    assert_eq!(
        pg.query_one("SELECT count(*) FROM noisefence.quality_jobs", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        2
    );
    assert_eq!(
        pg.query_one(
            "SELECT count(*) FROM noisefence.quality_batches WHERE id IN ('busy','bound','live')",
            &[]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        3
    );
    f.suspend().await;
    assert!(f.central.cleanup_management().await.is_err());
    f.resume().await;
    f.central.cleanup_management().await.unwrap();
    drop(pg);
    f.finish().await;
}
