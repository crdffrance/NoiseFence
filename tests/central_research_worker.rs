#[path = "common/postgres.rs"]
mod postgres;
use noisefence::central::research_worker::{Outcome, serve};
use serde_json::json;
fn complete() -> Outcome {
    Outcome {
        status: "complete".into(),
        report: json!({"status":"complete","may_activate":true}),
        model_sha256: None,
    }
}
async fn seed(db: &tokio_postgres::Client) -> Vec<String> {
    db.batch_execute(
        "INSERT INTO noisefence.users(username,password,admin) VALUES('admin','unused',true)",
    )
    .await
    .unwrap();
    let batch = uuid::Uuid::new_v4().to_string();
    db.execute("INSERT INTO noisefence.quality_batches(id,username,created,since,until,domain,seed,population,selected,purpose,cohort) VALUES($1,'admin',$2,$3,$2,'','seed',1,1,'development','')",&[&batch,&noisefence::now(),&(noisefence::now()-100)]).await.unwrap();
    let mut ids = Vec::new();
    for n in 1..=3 {
        let id = uuid::Uuid::from_u128(n).to_string();
        db.execute("INSERT INTO noisefence.quality_jobs(id,username,batch_id,operation,status,created) VALUES($1,'admin',$2,'compare','queued',$3)",&[&id,&batch,&noisefence::now()]).await.unwrap();
        ids.push(id);
    }
    ids
}
#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn dedicated_worker_session_fences_concurrency_outage_and_late_results() {
    let f = postgres::Fixture::new().await;
    let db = f.connect().await;
    let ids = seed(&db).await;
    let mut worker = f.central.research_worker("test-build").await.unwrap();
    assert!(f.central.research_worker("other-build").await.is_err());
    assert_eq!(worker.retained().await.unwrap(), ids);
    let invalid = uuid::Uuid::from_u128(99).to_string();
    db.execute("INSERT INTO noisefence.quality_jobs(id,username,batch_id,operation,status,created) SELECT $1,username,batch_id,'train','queued',created FROM noisefence.quality_jobs WHERE id=$2",&[&invalid,&ids[0]]).await.unwrap();
    db.execute(
        "UPDATE noisefence.quality_batches SET purpose='holdout'",
        &[],
    )
    .await
    .unwrap();
    let job = worker.claim().await.unwrap().unwrap();
    assert_eq!(
        db.query_one(
            "SELECT status FROM noisefence.quality_jobs WHERE id=$1",
            &[&invalid]
        )
        .await
        .unwrap()
        .get::<_, String>(0),
        "cancelled"
    );
    assert_eq!(job.id, ids[0]);
    assert!(worker.claim().await.is_err());
    assert!(worker.finish(&ids[1], complete()).await.is_err());
    let mut oversized = complete();
    oversized.report = json!({"text":"x".repeat(512*1024)});
    assert!(worker.finish(&job.id, oversized).await.is_err());
    assert_eq!(
        worker.finish(&job.id, complete()).await.unwrap(),
        "complete"
    );
    let report: serde_json::Value = db
        .query_one(
            "SELECT report FROM noisefence.quality_jobs WHERE id=$1",
            &[&job.id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(report["may_activate"], false);
    assert_eq!(report["observation_only"], true);
    assert!(worker.finish(&job.id, complete()).await.is_err());
    let interrupted = worker.claim().await.unwrap().unwrap();
    assert_eq!(interrupted.id, ids[1]);
    f.suspend().await;
    assert!(worker.heartbeat().await.is_err());
    f.resume().await;
    let db = f.connect().await;
    let mut replacement = f
        .central
        .research_worker("replacement-build")
        .await
        .unwrap();
    assert_eq!(
        db.query_one(
            "SELECT status FROM noisefence.quality_jobs WHERE id=$1",
            &[&ids[1]]
        )
        .await
        .unwrap()
        .get::<_, String>(0),
        "interrupted"
    );
    assert!(worker.finish(&ids[1], complete()).await.is_err());
    let next = replacement.claim().await.unwrap().unwrap();
    assert_eq!(next.id, ids[2]);
    db.execute(
        "UPDATE noisefence.users SET disabled=true WHERE username='admin'",
        &[],
    )
    .await
    .unwrap();
    assert_eq!(
        replacement.finish(&next.id, complete()).await.unwrap(),
        "cancelled"
    );
    assert!(replacement.claim().await.unwrap().is_none());
    drop(worker);
    drop(replacement);
    drop(db);
    f.finish().await;
}
#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn stdio_protocol_holds_database_ownership_and_fails_closed_on_invalid_input() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let f = postgres::Fixture::new().await;
    let db = f.connect().await;
    let ids = seed(&db).await;
    let (parent, child) = tokio::io::duplex(1024);
    let central = f.central.clone();
    let task = tokio::spawn(async move {
        let (read, write) = tokio::io::split(child);
        serve(&central, "protocol-test", BufReader::new(read), write).await
    });
    let (read, mut write) = tokio::io::split(parent);
    let mut lines = BufReader::new(read).lines();
    let ready: serde_json::Value =
        serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
    assert_eq!(ready["ready"], true);
    assert!(f.central.research_worker("competing").await.is_err());
    write.write_all(b"{\"command\":\"claim\"}\n").await.unwrap();
    let reply: serde_json::Value =
        serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
    assert_eq!(reply["result"]["id"], ids[0]);
    // Unknown fields cannot be interpreted as arbitrary commands or SQL.
    write
        .write_all(b"{\"command\":\"heartbeat\",\"sql\":\"untrusted\"}\n")
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(3), task)
            .await
            .expect("invalid requests close the session promptly")
            .unwrap()
            .is_err()
    );
    let mut next = None;
    for _ in 0..20 {
        match f.central.research_worker("after-protocol").await {
            Ok(w) => {
                next = Some(w);
                break;
            }
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(10)).await,
        }
    }
    let mut next = next.expect("session lock released when protocol ends");
    assert_eq!(next.claim().await.unwrap().unwrap().id, ids[1]);
    assert_eq!(
        db.query_one(
            "SELECT status FROM noisefence.quality_jobs WHERE id=$1",
            &[&ids[0]]
        )
        .await
        .unwrap()
        .get::<_, String>(0),
        "interrupted"
    );
    drop(next);
    drop(db);
    f.finish().await;
}
