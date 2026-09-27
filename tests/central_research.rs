#[allow(dead_code)]
mod common;
#[path = "common/postgres.rs"]
mod postgres;
use noisefence::{
    quality::workflow::{self, Request},
    store::Store,
};
fn request(batch: &str, operation: &str, candidate: Option<&str>) -> Request {
    Request {
        batch: batch.into(),
        operation: operation.into(),
        candidate: candidate.map(str::to_owned),
    }
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn research_queue_serializes_capacity_and_preserves_ownership_and_holdouts() {
    let fixture = postgres::Fixture::new().await;
    let db = fixture.connect().await;
    let root = tempfile::tempdir().unwrap();
    let local = Store::open(root.path()).unwrap();
    let store = local
        .clone()
        .with_management(fixture.central.clone())
        .await
        .unwrap();
    for (user, admin) in [("admin", true), ("other", true), ("reader", false)] {
        db.execute(
            "INSERT INTO noisefence.users(username,password,admin) VALUES($1,'unused',$2)",
            &[&user, &admin],
        )
        .await
        .unwrap();
    }
    let mut batches = Vec::new();
    for purpose in [
        "development",
        "regression",
        "holdout",
        "development",
        "development",
        "development",
    ] {
        let id = uuid::Uuid::new_v4().to_string();
        db.execute("INSERT INTO noisefence.quality_batches(id,username,created,since,until,domain,seed,population,selected,purpose,cohort) VALUES($1,'admin',$2,$3,$2,'example.test','synthetic-seed',1,1,$4,'')",&[&id,&noisefence::now(),&(noisefence::now()-100),&purpose]).await.unwrap();
        batches.push(id);
    }
    for index in [1, 2] {
        assert!(
            workflow::enqueue(
                &store,
                "admin".into(),
                request(&batches[index], "train", None)
            )
            .await
            .is_err()
        );
    }
    assert!(
        workflow::enqueue(&store, "reader".into(), request(&batches[0], "train", None))
            .await
            .is_err()
    );
    assert!(
        workflow::enqueue(&store, "other".into(), request(&batches[0], "train", None))
            .await
            .is_err()
    );
    assert!(
        workflow::enqueue(
            &store,
            "admin".into(),
            request(&batches[2], "evaluate", None)
        )
        .await
        .is_err()
    );
    let (a, b) = tokio::join!(
        workflow::enqueue(&store, "admin".into(), request(&batches[0], "train", None)),
        workflow::enqueue(&store, "admin".into(), request(&batches[0], "train", None))
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    let train = a.or(b).unwrap();
    assert!(
        workflow::cancel(&store, "other".into(), train.clone())
            .await
            .is_err()
    );
    assert!(
        fixture
            .central
            .quality_candidate("admin", &train)
            .await
            .unwrap()
            .is_none()
    );
    let hash = noisefence::message::digest(b"synthetic-candidate");
    db.execute("UPDATE noisefence.quality_jobs SET status='complete',model_sha256=$2,report=$3 WHERE id=$1",&[&train,&hash,&serde_json::json!({"status":"complete","observation_only":true})]).await.unwrap();
    assert_eq!(
        fixture
            .central
            .quality_candidate("admin", &train)
            .await
            .unwrap(),
        Some(hash)
    );
    assert!(
        fixture
            .central
            .quality_candidate("other", &train)
            .await
            .unwrap()
            .is_none()
    );
    // A central receipt alone cannot authorize a missing or changed model file.
    assert!(
        workflow::candidate(&store, root.path(), "admin".into(), train.clone())
            .await
            .is_err()
    );
    assert!(
        workflow::cancel(&store, "admin".into(), train.clone())
            .await
            .is_err()
    );
    let eval = workflow::enqueue(
        &store,
        "admin".into(),
        request(&batches[2], "evaluate", Some(&train)),
    )
    .await
    .unwrap();
    let compare = workflow::enqueue(
        &store,
        "admin".into(),
        request(&batches[1], "compare", None),
    )
    .await
    .unwrap();
    workflow::enqueue(&store, "admin".into(), request(&batches[3], "train", None))
        .await
        .unwrap();
    let (a, b) = tokio::join!(
        workflow::enqueue(&store, "admin".into(), request(&batches[4], "train", None)),
        workflow::enqueue(&store, "admin".into(), request(&batches[5], "train", None))
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert_eq!(
        db.query_one(
            "SELECT count(*) FROM noisefence.quality_jobs WHERE status='queued'",
            &[]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        4
    );
    let overview = workflow::list(&store, "admin".into()).await.unwrap();
    assert_eq!(overview["jobs"].as_array().unwrap().len(), 5);
    assert!(
        workflow::list(&store, "other".into()).await.unwrap()["jobs"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(workflow::list(&store, "reader".into()).await.is_err());
    workflow::cancel(&store, "admin".into(), compare.clone())
        .await
        .unwrap();
    assert!(
        workflow::cancel(&store, "admin".into(), compare)
            .await
            .is_err()
    );
    assert!(
        local
            .read(
                |db| Ok(db.query_row("SELECT count(*) FROM quality_jobs", [], |r| r
                    .get::<_, i64>(0))?)
            )
            .await
            .unwrap()
            == 0
    );
    db.execute(
        "UPDATE noisefence.users SET disabled=true WHERE username='admin'",
        &[],
    )
    .await
    .unwrap();
    assert!(
        workflow::cancel(&store, "admin".into(), eval)
            .await
            .is_err()
    );
    assert!(workflow::list(&store, "admin".into()).await.is_err());
    fixture.suspend().await;
    assert!(workflow::list(&store, "other".into()).await.is_err());
    fixture.resume().await;
    drop(db);
    fixture.finish().await;
}
