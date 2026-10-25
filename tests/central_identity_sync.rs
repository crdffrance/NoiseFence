#[path = "common/postgres.rs"]
mod postgres;
use noisefence::identity::sync::{self, Event, Failure, Outcome, Request};
#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn central_sync_receipts_are_authorized_durable_and_serialize_competing_collectors() {
    let fixture = postgres::Fixture::new().await;
    let db = fixture.connect().await;
    let now = noisefence::now();
    let session = "a".repeat(64);
    db.execute("INSERT INTO noisefence.users(username,password,admin) VALUES('admin','unused',true),('user','unused',false)",&[]).await.unwrap();
    db.execute("INSERT INTO noisefence.sessions(token_hash,username,csrf,expires) VALUES($1,'admin','csrf',$2)",&[&session,&(now+3600)]).await.unwrap();
    let req = Request {
        id: uuid::Uuid::new_v4().to_string(),
        runner: uuid::Uuid::new_v4().to_string(),
        source_id: "entra".into(),
        revision: 0,
        catalog_sha256: None,
        created: now,
        deadline: now + 360,
    };
    assert!(
        fixture
            .central
            .identity_sync_begin(&req, "user", &session)
            .await
            .is_err()
    );
    let (one, two) = tokio::join!(
        fixture.central.identity_sync_begin(&req, "admin", &session),
        fixture.central.identity_sync_begin(&req, "admin", &session)
    );
    assert_ne!(one.is_ok(), two.is_ok());
    let raw = fixture
        .central
        .identity_sync_read(&req.id, "admin", &session)
        .await
        .unwrap();
    assert_eq!(sync::latest(&raw).unwrap().len(), 1);
    db.execute(
        "UPDATE noisefence.users SET disabled=true WHERE username='admin'",
        &[],
    )
    .await
    .unwrap();
    assert!(
        fixture
            .central
            .identity_sync_read(&req.id, "admin", &session)
            .await
            .is_err()
    );
    let event = Event {
        request: req.clone(),
        outcome: Outcome::Failed {
            reason: Failure::Authorization,
        },
    };
    fixture
        .central
        .identity_sync_finish(&event, "admin")
        .await
        .unwrap();
    assert!(
        fixture
            .central
            .identity_sync_finish(&event, "admin")
            .await
            .is_err()
    );
    db.execute(
        "UPDATE noisefence.users SET disabled=false WHERE username='admin'",
        &[],
    )
    .await
    .unwrap();
    let new = noisefence::central::Central::new(&fixture.settings).unwrap();
    let raw = new
        .identity_sync_read(&req.id, "admin", &session)
        .await
        .unwrap();
    assert!(matches!(
        sync::latest(&raw).unwrap()[&req.id].outcome,
        Outcome::Failed { .. }
    ));
    assert_eq!(
        db.query_one(
            "SELECT count(*) FROM noisefence.schema_migrations WHERE version=1",
            &[]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        1
    );
    assert_eq!(
        db.query_one("SELECT count(*) FROM noisefence.policy_revisions", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    drop(new);
    fixture.finish().await;
}
