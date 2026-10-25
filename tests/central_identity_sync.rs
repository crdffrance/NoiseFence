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
    // A ready Google candidate carries bounded coverage through the same selected
    // authority journal. It remains inactive after reconnection.
    use noisefence::identity::{directory, management, runtime};
    let root = tempfile::tempdir().unwrap();
    let source = directory::Source {
        id: "google".into(),
        label: "Synthetic Google".into(),
        provider: directory::Provider::Google,
        authority: "C01234567".into(),
        scopes: std::collections::BTreeSet::from(["example.test".into()]),
        stale_after_seconds: 86400,
    };
    let snapshot = directory::Snapshot {
        schema: directory::SCHEMA.into(),
        source: source.clone(),
        generation: 1,
        completed_at: now,
        people: vec![],
        groups: vec![],
        memberships: Default::default(),
        delegations: Default::default(),
    };
    let empty = runtime::Document {
        schema: runtime::SCHEMA.into(),
        sources: vec![],
    };
    let mut candidate =
        management::preview_collected(&empty, snapshot, &source.scopes, now).unwrap();
    candidate.review.requires_attention = true;
    let selection = new
        .prepare_identity_directory(
            root.path().into(),
            serde_json::to_vec(&candidate.document).unwrap(),
            0,
            "admin",
            &session,
        )
        .await
        .unwrap();
    let req = Request {
        id: uuid::Uuid::new_v4().to_string(),
        source_id: source.id,
        ..req
    };
    new.identity_sync_begin(&req, "admin", &session)
        .await
        .unwrap();
    let Outcome::Ready { prepared } = serde_json::from_value::<Outcome>(serde_json::json!({
        "state": "ready", "prepared": { "revision": 0, "selection": selection, "review": candidate.review, "active": false,
        "collection": { "requests": 3, "pages": 3, "bytes": 500, "excluded_members": { "external_membership": 2 } } }
    })).unwrap() else { panic!("Expected prepared fixture") };
    let mut invalid = prepared.clone();
    invalid.collection.as_mut().unwrap().requests = 0;
    assert!(
        new.identity_sync_finish(
            &Event {
                request: req.clone(),
                outcome: Outcome::Ready { prepared: invalid }
            },
            "admin"
        )
        .await
        .is_err()
    );
    new.identity_sync_finish(
        &Event {
            request: req.clone(),
            outcome: Outcome::Ready {
                prepared: prepared.clone(),
            },
        },
        "admin",
    )
    .await
    .unwrap();
    let reopened = noisefence::central::Central::new(&fixture.settings).unwrap();
    let rows = reopened
        .identity_sync_read(&req.id, "admin", &session)
        .await
        .unwrap();
    let event = sync::latest(&rows).unwrap().remove(&req.id).unwrap();
    let Outcome::Ready { prepared: stored } = event.outcome else {
        panic!("Expected ready receipt")
    };
    assert_eq!(stored.collection, prepared.collection);
    assert_eq!(stored.selection, prepared.selection);
    assert!(!stored.active && stored.review.requires_attention);
    drop(reopened);
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
