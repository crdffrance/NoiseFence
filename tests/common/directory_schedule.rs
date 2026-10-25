use noisefence::{
    identity::{
        connections::{Record, Reference, vault::Key},
        schedule::{Grant, PROTOCOL},
        sync::{Event, Failure, Outcome, Request},
    },
    store::Store,
};
use std::path::Path;
pub fn reference(record: &Record) -> Reference {
    Reference {
        source_id: record.metadata.source.id.clone(),
        generation: record.metadata.generation.clone(),
    }
}
pub async fn enable(
    store: &Store,
    root: &Path,
    session: &str,
    record: &Record,
    expected: Option<String>,
) -> Grant {
    let now = noisefence::now();
    let grant = Grant {
        protocol: PROTOCOL.into(),
        id: uuid::Uuid::new_v4().to_string(),
        connection: reference(record),
        created: now,
        expires: now + 1800,
        interval_seconds: 900,
    };
    store
        .identity_schedule_save(
            reference(record),
            expected,
            grant.clone(),
            Key::load(root).unwrap(),
            "admin".into(),
            session.into(),
        )
        .await
        .unwrap();
    grant
}
pub fn request(record: &Record) -> Request {
    let now = noisefence::now();
    Request {
        connection: Some(reference(record)),
        scheduled: Some(
            record
                .schedule
                .as_ref()
                .unwrap()
                .binding(&record.metadata)
                .unwrap(),
        ),
        id: uuid::Uuid::new_v4().to_string(),
        source_id: record.metadata.source.id.clone(),
        runner: uuid::Uuid::new_v4().to_string(),
        revision: 0,
        catalog_sha256: None,
        created: now,
        deadline: now + 360,
    }
}
/// Same contract is exercised through SQLite and selected PostgreSQL Store APIs.
pub async fn exercise(store: &Store, root: &Path, session: &str, record: &Record) {
    assert!(store.identity_schedule_due(0).await.unwrap().is_empty());
    let grant = enable(store, root, session, record, None).await;
    let rows = store.identity_schedule_due(0).await.unwrap();
    assert_eq!(rows.len(), 1);
    let public = serde_json::to_string(
        &store
            .identity_connection_list("admin".into(), session.into())
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(
        !public.contains("signature") && !public.contains("sealed") && !public.contains("SECRET")
    );
    let mut competing = grant.clone();
    competing.id = uuid::Uuid::new_v4().to_string();
    assert!(
        store
            .identity_schedule_save(
                reference(record),
                None,
                competing,
                Key::load(root).unwrap(),
                "admin".into(),
                session.into()
            )
            .await
            .is_err()
    );
    let req = request(&rows[0]);
    let mut second = req.clone();
    second.id = uuid::Uuid::new_v4().to_string();
    let (a, b) = tokio::join!(
        store.identity_schedule_claim(req.clone(), Key::load(root).unwrap()),
        store.identity_schedule_claim(second.clone(), Key::load(root).unwrap())
    );
    assert_ne!(a.is_ok(), b.is_ok());
    let winner = if a.is_ok() { req } else { second };
    store
        .identity_schedule_authorized(winner.clone())
        .await
        .unwrap();
    assert!(store.identity_schedule_due(0).await.unwrap().is_empty());
    store
        .identity_schedule_finish(
            Event {
                request: winner.clone(),
                outcome: Outcome::Failed {
                    reason: Failure::Collection,
                },
            },
            "admin".into(),
        )
        .await
        .unwrap();
    assert!(store.identity_schedule_authorized(winner).await.is_err());
    let live = store
        .identity_connection_get(
            record.metadata.source.id.clone(),
            record.metadata.generation.clone(),
            "admin".into(),
            session.into(),
        )
        .await
        .unwrap();
    let schedule = live.schedule.unwrap();
    assert_eq!(schedule.failures, 1);
    assert!(schedule.next_due >= noisefence::now() + 1790);
    assert!(store.identity_schedule_due(0).await.unwrap().is_empty());
    store
        .identity_schedule_stop(
            reference(record),
            grant.id.clone(),
            "admin".into(),
            session.into(),
        )
        .await
        .unwrap();
    store
        .identity_schedule_stop(
            reference(record),
            grant.id.clone(),
            "admin".into(),
            session.into(),
        )
        .await
        .unwrap();
    assert!(
        store
            .identity_schedule_save(
                reference(record),
                Some(grant.id.clone()),
                grant.clone(),
                Key::load(root).unwrap(),
                "admin".into(),
                session.into()
            )
            .await
            .is_err()
    );
    let replacement = enable(store, root, session, record, Some(grant.id.clone())).await;
    assert!(
        store
            .identity_schedule_stop(reference(record), grant.id, "admin".into(), session.into())
            .await
            .is_err()
    );
    let row = store.identity_schedule_due(0).await.unwrap().remove(0);
    let req = request(&row);
    store
        .identity_schedule_claim(req.clone(), Key::load(root).unwrap())
        .await
        .unwrap();
    store
        .identity_schedule_stop(
            reference(record),
            replacement.id,
            "admin".into(),
            session.into(),
        )
        .await
        .unwrap();
    assert!(
        store
            .identity_schedule_authorized(req.clone())
            .await
            .is_err()
    );
    store
        .identity_schedule_finish(
            Event {
                request: req,
                outcome: Outcome::Failed {
                    reason: Failure::Authorization,
                },
            },
            "admin".into(),
        )
        .await
        .unwrap();
    assert!(store.identity_schedule_due(0).await.unwrap().is_empty());
}
