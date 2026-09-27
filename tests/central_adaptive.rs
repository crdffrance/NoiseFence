#[allow(dead_code)]
mod common;
#[path = "common/postgres.rs"]
mod postgres;
use noisefence::{
    adaptive::{self, Class, Tenant},
    central::outbox,
    native_filter::{Runtime, Settings},
    store::Store,
};

#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn adaptive_truth_and_exports_preserve_tenant_and_evaluation_boundaries() {
    let fixture = postgres::Fixture::new().await;
    let db = fixture.connect().await;
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path()).unwrap();
    let identity = store.run(|db| outbox::initialize(db, "mx1")).await.unwrap();
    fixture.central.register_source(&identity).await.unwrap();
    for (name, admin, grant) in [
        ("admin", true, None),
        ("alice", false, Some("alice@example.test")),
        ("peer", false, Some("alice@example.test")),
        ("bob", false, Some("bob@other.test")),
    ] {
        db.execute(
            "INSERT INTO noisefence.users(username,password,admin) VALUES($1,'unused',$2)",
            &[&name, &admin],
        )
        .await
        .unwrap();
        if let Some(grant) = grant {
            db.execute(
                "INSERT INTO noisefence.grants VALUES($1,$2)",
                &[&name, &grant],
            )
            .await
            .unwrap();
        }
        store
            .run(move |db| {
                db.execute(
                    "INSERT INTO users(username,password,admin) VALUES(?1,'unused',?2)",
                    rusqlite::params![name, admin],
                )?;
                if let Some(grant) = grant {
                    db.execute(
                        "INSERT INTO grants VALUES(?1,?2)",
                        rusqlite::params![name, grant],
                    )?;
                }
                Ok(())
            })
            .await
            .unwrap();
    }
    let native = Runtime::new(Settings {
        adaptive: Some(adaptive::Settings {
            domains: [("example.test".into(), Tenant::default())].into(),
        }),
        ..Default::default()
    })
    .unwrap();
    let mut ids = Vec::new();
    for n in 0..5 {
        let scan = noisefence::engine::Scan {
            complete: true,
            native_filter: Some(native.offline(common::MESSAGE, &["example.test".into()])),
            fingerprint: noisefence::message::digest(format!("campaign-{n}").as_bytes()),
            campaign_simhash: Some(if n >= 3 {
                format!("{:016x}", u64::MAX - (n == 3) as u64)
            } else {
                format!("{:016x}", 0x1234567890abcdefu64 + n)
            }),
            ..Default::default()
        };
        let id = uuid::Uuid::new_v4().to_string();
        ids.push(id.clone());
        store.run(move |db| {
            db.execute("INSERT INTO messages(id,created,sender,scan) VALUES(?1,?2,'private@example.org',?3)",rusqlite::params![id,noisefence::now()-100,serde_json::to_string(&scan)?])?;
            db.execute("INSERT INTO deliveries(message_id,address,destination,hosts,next_attempt) VALUES(?1,'alice@example.test','alice@example.test','[]',0)",[&id])?;
            if n==1 {db.execute("INSERT INTO deliveries(message_id,address,destination,hosts,next_attempt) VALUES(?1,'bob@other.test','bob@other.test','[]',0)",[&id])?;}
            Ok(())
        }).await.unwrap();
    }
    while fixture.central.synchronize_once(&store).await.unwrap() > 0 {}
    let central = store
        .clone()
        .with_management(fixture.central.clone())
        .await
        .unwrap();
    for s in [&store, &central] {
        for id in &ids {
            adaptive::data::label(
                s,
                "alice".into(),
                id.clone(),
                "example.test".into(),
                Some(Class::Phishing),
            )
            .await
            .unwrap();
        }
        adaptive::data::label(
            s,
            "peer".into(),
            ids[2].clone(),
            "example.test".into(),
            Some(Class::Legitimate),
        )
        .await
        .unwrap();
        assert!(
            adaptive::data::label(
                s,
                "bob".into(),
                ids[0].clone(),
                "example.test".into(),
                Some(Class::Spam)
            )
            .await
            .is_err()
        );
        assert!(
            adaptive::data::label(
                s,
                "alice".into(),
                ids[0].clone(),
                "other.test".into(),
                Some(Class::Spam)
            )
            .await
            .is_err()
        );
        let view = adaptive::data::labels(s, "bob".into(), ids[1].clone())
            .await
            .unwrap();
        assert_eq!(
            view["domains"],
            serde_json::json!([{"domain":"other.test","class":null}])
        );
    }
    assert_eq!(
        adaptive::data::labels(&store, "alice".into(), ids[0].clone())
            .await
            .unwrap(),
        adaptive::data::labels(&central, "alice".into(), ids[0].clone())
            .await
            .unwrap()
    );
    let time = noisefence::now() - 1;
    db.execute("UPDATE noisefence.adaptive_labels SET created=$1", &[&time])
        .await
        .unwrap();
    db.execute("INSERT INTO noisefence.quality_reserved(message_id,created,reason) VALUES($1,$2,'independent evaluation')",&[&ids[4],&time]).await.unwrap();
    let reserved = ids[4].clone();
    store.run(move |db| {
        db.execute("UPDATE adaptive_labels SET created=?1",[time])?;
        db.execute("INSERT INTO quality_reserved(message_id,created,reason) VALUES(?1,?2,'independent evaluation')",rusqlite::params![reserved,time])?;
        Ok(())
    }).await.unwrap();
    let old = root.path().join("legacy.jsonl");
    let new = root.path().join("central.jsonl");
    let a = adaptive::data::export(&store, "admin".into(), "example.test".into(), &old)
        .await
        .unwrap();
    let b = adaptive::data::export(&central, "admin".into(), "example.test".into(), &new)
        .await
        .unwrap();
    assert_eq!(a, b);
    assert_eq!(b["exported"], 1);
    assert_eq!(b["excluded"], 2);
    assert_eq!(std::fs::read(&old).unwrap(), std::fs::read(&new).unwrap());
    let (rows, _) = adaptive::data::read(&new).unwrap();
    assert_eq!(rows.len(), 1);
    let encoded = std::fs::read_to_string(&new).unwrap();
    for private in [
        "private@example.org",
        "alice@example.test",
        "bob@other.test",
    ] {
        assert!(!encoded.contains(private));
    }
    assert!(
        adaptive::data::export(
            &central,
            "alice".into(),
            "example.test".into(),
            &root.path().join("denied.jsonl")
        )
        .await
        .is_err()
    );
    // Binary correction invalidates the prior multiclass label atomically.
    fixture
        .central
        .record_feedback("alice", &ids[0], false, None)
        .await
        .unwrap();
    assert!(
        adaptive::data::labels(&central, "alice".into(), ids[0].clone())
            .await
            .unwrap()["domains"][0]["class"]
            .is_null()
    );
    adaptive::data::label(
        &central,
        "alice".into(),
        ids[0].clone(),
        "example.test".into(),
        Some(Class::Publicity),
    )
    .await
    .unwrap();
    let feedback=db.query_one("SELECT spam,category FROM noisefence.feedback WHERE username='alice' AND message_id=$1",&[&ids[0]]).await.unwrap();
    assert!(!feedback.get::<_, bool>(0));
    assert_eq!(feedback.get::<_, String>(1), "publicity");
    adaptive::data::label(
        &central,
        "alice".into(),
        ids[0].clone(),
        "example.test".into(),
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        db.query_one(
            "SELECT category FROM noisefence.feedback WHERE username='alice' AND message_id=$1",
            &[&ids[0]]
        )
        .await
        .unwrap()
        .get::<_, String>(0),
        "publicity"
    );
    db.execute("DELETE FROM noisefence.grants WHERE username='alice'", &[])
        .await
        .unwrap();
    assert!(
        adaptive::data::labels(&central, "alice".into(), ids[0].clone())
            .await
            .is_err()
    );
    assert!(
        adaptive::data::label(
            &central,
            "alice".into(),
            ids[0].clone(),
            "example.test".into(),
            Some(Class::Spam)
        )
        .await
        .is_err()
    );
    fixture.suspend().await;
    assert!(
        adaptive::data::labels(&central, "peer".into(), ids[2].clone())
            .await
            .is_err()
    );
    assert!(
        adaptive::data::labels(&store, "peer".into(), ids[2].clone())
            .await
            .is_ok()
    );
    fixture.resume().await;
    drop(db);
    fixture.finish().await;
}
