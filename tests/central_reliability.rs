#[allow(dead_code)]
mod common;
#[path = "common/postgres.rs"]
mod postgres;
use noisefence::{
    central::outbox,
    reliability::{self, Options},
    store::Store,
};

#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn reliability_preserves_scopes_labels_and_refuses_local_fallback() {
    let f = postgres::Fixture::new().await;
    let pg = f.connect().await;
    let root = tempfile::tempdir().unwrap();
    let local = Store::open(root.path()).unwrap();
    let identity = local.run(|db| outbox::initialize(db, "mx1")).await.unwrap();
    f.central.register_source(&identity).await.unwrap();
    for (user, grant) in [("alice", "alice@example.test"), ("owner", "*@example.test")] {
        pg.execute(
            "INSERT INTO noisefence.users(username,password) VALUES($1,'unused')",
            &[&user],
        )
        .await
        .unwrap();
        pg.execute(
            "INSERT INTO noisefence.grants VALUES($1,$2)",
            &[&user, &grant],
        )
        .await
        .unwrap();
        local
            .run(move |db| {
                db.execute(
                    "INSERT INTO users(username,password) VALUES(?1,'unused')",
                    [user],
                )?;
                db.execute(
                    "INSERT INTO grants VALUES(?1,?2)",
                    rusqlite::params![user, grant],
                )?;
                Ok(())
            })
            .await
            .unwrap();
    }
    let now = noisefence::now();
    let engine = noisefence::engine::Engine::new(common::config(root.path())).unwrap();
    let scan = serde_json::to_string(&engine.offline(common::MESSAGE)).unwrap();
    local.run(move |db| {
        for n in 0..8u128 {
            let id = uuid::Uuid::from_u128(500+n).to_string();
            let created = now - if n == 4 { 20 * 86400 } else if n == 5 { -240 } else { 100 };
            let raw = &scan;
            db.execute("INSERT INTO messages(id,created,sender,scan,is_dsn) VALUES(?1,?2,'PRIVATE@example.org',?3,?4)", rusqlite::params![id,created,raw,n==7])?;
            let recipients = if n == 3 { vec!["hidden@example.test"] } else { vec!["alice@example.test", "hidden@example.test"] };
            for address in recipients {
                db.execute("INSERT INTO deliveries(message_id,address,destination,hosts,next_attempt) VALUES(?1,?2,?2,'[]',0)", rusqlite::params![id,address])?;
            }
            if n == 0 { db.execute("INSERT INTO quality_labels VALUES('alice',?1,'legitimate',NULL,?2)", rusqlite::params![id,now])?; }
            if n == 1 { db.execute("INSERT INTO feedback(username,message_id,spam,created) VALUES('alice',?1,1,?2)", rusqlite::params![id,now])?; }
            // A label predating the message must not count as evaluation truth.
            if n == 2 { db.execute("INSERT INTO quality_labels VALUES('alice',?1,'spam',NULL,?2)", rusqlite::params![id,created-1])?; }
        }
        Ok(())
    }).await.unwrap();
    while f.central.synchronize_once(&local).await.unwrap() > 0 {}
    let invalid = uuid::Uuid::from_u128(506).to_string();
    pg.execute(
        "UPDATE noisefence.messages SET scan='{\"score\":\"invalid\"}'::jsonb WHERE id=$1",
        &[&invalid],
    )
    .await
    .unwrap();
    local
        .run(move |db| {
            db.execute(
                "UPDATE messages SET scan='{\"score\":\"invalid\"}' WHERE id=?1",
                [&invalid],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    for (n, risk, created) in [(0, "legitimate", now), (2, "spam", now - 101)] {
        pg.execute(
            "INSERT INTO noisefence.quality_labels VALUES('alice',$1,$2,NULL,$3)",
            &[&uuid::Uuid::from_u128(500 + n).to_string(), &risk, &created],
        )
        .await
        .unwrap();
    }
    pg.execute("INSERT INTO noisefence.feedback(username,message_id,spam,created) VALUES('alice',$1,true,$2)", &[&uuid::Uuid::from_u128(501).to_string(), &now]).await.unwrap();
    let central = local
        .clone()
        .with_management(f.central.clone())
        .await
        .unwrap();
    for (user, domain) in [
        ("alice", ""),
        ("owner", "example.test"),
        ("alice", "hidden.test"),
    ] {
        let options = Options {
            domain: domain.into(),
            ..Default::default()
        };
        let mut expected = reliability::audit(&local, user.into(), options.clone())
            .await
            .unwrap();
        let mut actual = reliability::audit(&central, user.into(), options)
            .await
            .unwrap();
        if user == "alice" && domain.is_empty() {
            assert_eq!(actual["observations"]["messages"], 3);
            assert_eq!(actual["invalid_scans"], 1);
            assert_eq!(actual["quality_labels"]["labelled"], 1);
            assert_eq!(actual["targeted_feedback"]["labelled"], 1);
            assert!(!actual.to_string().contains("PRIVATE"));
            assert!(!actual.to_string().contains("hidden@example.test"));
        }
        for report in [&mut expected, &mut actual] {
            report.as_object_mut().unwrap().remove("checked_at");
            report.as_object_mut().unwrap().remove("since");
        }
        assert_eq!(expected, actual);
    }
    pg.execute("DELETE FROM noisefence.grants WHERE username='alice'", &[])
        .await
        .unwrap();
    assert_eq!(
        reliability::audit(&central, "alice".into(), Options::default())
            .await
            .unwrap()["observations"]["messages"],
        0
    );
    pg.execute(
        "UPDATE noisefence.users SET disabled=true WHERE username='owner'",
        &[],
    )
    .await
    .unwrap();
    assert!(
        reliability::audit(&central, "owner".into(), Options::default())
            .await
            .is_err()
    );
    assert!(
        reliability::audit(&central, "missing".into(), Options::default())
            .await
            .is_err()
    );
    f.suspend().await;
    assert!(
        reliability::audit(&central, "alice".into(), Options::default())
            .await
            .is_err()
    );
    assert_eq!(
        reliability::audit(&local, "alice".into(), Options::default())
            .await
            .unwrap()["observations"]["messages"],
        3
    );
    f.resume().await;
    drop(pg);
    f.finish().await;
}
