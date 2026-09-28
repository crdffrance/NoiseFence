#[allow(dead_code)]
mod common;
#[path = "common/fusion.rs"]
mod fusion;
#[path = "common/postgres.rs"]
mod postgres;
use noisefence::{
    central::outbox,
    engine::Scan,
    evidence::{AuthResult, State},
    message::digest,
    quality, runtime_history,
    store::Store,
};
#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn local_detector_cache_preserves_votes_scopes_freshness_and_read_only_smtp() {
    let f = postgres::Fixture::new().await;
    let pg = f.connect().await;
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path()).unwrap();
    let identity = store.run(|db| outbox::initialize(db, "mx1")).await.unwrap();
    f.central.register_source(&identity).await.unwrap();
    pg.execute(
        "INSERT INTO noisefence.users(username,password,admin) VALUES('reviewer','unused',true)",
        &[],
    )
    .await
    .unwrap();
    store
        .run(|db| {
            db.execute(
                "INSERT INTO users(username,password,admin) VALUES('reviewer','unused',1)",
                [],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    let cfg = common::config(root.path());
    let (_, mut evidence) = fusion::fixture(&cfg);
    evidence.authentication.dmarc_state = State::Complete;
    evidence.authentication.dmarc_dkim = Some(AuthResult::Pass);
    let raw = format!(
        "From: Sender <sender@example.org>\r\nTo: alice@example.test\r\nSubject: PRIVATE SUBJECT\r\n\r\n{}",
        (0..150)
            .map(|i| format!(
                "lex{}{}word ",
                (b'a' + i / 26) as char,
                (b'a' + i % 26) as char
            ))
            .collect::<String>()
    );
    let native = noisefence::native_filter::Runtime::new(Default::default()).unwrap();
    let observation = native.offline(raw.as_bytes(), &["example.test".into()]);
    let features = observation.features.clone().unwrap();
    assert!(features.text_shingles >= 24);
    let scan = Scan {
        evidence: Some(evidence),
        features_complete: Some(true),
        complete: true,
        native_filter: Some(observation),
        protection: Some(noisefence::protection::Report {
            local_status: noisefence::protection::Status::Complete,
            ..Default::default()
        }),
        ..Default::default()
    };
    let scopes = vec!["example.test".into()];
    let recipient = noisefence::config::Recipient {
        address: "alice@example.test".into(),
        destination: "alice@example.test".into(),
        hosts: vec![],
    };
    let targets = Default::default();
    let empty = quality::history::inspect_with_context(
        root.path(),
        raw.as_bytes(),
        &scan,
        &scopes,
        std::slice::from_ref(&recipient),
        &targets,
    )
    .await;
    assert!(empty.key.is_some());
    for n in 0..5 {
        let mut old = scan.clone();
        old.fingerprint = digest(format!("campaign-{n}").as_bytes());
        old.raw_sha256 = Some(digest(format!("raw-{n}").as_bytes()));
        old.campaign_simhash = Some("fedcba9876543210".into());
        old.features = vec![(1, 1.); 80];
        old.sender_history = Some(empty.clone());
        old.subject = "PRIVATE SUBJECT".into();
        let id = uuid::Uuid::new_v4().to_string();
        let key = id.clone();
        let created = noisefence::now() - (n + 1) * 86400;
        store.run(move |db| {
            db.execute("INSERT INTO messages(id,created,sender,scan) VALUES(?1,?2,'sender@example.org',?3)",rusqlite::params![id,created,serde_json::to_string(&old)?])?;
            db.execute("INSERT INTO deliveries(message_id,address,destination,hosts,next_attempt) VALUES(?1,'alice@example.test','alice@example.test','[]',0)",[&id])?;
            db.execute("INSERT INTO feedback(username,message_id,spam,created) VALUES('reviewer',?1,0,?2)",rusqlite::params![id,created+1])?;Ok(())
        }).await.unwrap();
        while f.central.synchronize_once(&store).await.unwrap() > 0 {}
        pg.execute("INSERT INTO noisefence.feedback(username,message_id,spam,created) VALUES('reviewer',$1,false,$2)",&[&key,&(created+1)]).await.unwrap();
    }
    let before = quality::history::inspect_with_context(
        root.path(),
        raw.as_bytes(),
        &scan,
        &scopes,
        std::slice::from_ref(&recipient),
        &targets,
    )
    .await;
    let fuzzy_before =
        noisefence::native_filter::memory::inspect(root.path(), &features, &scopes, "current")
            .await;
    assert!(before.established);
    assert_eq!(before.behavior.as_ref().unwrap().status, "complete");
    assert_eq!(fuzzy_before.legitimate_examples, 5);
    let _central = store
        .clone()
        .with_management(f.central.clone())
        .await
        .unwrap();
    assert_eq!(
        quality::history::inspect(root.path(), raw.as_bytes(), &scan, &scopes)
            .await
            .status,
        "unavailable"
    );
    let snapshot = f.central.runtime_history(None).await.unwrap();
    let text = serde_json::to_string(&snapshot).unwrap();
    for secret in [
        "PRIVATE SUBJECT",
        "sender@example.org",
        "alice@example.test",
        "reviewer",
        "password",
    ] {
        assert!(!text.contains(secret));
    }
    runtime_history::install(root.path(), snapshot.clone())
        .await
        .unwrap();
    let after = quality::history::inspect_with_context(
        root.path(),
        raw.as_bytes(),
        &scan,
        &scopes,
        &[recipient],
        &targets,
    )
    .await;
    assert_eq!(
        serde_json::to_value(&before).unwrap(),
        serde_json::to_value(&after).unwrap()
    );
    assert_eq!(
        serde_json::to_value(&fuzzy_before).unwrap(),
        serde_json::to_value(
            noisefence::native_filter::memory::inspect(root.path(), &features, &scopes, "current")
                .await
        )
        .unwrap()
    );
    assert!(
        runtime_history::install(root.path(), snapshot)
            .await
            .is_err(),
        "replayed generation cannot extend lifetime"
    );
    assert!(
        !quality::history::inspect(root.path(), raw.as_bytes(), &scan, &["other.test".into()])
            .await
            .established
    );
    assert_eq!(
        noisefence::native_filter::memory::inspect(
            root.path(),
            &features,
            &["other.test".into()],
            "current"
        )
        .await
        .matches,
        0
    );
    f.suspend().await;
    assert!(
        quality::history::inspect(root.path(), raw.as_bytes(), &scan, &scopes)
            .await
            .established,
        "fresh local cache needs no PostgreSQL connection"
    );
    let db = rusqlite::Connection::open(root.path().join("runtime-history.sqlite3")).unwrap();
    db.execute(
        "UPDATE snapshot SET created=?1",
        [noisefence::now() - runtime_history::TTL - 1],
    )
    .unwrap();
    drop(db);
    assert_eq!(
        quality::history::inspect(root.path(), raw.as_bytes(), &scan, &scopes)
            .await
            .status,
        "unavailable"
    );
    assert_eq!(
        noisefence::native_filter::memory::inspect(root.path(), &features, &scopes, "current")
            .await
            .status,
        noisefence::native_filter::Status::Unavailable
    );
    f.resume().await;
    let pg = f.connect().await;
    pg.execute(
        "UPDATE noisefence.users SET disabled=true WHERE username='reviewer'",
        &[],
    )
    .await
    .unwrap();
    f.central.refresh_runtime_history(&store).await.unwrap();
    let now = quality::history::inspect(root.path(), raw.as_bytes(), &scan, &scopes).await;
    assert_eq!(now.status, "complete");
    assert!(!now.established);
    assert_eq!(now.legitimate_campaigns, 0);
    // Unlabelled messages still occupy the campaign detector's recent window.
    assert_eq!(
        runtime_history::open(root.path())
            .unwrap()
            .query_row("SELECT count(*) FROM messages", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        5
    );
    let path = root.path().join("runtime-history.sqlite3");
    std::fs::write(&path, b"damaged disposable cache").unwrap();
    assert!(runtime_history::open(root.path()).is_err());
    f.central.refresh_runtime_history(&store).await.unwrap();
    assert!(runtime_history::open(root.path()).is_ok());
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute(
        "UPDATE snapshot SET generation=9223372036854775807,created=?1",
        [noisefence::now() - runtime_history::TTL - 1],
    )
    .unwrap();
    drop(db);
    f.central.refresh_runtime_history(&store).await.unwrap();
    assert!(
        runtime_history::open(root.path()).is_ok(),
        "expired cache can recover after a database restore resets the sequence"
    );
    store
        .run(|db| {
            db.execute(
                "UPDATE cluster_state SET value='unsupported' WHERE key='runtime_history_protocol'",
                [],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    assert!(runtime_history::open(root.path()).is_err());
    drop(pg);
    f.finish().await;
}
