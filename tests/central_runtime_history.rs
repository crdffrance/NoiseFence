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
async fn credential_reads_allow_status_updates_but_respect_revocation_locks() {
    let f = postgres::Fixture::new().await;
    let peer = outbox::Identity {
        node: "mx2".into(),
        epoch: uuid::Uuid::new_v4().to_string(),
    };
    let hash = "a".repeat(64);
    f.central.register_source(&peer).await.unwrap();
    f.central
        .enroll_node(&peer, "Secondary", &hash)
        .await
        .unwrap();
    let authenticated = f
        .central
        .authenticate_node("mx2", &hash)
        .await
        .unwrap()
        .unwrap();
    let mut writer = f.connect().await;
    let tx = writer.transaction().await.unwrap();
    tx.execute(
        "UPDATE noisefence.cluster_nodes SET last_seen=100 WHERE node='mx2'",
        &[],
    )
    .await
    .unwrap();
    // Held until after the real authenticated history read: old FOR SHARE
    // waits for this unrelated status update and hits lock_timeout=500ms.
    f.central
        .runtime_history(Some(&authenticated))
        .await
        .unwrap();
    tx.commit().await.unwrap();

    let tx = writer.transaction().await.unwrap();
    tx.query_one(
        "SELECT node FROM noisefence.cluster_nodes WHERE node='mx2' FOR UPDATE",
        &[],
    )
    .await
    .unwrap();
    let error = f
        .central
        .runtime_history(Some(&authenticated))
        .await
        .err()
        .unwrap();
    assert!(
        error.to_string().contains("55P03"),
        "revocation must retain exclusive protection"
    );
    tx.execute(
        "UPDATE noisefence.cluster_nodes SET token_hash=$1 WHERE node='mx2'",
        &[&"b".repeat(64)],
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert!(
        f.central
            .runtime_history(Some(&authenticated))
            .await
            .is_err()
    );
    assert!(
        f.central
            .authenticate_node("mx2", &hash)
            .await
            .unwrap()
            .is_none()
    );

    let now = noisefence::now();
    assert_eq!(
        f.central.worker_health(60).await.unwrap()["stale_workers"],
        1
    );
    writer
        .execute(
            "UPDATE noisefence.cluster_nodes SET last_seen=$1 WHERE node='mx2'",
            &[&now],
        )
        .await
        .unwrap();
    assert_eq!(
        f.central.worker_health(60).await.unwrap()["stale_workers"],
        0
    );
    writer
        .execute(
            "UPDATE noisefence.cluster_nodes SET last_seen=$1 WHERE node='mx2'",
            &[&(now + 3600)],
        )
        .await
        .unwrap();
    assert_eq!(
        f.central.worker_health(60).await.unwrap()["stale_workers"],
        1
    );
    writer
        .execute(
            "UPDATE noisefence.cluster_nodes SET enabled=false WHERE node='mx2'",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(f.central.worker_health(60).await.unwrap()["workers"], 0);
    f.finish().await;
}
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
    // Sender votes and policy features must be identical across backends.
    // Diagnostic recency advances with wall time between the two inspections.
    let mut before_json = serde_json::to_value(&before).unwrap();
    let mut after_json = serde_json::to_value(&after).unwrap();
    before_json.as_object_mut().unwrap().remove("recency");
    after_json.as_object_mut().unwrap().remove("recency");
    assert_eq!(before_json, after_json);
    let a = after.recency.as_ref().unwrap();
    let b = before.recency.as_ref().unwrap();
    let elapsed = a.evaluated_at - b.evaluated_at;
    assert!(elapsed >= 0);
    assert_eq!(a.half_life_days, b.half_life_days);
    assert_eq!(
        a.last_seen_age_seconds,
        b.last_seen_age_seconds.map(|age| age + elapsed as u64)
    );
    let decay = 2f64.powf(-(elapsed as f64) / (14. * 86400.));
    assert!((a.wanted_weight - b.wanted_weight * decay).abs() < 1e-12);
    assert!((a.unwanted_weight - b.unwanted_weight * decay).abs() < 1e-12);
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

#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn automatic_correspondence_projects_unlabelled_messages_and_human_vetoes() {
    use noisefence::identity::learning::{self, Observation, Settings};
    let f = postgres::Fixture::new().await;
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path()).unwrap();
    let identity = store.run(|db| outbox::initialize(db, "mx1")).await.unwrap();
    f.central.register_source(&identity).await.unwrap();
    let cfg = common::config(root.path());
    let mut scan = noisefence::engine::Engine::new(cfg.clone())
        .unwrap()
        .offline(common::MESSAGE);
    let e = scan.evidence.as_mut().unwrap();
    e.source = noisefence::evidence::Source::SmtpSession;
    e.authentication.dmarc_state = State::Complete;
    e.authentication.dmarc_dkim = Some(AuthResult::Pass);
    let recipient = cfg.recipient("alice@example.test").unwrap();
    let targets = Default::default();
    let key = noisefence::identity::memory_key::Key::install(root.path(), None).unwrap();
    let sample =
        learning::capture(&key, common::MESSAGE, &scan, &recipient.address, &targets).unwrap();
    let now = noisefence::now();
    let mut ids = Vec::new();
    for n in 1..=6 {
        let mut captured = sample.clone();
        captured.campaign = digest(format!("contact campaign {n}").as_bytes());
        let mut accepted = scan.clone();
        accepted.contact_learning = Some(Observation {
            report: Default::default(),
            sample: Some(captured),
        });
        let id = uuid::Uuid::new_v4().to_string();
        ids.push(id.clone());
        store.run(move |db| {
            db.execute("INSERT INTO messages(id,created,sender,scan) VALUES(?1,?2,'sender@example.org',?3)",rusqlite::params![id,now-n*86400,serde_json::to_string(&accepted)?])?;
            db.execute("INSERT INTO deliveries(message_id,address,destination,hosts,next_attempt) VALUES(?1,'alice@example.test','alice@example.test','[]',0)",[&id])?;Ok(())
        }).await.unwrap();
    }
    while f.central.synchronize_once(&store).await.unwrap() > 0 {}
    let snapshot = f.central.runtime_history(None).await.unwrap();
    let contacts = snapshot.contacts.as_ref().unwrap();
    assert_eq!(contacts.rows.len(), 6);
    assert!(contacts.rows.iter().all(|r| r.unwanted_at.is_none()));
    assert!(snapshot.rows.iter().all(|r| r.votes.is_empty()));
    let serialized = serde_json::to_string(contacts).unwrap();
    assert!(!serialized.contains("alice@example.test"));
    assert!(!serialized.contains("sender@example.org"));
    noisefence::runtime_history::require(&store).await.unwrap();
    noisefence::runtime_history::install(root.path(), snapshot)
        .await
        .unwrap();
    let history = learning::prepare(
        Some(&key),
        root.path(),
        &Settings {
            key_id: Some(key.id().into()),
            ..Default::default()
        },
        common::MESSAGE,
        &scan,
        std::slice::from_ref(&recipient),
        &targets,
        "sender@example.org",
    )
    .await;
    assert!(history[&recipient.address].report.regular);
    let pg = f.connect().await;
    pg.execute(
        "INSERT INTO noisefence.users(username,password,admin) VALUES('reviewer','unused',true)",
        &[],
    )
    .await
    .unwrap();
    pg.execute("INSERT INTO noisefence.feedback(username,message_id,spam,created) VALUES('reviewer',$1,true,$2)",&[&ids[0],&(now-1)]).await.unwrap();
    let snapshot = f.central.runtime_history(None).await.unwrap();
    assert_eq!(
        snapshot
            .contacts
            .as_ref()
            .unwrap()
            .rows
            .iter()
            .filter(|r| r.unwanted_at.is_some())
            .count(),
        1
    );
    noisefence::runtime_history::install(root.path(), snapshot)
        .await
        .unwrap();
    let history = learning::prepare(
        Some(&key),
        root.path(),
        &Settings {
            key_id: Some(key.id().into()),
            ..Default::default()
        },
        common::MESSAGE,
        &scan,
        std::slice::from_ref(&recipient),
        &targets,
        "sender@example.org",
    )
    .await;
    assert_eq!(history[&recipient.address].report.status, "human_rejected");
    assert!(!history[&recipient.address].report.regular);
    // Mailbox owners can veto their own contact history, not another user's.
    pg.execute(
        "UPDATE noisefence.users SET admin=false WHERE username='reviewer'",
        &[],
    )
    .await
    .unwrap();
    assert!(
        f.central
            .runtime_history(None)
            .await
            .unwrap()
            .contacts
            .unwrap()
            .rows
            .iter()
            .all(|r| r.unwanted_at.is_none())
    );
    pg.execute(
        "INSERT INTO noisefence.grants(username,address) VALUES('reviewer','alice@example.test')",
        &[],
    )
    .await
    .unwrap();
    assert_eq!(
        f.central
            .runtime_history(None)
            .await
            .unwrap()
            .contacts
            .unwrap()
            .rows
            .iter()
            .filter(|r| r.unwanted_at.is_some())
            .count(),
        1
    );
    pg.execute(
        "UPDATE noisefence.users SET disabled=true WHERE username='reviewer'",
        &[],
    )
    .await
    .unwrap();
    assert!(
        f.central
            .runtime_history(None)
            .await
            .unwrap()
            .contacts
            .unwrap()
            .rows
            .iter()
            .all(|r| r.unwanted_at.is_none())
    );
    // A corrupt optional contact observation degrades only this projection.
    pg.execute("UPDATE noisefence.messages SET scan=jsonb_set(scan,'{contact_learning,sample}','{\"protocol\":\"corrupt\"}'::jsonb) WHERE id=$1", &[&ids[0]]).await.unwrap();
    let degraded = f.central.runtime_history(None).await.unwrap();
    assert!(degraded.contacts.as_ref().unwrap().limited);
    assert_eq!(degraded.contacts.as_ref().unwrap().rows.len(), 5);
    assert_eq!(degraded.rows.len(), 6);
    drop(pg);
    f.finish().await;
}
