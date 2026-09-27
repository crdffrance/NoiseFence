#[allow(dead_code)]
mod common;
#[path = "common/postgres.rs"]
mod postgres;
use noisefence::{
    central::outbox,
    engine::{Engine, Signal},
    search::Search,
    store::Store,
};
use serde_json::json;

#[tokio::test]
#[ignore = "requires disposable PostgreSQL on 127.0.0.1:15432 and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn central_search_preserves_scoped_results_scores_phrases_and_pagination() {
    let fixture = postgres::Fixture::new().await;
    let db = fixture.connect().await;
    let root = tempfile::tempdir().unwrap();
    let cfg = common::config(root.path());
    let engine = Engine::new(cfg).unwrap();
    let store = Store::open(root.path()).unwrap();
    let identity = store.run(|db| outbox::initialize(db, "mx1")).await.unwrap();
    fixture.central.register_source(&identity).await.unwrap();
    for (name, grant) in [
        ("alice", "alice@example.test"),
        ("hidden", "hidden@example.test"),
        ("owner", "*@example.test"),
    ] {
        db.execute(
            "INSERT INTO noisefence.users(username,password) VALUES($1,'synthetic-not-a-login')",
            &[&name],
        )
        .await
        .unwrap();
        db.execute(
            "INSERT INTO noisefence.grants VALUES($1,$2)",
            &[&name, &grant],
        )
        .await
        .unwrap();
        let name = name.to_owned();
        let grant = grant.to_owned();
        store
            .run(move |db| {
                db.execute(
                    "INSERT INTO users(username,password) VALUES(?1,'synthetic-not-a-login')",
                    [&name],
                )?;
                db.execute(
                    "INSERT INTO grants VALUES(?1,?2)",
                    rusqlite::params![name, grant],
                )?;
                Ok(())
            })
            .await
            .unwrap();
    }
    let mut records = Vec::new();
    for n in 1..=56u128 {
        let subject = match n {
            1 => "Café demain confirmé",
            2 => "Private needle message",
            _ => "Routine synthetic notice",
        };
        let raw = format!(
            "From: sender@example.org\r\nTo: alice@example.test\r\nSubject: {subject}\r\nDate: Sun, 06 Sep 2026 12:00:00 +0000\r\nMessage-ID: <{n}@example.org>\r\n\r\nHello, this is a synthetic fixture.\r\n"
        );
        let mut scan = engine.offline(raw.as_bytes());
        scan.reasons.push(Signal {
            id: "synthetic_rule".into(),
            detail: "Do not index this explanation".into(),
            weight: 0.0,
        });
        records.push((
            uuid::Uuid::from_u128(n).to_string(),
            serde_json::to_string(&scan).unwrap(),
            n,
        ));
    }
    store.run(move |db| {
        let tx=db.transaction()?;
        for (id,scan,n) in records {
            tx.execute("INSERT INTO messages(id,created,sender,scan) VALUES(?1,?2,'sender@example.org',?3)",rusqlite::params![id,noisefence::now(),scan])?;
            let recipients=match n {1=>vec!["alice@example.test","hidden@example.test"],2=>vec!["hidden@example.test"],_=>vec!["alice@example.test"]};
            for recipient in recipients {
                tx.execute("INSERT INTO deliveries(message_id,address,destination,hosts,next_attempt) VALUES(?1,?2,?2,'[]',0)",rusqlite::params![id,recipient])?;
            }
        }
        tx.commit()?;
        Ok(())
    }).await.unwrap();
    while fixture.central.synchronize_once(&store).await.unwrap() > 0 {}
    let central_store = store
        .clone()
        .with_management(fixture.central.clone())
        .await
        .unwrap();
    let cases = vec![
        Search::default(),
        Search {
            offset: 50,
            ..Default::default()
        },
        Search {
            q: "cafe".into(),
            ..Default::default()
        },
        Search {
            subject: "\"cafe demain\"".into(),
            ..Default::default()
        },
        Search {
            q: "confi".into(),
            ..Default::default()
        },
        Search {
            rule: "synthetic".into(),
            ..Default::default()
        },
        Search {
            q: "explanation".into(),
            ..Default::default()
        },
        Search {
            q: "hidden".into(),
            ..Default::default()
        },
        Search {
            recipient: "hidden".into(),
            ..Default::default()
        },
        Search {
            sender: "sender@example".into(),
            ..Default::default()
        },
        Search {
            domain: "other.test".into(),
            ..Default::default()
        },
        Search {
            min_score: Some(0.0),
            max_score: Some(100.0),
            ..Default::default()
        },
        Search {
            node: "local".into(),
            ..Default::default()
        },
    ];
    for username in ["alice", "hidden", "owner"] {
        for options in &cases {
            let local = store
                .search_messages_with_policy(username.into(), options.clone(), 95.0, false)
                .await
                .unwrap();
            let central = central_store
                .search_messages_with_policy(username.into(), options.clone(), 95.0, false)
                .await
                .unwrap();
            assert_eq!(
                serde_json::to_value(central).unwrap(),
                serde_json::to_value(local).unwrap(),
                "search parity: {username}, {options:?}"
            );
        }
        for filter in [
            "spam",
            "legitimate",
            "publicity",
            "publicity_signal",
            "review",
            "incomplete",
            "pending",
            "quarantined",
            "rspamd_all",
            "rspamd_disagreement",
            "rspamd_inconclusive",
            "rspamd_unavailable",
        ] {
            let options = Search {
                filter: filter.into(),
                ..Default::default()
            };
            let local = store
                .search_messages_with_policy(username.into(), options.clone(), 95.0, false)
                .await
                .unwrap();
            let central = central_store
                .search_messages_with_policy(username.into(), options, 95.0, false)
                .await
                .unwrap();
            assert_eq!(
                serde_json::to_value(central).unwrap(),
                serde_json::to_value(local).unwrap(),
                "filter parity: {username}, {filter}"
            );
        }
    }
    let hidden = central_store
        .search_messages_with_policy(
            "alice".into(),
            Search {
                q: "hidden".into(),
                ..Default::default()
            },
            95.0,
            false,
        )
        .await
        .unwrap();
    assert_eq!(
        hidden.total, 0,
        "a BCC address must not influence another user's matches"
    );
    let hidden = central_store
        .search_messages_with_policy(
            "alice".into(),
            Search {
                q: "needle".into(),
                ..Default::default()
            },
            95.0,
            false,
        )
        .await
        .unwrap();
    assert_eq!(
        hidden.total, 0,
        "private messages must not influence counts"
    );
    let first = central_store
        .search_messages_with_policy("alice".into(), Search::default(), 95.0, false)
        .await
        .unwrap();
    assert_eq!(first.total, 55);
    assert_eq!(first.messages.len(), 50);
    assert!(first.has_more);
    let id = uuid::Uuid::from_u128(1).to_string();
    let private = uuid::Uuid::from_u128(2).to_string();
    assert!(
        central_store
            .feedback("alice".into(), private, true)
            .await
            .is_err()
    );
    central_store
        .feedback_category(
            "alice".into(),
            id.clone(),
            noisefence::mailing::FeedbackCategory::Publicity,
        )
        .await
        .unwrap();
    let query = Search {
        id: id.clone(),
        ..Default::default()
    };
    let labelled = central_store
        .search_messages_with_policy("alice".into(), query.clone(), 95.0, false)
        .await
        .unwrap();
    assert_eq!(labelled.messages[0].feedback, Some(false));
    assert_eq!(
        labelled.messages[0].feedback_category,
        Some(noisefence::mailing::FeedbackCategory::Publicity)
    );
    assert_eq!(
        store
            .search_messages_with_policy("alice".into(), query.clone(), 95.0, false)
            .await
            .unwrap()
            .messages[0]
            .feedback,
        None
    );
    central_store
        .feedback("alice".into(), id.clone(), true)
        .await
        .unwrap();
    let labelled = central_store
        .search_messages_with_policy("alice".into(), query, 95.0, false)
        .await
        .unwrap();
    assert_eq!(labelled.messages[0].feedback, Some(true));
    assert_eq!(labelled.messages[0].feedback_category, None);
    db.execute(
        "INSERT INTO noisefence.quality_reserved VALUES($1,$2,'synthetic holdout')",
        &[&id, &noisefence::now()],
    )
    .await
    .unwrap();
    let count: i64 = db
        .query_one(
            "SELECT count(*) FROM noisefence.training_feedback WHERE message_id=$1",
            &[&id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        count, 0,
        "holdout annotations must not leak into training feedback"
    );
    assert_eq!(
        fixture.central.stats("alice", "").await.unwrap()["received"],
        55
    );
    assert_eq!(
        fixture.central.stats("alice", "other.test").await.unwrap()["received"],
        0
    );
    db.execute(
        "UPDATE noisefence.users SET disabled=true WHERE username='alice'",
        &[],
    )
    .await
    .unwrap();
    assert!(
        central_store
            .feedback("alice".into(), id, true)
            .await
            .is_err()
    );
    assert_eq!(
        central_store
            .search_messages_with_policy("alice".into(), Search::default(), 95.0, false)
            .await
            .unwrap()
            .total,
        0
    );
    assert_eq!(
        store
            .search_messages_with_policy("alice".into(), Search::default(), 95.0, false)
            .await
            .unwrap()
            .total,
        55,
        "central revocation must take precedence over stale local access"
    );
    let result = serde_json::to_value(first).unwrap();
    assert_ne!(result, json!(null));
    drop(central_store);
    drop(db);
    fixture.finish().await;
}
