mod common;
use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use noisefence::{api, engine::extract, search::Search, store::Store};
use rusqlite::params;
use tower::ServiceExt;

async fn fixture() -> (
    tempfile::TempDir,
    Store,
    std::sync::Arc<noisefence::config::Config>,
) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let cfg = common::config(dir.path());
    for (user, grants, admin) in [
        ("alice", vec!["alice@example.test"], false),
        ("bob", vec!["bob@example.test"], false),
        ("domain", vec!["*@example.test"], false),
        ("admin", vec![], true),
    ] {
        api::create_user(
            &store,
            user.into(),
            "synthetic-password-123".into(),
            grants.into_iter().map(str::to_owned).collect(),
            admin,
        )
        .await
        .unwrap();
    }
    let mut scan = extract(common::MESSAGE, 10000);
    scan.subject = "Réunion équipe facture septembre".into();
    scan.score = 91.2;
    scan.complete = false;
    scan.reasons = vec![noisefence::engine::Signal {
        id: "suspicious_link".into(),
        detail: "Visible rule".into(),
        weight: 1.0,
    }];
    store
        .enqueue(
            "shared-identifier".into(),
            "billing@example.org".into(),
            vec![
                cfg.recipient("alice@example.test").unwrap(),
                cfg.recipient("bob@example.test").unwrap(),
            ],
            scan,
            common::MESSAGE.to_vec(),
        )
        .await
        .unwrap();
    let mut hidden = extract(common::MESSAGE, 10000);
    hidden.subject = "Secret seulement Bob".into();
    store
        .enqueue(
            "hidden".into(),
            "hidden@other.test".into(),
            vec![cfg.recipient("bob@example.test").unwrap()],
            hidden,
            common::MESSAGE.to_vec(),
        )
        .await
        .unwrap();
    store
        .run(|db| {
            db.execute(
                "UPDATE deliveries SET status='quarantined' WHERE address='bob@example.test'",
                [],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    (dir, store, cfg)
}
async fn count(store: &Store, user: &str, options: Search) -> u64 {
    store
        .search_messages(user.into(), options, 80.0)
        .await
        .unwrap()
        .total
}
#[tokio::test]
async fn search_words_phrases_scores_and_acl_are_consistent() {
    let (_dir, store, _) = fixture().await;
    for q in [
        "reunion",
        "EQUIPE",
        "fact sept",
        "\"réunion équipe\"",
        "billing@example.org",
        "suspicious_link",
        "shared-ident",
        "alice@example.test",
    ] {
        assert_eq!(
            count(
                &store,
                "alice",
                Search {
                    q: q.into(),
                    ..Default::default()
                }
            )
            .await,
            1,
            "{q}"
        );
    }
    for q in [
        "\"facture équipe\"",
        "missing",
        "bob@example.test",
        "hidden",
        "OR nonexistent",
        "<script>",
    ] {
        assert_eq!(
            count(
                &store,
                "alice",
                Search {
                    q: q.into(),
                    ..Default::default()
                }
            )
            .await,
            0,
            "{q}"
        );
    }
    assert_eq!(
        count(
            &store,
            "alice",
            Search {
                recipient: "bob".into(),
                ..Default::default()
            }
        )
        .await,
        0
    );
    assert_eq!(
        count(
            &store,
            "alice",
            Search {
                status: "quarantined".into(),
                ..Default::default()
            }
        )
        .await,
        0
    );
    assert_eq!(
        count(
            &store,
            "domain",
            Search {
                status: "quarantined".into(),
                ..Default::default()
            }
        )
        .await,
        2
    );
    assert_eq!(
        count(
            &store,
            "domain",
            Search {
                recipient: "alice".into(),
                status: "quarantined".into(),
                ..Default::default()
            }
        )
        .await,
        0,
        "recipient and status must describe the same delivery"
    );
    let options = Search {
        subject: "fact".into(),
        sender: "EXAMPLE.ORG".into(),
        rule: "suspicious".into(),
        id: "shared".into(),
        domain: "example.test".into(),
        min_score: Some(91.0),
        max_score: Some(92.0),
        after: Some(noisefence::now() - 60),
        before: Some(noisefence::now() + 60),
        filter: "incomplete".into(),
        ..Default::default()
    };
    let page = store
        .search_messages("alice".into(), options, 80.0)
        .await
        .unwrap();
    assert_eq!(page.total, 1);
    assert!(!page.has_more);
    assert_eq!(page.messages[0].recipients.len(), 1);
    assert_eq!(page.messages[0].recipients[0].address, "alice@example.test");
    assert_eq!(count(&store, "admin", Search::default()).await, 2);
    assert_eq!(
        count(
            &store,
            "alice",
            Search {
                domain: "other.test".into(),
                ..Default::default()
            }
        )
        .await,
        0
    );
    // Revoked grants take effect for matches AND totals without rebuilding the index.
    store
        .run(|db| {
            db.execute("DELETE FROM grants WHERE username='alice'", [])?;
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(
        count(
            &store,
            "alice",
            Search {
                q: "reunion".into(),
                ..Default::default()
            }
        )
        .await,
        0
    );
}

#[tokio::test]
async fn index_backfill_update_retention_and_pagination() {
    let (dir, store, _) = fixture().await;
    // Simulate opening a database from the previous binary; no message is rewritten.
    store.run(|db|{
        db.execute_batch("DROP TRIGGER message_search_insert; DROP TRIGGER message_search_update; DROP TRIGGER message_search_delete; DROP VIEW message_search_source; DROP TABLE message_search;")?;Ok(())
    }).await.unwrap();
    drop(store);
    let store = Store::open(dir.path()).unwrap();
    assert_eq!(
        count(
            &store,
            "alice",
            Search {
                q: "reunion".into(),
                ..Default::default()
            }
        )
        .await,
        1
    );
    store.run(|db|{
        db.execute("UPDATE messages SET scan=json_set(scan,'$.subject','Updated subject','$.decision',json(?1)) WHERE id='shared-identifier'",[r#"{"source":"fusion","outcome":"undetermined","score":12.5,"model":"test"}"#])?;
        let tx=db.transaction()?;
        for i in 0..51 {
            let id=format!("page-{i:03}");
            tx.execute("INSERT INTO messages(id,created,sender,scan) SELECT ?1,created,sender,json_set(scan,'$.subject','Pagination') FROM messages WHERE id='shared-identifier'",[&id])?;
            tx.execute("INSERT INTO deliveries(message_id,address,destination,hosts,next_attempt) VALUES(?1,'alice@example.test','alice@example.test','[]',0)",[&id])?;
        }
        tx.commit()?;Ok(())
    }).await.unwrap();
    assert_eq!(
        count(
            &store,
            "alice",
            Search {
                q: "reunion".into(),
                ..Default::default()
            }
        )
        .await,
        0
    );
    assert_eq!(
        count(
            &store,
            "alice",
            Search {
                q: "updated".into(),
                min_score: Some(12.0),
                max_score: Some(13.0),
                ..Default::default()
            }
        )
        .await,
        1
    );
    assert_eq!(
        count(
            &store,
            "alice",
            Search {
                q: "updated".into(),
                min_score: Some(90.0),
                ..Default::default()
            }
        )
        .await,
        0
    );
    let page = store
        .search_messages(
            "alice".into(),
            Search {
                q: "pagination".into(),
                ..Default::default()
            },
            80.0,
        )
        .await
        .unwrap();
    assert_eq!(
        (page.total, page.messages.len(), page.has_more),
        (51, 50, true)
    );
    let next = store
        .search_messages(
            "alice".into(),
            Search {
                q: "pagination".into(),
                offset: 50,
                ..Default::default()
            },
            80.0,
        )
        .await
        .unwrap();
    assert_eq!(
        (next.total, next.messages.len(), next.has_more),
        (51, 1, false)
    );
    assert!(!page.messages.iter().any(|m| m.id == next.messages[0].id));
    let beyond = store
        .search_messages(
            "alice".into(),
            Search {
                q: "pagination".into(),
                offset: 100,
                ..Default::default()
            },
            80.0,
        )
        .await
        .unwrap();
    assert_eq!((beyond.total, beyond.messages.len()), (51, 0));
    store
        .run(|db| {
            db.execute(
                "UPDATE messages SET created=0,raw_present=0 WHERE id='shared-identifier'",
                [],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(
        count(
            &store,
            "alice",
            Search {
                q: "updated".into(),
                ..Default::default()
            }
        )
        .await,
        0
    );
    store.cleanup().await.unwrap();
    store
        .run(|db| {
            let n: i64 = db.query_row(
                "SELECT count(*) FROM message_search WHERE message_search MATCH 'updated'",
                [],
                |r| r.get(0),
            )?;
            assert_eq!(n, 0);
            db.execute(
                "INSERT INTO message_search(message_search) VALUES('integrity-check')",
                [],
            )?;
            assert_eq!(
                db.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))?,
                2
            );
            Ok(())
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn search_api_rejects_bad_queries_and_never_returns_unscoped_counts() {
    let (_dir, store, cfg) = fixture().await;
    let token = "a".repeat(64);
    let hash = noisefence::message::digest(token.as_bytes());
    store.run(move|db|{db.execute("INSERT INTO sessions(token_hash,username,csrf,expires) VALUES(?1,'alice','test',?2)",params![hash,noisefence::now()+60])?;Ok(())}).await.unwrap();
    let app = api::router(cfg, store).unwrap();
    let response = app
        .clone()
        .oneshot(
            Request::get("/api/v1/search/messages?q=reunion")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    for q in [
        "q=%22unfinished",
        "min_score=NaN",
        "min_score=90&max_score=10",
        "after=50&before=40",
        "status=whatever",
        "filter=nope",
        "offset=10000001",
        "q=%00",
        "q=%2A%2A",
        "body=secret",
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::get(format!("/api/v1/search/messages?{q}"))
                    .header(header::COOKIE, format!("noisefence_session={token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{q}");
    }
    for (query, expected) in [
        ("q=reunion", 1),
        ("q=bob", 0),
        ("recipient=bob", 0),
        ("status=quarantined", 0),
        ("q=%27%20OR%201%3D1--", 0),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::get(format!("/api/v1/search/messages?{query}"))
                    .header(header::COOKIE, format!("noisefence_session={token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // Punctuation-only fragments are invalid rather than interpreted as SQL.
        if query.starts_with("q=%27") {
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            continue;
        }
        assert_eq!(response.status(), StatusCode::OK, "{query}");
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["total"], expected);
        assert!(
            !String::from_utf8(body.to_vec())
                .unwrap()
                .contains("bob@example.test")
        );
    }
}

#[tokio::test]
async fn indexed_search_handles_ten_thousand_messages_with_exact_scoped_totals() {
    let (_dir, store, _) = fixture().await;
    store.run(|db| {
        let tx=db.transaction()?;
        tx.execute_batch("WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<10000)
            INSERT INTO messages(id,created,sender,scan,raw_present)
            SELECT printf('volume-%05d',i),1700000000+i,'archive@example.org',
            json_set(m.scan,'$.subject',CASE WHEN i%100=0 THEN 'Réunion volume sélection' ELSE 'Archive volume' END),1
            FROM n CROSS JOIN messages m WHERE m.id='shared-identifier';
            INSERT INTO deliveries(message_id,address,destination,hosts,next_attempt)
            SELECT id,'alice@example.test','alice@example.test','[]',0 FROM messages WHERE id GLOB 'volume-*';")?;
        tx.commit()?;Ok(())
    }).await.unwrap();
    let start = std::time::Instant::now();
    let result = store
        .search_messages(
            "alice".into(),
            Search {
                q: "reunion selection".into(),
                ..Default::default()
            },
            80.0,
        )
        .await
        .unwrap();
    assert_eq!(
        (result.total, result.messages.len(), result.has_more),
        (100, 50, true)
    );
    eprintln!(
        "10,000-message metadata search, count + first page: {:?}",
        start.elapsed()
    );
    assert_eq!(
        count(
            &store,
            "bob",
            Search {
                q: "volume".into(),
                ..Default::default()
            }
        )
        .await,
        0
    );
}
