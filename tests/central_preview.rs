#[allow(dead_code)]
mod common;
#[path = "common/postgres.rs"]
mod postgres;
#[allow(dead_code)]
#[path = "common/web_auth.rs"]
mod web_auth;
use noisefence::{central::outbox, store::Store};
use serde_json::json;

#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn recipient_preview_uses_central_snapshots_and_rechecks_administrator() {
    let f = postgres::Fixture::new().await;
    let pg = f.connect().await;
    let root = tempfile::tempdir().unwrap();
    let config = common::config(root.path());
    let local = Store::open(root.path()).unwrap();
    let identity = local.run(|db| outbox::initialize(db, "mx1")).await.unwrap();
    f.central.register_source(&identity).await.unwrap();
    let ids: Vec<String> = (0..5).map(|_| uuid::Uuid::new_v4().to_string()).collect();
    let records = ids.clone();
    let scan = noisefence::engine::Engine::new(config.clone())
        .unwrap()
        .offline(common::MESSAGE);
    let expected_scan = serde_json::to_value(&scan).unwrap();
    local.run(move|db| {
        for (n,id) in records.iter().take(4).enumerate() {
            db.execute("INSERT INTO messages(id,created,sender,scan,raw_present) VALUES(?1,?2,'sender@example.org',?3,?4)",rusqlite::params![id,noisefence::now(),serde_json::to_string(&scan)?,n==3])?;
            let address=if n==1 {"bob@example.test"}else{"alice@example.test"};
            db.execute("INSERT INTO deliveries(message_id,address,destination,hosts,next_attempt) VALUES(?1,?2,?2,'[]',0)",rusqlite::params![id,address])?;
        } Ok(())
    }).await.unwrap();
    while f.central.synchronize_once(&local).await.unwrap() > 0 {}
    pg.execute(
        "UPDATE noisefence.messages SET created=$1 WHERE id=ANY($2::text[])",
        &[&(noisefence::now() - 31 * 86400), &&ids[2..4]],
    )
    .await
    .unwrap();
    pg.batch_execute("INSERT INTO noisefence.users(username,password,admin) VALUES('admin','unused',true),('reader','unused',false)").await.unwrap();
    let token = "a".repeat(64);
    pg.execute("INSERT INTO noisefence.sessions(token_hash,username,csrf,expires) VALUES($1,'admin','test-csrf',$2)",&[&noisefence::message::digest(token.as_bytes()),&(noisefence::now()+3600)]).await.unwrap();
    let selected = vec![
        ids[3].clone(),
        ids[1].clone(),
        ids[4].clone(),
        ids[0].clone(),
        ids[2].clone(),
    ];
    let rows = f
        .central
        .preview_snapshots("admin", &selected, "alice@example.test")
        .await
        .unwrap();
    assert_eq!(
        rows.iter().map(|r| r.0.clone()).collect::<Vec<_>>(),
        selected
    );
    for n in [0, 3] {
        assert_eq!(rows[n].1.as_ref().unwrap().0, "sender@example.org");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&rows[n].1.as_ref().unwrap().1).unwrap(),
            expected_scan
        );
    }
    for n in [1, 2, 4] {
        assert!(rows[n].1.is_none());
    }
    assert!(
        f.central
            .preview_snapshots("reader", &selected, "alice@example.test")
            .await
            .is_err()
    );
    assert!(
        f.central
            .preview_snapshots(
                "admin",
                &[ids[0].clone(), ids[0].clone()],
                "alice@example.test"
            )
            .await
            .is_err()
    );
    let store = local
        .clone()
        .with_management(f.central.clone())
        .await
        .unwrap();
    // Remove the old local history: the Web preview must still use PostgreSQL.
    local
        .run(|db| {
            db.execute("DELETE FROM messages", [])?;
            Ok(())
        })
        .await
        .unwrap();
    let app = noisefence::api::router(config.clone(), store).unwrap();
    let cookie = format!("noisefence_session={token}");
    f.central
        .enroll_node(&identity, "Synthetic MX", &"f".repeat(64))
        .await
        .unwrap();
    pg.execute(
        "UPDATE noisefence.cluster_nodes SET status=$1,last_seen=$2 WHERE node='mx1'",
        &[
            &json!({"research_archive":{"enabled":true,"messages":7}}),
            &noisefence::now(),
        ],
    )
    .await
    .unwrap();
    let (status, archive, _) = web_auth::call(
        &app,
        &config.web.public_origin,
        "/admin/research-archive",
        &cookie,
        "",
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(archive["workers"].as_array().unwrap().len(), 1);
    assert_eq!(archive["workers"][0]["status"]["messages"], 7);
    pg.execute(
        "UPDATE noisefence.cluster_nodes SET enabled=false WHERE node='mx1'",
        &[],
    )
    .await
    .unwrap();
    assert_eq!(
        web_auth::call(
            &app,
            &config.web.public_origin,
            "/admin/research-archive",
            &cookie,
            "",
            None
        )
        .await
        .1["workers"],
        json!([])
    );
    let policy = serde_json::to_value(noisefence::custom_filtering::Policy::default()).unwrap();
    let request = json!({"policy":policy,"recipient":"alice@example.test","message_ids":selected});
    let (status, report, _) = web_auth::call(
        &app,
        &config.web.public_origin,
        "/admin/filtering/sample",
        &cookie,
        "test-csrf",
        Some(request),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{report}");
    assert_eq!(report["rows"][0]["status"], "simulated");
    assert_eq!(report["rows"][1]["status"], "not_available");
    pg.execute(
        "UPDATE noisefence.users SET disabled=true WHERE username='admin'",
        &[],
    )
    .await
    .unwrap();
    assert!(
        f.central
            .preview_snapshots("admin", &ids, "alice@example.test")
            .await
            .is_err()
    );
    f.suspend().await;
    assert!(
        f.central
            .preview_snapshots("admin", &ids, "alice@example.test")
            .await
            .is_err()
    );
    f.resume().await;
    drop(pg);
    f.finish().await;
}
