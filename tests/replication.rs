mod common;
use noisefence::{
    api,
    cluster::{self, Role},
    config::Config,
    engine, ha,
    store::Store,
};
use std::{path::Path, sync::Arc};
use tokio::net::TcpListener;

struct Pair {
    _a: tempfile::TempDir,
    _b: tempfile::TempDir,
    a: Store,
    b: Store,
    config: Arc<Config>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}
impl Drop for Pair {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}
fn config(root: &Path, id: &str, peer: &str, url: String, key: &str) -> Arc<Config> {
    let mut c = (*common::config(root)).clone();
    let credential = root.join("replica.key");
    cluster::protocol::private_write(&credential, key.as_bytes()).unwrap();
    c.cluster = Some(cluster::Settings {
        role: Role::Coordinator,
        node_id: id.into(),
        coordinator_url: None,
        credential_file: None,
        poll_seconds: 2,
        max_stale_seconds: 60,
        allow_loopback_http: true,
    });
    c.replication = Some(ha::Settings {
        peer_id: peer.into(),
        peer_url: url,
        credential_file: credential,
        timeout_seconds: 5,
        max_replica_bytes: 64 * 1024 * 1024,
        allow_loopback_http: true,
    });
    c.validate().unwrap();
    Arc::new(c)
}
async fn pair() -> Pair {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let l1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let l2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let key = api::random_token();
    let c1 = config(
        a.path(),
        "mx1",
        "mx2",
        format!("http://{}", l2.local_addr().unwrap()),
        &key,
    );
    let c2 = config(
        b.path(),
        "mx2",
        "mx1",
        format!("http://{}", l1.local_addr().unwrap()),
        &key,
    );
    let s1 = Store::open(a.path()).unwrap();
    let s2 = Store::open(b.path()).unwrap();
    for (s, c) in [(&s1, &c1), (&s2, &c2)] {
        cluster::prepare(c, s).await.unwrap();
        ha::initialize(s, c).await.unwrap();
    }
    let r1 = api::router(c1.clone(), s1.clone()).unwrap();
    let r2 = api::router(c2.clone(), s2.clone()).unwrap();
    let tasks = vec![
        tokio::spawn(async move {
            axum::serve(l1, r1).await.unwrap();
        }),
        tokio::spawn(async move {
            axum::serve(l2, r2).await.unwrap();
        }),
    ];
    Pair {
        _a: a,
        _b: b,
        a: s1,
        b: s2,
        config: c1,
        tasks,
    }
}
async fn enqueue(p: &Pair, id: &str) -> anyhow::Result<()> {
    p.a.enqueue(
        id.into(),
        "sender@example.org".into(),
        vec![
            p.config.recipient("alice@example.test").unwrap(),
            p.config.recipient("bob@example.test").unwrap(),
        ],
        engine::extract(common::MESSAGE, 1024 * 1024),
        common::MESSAGE.to_vec(),
    )
    .await
}
async fn remote(p: &Pair, id: &str) -> ha::replica::Manifest {
    let id = id.to_owned();
    p.b.read(move |db| {
        Ok(serde_json::from_str(&db.query_row(
            "SELECT manifest FROM ha_remote WHERE owner='mx1' AND id=?1",
            [id],
            |r| r.get::<_, String>(0),
        )?)?)
    })
    .await
    .unwrap()
}
#[tokio::test]
async fn accepted_message_has_two_durable_bodies_and_only_one_queue_owner() {
    let p = pair().await;
    let id = uuid::Uuid::new_v4().to_string();
    enqueue(&p, &id).await.unwrap();
    assert_eq!(std::fs::read(p.a.raw_path(&id)).unwrap(), common::MESSAGE);
    assert_eq!(
        std::fs::read(ha::replica::body_path(&p.b, "mx1", &id)).unwrap(),
        common::MESSAGE
    );
    assert!(!remote(&p, &id).await.confirmed);
    assert!(p.a.claim().await.unwrap().is_none());
    assert!(p.b.claim().await.unwrap().is_none());
    ha::replica::synchronize(&p.a).await.unwrap();
    assert!(remote(&p, &id).await.confirmed);
    assert!(p.a.claim().await.unwrap().is_some());
    assert!(p.b.claim().await.unwrap().is_none());
    let reopened = Store::open(&p.b.root).unwrap();
    assert_eq!(ha::status(&reopened).await.unwrap().remote_messages, 1);
    assert!(reopened.claim().await.unwrap().is_none());
}
#[tokio::test]
async fn peer_failure_refuses_acceptance_without_leaking_a_local_deliverable_message() {
    let p = pair().await;
    p.tasks[1].abort();
    let id = uuid::Uuid::new_v4().to_string();
    assert!(enqueue(&p, &id).await.is_err());
    assert!(!p.a.raw_path(&id).exists());
    assert!(p.a.claim().await.unwrap().is_none());
    assert_eq!(
        p.a.read(|db| Ok(
            db.query_row("SELECT COUNT(*) FROM messages", [], |r| r.get::<_, i64>(0))?
        ))
        .await
        .unwrap(),
        0
    );
}
#[tokio::test]
async fn recipient_progress_survives_restart_and_body_cleanup_waits_for_peer_ack() {
    let p = pair().await;
    let id = uuid::Uuid::new_v4().to_string();
    enqueue(&p, &id).await.unwrap();
    ha::replica::synchronize(&p.a).await.unwrap();
    let a = p.a.claim().await.unwrap().unwrap();
    ha::replica::synchronize_message(&p.a, id.clone())
        .await
        .unwrap();
    assert_eq!(
        remote(&p, &id)
            .await
            .deliveries
            .iter()
            .filter(|d| d.status == "sending")
            .count(),
        1
    );
    p.a.finish(&a, "delivered", "", 0).await.unwrap();
    let b = p.a.claim().await.unwrap().unwrap();
    p.a.finish(&b, "delivered", "", 0).await.unwrap();
    p.a.cleanup().await.unwrap();
    assert!(p.a.raw_path(&id).exists());
    ha::replica::synchronize(&p.a).await.unwrap();
    p.a.cleanup().await.unwrap();
    assert!(!p.a.raw_path(&id).exists());
    ha::replica::synchronize(&p.a).await.unwrap();
    assert!(!ha::replica::body_path(&p.b, "mx1", &id).exists());
    assert!(remote(&p, &id).await.resolved());
}
#[tokio::test]
async fn replicas_reject_foreign_identity_bad_hash_and_missing_body() {
    let p = pair().await;
    let id = uuid::Uuid::new_v4().to_string();
    let url = p.config.replication.as_ref().unwrap().peer_url.clone();
    let http = reqwest::Client::new();
    assert_eq!(
        http.post(format!("{url}/api/v1/replication/v1/ping"))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    let key =
        cluster::protocol::credential(&p.config.replication.as_ref().unwrap().credential_file)
            .unwrap();
    let response = http
        .post(format!("{url}/api/v1/replication/v1/body/{id}"))
        .bearer_auth(&key)
        .header("x-noisefence-node", "mx1")
        .header("x-noisefence-sha256", "0".repeat(64))
        .header("x-noisefence-bytes", 3)
        .body("bad")
        .send()
        .await
        .unwrap();
    assert!(!response.status().is_success());
    assert!(!ha::replica::body_path(&p.b, "mx1", &id).exists());
    enqueue(&p, &id).await.unwrap();
    let mut m = remote(&p, &id).await;
    m.id = uuid::Uuid::new_v4().to_string();
    assert!(
        !http
            .post(format!("{url}/api/v1/replication/v1/manifest"))
            .bearer_auth(key)
            .header("x-noisefence-node", "mx1")
            .json(&m)
            .send()
            .await
            .unwrap()
            .status()
            .is_success()
    );
}
#[tokio::test]
async fn existing_queue_is_backfilled_and_required_policy_cannot_disappear_on_restart() {
    let p = pair().await;
    assert_eq!(
        p.a.read(|db| Ok(db.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))?))
            .await
            .unwrap(),
        5
    );
    let mut without = (*p.config).clone();
    without.replication = None;
    assert!(
        ha::initialize(&Store::open(&p.a.root).unwrap(), &without)
            .await
            .is_err()
    );
    let root = tempfile::tempdir().unwrap();
    let s = Store::open(root.path()).unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    s.enqueue(
        id.clone(),
        "sender@example.org".into(),
        vec![p.config.recipient("alice@example.test").unwrap()],
        engine::extract(common::MESSAGE, 1024 * 1024),
        common::MESSAGE.to_vec(),
    )
    .await
    .unwrap();
    let mut c = (*p.config).clone();
    c.data_dir = root.path().into();
    ha::initialize(&s, &c).await.unwrap();
    assert!(s.claim().await.unwrap().is_none());
    ha::replica::synchronize(&s).await.unwrap();
    assert!(s.claim().await.unwrap().is_some());
}

fn fence(root: &Path) -> std::path::PathBuf {
    let path = root.join("test-fence.json");
    cluster::protocol::private_write(&path,serde_json::to_string(&serde_json::json!({"owner":"mx1","fenced":true,"created":noisefence::now(),"operation":uuid::Uuid::new_v4().to_string(),"fixture_only":true})).unwrap().as_bytes()).unwrap();
    path
}

#[tokio::test]
async fn restore_from_a_crashed_sender_holds_uncertainty_and_does_not_replay_delivered_recipients()
{
    let p = pair().await;
    let id = uuid::Uuid::new_v4().to_string();
    enqueue(&p, &id).await.unwrap();
    ha::replica::synchronize(&p.a).await.unwrap();
    let first = p.a.claim().await.unwrap().unwrap();
    p.a.finish(&first, "delivered", "", 0).await.unwrap();
    let second = p.a.claim().await.unwrap().unwrap();
    ha::replica::synchronize_message(&p.a, id.clone())
        .await
        .unwrap();
    let target = tempfile::tempdir().unwrap();
    ha::recovery::snapshot_database(
        &p.a.root.join("state.sqlite3"),
        &target.path().join("state.sqlite3"),
    )
    .unwrap();
    let receipt = fence(p._a.path());
    let report = ha::recovery::restore_queue(&p.b.root, target.path(), "mx1", &receipt)
        .await
        .unwrap();
    assert_eq!(report["held_recipients"], 1);
    assert_eq!(report["copied"], 1);
    let restored = Store::open(target.path()).unwrap();
    restored.recover().await.unwrap();
    assert!(restored.claim().await.unwrap().is_none());
    let states = restored
        .read(|db| {
            Ok(db
                .prepare("SELECT status FROM deliveries ORDER BY id")?
                .query_map([], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .await
        .unwrap();
    assert_eq!(states, vec!["delivered", "quarantined"]);
    let again = ha::recovery::restore_queue(&p.b.root, target.path(), "mx1", &receipt)
        .await
        .unwrap();
    assert_eq!(again["already_restored"], 1);
    assert_eq!(
        std::fs::read(restored.raw_path(&id)).unwrap(),
        common::MESSAGE
    );
    assert_eq!(second.message_id, id);
}

#[tokio::test]
async fn candidate_without_acceptance_confirmation_is_recovered_for_review_only() {
    let p = pair().await;
    let id = uuid::Uuid::new_v4().to_string();
    enqueue(&p, &id).await.unwrap();
    let target = tempfile::tempdir().unwrap();
    let receipt = fence(p._a.path());
    let report = ha::recovery::restore_queue(&p.b.root, target.path(), "mx1", &receipt)
        .await
        .unwrap();
    assert_eq!(report["held_recipients"], 2);
    assert_eq!(report["pending_recipients"], 0);
    assert!(
        Store::open(target.path())
            .unwrap()
            .claim()
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn restoration_rejects_missing_fence_wrong_owner_and_damaged_body() {
    let p = pair().await;
    let id = uuid::Uuid::new_v4().to_string();
    enqueue(&p, &id).await.unwrap();
    let target = tempfile::tempdir().unwrap();
    let receipt = fence(p._a.path());
    assert!(
        ha::recovery::restore_queue(&p.b.root, target.path(), "mx2", &receipt)
            .await
            .is_err()
    );
    assert!(
        ha::recovery::restore_queue(
            &p.b.root,
            target.path(),
            "mx1",
            &target.path().join("absent")
        )
        .await
        .is_err()
    );
    std::fs::write(ha::replica::body_path(&p.b, "mx1", &id), b"damaged").unwrap();
    assert!(
        ha::recovery::restore_queue(&p.b.root, target.path(), "mx1", &receipt)
            .await
            .is_err()
    );
    assert!(
        Store::open(target.path())
            .unwrap()
            .claim()
            .await
            .unwrap()
            .is_none()
    );
}

#[test]
fn live_sqlite_snapshot_includes_committed_wal_and_refuses_overwrite() {
    let root = tempfile::tempdir().unwrap();
    let db = root.path().join("live.sqlite3");
    let output = root.path().join("snapshot.sqlite3");
    let live = rusqlite::Connection::open(&db).unwrap();
    live.execute_batch(
        "PRAGMA journal_mode=WAL; CREATE TABLE pairs(a,b); INSERT INTO pairs VALUES(1,1)",
    )
    .unwrap();
    let tx = live.unchecked_transaction().unwrap();
    tx.execute("INSERT INTO pairs VALUES(2,2)", []).unwrap();
    tx.commit().unwrap();
    ha::recovery::snapshot_database(&db, &output).unwrap();
    let snapshot = rusqlite::Connection::open(&output).unwrap();
    assert_eq!(
        snapshot
            .query_row("SELECT COUNT(*) FROM pairs WHERE a=b", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        2
    );
    assert!(ha::recovery::snapshot_database(&db, &output).is_err());
}

#[tokio::test]
async fn final_checkpoint_delivery_wins_over_an_older_replica_sending_intent() {
    let p = pair().await;
    let id = uuid::Uuid::new_v4().to_string();
    enqueue(&p, &id).await.unwrap();
    ha::replica::synchronize(&p.a).await.unwrap();
    for _ in 0..2 {
        let job = p.a.claim().await.unwrap().unwrap();
        ha::replica::synchronize_message(&p.a, id.clone())
            .await
            .unwrap();
        p.a.finish(&job, "delivered", "", 0).await.unwrap();
    }
    let remote_generation = remote(&p, &id).await.generation;
    let target = tempfile::tempdir().unwrap();
    ha::recovery::snapshot_database(
        &p.a.root.join("state.sqlite3"),
        &target.path().join("state.sqlite3"),
    )
    .unwrap();
    let result = ha::recovery::restore_queue(&p.b.root, target.path(), "mx1", &fence(p._a.path()))
        .await
        .unwrap();
    assert_eq!(result["held_recipients"], 0);
    let restored = Store::open(target.path()).unwrap();
    assert_eq!(
        restored
            .read(|db| Ok(db.query_row(
                "SELECT COUNT(*) FROM deliveries WHERE status='delivered'",
                [],
                |r| r.get::<_, i64>(0)
            )?))
            .await
            .unwrap(),
        2
    );
    assert!(
        restored
            .read(move |db| Ok(db.query_row(
                "SELECT generation FROM ha_local WHERE message_id=?1",
                [id],
                |r| r.get::<_, i64>(0)
            )?))
            .await
            .unwrap()
            > remote_generation
    );
}

#[tokio::test]
async fn existing_legacy_notifications_are_backfilled_and_candidates_never_expire() {
    let p = pair().await;
    let root = tempfile::tempdir().unwrap();
    let s = Store::open(root.path()).unwrap();
    s.enqueue(
        "dsn-201".into(),
        "".into(),
        vec![p.config.recipient("alice@example.test").unwrap()],
        engine::extract(common::MESSAGE, 1048576),
        common::MESSAGE.to_vec(),
    )
    .await
    .unwrap();
    s.run(|db| {
        db.execute("UPDATE messages SET is_dsn=1 WHERE id='dsn-201'", [])?;
        Ok(())
    })
    .await
    .unwrap();
    let mut c = (*p.config).clone();
    c.data_dir = root.path().into();
    ha::initialize(&s, &c).await.unwrap();
    ha::replica::synchronize(&s).await.unwrap();
    assert!(remote(&p, "dsn-201").await.is_dsn);
    let id = uuid::Uuid::new_v4().to_string();
    enqueue(&p, &id).await.unwrap();
    p.b.run(|db| {
        db.execute("UPDATE ha_blobs SET updated=1", [])?;
        Ok(())
    })
    .await
    .unwrap();
    ha::replica::cleanup(&p.b).await.unwrap();
    assert!(ha::replica::body_path(&p.b, "mx1", &id).exists());
}

#[tokio::test]
async fn two_simultaneous_acceptances_do_not_contend_with_the_peer_receiver() {
    let p = pair().await;
    let a = uuid::Uuid::new_v4().to_string();
    let b = uuid::Uuid::new_v4().to_string();
    let (a, b) = tokio::join!(enqueue(&p, &a), enqueue(&p, &b));
    a.unwrap();
    b.unwrap();
    assert_eq!(ha::status(&p.b).await.unwrap().remote_messages, 2);
}

#[tokio::test]
async fn smtp_accepts_only_after_two_copies_and_defers_when_the_peer_dies_during_data() {
    use noisefence::{engine::Engine, relay, smtp};
    use tokio::io::{AsyncWriteExt, BufReader};
    let p = pair().await;
    ha::replica::synchronize(&p.a).await.unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, rx) = tokio::sync::watch::channel(false);
    let state = smtp::State {
        config: p.config.clone(),
        store: p.a.clone(),
        engine: Arc::new(Engine::new(p.config.clone()).unwrap()),
        processing: Arc::new(tokio::sync::Semaphore::new(2)),
    };
    let task = tokio::spawn(smtp::serve(listener, state, rx));
    let mut io: smtp::Wire = BufReader::new(Box::new(
        tokio::net::TcpStream::connect(address).await.unwrap(),
    ));
    assert_eq!(relay::response(&mut io).await.unwrap().code, 220);
    smtp::reply(&mut io, "EHLO example.org\r\n").await.unwrap();
    assert_eq!(relay::response(&mut io).await.unwrap().code, 250);
    for fail in [false, true] {
        for (command, code) in [
            ("MAIL FROM:<sender@example.org>\r\n", 250),
            ("RCPT TO:<alice@example.test>\r\n", 250),
            ("DATA\r\n", 354),
        ] {
            smtp::reply(&mut io, command).await.unwrap();
            assert_eq!(relay::response(&mut io).await.unwrap().code, code);
        }
        if fail {
            p.tasks[1].abort();
            tokio::task::yield_now().await;
        }
        io.write_all(common::MESSAGE).await.unwrap();
        io.write_all(b".\r\n").await.unwrap();
        io.flush().await.unwrap();
        assert_eq!(
            relay::response(&mut io).await.unwrap().code,
            if fail { 451 } else { 250 }
        );
    }
    assert_eq!(
        p.a.read(|db| Ok(
            db.query_row("SELECT COUNT(*) FROM messages", [], |r| r.get::<_, i64>(0))?
        ))
        .await
        .unwrap(),
        1
    );
    assert_eq!(ha::status(&p.b).await.unwrap().remote_messages, 1);
    drop(io);
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
}
