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
async fn rspamd_report_propagates_over_ha_without_changing_ownership_or_delivery() {
    use noisefence::{
        fusion::runtime::{Decision, Outcome},
        rspamd::{Comparison, Report, Status, Symbol},
    };
    use serde_json::{json, to_value};

    let p = pair().await;
    let id = uuid::Uuid::new_v4().to_string();
    let pending = Report {
        status: Status::Pending,
        job_id: uuid::Uuid::new_v4().to_string(),
        started_at: noisefence::now(),
        expires_at: noisefence::now() + 610,
        raw_sha256: noisefence::message::digest(common::MESSAGE),
        profile: "rspamd-ha-fixture".into(),
        settings_sha256: noisefence::message::digest(b"local comparison settings"),
        server: None,
        elapsed_ms: 0,
        score: None,
        required_score: None,
        action: None,
        symbols: vec![],
        noisefence_outcome: Some(Outcome::Legitimate),
        comparison: Comparison::Inconclusive,
    };
    let mut scan = engine::extract(common::MESSAGE, 1024 * 1024);
    scan.score = 12.5;
    scan.complete = true;
    scan.decision = Some(Decision::legacy(&scan, p.config.filter.threshold));
    scan.rspamd = Some(pending.clone());
    p.a.enqueue(
        id.clone(),
        "sender@example.org".into(),
        vec![
            p.config.recipient("alice@example.test").unwrap(),
            p.config.recipient("bob@example.test").unwrap(),
        ],
        scan.clone(),
        common::MESSAGE.to_vec(),
    )
    .await
    .unwrap();
    let candidate = remote(&p, &id).await;
    assert_eq!(candidate.scan, to_value(&scan).unwrap());
    assert_eq!(candidate.owner, "mx1");
    assert!(!candidate.confirmed);
    assert!(p.a.claim().await.unwrap().is_none());
    assert!(p.b.claim().await.unwrap().is_none());

    ha::replica::synchronize(&p.a).await.unwrap();
    let delivered = p.a.claim().await.unwrap().unwrap();
    assert_eq!(delivered.destination, "alice@example.test");
    p.a.finish(&delivered, "delivered", "", 0).await.unwrap();
    ha::replica::synchronize(&p.a).await.unwrap();
    let before = ha::replica::export(&p.a, id.clone()).await.unwrap();
    let before_json = to_value(&before).unwrap();
    assert!(before.confirmed);
    assert_eq!(before.scan, to_value(&scan).unwrap());
    assert_eq!(before.deliveries[0].status, "delivered");
    assert_eq!(before.deliveries[1].status, "pending");
    assert_eq!(to_value(remote(&p, &id).await).unwrap(), before_json);

    // Inject the comparator's metadata-only completion; exercise the real HA
    // export, HTTP receiver and durable replica, independently of scanner tests.
    let complete = Report {
        status: Status::Complete,
        server: Some("rspamd/test".into()),
        elapsed_ms: 125,
        score: Some(7.25),
        required_score: Some(6.0),
        action: Some("reject".into()),
        symbols: vec![
            Symbol {
                name: "TEST_SPAM".into(),
                score: 8.0,
            },
            Symbol {
                name: "TEST_HAM".into(),
                score: -0.75,
            },
        ],
        comparison: Comparison::Disagreement,
        ..pending
    };
    let report_json = to_value(&complete).unwrap();
    let key = id.clone();
    let report = serde_json::to_string(&complete).unwrap();
    p.a.run(move |db| {
        assert_eq!(
            db.execute(
                "UPDATE messages SET scan=json_set(scan,'$.rspamd',json(?2)) WHERE id=?1",
                rusqlite::params![key, report],
            )?,
            1
        );
        Ok(())
    })
    .await
    .unwrap();
    let mut expected = before_json.clone();
    expected["generation"] = json!(before.generation + 1);
    expected["scan"]["rspamd"] = report_json.clone();
    assert_eq!(
        to_value(ha::replica::export(&p.a, id.clone()).await.unwrap()).unwrap(),
        expected
    );
    assert_eq!(to_value(remote(&p, &id).await).unwrap(), before_json);

    ha::replica::synchronize_message(&p.a, id.clone())
        .await
        .unwrap();
    let replicated = remote(&p, &id).await;
    // The complete manifest must differ only in comparison metadata and generation:
    // ownership, native decision, recipient states, attempts and body stay intact.
    assert_eq!(to_value(&replicated).unwrap(), expected);
    let restored: engine::Scan = serde_json::from_value(replicated.scan).unwrap();
    assert_eq!(to_value(restored.rspamd.unwrap()).unwrap(), report_json);
    assert_eq!(restored.decision, scan.decision);
    assert_eq!(std::fs::read(p.a.raw_path(&id)).unwrap(), common::MESSAGE);
    assert_eq!(
        std::fs::read(ha::replica::body_path(&p.b, "mx1", &id)).unwrap(),
        common::MESSAGE
    );
    let reopened = Store::open(&p.b.root).unwrap();
    let key = id.clone();
    let persisted: serde_json::Value = reopened
        .read(move |db| {
            let manifest: String = db.query_row(
                "SELECT manifest FROM ha_remote WHERE owner='mx1' AND id=?1",
                [key],
                |r| r.get(0),
            )?;
            Ok(serde_json::from_str(&manifest)?)
        })
        .await
        .unwrap();
    assert_eq!(persisted, expected);
    assert!(reopened.claim().await.unwrap().is_none());
    assert!(p.b.claim().await.unwrap().is_none());
    let remaining = p.a.claim().await.unwrap().unwrap();
    assert_eq!(remaining.message_id, id);
    assert_eq!(remaining.destination, "bob@example.test");
    assert!(p.a.claim().await.unwrap().is_none());
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
async fn an_original_is_retained_when_its_queued_failure_notice_was_not_replicated() {
    let p = pair().await;
    let id = uuid::Uuid::new_v4().to_string();
    enqueue(&p, &id).await.unwrap();
    // A local DSN enqueue may be recorded before that new DSN's first peer copy.
    p.a.run(|db| {
        db.execute(
            "UPDATE deliveries SET status='notified',dsn_id='dsn-999'",
            [],
        )?;
        Ok(())
    })
    .await
    .unwrap();
    ha::replica::synchronize(&p.a).await.unwrap();
    let target = tempfile::tempdir().unwrap();
    let report = ha::recovery::restore_queue(&p.b.root, target.path(), "mx1", &fence(p._a.path()))
        .await
        .unwrap();
    assert_eq!(report["held_recipients"], 2);
    let restored = Store::open(target.path()).unwrap();
    restored.recover().await.unwrap();
    restored.cleanup().await.unwrap();
    assert!(restored.claim().await.unwrap().is_none());
    assert_eq!(
        std::fs::read(restored.raw_path(&id)).unwrap(),
        common::MESSAGE
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
async fn metadata_retention_waits_for_the_peer_tombstone_acknowledgement() {
    let p = pair().await;
    let id = uuid::Uuid::new_v4().to_string();
    enqueue(&p, &id).await.unwrap();
    p.a.run(|db| {
        db.execute(
            "UPDATE messages SET created=?1",
            [noisefence::now() - 31 * 86400],
        )?;
        Ok(())
    })
    .await
    .unwrap();
    ha::replica::synchronize(&p.a).await.unwrap();
    for _ in 0..2 {
        let job = p.a.claim().await.unwrap().unwrap();
        p.a.finish(&job, "delivered", "", 0).await.unwrap();
    }
    ha::replica::synchronize(&p.a).await.unwrap();
    p.a.cleanup().await.unwrap();
    assert!(!p.a.raw_path(&id).exists());
    assert_eq!(
        p.a.read(|db| Ok(
            db.query_row("SELECT COUNT(*) FROM messages", [], |r| r.get::<_, i64>(0))?
        ))
        .await
        .unwrap(),
        1
    );
    assert!(ha::replica::body_path(&p.b, "mx1", &id).exists());
    ha::replica::synchronize(&p.a).await.unwrap();
    p.a.cleanup().await.unwrap();
    assert!(!ha::replica::body_path(&p.b, "mx1", &id).exists());
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
async fn resync_requires_a_stopped_queue_and_rebuilds_a_replaced_peer_without_replaying_states() {
    let p = pair().await;
    let id = uuid::Uuid::new_v4().to_string();
    enqueue(&p, &id).await.unwrap();
    ha::replica::synchronize(&p.a).await.unwrap();
    let job = p.a.claim().await.unwrap().unwrap();
    p.a.finish(&job, "delivered", "", 0).await.unwrap();
    ha::replica::synchronize(&p.a).await.unwrap();
    let lock = p.a.daemon_lock().unwrap();
    assert!(ha::recovery::resync(&p.a.root).await.is_err());
    drop(lock);
    p.b.run(|db| {
        db.execute("DELETE FROM ha_remote", [])?;
        db.execute("DELETE FROM ha_blobs", [])?;
        Ok(())
    })
    .await
    .unwrap();
    let report = ha::recovery::resync(&p.a.root).await.unwrap();
    assert_eq!(report["tracked"], 1);
    assert!(p.a.claim().await.unwrap().is_none());
    ha::replica::synchronize(&p.a).await.unwrap();
    let states = remote(&p, &id).await.deliveries;
    assert_eq!(states.iter().filter(|d| d.status == "delivered").count(), 1);
    assert_eq!(states.iter().filter(|d| d.status == "pending").count(), 1);
    assert_eq!(ha::status(&p.a).await.unwrap().unprotected, 0);
}

#[tokio::test]
async fn successful_idle_heartbeat_clears_the_previous_replication_incident() {
    let p = pair().await;
    p.a.run(|db| {
        db.execute(
            "INSERT INTO cluster_state VALUES('ha_last_error','fixture outage')",
            [],
        )?;
        Ok(())
    })
    .await
    .unwrap();
    ha::replica::synchronize(&p.a).await.unwrap();
    assert!(ha::status(&p.a).await.unwrap().last_error.is_none());
}

#[tokio::test]
async fn a_planned_fence_can_flush_all_pending_replicas_without_starting_a_relay() {
    let p = pair().await;
    let id = uuid::Uuid::new_v4().to_string();
    enqueue(&p, &id).await.unwrap();
    let lock = p.a.daemon_lock().unwrap();
    assert!(ha::flush(&p.a, &p.config).await.is_err());
    drop(lock);
    let mut wrong_owner = (*p.config).clone();
    wrong_owner.cluster.as_mut().unwrap().node_id = "wrong-owner".into();
    assert!(ha::flush(&p.a, &wrong_owner).await.is_err());
    let report = ha::flush(&p.a, &p.config).await.unwrap();
    assert_eq!(report.pending_updates, 0);
    assert_eq!(report.unprotected, 0);
    assert!(remote(&p, &id).await.confirmed);
    assert!(
        remote(&p, &id)
            .await
            .deliveries
            .iter()
            .all(|d| d.status == "pending")
    );
    assert!(p.b.claim().await.unwrap().is_none());
}

#[tokio::test]
async fn an_existing_replica_consumes_the_stream_before_acknowledging_without_rewriting_it() {
    use std::os::unix::fs::MetadataExt;
    use tokio::io::AsyncWriteExt;
    let p = pair().await;
    let id = uuid::Uuid::new_v4().to_string();
    enqueue(&p, &id).await.unwrap();
    let path = ha::replica::body_path(&p.b, "mx1", &id);
    let inode = std::fs::metadata(&path).unwrap().ino();
    let settings = p.config.replication.as_ref().unwrap();
    let (mut writer, reader) = tokio::io::duplex(64);
    let request = reqwest::Client::new()
        .post(format!(
            "{}/api/v1/replication/v1/body/{id}",
            settings.peer_url
        ))
        .bearer_auth(std::fs::read_to_string(&settings.credential_file).unwrap())
        .header("x-noisefence-node", "mx1")
        .header(
            "x-noisefence-sha256",
            noisefence::message::digest(common::MESSAGE),
        )
        .header("x-noisefence-bytes", common::MESSAGE.len())
        .body(reqwest::Body::wrap_stream(
            tokio_util::io::ReaderStream::new(reader),
        ));
    let task = tokio::spawn(async move { request.send().await });
    writer.write_all(&common::MESSAGE[..16]).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert!(
        !task.is_finished(),
        "Replica acknowledged before consuming the body"
    );
    writer.write_all(&common::MESSAGE[16..]).await.unwrap();
    writer.shutdown().await.unwrap();
    let response = task.await.unwrap().unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(std::fs::metadata(&path).unwrap().ino(), inode);
    assert_eq!(std::fs::read(path).unwrap(), common::MESSAGE);
}

#[tokio::test]
async fn console_material_verification_rejects_a_key_that_cannot_decrypt_its_mfa_records() {
    let p = pair().await;
    let key = noisefence::mfa::Key::open(&p.a.root).unwrap();
    let secret = key.seal("fixture", &[42; 20]).unwrap();
    p.a.run(move|db| {
        db.execute("INSERT INTO users(username,password) VALUES('fixture','unusable-fixture-password')",[])?;
        db.execute("INSERT INTO mfa_credentials(username,secret,enabled,pending_until) VALUES('fixture',?1,1,0)",[secret])?;Ok(())
    }).await.unwrap();
    ha::recovery::verify_mfa(&p.a.root).unwrap();
    std::fs::write(p.a.root.join("mfa.key"), [0; 32]).unwrap();
    assert!(ha::recovery::verify_mfa(&p.a.root).is_err());
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
