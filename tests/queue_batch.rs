mod common;
use noisefence::{
    actions::{Action, Applied},
    engine::extract,
    fusion::runtime::{Decision, DecisionSource, Outcome},
    message::{self, SubjectTag},
    store::{Store, batch::Message},
};
use rusqlite::params;

fn variant(cfg: &noisefence::config::Config, recipient: &str, action: Action, id: &str) -> Message {
    let mut scan = extract(common::MESSAGE, 10000);
    scan.score = if action == Action::Deliver {
        70.0
    } else {
        95.0
    };
    scan.model = "fixture".into();
    scan.decision = Some(Decision {
        source: DecisionSource::Legacy,
        outcome: if action == Action::Deliver {
            Outcome::Undetermined
        } else {
            Outcome::Unwanted
        },
        score: Some(scan.score),
        model: "fixture".into(),
    });
    scan.action = Some(Applied {
        requested: action,
        effective: action,
        reason: "fixture".into(),
        quarantine_days: 14,
    });
    scan.tagged = action == Action::Tag;
    let raw = message::rewrite_with_tag(
        common::MESSAGE,
        scan.tagged.then_some(SubjectTag::Spam),
        &format!("X-NoiseFence-Id: {id}\r\n"),
    )
    .unwrap();
    Message {
        id: id.into(),
        recipients: vec![cfg.recipient(recipient).unwrap()],
        scan,
        raw,
    }
}
fn id() -> String {
    uuid::Uuid::new_v4().to_string()
}
async fn count(store: &Store, sql: &str) -> i64 {
    let sql = sql.to_owned();
    store
        .run(move |db| Ok(db.query_row(&sql, [], |r| r.get(0))?))
        .await
        .unwrap()
}

#[tokio::test]
async fn variants_persist_together_and_recover_with_their_own_bytes_actions_and_scopes() {
    let root = tempfile::tempdir().unwrap();
    let cfg = common::config(root.path());
    let store = Store::open(root.path()).unwrap();
    let a = id();
    let b = id();
    let first = variant(&cfg, "alice@example.test", Action::Deliver, &a);
    let second = variant(&cfg, "bob@example.test", Action::Tag, &b);
    let first_wire = first.raw.clone();
    let second_wire = second.raw.clone();
    store
        .enqueue_batch(a.clone(), "sender@example.org".into(), vec![first, second])
        .await
        .unwrap();
    assert_eq!(count(&store, "SELECT COUNT(*) FROM queue_batches").await, 2);
    assert_eq!(
        count(&store, "SELECT COUNT(DISTINCT queue_id) FROM queue_batches").await,
        1
    );
    let job = store.claim().await.unwrap().unwrap();
    assert_eq!(job.message_id, a);
    drop(store);
    let store = Store::open(root.path()).unwrap();
    store.recover().await.unwrap();
    assert_eq!(std::fs::read(store.raw_path(&a)).unwrap(), first_wire);
    assert_eq!(std::fs::read(store.raw_path(&b)).unwrap(), second_wire);
    assert_eq!(
        message::fields(&first_wire).unwrap().1,
        message::fields(&second_wire).unwrap().1
    );
    let mut jobs = vec![];
    while let Some(job) = store.claim().await.unwrap() {
        jobs.push(job);
    }
    assert_eq!(jobs.len(), 2);
    assert!(
        jobs.iter()
            .any(|j| j.message_id == a && j.destination == "alice@example.test" && j.attempts == 2)
    );
    assert!(
        jobs.iter()
            .any(|j| j.message_id == b && j.destination == "bob@example.test" && j.attempts == 1)
    );
    // Delivery/retention of one variant never deletes its unresolved sibling.
    let delivered = jobs.iter().find(|j| j.message_id == a).unwrap();
    store.finish(delivered, "delivered", "", 0).await.unwrap();
    store.cleanup().await.unwrap();
    assert!(!store.raw_path(&a).exists());
    assert!(store.raw_path(&b).exists());
    let late = jobs.iter().find(|j| j.message_id == b).unwrap();
    store
        .finish(late, "pending", "451 retry", noisefence::now() + 60)
        .await
        .unwrap();
    store.cleanup().await.unwrap();
    assert!(store.raw_path(&b).exists());
    store.finish(late, "delivered", "", 0).await.unwrap();
    store.cleanup().await.unwrap();
    assert!(!store.raw_path(&b).exists());
}

#[tokio::test]
async fn second_variant_sql_failure_rolls_back_both_messages_and_their_spool() {
    let root = tempfile::tempdir().unwrap();
    let cfg = common::config(root.path());
    let store = Store::open(root.path()).unwrap();
    store.run(|db| { db.execute_batch("CREATE TRIGGER fail_second BEFORE INSERT ON deliveries WHEN NEW.address='bob@example.test' BEGIN SELECT RAISE(ABORT,'simulated storage failure'); END;")?;Ok(()) }).await.unwrap();
    let a = id();
    let b = id();
    let result = store
        .enqueue_batch(
            a.clone(),
            String::new(),
            vec![
                variant(&cfg, "alice@example.test", Action::Deliver, &a),
                variant(&cfg, "bob@example.test", Action::Quarantine, &b),
            ],
        )
        .await;
    assert!(result.is_err());
    for table in ["messages", "deliveries", "delivery_policy", "queue_batches"] {
        assert_eq!(
            count(&store, &format!("SELECT COUNT(*) FROM {table}")).await,
            0
        );
    }
    assert!(!store.raw_path(&a).exists() && !store.raw_path(&b).exists());
    store.recover().await.unwrap();
    assert!(store.claim().await.unwrap().is_none());
}

#[tokio::test]
async fn file_collision_preserves_existing_data_and_removes_only_the_new_variant() {
    let root = tempfile::tempdir().unwrap();
    let cfg = common::config(root.path());
    let store = Store::open(root.path()).unwrap();
    let a = id();
    let b = id();
    std::fs::write(store.raw_path(&b), b"existing owned file").unwrap();
    assert!(
        store
            .enqueue_batch(
                a.clone(),
                String::new(),
                vec![
                    variant(&cfg, "alice@example.test", Action::Deliver, &a),
                    variant(&cfg, "bob@example.test", Action::Deliver, &b)
                ]
            )
            .await
            .is_err()
    );
    assert!(!store.raw_path(&a).exists());
    assert_eq!(
        std::fs::read(store.raw_path(&b)).unwrap(),
        b"existing owned file"
    );
    assert_eq!(count(&store, "SELECT COUNT(*) FROM messages").await, 0);
}

#[tokio::test]
async fn second_file_storage_failure_does_not_leave_an_accepted_partial_batch() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let cfg = common::config(root.path());
    let store = Store::open(root.path()).unwrap();
    let a = id();
    let b = id();
    // create_new rejects this before writing; the target must never be followed.
    let sentinel = root.path().join("sentinel");
    std::fs::write(&sentinel, b"intact").unwrap();
    symlink(&sentinel, store.raw_path(&b)).unwrap();
    assert!(
        store
            .enqueue_batch(
                a.clone(),
                String::new(),
                vec![
                    variant(&cfg, "alice@example.test", Action::Tag, &a),
                    variant(&cfg, "bob@example.test", Action::Deliver, &b)
                ]
            )
            .await
            .is_err()
    );
    assert_eq!(std::fs::read(sentinel).unwrap(), b"intact");
    assert!(!store.raw_path(&a).exists());
    assert_eq!(count(&store, "SELECT COUNT(*) FROM queue_batches").await, 0);
}

#[tokio::test]
async fn variants_never_disclose_sibling_decisions_through_console_or_diagnostics() {
    let root = tempfile::tempdir().unwrap();
    let cfg = common::config(root.path());
    let store = Store::open(root.path()).unwrap();
    store
        .run(|db| {
            for user in ["alice", "bob"] {
                db.execute(
                    "INSERT INTO users(username,password) VALUES(?1,'fixture-only')",
                    [user],
                )?;
                db.execute(
                    "INSERT INTO grants(username,address) VALUES(?1,?2)",
                    params![user, format!("{user}@example.test")],
                )?;
            }
            Ok(())
        })
        .await
        .unwrap();
    let a = id();
    let b = id();
    let first = variant(&cfg, "alice@example.test", Action::Deliver, &a);
    let mut second = variant(&cfg, "bob@example.test", Action::Quarantine, &b);
    second.scan.reasons.push(noisefence::engine::Signal {
        id: "bob_private_fixture".into(),
        detail: "Private scoped decision".into(),
        weight: 0.0,
    });
    store
        .enqueue_batch(a.clone(), "sender@example.org".into(), vec![first, second])
        .await
        .unwrap();
    for (user, own, other, category) in [
        ("alice", &a, &b, noisefence::mailing::Category::Undetermined),
        ("bob", &b, &a, noisefence::mailing::Category::Spam),
    ] {
        let list = store
            .list_scoped(
                user.into(),
                String::new(),
                "all".into(),
                0,
                80.0,
                String::new(),
            )
            .await
            .unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(&list[0].id, own);
        assert_eq!(list[0].category, category);
        let json = serde_json::to_string(&list).unwrap();
        assert!(!json.contains(other));
        if user == "alice" {
            assert!(!json.contains("bob_private_fixture") && !json.contains("bob@example.test"));
        }
        assert!(
            store
                .diagnostics(user.into(), other.into())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .diagnostics(user.into(), own.into())
                .await
                .unwrap()
                .is_some()
        );
    }
}

#[tokio::test]
async fn malformed_or_unrelated_variants_are_rejected_before_disk_writes() {
    let root = tempfile::tempdir().unwrap();
    let cfg = common::config(root.path());
    let store = Store::open(root.path()).unwrap();
    for case in 0..7 {
        let a = id();
        let b = id();
        let first = variant(&cfg, "alice@example.test", Action::Deliver, &a);
        let mut second = variant(&cfg, "bob@example.test", Action::Deliver, &b);
        match case {
            0 => second.id = a.clone(),
            1 => second.id = "../outside".into(),
            2 => second.recipients = first.recipients.clone(),
            3 => second.recipients.clear(),
            4 => second.raw.extend_from_slice(b"changed body"),
            5 => second.scan.raw_sha256 = None,
            _ => second.scan.raw_sha256 = Some("0".repeat(64)),
        }
        assert!(
            store
                .enqueue_batch(a, String::new(), vec![first, second])
                .await
                .is_err()
        );
        assert_eq!(count(&store, "SELECT COUNT(*) FROM messages").await, 0);
        assert_eq!(
            std::fs::read_dir(root.path().join("spool"))
                .unwrap()
                .count(),
            0
        );
    }
}
