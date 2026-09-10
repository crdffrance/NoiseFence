use super::*;
use crate::store::Store;
const ALICE: &str = "alice@example.test";
const BOB: &str = "bob@example.test";
fn scope(address: &str) -> Vec<(String, String)> {
    vec![(address.into(), address.into())]
}
async fn setup() -> (tempfile::TempDir, Store) {
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path()).unwrap();
    store.run(|db| {db.execute_batch("INSERT INTO users(username,password,admin) VALUES('alice','unused',0),('bob','unused',0),('outsider','unused',0); INSERT INTO grants(username,address) VALUES('alice','alice@example.test'),('bob','bob@example.test');")?;Ok(())}).await.unwrap();
    (root, store)
}
async fn snapshot(store: &Store, scopes: Vec<(String, String)>) -> Epoch {
    store
        .run(move |db| {
            let tx = db.transaction()?;
            Epoch::capture(&tx, crate::now(), &scopes)
        })
        .await
        .unwrap()
}
async fn valid(store: &Store, epoch: Epoch) -> bool {
    store
        .run(move |db| {
            let tx = db.transaction()?;
            Ok(epoch.validate(&tx, crate::now()).is_ok())
        })
        .await
        .unwrap()
}
async fn sql(store: &Store, sql: &str) {
    let sql = sql.to_owned();
    store
        .run(move |db| {
            db.execute_batch(&sql)?;
            Ok(())
        })
        .await
        .unwrap();
}
async fn shared(store: &Store) {
    sql(store,"INSERT INTO messages(id,created,sender,scan) VALUES('shared',unixepoch(),'sender@example.org','{}');
      INSERT INTO deliveries(id,message_id,address,destination,hosts,next_attempt) VALUES(100,'shared','alice@example.test','alice@example.test','[]',0),(101,'shared','bob@example.test','bob@example.test','[]',0);
      INSERT INTO sender_history_receipts(message_id,delivery_id,recipient,destination,sender,domain,received,raw_hash,eligible)
      SELECT message_id,id,address,destination,'sender@example.org','example.org',unixepoch(),'fixture',1 FROM deliveries WHERE message_id='shared';").await;
}
#[tokio::test]
async fn unrelated_labels_on_shared_mail_do_not_change_the_other_recipient() {
    let (_root, store) = setup().await;
    shared(&store).await;
    for (operation, sql_text) in [
        (
            "insert",
            "INSERT INTO feedback VALUES('bob','shared',1,unixepoch())",
        ),
        ("update", "UPDATE feedback SET spam=0 WHERE username='bob'"),
        (
            "subtype",
            "INSERT INTO feedback_categories VALUES('bob','shared','publicity')",
        ),
        (
            "subtype removal",
            "DELETE FROM feedback_categories WHERE username='bob'",
        ),
        ("delete", "DELETE FROM feedback WHERE username='bob'"),
    ] {
        let alice = snapshot(&store, scope(ALICE)).await;
        let bob = snapshot(&store, scope(BOB)).await;
        sql(&store, sql_text).await;
        assert!(
            valid(&store, alice).await,
            "Alice must be unaffected by {operation}"
        );
        assert!(
            !valid(&store, bob).await,
            "Bob must recheck after {operation}"
        );
    }
}
#[tokio::test]
async fn scope_selection_removes_an_ordinary_siblings_grant_guard() {
    let (_root, store) = setup().await;
    let both = snapshot(
        &store,
        vec![(ALICE.into(), ALICE.into()), (BOB.into(), BOB.into())],
    )
    .await;
    let alice = both.select(&[0]);
    let bob = both.select(&[1]);
    sql(&store, "DELETE FROM grants WHERE username='bob'").await;
    assert!(valid(&store, alice).await);
    assert!(!valid(&store, bob).await);
}
#[tokio::test]
async fn grant_domains_cover_alias_source_and_destination_without_cross_domain_invalidation() {
    let (_root, store) = setup().await;
    let scopes = vec![("alias@source.test".into(), "box@destination.test".into())];
    for grant in [
        "box@destination.test",
        "*@SOURCE.TEST",
        "*@DESTINATION.TEST",
    ] {
        let epoch = snapshot(&store, scopes.clone()).await;
        sql(
            &store,
            &format!("INSERT INTO grants VALUES('outsider','{grant}')"),
        )
        .await;
        assert!(!valid(&store, epoch).await, "{grant}");
        sql(&store, "DELETE FROM grants WHERE username='outsider'").await;
    }
    let epoch = snapshot(&store, scopes).await;
    sql(
        &store,
        "INSERT INTO grants VALUES('outsider','*@unrelated.test')",
    )
    .await;
    assert!(valid(&store, epoch).await);
}
#[tokio::test]
async fn account_changes_cover_current_and_newly_authorized_votes_including_cascades() {
    let (_root, store) = setup().await;
    shared(&store).await;
    sql(
        &store,
        "INSERT INTO feedback VALUES('bob','shared',1,unixepoch())",
    )
    .await;
    let alice = snapshot(&store, scope(ALICE)).await;
    sql(
        &store,
        "UPDATE users SET password='changed' WHERE username='bob'",
    )
    .await;
    assert!(valid(&store, alice).await);
    for update in [
        "UPDATE users SET admin=1 WHERE username='bob'",
        "UPDATE users SET disabled=1 WHERE username='bob'",
        "UPDATE users SET disabled=0 WHERE username='bob'",
        "DELETE FROM users WHERE username='bob'",
    ] {
        let alice = snapshot(&store, scope(ALICE)).await;
        sql(&store, update).await;
        assert!(!valid(&store, alice).await, "{update}");
    }
}
#[tokio::test]
async fn routing_proof_edits_and_deletions_invalidate_exact_original_scopes() {
    for change in [
        "UPDATE deliveries SET destination='moved@example.test' WHERE id=100",
        "UPDATE messages SET is_dsn=1 WHERE id='shared'",
        "UPDATE sender_history_receipts SET message_id='replacement' WHERE delivery_id=100",
        "DELETE FROM deliveries WHERE id=100",
        "DELETE FROM messages WHERE id='shared'",
    ] {
        let (_root, store) = setup().await;
        shared(&store).await;
        sql(&store,"INSERT INTO feedback VALUES('alice','shared',0,unixepoch());INSERT INTO messages(id,created,sender,scan) VALUES('replacement',unixepoch(),'sender@example.org','{}')").await;
        let alice = snapshot(&store, scope(ALICE)).await;
        sql(&store, change).await;
        assert!(!valid(&store, alice).await, "{change}");
    }
}
#[tokio::test]
async fn pruning_old_keys_preserves_live_proofs_but_recreation_never_reuses_a_revision() {
    let (_root, store) = setup().await;
    sql(
        &store,
        "UPDATE sender_history_revisions SET updated=unixepoch()-61",
    )
    .await;
    let old = snapshot(&store, scope(ALICE)).await;
    store.run(|db| prune(db, crate::now())).await.unwrap();
    assert!(valid(&store, old.clone()).await);
    sql(
        &store,
        "UPDATE grants SET address=address WHERE username='alice'",
    )
    .await;
    assert!(!valid(&store, old).await);
}
#[tokio::test]
async fn proof_age_is_bounded_and_schema_reopening_preserves_revisions() {
    let (root, store) = setup().await;
    let old = snapshot(&store, scope(ALICE)).await;
    let other = Store::open(root.path()).unwrap();
    assert!(valid(&other, old.clone()).await);
    store
        .run(move |db| {
            let tx = db.transaction()?;
            old.validate(&tx, old.as_of)?;
            assert!(old.validate(&tx, old.as_of - 1).is_err());
            assert!(old.validate(&tx, old.as_of + 5).is_err());
            Ok(())
        })
        .await
        .unwrap();
    let old = snapshot(&store, scope(ALICE)).await;
    sql(
        &other,
        "UPDATE users SET password='changed' WHERE username='alice'",
    )
    .await;
    assert!(!valid(&store, old).await);
}
#[tokio::test]
async fn capacity_fallback_prevents_silent_loss_and_recovers_after_pruning() {
    let (_root, store) = setup().await;
    store.run(|db|{let tx=db.transaction()?;
        tx.execute_batch(&format!("WITH RECURSIVE x(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM x WHERE n<{})
          INSERT INTO sender_history_revisions(kind,a,b,revision,updated) SELECT 'g','fixture-'||n,'',1,unixepoch() FROM x;",MAX_KEYS))?;
        let count:i64=tx.query_row("SELECT COUNT(*) FROM sender_history_revisions",[],|r|r.get(0))?;assert_eq!(count,MAX_KEYS as i64);
        let recorded:i64=tx.query_row("SELECT records FROM sender_history_revision_state WHERE id=1",[],|r|r.get(0))?;assert_eq!(count,recorded);tx.commit()?;Ok(())}).await.unwrap();
    let old = snapshot(&store, scope("untracked@example.test")).await;
    sql(
        &store,
        "INSERT INTO grants VALUES('outsider','untracked@example.test')",
    )
    .await;
    assert!(!valid(&store, old).await);
    // Only counters age here; the real grant remains in force for a new read.
    sql(
        &store,
        "UPDATE users SET password='capacity-change' WHERE username='outsider'",
    )
    .await;
    store
        .run(|db| {
            let password: String = db.query_row(
                "SELECT password FROM users WHERE username='outsider'",
                [],
                |r| r.get(0),
            )?;
            assert_eq!(password, "capacity-change");
            Ok(())
        })
        .await
        .unwrap();
    // An ignored counter INSERT must not suppress its enclosing account action.
    sql(&store, "DELETE FROM users WHERE username='outsider'").await;
    store
        .run(|db| {
            let count: i64 = db.query_row(
                "SELECT COUNT(*) FROM users WHERE username='outsider'",
                [],
                |r| r.get(0),
            )?;
            assert_eq!(count, 0);
            Ok(())
        })
        .await
        .unwrap();
    sql(&store,"INSERT INTO users(username,password,admin) VALUES('outsider','unused',0); INSERT INTO grants VALUES('outsider','untracked@example.test')").await;
    sql(
        &store,
        "UPDATE sender_history_revisions SET updated=unixepoch()-61",
    )
    .await;
    store.run(|db| prune(db, crate::now())).await.unwrap();
    let other = snapshot(&store, scope(BOB)).await;
    let own = snapshot(&store, scope("untracked@example.test")).await;
    sql(&store, "DELETE FROM grants WHERE username='outsider'").await;
    assert!(valid(&store, other).await);
    assert!(!valid(&store, own).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_readers_keep_their_proofs_during_unrelated_feedback_writes() {
    let (root, store) = setup().await;
    shared(&store).await;
    sql(
        &store,
        "INSERT INTO feedback VALUES('bob','shared',0,unixepoch())",
    )
    .await;
    let readers: Vec<_> = (0..4).map(|_| Store::open(root.path()).unwrap()).collect();
    let writer = Store::open(root.path()).unwrap();
    let mut snapshot_us = Vec::new();
    let mut validation_us = Vec::new();
    let mut accepted = 0;
    let mut global_would_retry = 0;
    for round in 0..64 {
        let mut captures = tokio::task::JoinSet::new();
        for reader in &readers {
            let reader = reader.clone();
            captures.spawn(async move {
                let result = reader
                    .run(|db| {
                        let tx = db.transaction()?;
                        let started = std::time::Instant::now();
                        let epoch = Epoch::capture(&tx, crate::now(), &scope(ALICE))?;
                        let elapsed = started.elapsed().as_micros() as u64;
                        let legacy: i64 = tx.query_row(
                            "SELECT revision FROM sender_history_epoch WHERE id=1",
                            [],
                            |r| r.get(0),
                        )?;
                        Ok((epoch, legacy, elapsed))
                    })
                    .await
                    .unwrap();
                (reader, result)
            });
        }
        let mut snapshots = Vec::new();
        while let Some(value) = captures.join_next().await {
            snapshots.push(value.unwrap());
        }
        writer
            .run(move |db| {
                db.execute(
                    "UPDATE feedback SET spam=?1,created=unixepoch() WHERE username='bob'",
                    [round % 2],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        let mut validators = tokio::task::JoinSet::new();
        for (reader, (epoch, legacy, captured_us)) in snapshots {
            snapshot_us.push(captured_us);
            validators.spawn(async move {
                reader
                    .run(move |db| {
                        let tx = db.transaction()?;
                        let started = std::time::Instant::now();
                        let valid = epoch.validate(&tx, crate::now()).is_ok();
                        let elapsed = started.elapsed().as_micros() as u64;
                        let current: i64 = tx.query_row(
                            "SELECT revision FROM sender_history_epoch WHERE id=1",
                            [],
                            |r| r.get(0),
                        )?;
                        Ok((valid, current != legacy, elapsed))
                    })
                    .await
                    .unwrap()
            });
        }
        while let Some(result) = validators.join_next().await {
            let (valid, global_changed, elapsed) = result.unwrap();
            assert!(valid);
            assert!(global_changed);
            accepted += usize::from(valid);
            global_would_retry += usize::from(global_changed);
            validation_us.push(elapsed);
        }
    }
    assert_eq!(accepted, 256);
    if let Ok(path) = std::env::var("NOISEFENCE_HISTORY_REVISION_BENCHMARK") {
        std::fs::write(path,serde_json::to_vec_pretty(&serde_json::json!({
            "schema":1,"reader_connections":4,"feedback_transactions":64,"scoped_proofs_valid":accepted,
            "global_guard_would_retry":global_would_retry,"snapshot_us":snapshot_us,"validation_us":validation_us,
            "comparison":"Global value-inequality predicate from dev.4, evaluated on the same changes; not an old-binary throughput run",
            "scope":"Only revision capture and verification; excludes authentication, classification, spool sync and outbound SMTP"
        })).unwrap()).unwrap();
    }
}
