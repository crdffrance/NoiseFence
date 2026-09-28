#[allow(dead_code)]
mod common;
#[path = "common/postgres.rs"]
mod postgres;
use noisefence::{
    central::{
        import::{
            AccountsSnapshot, DeliveryIdentities, PolicySnapshot, PreparedImport, QualitySnapshot,
            ReconciledSpools, SourceLocks, SpoolSnapshot,
        },
        outbox,
        selection::{Selection, key_digest},
    },
    cluster::{
        Role,
        activation::{Acknowledgement, Journal, Progress},
        artifacts,
    },
    control::Settings,
    store::Store,
};
use rusqlite::{Connection, Transaction, TransactionBehavior};

fn capture(tx: &[Transaction<'_>], key: &noisefence::mfa::Key) -> PreparedImport {
    let epochs = tx
        .iter()
        .map(|t| {
            let i = outbox::identity(t).unwrap();
            (i.node, i.epoch)
        })
        .collect();
    PreparedImport::new(
        AccountsSnapshot::capture(&tx[0], Some(key)).unwrap(),
        DeliveryIdentities::capture(&tx[0]).unwrap(),
        QualitySnapshot::capture(&tx[0]).unwrap(),
        PolicySnapshot::capture(&tx[0], epochs).unwrap(),
        ReconciledSpools::verify(
            tx.iter()
                .map(|t| match Selection::read(t).unwrap() {
                    Some(selected) => SpoolSnapshot::read_selected(t, &selected).unwrap(),
                    None => SpoolSnapshot::read_seeded(t).unwrap(),
                })
                .collect(),
        )
        .unwrap(),
    )
    .unwrap()
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn destination_activates_only_after_all_durable_selections_and_rejects_reactivation() {
    let f = postgres::Fixture::new().await;
    let pg = f.connect().await;
    let roots = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
    let mut dbs = Vec::new();
    let mut guards = Vec::new();
    let key = noisefence::mfa::Key::open(roots[0].path()).unwrap();
    for (i, root) in roots.iter().enumerate() {
        drop(Store::open(root.path()).unwrap());
        guards.push(SourceLocks::acquire(root.path()).unwrap());
        let mut db = Connection::open(root.path().join("state.sqlite3")).unwrap();
        db.execute_batch("PRAGMA synchronous=FULL; PRAGMA user_version=6;")
            .unwrap();
        let node = format!("mx{}", i + 1);
        outbox::initialize(&mut db, &node).unwrap();
        db.execute("INSERT INTO cluster_state VALUES('node_id',?1)", [&node])
            .unwrap();
        db.execute(
            "INSERT INTO cluster_state VALUES('role',?1)",
            [if i == 0 { "coordinator" } else { "worker" }],
        )
        .unwrap();
        dbs.push(db);
    }
    let config = common::config(roots[0].path());
    let baseline = artifacts::capture(&config, Settings::from_config(&config), 0)
        .unwrap()
        .bundle;
    let mut candidate = baseline.clone();
    candidate.revision = 1;
    candidate.digest = candidate.hash().unwrap();
    let tx = dbs[0].transaction().unwrap();
    tx.execute_batch("INSERT INTO users VALUES('admin','synthetic',1,0)")
        .unwrap();
    tx.execute("INSERT INTO cluster_nodes(id,name,token_hash,enabled,created,version) VALUES('mx2','Worker',?1,1,1,1)",["a".repeat(64)]).unwrap();
    tx.execute(
        "INSERT INTO console_revisions VALUES(1,3,'admin',?1)",
        [serde_json::to_string(&candidate.settings).unwrap()],
    )
    .unwrap();
    Journal::initialize(&tx, "mx1", baseline).unwrap();
    let journal = Journal::begin(&tx, candidate, vec!["mx1".into(), "mx2".into()], 1).unwrap();
    let epoch = journal.rollout().unwrap().epoch().clone();
    for node in ["mx1", "mx2"] {
        Journal::acknowledge(
            &tx,
            node,
            &Acknowledgement {
                epoch: epoch.clone(),
                progress: Progress::Prepared,
            },
            2,
        )
        .unwrap();
    }
    Journal::commit(&tx, &epoch, 3).unwrap();
    for node in ["mx1", "mx2"] {
        Journal::acknowledge(
            &tx,
            node,
            &Acknowledgement {
                epoch: epoch.clone(),
                progress: Progress::Applied,
            },
            4,
        )
        .unwrap();
    }
    let released = Journal::release(&tx, &epoch, 5).unwrap();
    tx.commit().unwrap();
    for (i, db) in dbs.iter_mut().enumerate() {
        let local = serde_json::json!({"version":1,"node":format!("mx{}",i+1),"authority":released,"installed":released.current(),"installed_epoch":epoch,"prepared":epoch});
        db.execute(
            "INSERT INTO cluster_state VALUES('activation_participant',?1)",
            [local.to_string()],
        )
        .unwrap();
        let mut tx = db.transaction().unwrap();
        SpoolSnapshot::capture(&mut tx).unwrap();
        tx.commit().unwrap();
    }
    // These real SQLite write reservations survive both destination parity and
    // the final local commits; the process locks remain held for the entire test.
    let txs = dbs
        .iter_mut()
        .map(|db| {
            db.transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap()
        })
        .collect::<Vec<_>>();
    let receipt = f.central.stage_import(capture(&txs, &key)).await.unwrap();
    let prepared = capture(&txs, &key);
    let selections = txs
        .iter()
        .enumerate()
        .map(|(i, tx)| {
            Selection::new(
                receipt.database.clone(),
                outbox::identity(tx).unwrap(),
                if i == 0 {
                    Role::Coordinator
                } else {
                    Role::Worker
                },
                epoch.clone(),
                if i == 0 {
                    Some(key_digest(roots[0].path()).unwrap())
                } else {
                    None
                },
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let runtime = noisefence::central::Central::new_bound(&f.settings, &receipt.database).unwrap();
    assert!(runtime.health().await.is_err());
    assert!(
        f.central
            .activate_import(&receipt.database, &prepared, &selections[..1], || panic!(
                "must reject incomplete source set before local writes"
            ))
            .await
            .is_err()
    );
    pg.batch_execute("UPDATE noisefence.users SET disabled=true")
        .await
        .unwrap();
    assert!(
        f.central
            .activate_import(&receipt.database, &prepared, &selections, || panic!(
                "must check destination parity before local writes"
            ))
            .await
            .is_err()
    );
    pg.batch_execute("UPDATE noisefence.users SET disabled=false")
        .await
        .unwrap();
    let mut pending = txs.into_iter();
    let first = pending.next().unwrap();
    assert!(
        f.central
            .activate_import(&receipt.database, &prepared, &selections, || {
                selections[0].install(&first)?;
                first.commit()?;
                anyhow::bail!("synthetic interruption after first durable selection")
            })
            .await
            .is_err()
    );
    assert!(runtime.health().await.is_err());
    assert!(
        pg.query_one(
            "SELECT activated_at FROM noisefence.migration_state WHERE id=1",
            &[]
        )
        .await
        .unwrap()
        .get::<_, Option<i64>>(0)
        .is_none()
    );
    // A fresh capture with one source at format seven and the other still at
    // format six has exactly the same management digest and destination parity.
    {
        let mut readers = roots
            .iter()
            .map(|root| Connection::open(root.path().join("state.sqlite3")).unwrap())
            .collect::<Vec<_>>();
        let reads = readers
            .iter_mut()
            .map(|db| db.transaction().unwrap())
            .collect::<Vec<_>>();
        let recovered = capture(&reads, &key);
        f.central
            .verify_import_sources(&receipt.database, &recovered)
            .await
            .unwrap();
    }
    // Resume this same attempt while the remaining transaction and all process
    // locks are still held. Cross-process recovery is a separate orchestration gate.
    let second = pending.next().unwrap();
    drop(pending);
    assert!(
        f.central
            .activate_import(&receipt.database, &prepared, &selections, || {
                selections[1].install(&second)?;
                second.commit()?;
                Ok(vec![selections[1].clone()])
            })
            .await
            .is_err(),
        "missing coordinator receipt cannot open runtime"
    );
    assert!(runtime.health().await.is_err());
    f.central
        .activate_import(&receipt.database, &prepared, &selections, || {
            roots
                .iter()
                .map(|root| {
                    let db = Connection::open(root.path().join("state.sqlite3"))?;
                    Selection::read(&db)?
                        .ok_or_else(|| anyhow::anyhow!("missing durable selection"))
                })
                .collect()
        })
        .await
        .unwrap();
    runtime.health().await.unwrap();
    let row = pg
        .query_one(
            "SELECT report,activated_at FROM noisefence.migration_state WHERE id=1",
            &[],
        )
        .await
        .unwrap();
    let report: serde_json::Value = row.get(0);
    assert_eq!(report["phase"], "active");
    assert_eq!(
        report["selections"],
        serde_json::to_value(&selections).unwrap()
    );
    assert!(row.get::<_, Option<i64>>(1).is_some());
    assert!(
        f.central
            .activate_import(&receipt.database, &prepared, &selections, || panic!(
                "already active must never re-run local commits"
            ))
            .await
            .is_err()
    );
    for (db, selection) in dbs.iter().zip(&selections) {
        assert_eq!(Selection::read(db).unwrap().as_ref(), Some(selection));
    }
    drop(runtime);
    drop(guards);
    f.finish().await;
}
