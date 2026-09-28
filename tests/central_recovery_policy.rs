#[allow(dead_code)]
mod common;
#[path = "common/postgres.rs"]
mod postgres;
use noisefence::{
    central::{
        Central,
        binding::Binding,
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
use serde_json::json;

#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn restores_unanimous_installed_policy_without_reopening_admission() {
    recovery_case(false).await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn released_policy_timestamp_refresh_is_not_a_conflicting_revision() {
    recovery_case(true).await;
}

async fn recovery_case(timestamp_refresh: bool) {
    let f = postgres::Fixture::new().await;
    let pg = f.connect().await;
    let binding = Binding {
        instance: uuid::Uuid::new_v4().to_string(),
        source_digest: "d".repeat(64),
    };
    pg.execute(
        "INSERT INTO noisefence.migration_state VALUES(1,$1,100,101,$2)",
        &[
            &binding.source_digest,
            &json!({"instance":binding.instance}),
        ],
    )
    .await
    .unwrap();
    let central = Central::new_bound(&f.settings, &binding).unwrap();
    let roots = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
    let mut configs = Vec::new();
    let mut dbs = Vec::new();
    let mut identities = Vec::new();
    for (i, root) in roots.iter().enumerate() {
        let path = root.path().canonicalize().unwrap();
        drop(Store::open(&path).unwrap());
        let mut config = (*common::config(&path)).clone();
        let role = if i == 0 { "coordinator" } else { "worker" };
        let node = format!("mx{}", i + 1);
        config.cluster = Some(toml::from_str(&format!("role='{role}'\nnode_id='{node}'")).unwrap());
        if i == 1 {
            let cluster = config.cluster.as_mut().unwrap();
            cluster.coordinator_url = Some("https://mx1.example.test".into());
            cluster.credential_file = Some(path.join("worker.json"));
        }
        config.validate().unwrap();
        let mut db = rusqlite::Connection::open(path.join("state.sqlite3")).unwrap();
        db.execute(
            "INSERT INTO cluster_state VALUES('role',?1),('node_id',?2)",
            rusqlite::params![role, node],
        )
        .unwrap();
        let identity = outbox::initialize(&mut db, &node).unwrap();
        central.register_source(&identity).await.unwrap();
        identities.push(identity);
        configs.push(config);
        dbs.push(db);
    }
    noisefence::mfa::Key::open(&configs[0].data_dir).unwrap();
    let baseline = artifacts::capture(&configs[0], Settings::from_config(&configs[0]), 0)
        .unwrap()
        .bundle;
    central
        .initialize_policy(&identities[0], baseline.clone())
        .await
        .unwrap();
    let mut candidate = baseline.clone();
    candidate.revision = 1;
    candidate.settings.filters.threshold = 90.0;
    candidate.digest = candidate.hash().unwrap();
    let tx = dbs[0].transaction().unwrap();
    Journal::initialize(&tx, "mx1", baseline).unwrap();
    let j = Journal::begin(&tx, candidate, vec!["mx1".into(), "mx2".into()], 1).unwrap();
    let epoch = j.rollout().unwrap().epoch().clone();
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
    let op = uuid::Uuid::new_v4().to_string();
    central
        .recover_access(
            &op,
            "recovery-policy",
            &noisefence::api::hash_password("synthetic-policy-password").unwrap(),
        )
        .await
        .unwrap();
    for (i, db) in dbs.iter_mut().enumerate() {
        let local = json!({"version":1,"node":identities[i].node,"authority":released,"installed":released.current(),"installed_epoch":epoch,"prepared":epoch});
        let selection = Selection::new(
            binding.clone(),
            identities[i].clone(),
            if i == 0 {
                Role::Coordinator
            } else {
                Role::Worker
            },
            epoch.clone(),
            if i == 0 {
                Some(key_digest(&configs[0].data_dir).unwrap())
            } else {
                None
            },
        )
        .unwrap();
        for (key, value) in [
            ("activation_participant", local.to_string()),
            (
                "management_selection",
                serde_json::to_string(&selection).unwrap(),
            ),
            (
                "management_transport",
                noisefence::central::transport::PROTOCOL.into(),
            ),
            (
                "runtime_history_protocol",
                noisefence::runtime_history::PROTOCOL.into(),
            ),
            (
                "management_recovery_required",
                json!({"protocol":"noisefence-management-recovery-1","operation":op}).to_string(),
            ),
        ] {
            db.execute(
                "INSERT INTO cluster_state VALUES(?1,?2)",
                rusqlite::params![key, value],
            )
            .unwrap();
        }
        db.pragma_update(None, "user_version", 7).unwrap();
    }
    // A missing participant cannot authorize changing the destination.
    assert!(
        central
            .reconcile_recovered_policy(&configs[..1], &op)
            .await
            .is_err()
    );
    assert_eq!(
        pg.query_one("SELECT revision FROM noisefence.policy_head", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    // Two valid but disagreeing installed journals are never arbitrated by node order.
    let original: String = dbs[1]
        .query_row(
            "SELECT value FROM cluster_state WHERE key='activation_participant'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let mut local: serde_json::Value = serde_json::from_str(&original).unwrap();
    let mut different = released.current().clone();
    different.settings.filters.threshold = 80.0;
    different.digest = different.hash().unwrap();
    local["installed"] = json!(different);
    local["installed_epoch"]["digest"] = json!(different.digest);
    local["prepared"]["digest"] = json!(different.digest);
    local["authority"]["current"] = json!(different);
    local["authority"]["rollout"]["candidate"] = json!(different);
    local["authority"]["rollout"]["epoch"]["digest"] = json!(different.digest);
    // The selected cutover baseline stays below both installed candidates.
    // This makes the refusal specifically check participant disagreement.
    let error: String;
    {
        let mut chosen: serde_json::Value = serde_json::from_str(
            &dbs[1]
                .query_row(
                    "SELECT value FROM cluster_state WHERE key='management_selection'",
                    [],
                    |r| r.get::<_, String>(0),
                )
                .unwrap(),
        )
        .unwrap();
        let original_selection = chosen.to_string();
        chosen["baseline"]["sequence"] = json!(0);
        dbs[1]
            .execute(
                "UPDATE cluster_state SET value=?1 WHERE key='management_selection'",
                [chosen.to_string()],
            )
            .unwrap();
        dbs[1]
            .execute(
                "UPDATE cluster_state SET value=?1 WHERE key='activation_participant'",
                [local.to_string()],
            )
            .unwrap();
        error = central
            .reconcile_recovered_policy(&configs, &op)
            .await
            .unwrap_err()
            .to_string();
        dbs[1]
            .execute(
                "UPDATE cluster_state SET value=?1 WHERE key='management_selection'",
                [original_selection],
            )
            .unwrap();
        dbs[1]
            .execute(
                "UPDATE cluster_state SET value=?1 WHERE key='activation_participant'",
                [original],
            )
            .unwrap();
    }
    assert!(error.contains("disagree on policy authority"), "{error}");
    // A revision collision fails atomically before advancing the central head.
    pg.execute(
        "INSERT INTO noisefence.policy_revisions VALUES(1,0,'synthetic','{}',$1)",
        &[&"a".repeat(64)],
    )
    .await
    .unwrap();
    let error = central
        .reconcile_recovered_policy(&configs, &op)
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("conflicts with existing history"),
        "{error:#}"
    );
    pg.execute("DELETE FROM noisefence.policy_revisions WHERE id=1", &[])
        .await
        .unwrap();
    pg.execute(
        "INSERT INTO noisefence.policy_peers VALUES($1,$2,1,'test','test',0,'')",
        &[&identities[1].node, &identities[1].epoch],
    )
    .await
    .unwrap();
    if timestamp_refresh {
        let mut refreshed = json!(released);
        refreshed["rollout"]["updated"] =
            json!(refreshed["rollout"]["updated"].as_i64().unwrap() + 1);
        let settings = serde_json::to_value(&released.current().settings).unwrap();
        let hash =
            noisefence::message::digest(&serde_json::to_vec(&released.current().settings).unwrap());
        pg.execute(
            "INSERT INTO noisefence.policy_revisions VALUES(1,0,'synthetic',$1,$2)",
            &[&settings, &hash],
        )
        .await
        .unwrap();
        pg.execute(
            "UPDATE noisefence.policy_authority SET journal=$1",
            &[&refreshed],
        )
        .await
        .unwrap();
        pg.execute(
            "UPDATE noisefence.policy_head SET revision=1,activation_epoch=$1",
            &[&json!(epoch)],
        )
        .await
        .unwrap();
    }
    let result = central
        .reconcile_recovered_policy(&configs, &op)
        .await
        .unwrap();
    assert_eq!(result["epoch"], json!(epoch));
    assert_eq!(result["sources"], 2);
    if timestamp_refresh {
        assert_eq!(
            result["restored_rollout_updated"].as_i64().unwrap(),
            result["installed_rollout_updated"].as_i64().unwrap() + 1
        );
    }
    assert_eq!(result["central_management_recovery_required"], true);
    let row = pg
        .query_one(
            "SELECT revision,activated_at FROM noisefence.policy_head",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, i64>(0), 1);
    assert_eq!(row.get::<_, i64>(1), 0);
    assert_eq!(
        pg.query_one("SELECT journal FROM noisefence.policy_authority", &[])
            .await
            .unwrap()
            .get::<_, serde_json::Value>(0),
        json!(released)
    );
    let counter = pg
        .query_one(
            "SELECT count(*) FROM noisefence.audit WHERE action='recover_installed_policy'",
            &[],
        )
        .await
        .unwrap()
        .get::<_, i64>(0);
    assert_eq!(counter, 1);
    assert_eq!(
        pg.query_one("SELECT count(*) FROM noisefence.policy_peers", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    pg.execute(
        "INSERT INTO noisefence.policy_peers VALUES($1,$2,2,'test','test',1,'')",
        &[&identities[1].node, &identities[1].epoch],
    )
    .await
    .unwrap();

    assert_eq!(
        central
            .reconcile_recovered_policy(&configs, &op)
            .await
            .unwrap(),
        result
    );
    assert_eq!(
        pg.query_one(
            "SELECT count(*) FROM noisefence.audit WHERE action='recover_installed_policy'",
            &[]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        counter
    );
    assert_eq!(
        pg.query_one("SELECT count(*) FROM noisefence.policy_peers", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    for db in &dbs {
        assert!(db.query_row("SELECT EXISTS(SELECT 1 FROM cluster_state WHERE key='management_recovery_required')",[],|r|r.get::<_,bool>(0)).unwrap());
    }
    // A newer valid destination journal cannot be overwritten by an older cache.
    let mut newer = json!(released);
    newer["sequence"] = json!(2);
    newer["current_sequence"] = json!(2);
    newer["rollout"]["epoch"]["sequence"] = json!(2);
    let mut newer_epoch = json!(epoch);
    newer_epoch["sequence"] = json!(2);
    pg.execute(
        "UPDATE noisefence.policy_authority SET journal=$1",
        &[&newer],
    )
    .await
    .unwrap();
    pg.execute(
        "UPDATE noisefence.policy_head SET activation_epoch=$1",
        &[&newer_epoch],
    )
    .await
    .unwrap();
    assert_eq!(
        central
            .policy_journal(&identities[0])
            .await
            .unwrap()
            .current_epoch()
            .sequence,
        2
    );
    assert!(
        central
            .reconcile_recovered_policy(&configs, &op)
            .await
            .unwrap_err()
            .to_string()
            .contains("newer or conflicting policy")
    );
    pg.execute(
        "UPDATE noisefence.policy_authority SET journal=$1",
        &[&json!(released)],
    )
    .await
    .unwrap();
    pg.execute(
        "UPDATE noisefence.policy_head SET activation_epoch=$1",
        &[&json!(epoch)],
    )
    .await
    .unwrap();
    // An acknowledged recovery must still notice later destination damage.
    pg.execute("UPDATE noisefence.policy_head SET activated_at=NULL", &[])
        .await
        .unwrap();
    assert!(
        central
            .reconcile_recovered_policy(&configs, &op)
            .await
            .unwrap_err()
            .to_string()
            .contains("head changed")
    );
    drop(central);
    drop(pg);
    f.finish().await;
}
