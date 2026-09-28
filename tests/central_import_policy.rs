#[allow(dead_code)]
mod common;
#[path = "common/postgres.rs"]
mod postgres;
use noisefence::{
    central::{import::PolicySnapshot, outbox::Identity},
    cluster::{
        activation::{Acknowledgement, Journal, Progress},
        artifacts,
    },
    control::Settings,
    store::Store,
};
use std::collections::BTreeMap;

#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn import_preserves_policy_epochs_revocations_audit_ids_and_revisions() {
    let f = postgres::Fixture::new().await;
    let pg = f.connect().await;
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path()).unwrap();
    let config = common::config(root.path());
    let local_identity = store
        .run(|db| noisefence::central::outbox::initialize(db, "mx1"))
        .await
        .unwrap();
    let base = artifacts::capture(&config, Settings::from_config(&config), 0)
        .unwrap()
        .bundle;
    let mut next = base.clone();
    next.revision = 7;
    next.settings.filters.threshold = 90.;
    next.digest = next.hash().unwrap();
    let expected_settings = serde_json::to_value(&next.settings).unwrap();
    let mut aborted = next.clone();
    aborted.revision = 8;
    aborted.digest = aborted.hash().unwrap();
    let mut nodes: BTreeMap<String, String> = ["mx1", "mx2", "retired"]
        .into_iter()
        .map(|n| (n.into(), uuid::Uuid::new_v4().to_string()))
        .collect();
    nodes.insert("mx1".into(), local_identity.epoch);
    let identities = nodes.clone();
    let (snapshot,journal)=store.run(move |db| {
        db.execute_batch("INSERT INTO cluster_state VALUES('node_id','mx1'),('role','coordinator');")?;
        let tx=db.transaction()?;
        let token="a".repeat(64);
        tx.execute("INSERT INTO cluster_nodes(id,name,token_hash,enabled,created,version) VALUES('mx2','Worker',?1,1,100,9),('retired','Retired worker',?1,0,99,13)",[token])?;
        Journal::initialize(&tx,"mx1",base)?;
        let staging=Journal::begin(&tx,next.clone(),vec!["mx1".into(),"mx2".into()],101)?;
        let epoch=staging.rollout().unwrap().epoch().clone();
        assert!(PolicySnapshot::capture(&tx,identities.clone()).is_err());
        for node in ["mx1","mx2"] {Journal::acknowledge(&tx,node,&Acknowledgement{epoch:epoch.clone(),progress:Progress::Prepared},102)?;}
        Journal::commit(&tx,&epoch,103)?;
        for node in ["mx1","mx2"] {Journal::acknowledge(&tx,node,&Acknowledgement{epoch:epoch.clone(),progress:Progress::Applied},104)?;}
        Journal::release(&tx,&epoch,105)?;
        let staged=Journal::begin(&tx,aborted,vec!["mx1".into(),"mx2".into()],106)?;
        Journal::abort(&tx,staged.rollout().unwrap().epoch(),107)?;
        tx.execute("INSERT INTO console_revisions VALUES(7,103,'admin',?1)",[serde_json::to_string(&next.settings)?])?;
        tx.execute_batch("INSERT INTO audit VALUES(2,101,'admin','configuration_staged','1'),(10,103,'admin','configuration','1');")?;
        let journal=serde_json::to_value(Journal::read(&tx)?.unwrap())?;
        let mut wrong=identities.clone();wrong.insert("mx1".into(),uuid::Uuid::new_v4().to_string());
        assert!(PolicySnapshot::capture(&tx,wrong).is_err());
        tx.execute("INSERT INTO cluster_commands VALUES('pending','mx2','message','alice@example.test','retry','admin',100,9999999999,NULL,NULL)",[])?;
        assert!(PolicySnapshot::capture(&tx,identities.clone()).is_err());
        tx.execute("DELETE FROM cluster_commands WHERE id='pending'",[])?;
        let snapshot=PolicySnapshot::capture(&tx,identities)?;
        tx.commit()?;
        Ok((snapshot,journal))
    }).await.unwrap();
    assert_eq!(journal["sequence"], 2);
    assert_eq!(journal["current_sequence"], 1);
    assert!(f.central.import_policy(&snapshot).await.is_err());
    for (node, epoch) in &nodes {
        f.central
            .register_source(&Identity {
                node: node.clone(),
                epoch: epoch.clone(),
            })
            .await
            .unwrap();
    }
    pg.execute(
        "UPDATE noisefence.sources SET enabled=false WHERE node='mx2'",
        &[],
    )
    .await
    .unwrap();
    assert!(
        f.central
            .import_policy(&snapshot)
            .await
            .unwrap_err()
            .to_string()
            .contains("re-enable")
    );
    pg.execute(
        "UPDATE noisefence.sources SET enabled=true WHERE node='mx2'",
        &[],
    )
    .await
    .unwrap();
    pg.batch_execute("CREATE FUNCTION noisefence.break_policy_import() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic'; END $$; CREATE TRIGGER break_policy_import BEFORE INSERT ON noisefence.policy_authority FOR EACH ROW EXECUTE FUNCTION noisefence.break_policy_import();").await.unwrap();
    assert!(f.central.import_policy(&snapshot).await.is_err());
    for table in [
        "audit",
        "policy_revisions",
        "cluster_nodes",
        "policy_head",
        "policy_authority",
    ] {
        assert_eq!(
            pg.query_one(&format!("SELECT count(*) FROM noisefence.{table}"), &[])
                .await
                .unwrap()
                .get::<_, i64>(0),
            0
        );
    }
    assert!(
        pg.query_one(
            "SELECT enabled FROM noisefence.sources WHERE node='retired'",
            &[]
        )
        .await
        .unwrap()
        .get::<_, bool>(0)
    );
    pg.batch_execute("DROP TRIGGER break_policy_import ON noisefence.policy_authority;")
        .await
        .unwrap();
    f.central.import_policy(&snapshot).await.unwrap();
    assert_eq!(
        pg.query_one("SELECT journal FROM noisefence.policy_authority", &[])
            .await
            .unwrap()
            .get::<_, serde_json::Value>(0),
        journal
    );
    assert_eq!(
        pg.query_one(
            "SELECT settings FROM noisefence.policy_revisions WHERE id=7",
            &[]
        )
        .await
        .unwrap()
        .get::<_, serde_json::Value>(0),
        expected_settings
    );
    let authority = f
        .central
        .policy_journal(&Identity {
            node: "mx1".into(),
            epoch: nodes["mx1"].clone(),
        })
        .await
        .unwrap();
    assert_eq!(authority.current_epoch().sequence, 1);
    assert_eq!(authority.rollout().unwrap().epoch().sequence, 2);
    assert_eq!(
        pg.query_one(
            "SELECT version FROM noisefence.cluster_nodes WHERE node='mx2'",
            &[]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        9
    );
    assert!(
        !pg.query_one(
            "SELECT enabled FROM noisefence.sources WHERE node='retired'",
            &[]
        )
        .await
        .unwrap()
        .get::<_, bool>(0)
    );
    assert!(
        f.central
            .authenticate_node("retired", &"a".repeat(64))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        f.central
            .authenticate_node("mx2", &"a".repeat(64))
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        pg.query_one("SELECT count(*) FROM noisefence.policy_peers", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    let next_audit:i64=pg.query_one("INSERT INTO noisefence.audit(created,username,action,object_id) VALUES(200,'admin','test','synthetic') RETURNING id",&[]).await.unwrap().get(0);
    assert!(next_audit > 10);
    assert!(f.central.import_policy(&snapshot).await.is_err());
    f.finish().await;
}
