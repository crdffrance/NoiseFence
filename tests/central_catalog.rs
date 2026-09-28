#[allow(dead_code)]
mod common;
#[path = "common/postgres.rs"]
mod postgres;
use noisefence::{cluster::artifacts, control::Settings, engine, model_catalog};
use std::sync::Arc;

#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn catalog_uses_central_authority_and_keeps_intent_when_outcome_logging_fails() {
    let f = postgres::Fixture::new().await;
    let pg = f.connect().await;
    let root = tempfile::tempdir().unwrap();
    let mut config = (*common::config(root.path())).clone();
    let path = root.path().join("source-model.json");
    let model = engine::Model {
        version: "catalog-fixture".into(),
        algorithm: engine::Algorithm::Logistic,
        feature_version: 1,
        bias: -4.,
        weights: vec![0.; engine::FEATURE_COUNT],
        idf: vec![],
        trained_at: noisefence::now(),
        examples: 2,
    };
    std::fs::write(&path, serde_json::to_vec(&model).unwrap()).unwrap();
    config.filter.model = Some(path.clone());
    let publication =
        Arc::new(artifacts::capture(&config, Settings::from_config(&config), 1).unwrap());
    let session = "a".repeat(64);
    let reader = "b".repeat(64);
    for (user, admin, token) in [("admin", true, &session), ("reader", false, &reader)] {
        pg.execute(
            "INSERT INTO noisefence.users(username,password,admin) VALUES($1,'unused',$2)",
            &[&user, &admin],
        )
        .await
        .unwrap();
        pg.execute("INSERT INTO noisefence.sessions(token_hash,username,csrf,expires) VALUES($1,$2,'unused',$3)", &[token,&user,&(noisefence::now()+3600)]).await.unwrap();
    }
    let retain = |actor: String, token: String| {
        let central = f.central.clone();
        let directory = root.path().to_owned();
        let publication = publication.clone();
        async move {
            central
                .retain_catalog(
                    directory,
                    publication,
                    "Test models".into(),
                    0,
                    &actor,
                    &token,
                )
                .await
        }
    };
    assert!(retain("reader".into(), reader.clone()).await.is_err());
    assert!(retain("admin".into(), "expired".into()).await.is_err());
    assert!(
        retain("old-local-admin".into(), session.clone())
            .await
            .is_err()
    );
    assert!(model_catalog::list(root.path()).unwrap().is_empty());
    assert_eq!(
        pg.query_one("SELECT count(*) FROM noisefence.audit", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    let entry = retain("admin".into(), session.clone()).await.unwrap();
    entry.verify(root.path()).unwrap();
    let records = pg
        .query(
            "SELECT action,object_id FROM noisefence.audit ORDER BY id",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].get::<_, String>(0), "model_set_retain_started");
    assert_eq!(records[1].get::<_, String>(0), "model_set_retain_completed");
    assert_eq!(
        records[0].get::<_, String>(1),
        records[1].get::<_, String>(1)
    );
    assert!(records[0].get::<_, String>(1).ends_with(&entry.id));
    pg.execute(
        "UPDATE noisefence.users SET disabled=true WHERE username='admin'",
        &[],
    )
    .await
    .unwrap();
    assert!(
        f.central
            .remove_catalog(root.path().into(), entry.id.clone(), "admin", &session)
            .await
            .is_err()
    );
    entry.verify(root.path()).unwrap();
    pg.execute(
        "UPDATE noisefence.users SET disabled=false WHERE username='admin'",
        &[],
    )
    .await
    .unwrap();
    // Completion-log failure must return an error, leave the durable intent,
    // and never pretend that a successful filesystem change was rolled back.
    pg.batch_execute("CREATE FUNCTION reject_catalog_completion() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='model_set_remove_completed' THEN RAISE EXCEPTION 'synthetic audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_catalog_completion BEFORE INSERT ON noisefence.audit FOR EACH ROW EXECUTE FUNCTION reject_catalog_completion();").await.unwrap();
    let error = f
        .central
        .remove_catalog(root.path().into(), entry.id.clone(), "admin", &session)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("outcome not recorded"));
    assert!(model_catalog::list(root.path()).unwrap().is_empty());
    assert_eq!(
        pg.query_one(
            "SELECT count(*) FROM noisefence.audit WHERE action='model_set_remove_started'",
            &[]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        1
    );
    assert_eq!(
        pg.query_one(
            "SELECT count(*) FROM noisefence.audit WHERE action='model_set_remove_completed'",
            &[]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        0
    );
    pg.batch_execute("DROP TRIGGER reject_catalog_completion ON noisefence.audit; DROP FUNCTION reject_catalog_completion();").await.unwrap();
    assert!(
        f.central
            .remove_catalog(root.path().into(), entry.id.clone(), "admin", &session)
            .await
            .is_err()
    );
    assert_eq!(
        pg.query_one(
            "SELECT count(*) FROM noisefence.audit WHERE action='model_set_remove_failed'",
            &[]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        1
    );
    // An outage before authorization cannot perform a file operation.
    f.suspend().await;
    assert!(retain("admin".into(), session.clone()).await.is_err());
    assert!(model_catalog::list(root.path()).unwrap().is_empty());
    f.resume().await;
    let entry = retain("admin".into(), session.clone()).await.unwrap();
    f.central
        .remove_catalog(root.path().into(), entry.id, "admin", &session)
        .await
        .unwrap();
    drop(pg);
    f.finish().await;
}
