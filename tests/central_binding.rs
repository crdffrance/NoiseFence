#[path = "common/postgres.rs"]
mod postgres;
use noisefence::central::{Central, binding::Binding};

#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn database_binding_is_checked_on_new_and_reused_connections_in_both_pools() {
    let f = postgres::Fixture::new().await;
    let pg = f.connect().await;
    let binding = Binding {
        instance: uuid::Uuid::new_v4().to_string(),
        source_digest: "a".repeat(64),
    };
    let runtime = Central::new_bound(&f.settings, &binding).unwrap();
    assert!(runtime.health().await.is_err());
    pg.execute(
        "INSERT INTO noisefence.migration_state VALUES(1,$1,100,NULL,$2)",
        &[
            &binding.source_digest,
            &serde_json::json!({"instance":binding.instance}),
        ],
    )
    .await
    .unwrap();
    assert!(runtime.health().await.is_err());
    pg.execute(
        "UPDATE noisefence.migration_state SET activated_at=101",
        &[],
    )
    .await
    .unwrap();
    runtime.health().await.unwrap();
    let wrong = Binding {
        instance: uuid::Uuid::new_v4().to_string(),
        ..binding.clone()
    };
    assert!(
        Central::new_bound(&f.settings, &wrong)
            .unwrap()
            .health()
            .await
            .is_err()
    );
    // The already-created interactive connection must not survive a binding change.
    pg.execute(
        "UPDATE noisefence.migration_state SET source_digest=$1",
        &[&"b".repeat(64)],
    )
    .await
    .unwrap();
    assert!(runtime.health().await.is_err());
    assert!(runtime.password_hash("admin").await.is_err());
    // Ingestion has a different pool. An identity mismatch cannot register a node.
    let node = noisefence::central::outbox::Identity {
        node: "mx1".into(),
        epoch: uuid::Uuid::new_v4().to_string(),
    };
    assert!(runtime.register_source(&node).await.is_err());
    assert_eq!(
        pg.query_one("SELECT count(*) FROM noisefence.sources", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    pg.execute(
        "UPDATE noisefence.migration_state SET source_digest=$1",
        &[&binding.source_digest],
    )
    .await
    .unwrap();
    runtime.register_source(&node).await.unwrap();
    pg.execute(
        "UPDATE noisefence.migration_state SET activated_at=NULL",
        &[],
    )
    .await
    .unwrap();
    assert!(runtime.register_source(&node).await.is_err());
    pg.execute(
        "UPDATE noisefence.migration_state SET activated_at=101",
        &[],
    )
    .await
    .unwrap();
    pg.execute(
        "UPDATE noisefence.schema_migrations SET sha256=$1",
        &[&"c".repeat(64)],
    )
    .await
    .unwrap();
    assert!(runtime.health().await.is_err());
    pg.execute(
        "UPDATE noisefence.schema_migrations SET sha256=$1",
        &[&noisefence::message::digest(include_bytes!(
            "../src/central/schema.sql"
        ))],
    )
    .await
    .unwrap();
    runtime.health().await.unwrap();
    f.suspend().await;
    let cold = Central::new_bound(&f.settings, &binding).unwrap();
    assert!(cold.health().await.is_err());
    f.resume().await;
    cold.health().await.unwrap();
    assert!(
        Central::new_bound(
            &f.settings,
            &Binding {
                instance: "invalid".into(),
                source_digest: "a".repeat(64)
            }
        )
        .is_err()
    );
    f.finish().await;
}
