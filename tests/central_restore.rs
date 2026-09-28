#[path = "common/postgres.rs"]
mod postgres;
use std::process::Stdio;
use tokio::io::AsyncWriteExt;

#[tokio::test]
#[ignore = "requires disposable PostgreSQL, its Docker container ID and test credentials"]
async fn custom_dump_restores_every_management_table_sequences_and_runtime_binding() {
    let container = std::env::var("NOISEFENCE_TEST_PG_CONTAINER")
        .expect("explicit disposable container required");
    assert!(
        !container.is_empty()
            && container.len() <= 128
            && container
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
            && !container.starts_with('-')
    );
    let source = postgres::Fixture::new().await;
    let destination = postgres::Fixture::new().await;
    let src = source.connect().await;
    let dst = destination.connect().await;
    let binding = noisefence::central::binding::Binding {
        instance: uuid::Uuid::new_v4().to_string(),
        source_digest: "a".repeat(64),
    };
    src.batch_execute("INSERT INTO noisefence.users VALUES('admin','synthetic-hash',true,false,7); INSERT INTO noisefence.grants VALUES('admin','*@example.test'); INSERT INTO noisefence.sessions VALUES(repeat('a',64),'admin','synthetic-csrf',9999999999,true); INSERT INTO noisefence.mfa_credentials VALUES('admin',decode(repeat('ab',48),'hex'),true,0,123); INSERT INTO noisefence.audit(created,username,action,object_id) VALUES(1,'admin','synthetic','fixture'); SELECT setval('noisefence.deliveries_id_seq',42,true); SELECT setval('noisefence.runtime_history_generation',19,true);").await.unwrap();
    src.execute(
        "INSERT INTO noisefence.migration_state VALUES(1,$1,1,2,$2)",
        &[
            &binding.source_digest,
            &serde_json::json!({"instance":binding.instance,"phase":"synthetic-test-only"}),
        ],
    )
    .await
    .unwrap();
    let dumped = tokio::process::Command::new("docker")
        .args([
            "exec",
            &container,
            "pg_dump",
            "--no-password",
            "--username=postgres",
            "--format=custom",
            "--dbname",
            &source.settings.database,
        ])
        .output()
        .await
        .unwrap();
    assert!(dumped.status.success(), "pg_dump failed");
    assert!(dumped.stdout.starts_with(b"PGDMP") && dumped.stdout.len() < 4 * 1024 * 1024);
    // Both databases belong exclusively to this synthetic fixture. Never pass
    // user-supplied database names/hosts or a production archive to this test.
    assert!(destination.settings.database.starts_with("nf_test_"));
    dst.batch_execute("DROP SCHEMA noisefence CASCADE")
        .await
        .unwrap();
    let mut restore = tokio::process::Command::new("docker")
        .args([
            "exec",
            "-i",
            &container,
            "pg_restore",
            "--no-password",
            "--username=postgres",
            "--exit-on-error",
            "--single-transaction",
            "--no-owner",
            "--no-acl",
            "--dbname",
            &destination.settings.database,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    restore
        .stdin
        .take()
        .unwrap()
        .write_all(&dumped.stdout)
        .await
        .unwrap();
    let restored = restore.wait_with_output().await.unwrap();
    assert!(restored.status.success(), "pg_restore failed");
    let tables = src
        .query(
            "SELECT tablename FROM pg_tables WHERE schemaname='noisefence' ORDER BY tablename",
            &[],
        )
        .await
        .unwrap();
    let restored_tables = dst
        .query(
            "SELECT tablename FROM pg_tables WHERE schemaname='noisefence' ORDER BY tablename",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(
        tables
            .iter()
            .map(|r| r.get::<_, String>(0))
            .collect::<Vec<_>>(),
        restored_tables
            .iter()
            .map(|r| r.get::<_, String>(0))
            .collect::<Vec<_>>()
    );
    for row in tables {
        let table: String = row.get(0);
        assert!(table.bytes().all(|c| c.is_ascii_lowercase() || c == b'_'));
        let sql = format!(
            "SELECT to_jsonb(t) FROM noisefence.{table} t ORDER BY to_jsonb(t)::text COLLATE \"C\""
        );
        let before = src
            .query(&sql, &[])
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.get::<_, serde_json::Value>(0))
            .collect::<Vec<_>>();
        let after = dst
            .query(&sql, &[])
            .await
            .unwrap()
            .into_iter()
            .map(|r| r.get::<_, serde_json::Value>(0))
            .collect::<Vec<_>>();
        assert_eq!(before, after, "table parity: {table}");
    }
    let sql = "SELECT sequencename,last_value FROM pg_sequences WHERE schemaname='noisefence' ORDER BY sequencename";
    let before = src
        .query(sql, &[])
        .await
        .unwrap()
        .into_iter()
        .map(|r| (r.get::<_, String>(0), r.get::<_, Option<i64>>(1)))
        .collect::<Vec<_>>();
    let after = dst
        .query(sql, &[])
        .await
        .unwrap()
        .into_iter()
        .map(|r| (r.get::<_, String>(0), r.get::<_, Option<i64>>(1)))
        .collect::<Vec<_>>();
    assert_eq!(before, after);
    let runtime = noisefence::central::Central::new_bound(&destination.settings, &binding).unwrap();
    runtime.health().await.unwrap();
    drop(runtime);
    destination.finish().await;
    source.finish().await;
}
