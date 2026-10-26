#[path = "common/scim.rs"]
mod common;
use noisefence::{
    identity::{
        connections::Reference,
        scim::{Command, Reply, ResourceType},
    },
    store::Store,
};
use serde_json::json;
async fn setup() -> (tempfile::TempDir, Store) {
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path()).unwrap();
    store
        .run(|db| {
            db.execute_batch(
                "INSERT INTO users VALUES('admin','unused',1,0),('reader','unused',0,0)",
            )?;
            db.execute(
                "INSERT INTO sessions VALUES(?1,'admin','csrf',?2)",
                rusqlite::params![common::SESSION, noisefence::now() + 3600],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    (root, store)
}
#[tokio::test]
async fn sqlite_scim_real_transaction_suite() {
    let (_root, store) = setup().await;
    common::exercise(&store).await;
}
#[tokio::test]
async fn sqlite_scim_restarts_keep_objects_and_tokens_remain_private() {
    let (root, store) = setup().await;
    let e = common::enroll(&store, "restart", None).await;
    let user = common::resource(&store, &e, common::user("alice")).await;
    drop(store);
    let reopened = Store::open(root.path()).unwrap();
    assert_eq!(common::get(&reopened, &e, &user).await, user);
    let raw = reopened
        .read(|db| {
            let mut stmt = db.prepare(
                "SELECT object_id FROM audit UNION ALL SELECT record FROM identity_connections",
            )?;
            Ok(stmt
                .query_map([], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?
                .join("\n"))
        })
        .await
        .unwrap();
    assert!(!raw.contains(&e.token));
    let rows = reopened
        .read(|db| {
            Ok(
                db.query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |r| {
                    r.get::<_, i64>(0)
                })?,
            )
        })
        .await
        .unwrap();
    assert_eq!(rows, 0);
}
#[tokio::test]
async fn sqlite_scim_revoked_owner_and_missing_vault_fail_closed() {
    let (root, store) = setup().await;
    let e = common::enroll(&store, "owner", None).await;
    store
        .scim_request(e.access(), Command::Authenticate)
        .await
        .unwrap();
    store
        .run(|db| {
            db.execute(
                "INSERT INTO console_user_versions(username,version) VALUES('admin',1)",
                [],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    common::status(
        store.scim_request(e.access(), Command::Authenticate).await,
        401,
    );
    store
        .run(|db| {
            db.execute(
                "UPDATE console_user_versions SET version=0 WHERE username='admin'",
                [],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    std::fs::rename(
        root.path().join("directory-vault/key"),
        root.path().join("directory-vault/saved-key"),
    )
    .unwrap();
    assert!(
        store
            .scim_request(e.access(), Command::Authenticate)
            .await
            .is_err()
    );
    assert!(!root.path().join("directory-vault/key").exists());
}
#[tokio::test]
async fn sqlite_scim_rejected_mutations_consume_rate_but_do_not_change_revision() {
    let (_root, store) = setup().await;
    let e = common::enroll(&store, "rate", None).await;
    common::status(
        store
            .scim_request(
                e.access(),
                Command::Create {
                    kind: ResourceType::User,
                    body: b"invalid".to_vec(),
                },
            )
            .await,
        400,
    );
    let counters = store
        .read(|db| {
            Ok(db.query_row(
                "SELECT requests,sequence,users FROM identity_scim_sources",
                [],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, i64>(2)?,
                    ))
                },
            )?)
        })
        .await
        .unwrap();
    assert_eq!(counters, (1, 0, 0));
    store
        .run(|db| {
            db.execute("UPDATE identity_scim_sources SET requests=600", [])?;
            Ok(())
        })
        .await
        .unwrap();
    common::status(
        store.scim_request(e.access(), Command::Authenticate).await,
        429,
    );
    store
        .run(|db| {
            db.execute(
                "UPDATE identity_scim_sources SET window_started=window_started-61",
                [],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    assert!(
        store
            .scim_request(e.access(), Command::Authenticate)
            .await
            .is_ok()
    );
}
#[tokio::test]
async fn sqlite_scim_storage_quota_rolls_back_the_entire_mutation() {
    let (_root, store) = setup().await;
    let e = common::enroll(&store, "quota", None).await;
    store
        .scim_request(e.access(), Command::Authenticate)
        .await
        .unwrap();
    store
        .run(|db| {
            db.execute(
                "UPDATE identity_scim_sources SET reserved_bytes=67108863",
                [],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    common::status(
        store.scim_request(e.access(), common::user("alice")).await,
        413,
    );
    let count = store
        .read(|db| {
            Ok(
                db.query_row("SELECT count(*) FROM identity_scim_resources", [], |r| {
                    r.get::<_, i64>(0)
                })?,
            )
        })
        .await
        .unwrap();
    assert_eq!(count, 0);
    let sequence = store
        .read(|db| {
            Ok(
                db.query_row("SELECT sequence FROM identity_scim_sources", [], |r| {
                    r.get::<_, i64>(0)
                })?,
            )
        })
        .await
        .unwrap();
    assert_eq!(sequence, 0);
}
#[tokio::test]
async fn sqlite_scim_failed_member_update_preserves_resource_and_reference_counts() {
    let (_root, store) = setup().await;
    let e = common::enroll(&store, "edges", None).await;
    let p = common::resource(&store, &e, common::user("alice")).await;
    let g = common::resource(&store, &e, common::group("Team", json!([{"value":p.id()}]))).await;
    let before = store
        .scim_inventory(e.reference(), "admin".into(), common::SESSION.into())
        .await
        .unwrap();
    common::status(store.scim_request(e.access(),common::patch(&g,json!([{"op":"replace","path":"members","value":[{"value":uuid::Uuid::new_v4().to_string()}]}]))).await,400);
    assert_eq!(common::get(&store, &e, &g).await, g);
    let after = store
        .scim_inventory(e.reference(), "admin".into(), common::SESSION.into())
        .await
        .unwrap();
    assert_eq!(before.stage.revision, after.stage.revision);
    assert_eq!(before.stage.reserved_bytes, after.stage.reserved_bytes);
}
#[tokio::test]
async fn sqlite_scim_schema_tampering_is_not_reinitialized() {
    let (_root, store) = setup().await;
    let e = common::enroll(&store, "schema", None).await;
    store
        .scim_request(e.access(), Command::Authenticate)
        .await
        .unwrap();
    store
        .run(|db| {
            db.execute("UPDATE identity_scim_schema SET sha256='bad'", [])?;
            Ok(())
        })
        .await
        .unwrap();
    assert!(
        store
            .scim_request(e.access(), common::user("alice"))
            .await
            .is_err()
    );
}
#[tokio::test]
async fn sqlite_scim_cycle_cannot_become_a_runtime_candidate() {
    let (_root, store) = setup().await;
    let e = common::enroll(&store, "cycle", None).await;
    let a = common::resource(&store, &e, common::group("A", json!([]))).await;
    let b = common::resource(
        &store,
        &e,
        common::group("B", json!([{"value":a.id(),"type":"Group"}])),
    )
    .await;
    common::resource(
        &store,
        &e,
        common::patch(
            &a,
            json!([{"op":"add","path":"members","value":[{"value":b.id(),"type":"Group"}]}]),
        ),
    )
    .await;
    let inv = store
        .scim_inventory(e.reference(), "admin".into(), common::SESSION.into())
        .await
        .unwrap();
    assert!(
        noisefence::identity::scim::Candidate::prepare(
            inv.source,
            inv.stage.revision,
            1,
            &inv.resources,
            noisefence::now(),
            noisefence::now()
        )
        .is_err()
    );
    let a = common::get(&store, &e, &a).await;
    assert!(matches!(
        store
            .scim_request(
                e.access(),
                Command::Delete {
                    kind: ResourceType::Group,
                    id: a.id().into(),
                    expected: Some(a.etag())
                }
            )
            .await
            .unwrap(),
        Reply::Deleted
    ));
    let inv = store
        .scim_inventory(
            Reference {
                source_id: e.record.metadata.source.id.clone(),
                generation: e.record.metadata.generation.clone(),
            },
            "admin".into(),
            common::SESSION.into(),
        )
        .await
        .unwrap();
    assert_eq!(inv.stage.memberships, 0);
}

#[tokio::test]
async fn sqlite_scim_capabilities_cannot_be_dropped_by_account_import() {
    let (_root, store) = setup().await;
    let _enrolled = common::enroll(&store, "import-guard", None).await;
    assert!(
        store
            .run(|db| {
                let tx = db.transaction()?;
                noisefence::central::import::AccountsSnapshot::capture(&tx, None).map(|_| ())
            })
            .await
            .is_err()
    );
}

#[tokio::test]
async fn sqlite_scim_group_membership_batches_preserve_accounting() {
    let (_root, store) = setup().await;
    common::membership_batches(&store).await;
}
