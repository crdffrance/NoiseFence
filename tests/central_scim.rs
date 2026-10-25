#[path = "common/scim.rs"]
mod common;
#[path = "common/postgres.rs"]
mod postgres;
use noisefence::{identity::scim::Command, store::Store};
async fn setup(f: &postgres::Fixture) -> (tempfile::TempDir, Store) {
    let db = f.connect().await;
    db.execute("INSERT INTO noisefence.users(username,password,admin) VALUES('admin','unused',true),('reader','unused',false)",&[]).await.unwrap();
    db.execute("INSERT INTO noisefence.sessions(token_hash,username,csrf,expires) VALUES($1,'admin','csrf',$2)",&[&common::SESSION,&(noisefence::now()+3600)]).await.unwrap();
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path())
        .unwrap()
        .with_management(f.central.clone())
        .await
        .unwrap();
    (root, store)
}
#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn selected_postgres_scim_real_transaction_suite() {
    let f = postgres::Fixture::new().await;
    let (_root, store) = setup(&f).await;
    common::exercise(&store).await;
    drop(store);
    f.finish().await;
}
#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn selected_postgres_scim_refuses_shadow_and_changed_owner() {
    let f = postgres::Fixture::new().await;
    let (root, store) = setup(&f).await;
    let e = common::enroll(&store, "authority", None).await;
    let p = common::resource(&store, &e, common::user("alice")).await;
    drop(store);
    let reopened = Store::open(root.path())
        .unwrap()
        .with_management(noisefence::central::Central::new(&f.settings).unwrap())
        .await
        .unwrap();
    assert_eq!(common::get(&reopened, &e, &p).await, p);
    // A populated local shadow must not serve requests if selected PG fails.
    let local = Store::open(root.path()).unwrap();
    local
        .run(|db| {
            db.execute_batch("INSERT INTO users VALUES('admin','unused',1,0)")?;
            db.execute(
                "INSERT INTO sessions VALUES(?1,'admin','csrf',?2)",
                rusqlite::params![common::SESSION, noisefence::now() + 3600],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    let shadow = common::enroll(&local, "authority", None).await;
    common::resource(&local, &shadow, common::user("shadow")).await;
    common::status(
        reopened
            .scim_request(shadow.access(), Command::Authenticate)
            .await,
        401,
    );
    f.suspend().await;
    assert!(
        reopened
            .scim_request(e.access(), Command::Authenticate)
            .await
            .is_err()
    );
    assert!(
        reopened
            .scim_request(shadow.access(), Command::Authenticate)
            .await
            .is_err()
    );
    f.resume().await;
    let db = f.connect().await;
    db.execute(
        "UPDATE noisefence.users SET version=version+1 WHERE username='admin'",
        &[],
    )
    .await
    .unwrap();
    common::status(
        reopened
            .scim_request(e.access(), Command::Authenticate)
            .await,
        401,
    );
    drop(reopened);
    drop(local);
    f.finish().await;
}
#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn selected_postgres_scim_rate_quota_and_component_checks() {
    let f = postgres::Fixture::new().await;
    let (_root, store) = setup(&f).await;
    let e = common::enroll(&store, "limits", None).await;
    common::status(
        store
            .scim_request(
                e.access(),
                noisefence::identity::scim::Command::Create {
                    kind: noisefence::identity::scim::ResourceType::User,
                    body: b"invalid".to_vec(),
                },
            )
            .await,
        400,
    );
    let db = f.connect().await;
    let row = db
        .query_one(
            "SELECT requests,sequence,users FROM noisefence.identity_scim_sources",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(
        (
            row.get::<_, i64>(0),
            row.get::<_, i64>(1),
            row.get::<_, i64>(2)
        ),
        (1, 0, 0)
    );
    db.execute(
        "UPDATE noisefence.identity_scim_sources SET requests=600",
        &[],
    )
    .await
    .unwrap();
    common::status(
        store.scim_request(e.access(), Command::Authenticate).await,
        429,
    );
    db.execute("UPDATE noisefence.identity_scim_sources SET window_started=window_started-61,reserved_bytes=67108863",&[]).await.unwrap();
    common::status(
        store.scim_request(e.access(), common::user("alice")).await,
        413,
    );
    assert_eq!(
        db.query_one(
            "SELECT count(*) FROM noisefence.identity_scim_resources",
            &[]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        0
    );
    db.execute(
        "UPDATE noisefence.identity_scim_schema SET sha256='bad'",
        &[],
    )
    .await
    .unwrap();
    assert!(
        store
            .scim_request(e.access(), Command::Authenticate)
            .await
            .is_err()
    );
    drop(store);
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn selected_postgres_scim_group_membership_batches_preserve_accounting() {
    let f = postgres::Fixture::new().await;
    let (_root, store) = setup(&f).await;
    common::membership_batches(&store).await;
    drop(store);
    f.finish().await;
}
