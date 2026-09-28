#[path = "common/postgres.rs"]
mod postgres;
use noisefence::{
    operator::{self, AccountChange},
    store::Store,
};

#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn operator_recovery_uses_selected_authority_and_preserves_last_admin() {
    let f = postgres::Fixture::new().await;
    let pg = f.connect().await;
    let root = tempfile::tempdir().unwrap();
    let local = Store::open(root.path()).unwrap();
    let central = local
        .clone()
        .with_management(f.central.clone())
        .await
        .unwrap();
    let password = "synthetic-long-password";
    // The helper used by `user-add` must create only a central account.
    noisefence::api::create_user(&central, "admin".into(), password.into(), vec![], true)
        .await
        .unwrap();
    noisefence::api::create_user(&central, "peer".into(), password.into(), vec![], true)
        .await
        .unwrap();
    noisefence::api::create_user(
        &central,
        "alice".into(),
        password.into(),
        vec!["alice@example.test".into()],
        false,
    )
    .await
    .unwrap();
    assert_eq!(
        local
            .read(|db| Ok(db.query_row("SELECT count(*) FROM users", [], |r| r.get::<_, i64>(0))?))
            .await
            .unwrap(),
        0
    );
    // Leave a conflicting legacy account to detect any local fallback.
    noisefence::api::create_user(&local, "alice".into(), password.into(), vec![], false)
        .await
        .unwrap();
    let legacy_hash = local
        .read(|db| {
            Ok(db.query_row(
                "SELECT password FROM users WHERE username='alice'",
                [],
                |r| r.get::<_, String>(0),
            )?)
        })
        .await
        .unwrap();
    let token = "a".repeat(64);
    pg.execute(
        "INSERT INTO noisefence.sessions VALUES($1,'alice','csrf',$2,false)",
        &[&token, &(noisefence::now() + 3600)],
    )
    .await
    .unwrap();
    pg.execute("INSERT INTO noisefence.mfa_credentials(username,secret,enabled,pending_until) VALUES('alice',$1,true,0)",&[&vec![1u8,2,3]]).await.unwrap();
    pg.batch_execute("INSERT INTO noisefence.mfa_recovery VALUES('alice','synthetic'); INSERT INTO noisefence.mfa_attempts VALUES('alice',9999999999,3)").await.unwrap();
    operator::account(&central, "alice".into(), AccountChange::ResetMfa)
        .await
        .unwrap();
    for table in [
        "sessions",
        "mfa_credentials",
        "mfa_recovery",
        "mfa_attempts",
    ] {
        assert_eq!(
            pg.query_one(
                &format!("SELECT count(*) FROM noisefence.{table} WHERE username='alice'"),
                &[]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
            0
        );
    }
    let reset_hash = noisefence::api::hash_password("replacement-password-123").unwrap();
    operator::account(
        &central,
        "alice".into(),
        AccountChange::ResetPassword {
            password_hash: reset_hash.clone(),
        },
    )
    .await
    .unwrap();
    assert_eq!(
        f.central.password_hash("alice").await.unwrap(),
        Some(reset_hash.clone())
    );
    operator::account(&central, "alice".into(), AccountChange::Disable)
        .await
        .unwrap();
    assert!(f.central.password_hash("alice").await.unwrap().is_none());
    assert_eq!(
        pg.query_one(
            "SELECT version FROM noisefence.users WHERE username='alice'",
            &[]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        3
    );
    // Two simultaneous requests must not disable both remaining administrators.
    let (a, b) = tokio::join!(
        operator::account(&central, "admin".into(), AccountChange::Disable),
        operator::account(&central, "peer".into(), AccountChange::Disable)
    );
    assert_ne!(a.is_ok(), b.is_ok());
    assert_eq!(
        pg.query_one(
            "SELECT count(*) FROM noisefence.users WHERE admin AND NOT disabled",
            &[]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        1
    );
    assert!(
        operator::account(&central, "missing".into(), AccountChange::ResetMfa)
            .await
            .is_err()
    );
    assert!(
        operator::account(
            &central,
            "duplicate".into(),
            AccountChange::Create {
                password_hash: reset_hash.clone(),
                admin: false,
                addresses: vec!["a@example.test".into(); 2]
            }
        )
        .await
        .is_err()
    );
    assert_eq!(
        pg.query_one(
            "SELECT count(*) FROM noisefence.users WHERE username='duplicate'",
            &[]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        0
    );
    let actions: Vec<String> = pg
        .query(
            "SELECT action FROM noisefence.audit WHERE object_id='alice' ORDER BY id",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    assert_eq!(actions, vec!["mfa_reset", "account", "account"]);
    f.suspend().await;
    assert!(
        operator::account(
            &central,
            "alice".into(),
            AccountChange::ResetPassword {
                password_hash: reset_hash
            }
        )
        .await
        .is_err()
    );
    let (hash,disabled,version)=local.read(|db|Ok(db.query_row("SELECT u.password,u.disabled,COALESCE(v.version,0) FROM users u LEFT JOIN console_user_versions v USING(username) WHERE u.username='alice'",[],|r|Ok((r.get::<_,String>(0)?,r.get::<_,bool>(1)?,r.get::<_,i64>(2)?)))?)).await.unwrap();
    assert_eq!((hash, disabled, version), (legacy_hash, false, 0));
    f.resume().await;
    drop(pg);
    f.finish().await;
}
