use noisefence::{
    operator::{self, AccountChange},
    store::Store,
};

#[tokio::test]
async fn local_recovery_is_atomic_and_revokes_sessions_and_approvals() {
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path()).unwrap();
    let hash = noisefence::api::hash_password("synthetic-long-password").unwrap();
    for (user, admin) in [("admin", true), ("alice", false)] {
        operator::account(
            &store,
            user.into(),
            AccountChange::Create {
                password_hash: hash.clone(),
                admin,
                addresses: vec![format!("{user}@example.test")],
            },
        )
        .await
        .unwrap();
    }
    assert!(
        operator::account(&store, "admin".into(), AccountChange::Disable)
            .await
            .is_err()
    );
    assert!(
        operator::account(
            &store,
            "duplicate".into(),
            AccountChange::Create {
                password_hash: hash.clone(),
                admin: false,
                addresses: vec!["a@example.test".into(); 2]
            }
        )
        .await
        .is_err()
    );
    store.run(|db| {
        assert_eq!(db.query_row("SELECT count(*) FROM users WHERE username='duplicate'",[],|r|r.get::<_,i64>(0))?,0);
        assert!(!db.query_row("SELECT disabled FROM users WHERE username='admin'",[],|r|r.get::<_,bool>(0))?);
        db.execute("INSERT INTO sessions VALUES('synthetic','alice','csrf',?1)",[noisefence::now()+3600])?;
        db.execute("INSERT INTO mfa_credentials(username,secret,enabled,pending_until) VALUES('alice',X'010203',1,0)",[])?;
        db.execute("INSERT INTO mfa_recovery VALUES('alice','synthetic')",[])?;
        db.execute("INSERT INTO mfa_attempts VALUES('alice',9999999999,3)",[])?;
        Ok(())
    }).await.unwrap();
    operator::account(&store, "alice".into(), AccountChange::ResetMfa)
        .await
        .unwrap();
    store
        .read(|db| {
            for table in [
                "sessions",
                "mfa_credentials",
                "mfa_recovery",
                "mfa_attempts",
            ] {
                assert_eq!(
                    db.query_row(
                        &format!("SELECT count(*) FROM {table} WHERE username='alice'"),
                        [],
                        |r| r.get::<_, i64>(0)
                    )?,
                    0
                );
            }
            assert_eq!(
                db.query_row(
                    "SELECT version FROM console_user_versions WHERE username='alice'",
                    [],
                    |r| r.get::<_, i64>(0)
                )?,
                1
            );
            Ok(())
        })
        .await
        .unwrap();
    let next = noisefence::api::hash_password("another-synthetic-password").unwrap();
    operator::account(
        &store,
        "alice".into(),
        AccountChange::ResetPassword {
            password_hash: next.clone(),
        },
    )
    .await
    .unwrap();
    operator::account(&store, "alice".into(), AccountChange::Disable)
        .await
        .unwrap();
    store.read(move|db| {
        let record:(String,bool,i64)=db.query_row("SELECT u.password,u.disabled,v.version FROM users u JOIN console_user_versions v USING(username) WHERE u.username='alice'",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
        assert_eq!(record,(next,true,3));
        assert_eq!(db.query_row("SELECT count(*) FROM audit WHERE username='local-administrator'",[],|r|r.get::<_,i64>(0))?,3);
        Ok(())
    }).await.unwrap();
    assert!(
        operator::account(&store, "missing".into(), AccountChange::ResetMfa)
            .await
            .is_err()
    );
    assert!(
        operator::account(
            &store,
            "alice".into(),
            AccountChange::ResetPassword {
                password_hash: "not a password hash".into()
            }
        )
        .await
        .is_err()
    );
}
