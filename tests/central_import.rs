#[path = "common/postgres.rs"]
mod postgres;
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use noisefence::{central::import::AccountsSnapshot, mfa::Key, store::Store};

#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn account_import_preserves_authentication_and_rolls_back_every_partial_write() {
    let fixture = postgres::Fixture::new().await;
    let pg = fixture.connect().await;
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path()).unwrap();
    noisefence::api::create_user(
        &store,
        "ZAdmin".into(),
        "synthetic-password-123".into(),
        vec![],
        true,
    )
    .await
    .unwrap();
    noisefence::api::create_user(
        &store,
        "alice".into(),
        "synthetic-password-456".into(),
        vec!["alice@example.test".into(), "*@tenant.test".into()],
        false,
    )
    .await
    .unwrap();
    let key = Key::open(root.path()).unwrap();
    let sealed = key.seal("alice", &noisefence::mfa::secret()).unwrap();
    let original = sealed.clone();
    store.run(move |db| {
        db.execute("INSERT INTO mfa_credentials VALUES('alice',?1,1,0,12345)", [sealed])?;
        db.execute_batch("INSERT INTO console_user_versions VALUES('alice',19),('ZAdmin',7);
            INSERT INTO mfa_recovery VALUES('alice','recovery-digest');
            INSERT INTO mfa_attempts VALUES('alice',123456,4);
            INSERT INTO sessions VALUES(printf('%064d',1),'alice','verified-csrf',9999999999),(printf('%064d',2),'alice','unverified-csrf',9999999999);
            INSERT INTO mfa_sessions VALUES(printf('%064d',1));
            INSERT INTO console_invitations VALUES('invite','token-digest','guest',0,'[\"guest@example.test\"]','ZAdmin',7,12345,9999999999,3,NULL,NULL);")?;
        Ok(())
    }).await.unwrap();
    let wrong_root = tempfile::tempdir().unwrap();
    let wrong_key = Key::open(wrong_root.path()).unwrap();
    store
        .run(move |db| {
            let tx = db.transaction()?;
            assert!(AccountsSnapshot::capture(&tx, None).is_err());
            assert!(AccountsSnapshot::capture(&tx, Some(&wrong_key)).is_err());
            Ok(())
        })
        .await
        .unwrap();
    let snapshot = store
        .run(move |db| AccountsSnapshot::capture(&db.transaction()?, Some(&key)))
        .await
        .unwrap();
    // A late write failure cannot leave users or sessions imported on their own.
    pg.batch_execute("CREATE FUNCTION noisefence.break_import() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic'; END $$;
        CREATE TRIGGER break_import BEFORE INSERT ON noisefence.invitations FOR EACH ROW EXECUTE FUNCTION noisefence.break_import();").await.unwrap();
    assert!(fixture.central.import_accounts(&snapshot).await.is_err());
    for table in [
        "users",
        "grants",
        "sessions",
        "mfa_credentials",
        "mfa_recovery",
        "mfa_attempts",
        "invitations",
    ] {
        assert_eq!(
            pg.query_one(&format!("SELECT count(*) FROM noisefence.{table}"), &[])
                .await
                .unwrap()
                .get::<_, i64>(0),
            0
        );
    }
    pg.batch_execute("DROP TRIGGER break_import ON noisefence.invitations;
        CREATE FUNCTION noisefence.change_import() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN NEW.version=NEW.version+1; RETURN NEW; END $$;
        CREATE TRIGGER change_import BEFORE INSERT ON noisefence.users FOR EACH ROW EXECUTE FUNCTION noisefence.change_import();").await.unwrap();
    assert!(
        fixture
            .central
            .import_accounts(&snapshot)
            .await
            .unwrap_err()
            .to_string()
            .contains("parity")
    );
    assert_eq!(
        pg.query_one("SELECT count(*) FROM noisefence.users", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    pg.batch_execute("DROP TRIGGER change_import ON noisefence.users")
        .await
        .unwrap();
    fixture.central.import_accounts(&snapshot).await.unwrap();
    let r = pg
        .query_one(
            "SELECT secret,last_step FROM noisefence.mfa_credentials WHERE username='alice'",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(r.get::<_, Vec<u8>>(0), original);
    assert_eq!(r.get::<_, i64>(1), 12345);
    fixture.central.validate_mfa_key(root.path()).await.unwrap();
    assert!(
        fixture
            .central
            .validate_mfa_key(wrong_root.path())
            .await
            .is_err()
    );
    let sessions = pg
        .query(
            "SELECT csrf,mfa_verified FROM noisefence.sessions ORDER BY token_hash",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(sessions.len(), 2);
    assert!(sessions[0].get::<_, bool>(1));
    assert!(!sessions[1].get::<_, bool>(1));
    let password = fixture
        .central
        .password_hash("alice")
        .await
        .unwrap()
        .unwrap();
    assert!(
        Argon2::default()
            .verify_password(
                b"synthetic-password-456",
                &PasswordHash::new(&password).unwrap()
            )
            .is_ok()
    );
    assert_eq!(
        pg.query_one(
            "SELECT version FROM noisefence.users WHERE username='alice'",
            &[]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        19
    );
    assert_eq!(
        pg.query_one(
            "SELECT creator_version FROM noisefence.invitations WHERE id='invite'",
            &[]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        7
    );
    // An uncertain client response is never handled by overwriting the target.
    assert!(fixture.central.import_accounts(&snapshot).await.is_err());
    store
        .read(|db| {
            assert_eq!(
                db.query_row(
                    "SELECT version FROM console_user_versions WHERE username='alice'",
                    [],
                    |r| r.get::<_, i64>(0)
                )?,
                19
            );
            assert_eq!(
                db.query_row("SELECT count(*) FROM sessions", [], |r| r.get::<_, i64>(0))?,
                2
            );
            Ok(())
        })
        .await
        .unwrap();
    fixture.finish().await;
}
