use noisefence::{central::import::AccountsSnapshot, store::Store};

#[tokio::test]
async fn account_snapshot_rejects_malformed_or_oversized_source_without_repairing_it() {
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path()).unwrap();
    store.run(|db| {
        db.execute("INSERT INTO users VALUES('admin','synthetic',1,0)",[])?;
        assert!(AccountsSnapshot::capture(&db.transaction()?,None).is_ok());
        db.execute("UPDATE users SET admin=2",[])?;
        assert!(AccountsSnapshot::capture(&db.transaction()?,None).is_err());
        db.execute("UPDATE users SET admin=1,password=?1",["a".repeat(262144)])?;
        assert!(AccountsSnapshot::capture(&db.transaction()?,None).is_err());
        db.execute("UPDATE users SET password='synthetic'",[])?;
        db.execute_batch("PRAGMA foreign_keys=OFF; INSERT INTO grants VALUES('missing','x@example.test');")?;
        assert!(AccountsSnapshot::capture(&db.transaction()?,None).is_err());
        assert_eq!(db.query_row("SELECT count(*) FROM grants WHERE username='missing'",[],|r|r.get::<_,i64>(0))?,1);
        db.execute("DELETE FROM grants WHERE username='missing'",[])?;
        db.execute_batch("PRAGMA foreign_keys=ON; WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<1000) INSERT INTO users SELECT 'user'||x,'synthetic',0,0 FROM n;")?;
        assert!(AccountsSnapshot::capture(&db.transaction()?,None).is_err());
        assert_eq!(db.query_row("SELECT count(*) FROM users",[],|r|r.get::<_,i64>(0))?,1001);
        Ok(())
    }).await.unwrap();
}
