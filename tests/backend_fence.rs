#[allow(dead_code)]
mod common;

#[test]
fn cli_refuses_newer_formats_even_without_cluster_tables() {
    for version in [-1, 7, 100] {
        let root = tempfile::tempdir().unwrap();
        let config = common::config(root.path());
        let db = rusqlite::Connection::open(root.path().join("state.sqlite3")).unwrap();
        db.pragma_update(None, "user_version", version).unwrap();
        assert!(noisefence::control::effective_from_disk(config).is_err());
    }
}

#[test]
fn cli_refuses_stale_local_policy_after_central_selection() {
    for marker in ["management_transport", "runtime_history_protocol"] {
        let root = tempfile::tempdir().unwrap();
        let config = common::config(root.path());
        let db = rusqlite::Connection::open(root.path().join("state.sqlite3")).unwrap();
        db.execute_batch("CREATE TABLE cluster_state(key TEXT PRIMARY KEY,value TEXT NOT NULL); PRAGMA user_version=2;").unwrap();
        db.execute("INSERT INTO cluster_state VALUES(?1,'unknown')", [marker])
            .unwrap();
        let error = noisefence::control::effective_from_disk(config).unwrap_err();
        assert!(error.to_string().contains("explicit central backend"));
        let count: i64 = db
            .query_row("SELECT count(*) FROM cluster_state", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }
}
