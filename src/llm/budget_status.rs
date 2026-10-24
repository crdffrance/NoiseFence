//! Read the existing budget ledger without initializing or migrating it.
use anyhow::Result;
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use serde_json::{Value, json};
use std::{path::Path, time::Duration};

pub(crate) fn read(path: &Path, maximum: u64) -> Result<Value> {
    if !path.try_exists()? {
        return Ok(json!({"status":"not_started"}));
    }
    let mut db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    db.busy_timeout(Duration::from_millis(100))?;
    let tx = db.transaction()?;
    let month: String = tx.query_row("SELECT strftime('%Y-%m','now')", [], |r| r.get(0))?;
    let (accounted, requests): (u64, u64) = tx
        .query_row(
            "SELECT accounted,requests FROM llm_months WHERE month=?1",
            [&month],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?
        .unwrap_or((0, 0));
    let worker: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM cluster_wallet_mode)",
        [],
        |r| r.get(0),
    )?;
    let issued: u64 = tx.query_row(
        "SELECT COALESCE(SUM(amount),0) FROM cluster_allocations WHERE resource='llm' AND window=?1", [&month], |r| r.get(0),
    )?;
    let ceiling = crate::cluster::budget::ceiling(&tx, "llm", &month, maximum)?;
    let remaining = ceiling.saturating_sub(accounted);
    Ok(
        json!({"status":"available","month":month,"accounted_micro_eur":accounted,"requests":requests,
        "worker_wallet":worker,"issued_micro_eur":issued,"ceiling_micro_eur":ceiling,"remaining_micro_eur":remaining}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn absence_and_invalid_schema_never_initialize_a_ledger() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("budget.sqlite3");
        assert_eq!(read(&p, 200).unwrap()["status"], "not_started");
        assert!(!p.exists());
        let db = Connection::open(&p).unwrap();
        assert!(read(&p, 200).is_err());
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM sqlite_master", [], |r| r
                .get::<_, u64>(0))
                .unwrap(),
            0
        );
    }
    #[test]
    fn current_month_reservations_and_worker_credits_remain_distinct() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("budget.sqlite3");
        let budget = super::super::Budget::open(&p).unwrap();
        let db = budget.connection.lock().unwrap();
        db.execute(
            "INSERT INTO llm_months VALUES(strftime('%Y-%m','now'),400,2)",
            [],
        )
        .unwrap();
        db.execute("INSERT INTO llm_months VALUES('2000-01',9999,99)", [])
            .unwrap();
        db.execute(
            "INSERT INTO cluster_allocations VALUES('mx2','llm',strftime('%Y-%m','now'),300)",
            [],
        )
        .unwrap();
        let s = read(&p, 1000).unwrap();
        assert_eq!(s["accounted_micro_eur"], 400);
        assert_eq!(s["issued_micro_eur"], 300);
        assert_eq!(s["remaining_micro_eur"], 600);
        assert_eq!(s["worker_wallet"], false);
        db.execute("INSERT INTO cluster_wallet_mode VALUES(1)", [])
            .unwrap();
        assert_eq!(read(&p, 1000).unwrap()["ceiling_micro_eur"], 0);
        db.execute(
            "INSERT INTO cluster_wallet VALUES('llm',strftime('%Y-%m','now'),500,0)",
            [],
        )
        .unwrap();
        let s = read(&p, 1000).unwrap();
        assert_eq!(s["worker_wallet"], true);
        assert_eq!(s["ceiling_micro_eur"], 500);
        assert_eq!(s["remaining_micro_eur"], 100);
        assert_eq!(read(&p, 200).unwrap()["remaining_micro_eur"], 0);
        let count: u64 = db
            .query_row("SELECT COUNT(*) FROM llm_months", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 2);
    }
}
