//! Escrow budgets: issued credits remain charged to the authority until window expiry.
//! A lost reply returns the same cumulative grant; offline credit is never reissued.
use anyhow::{Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path};

pub const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS cluster_wallet_mode(id INTEGER PRIMARY KEY CHECK(id=1));
 CREATE TABLE IF NOT EXISTS cluster_wallet(resource TEXT,window TEXT,amount INTEGER NOT NULL,unlimited INTEGER NOT NULL,PRIMARY KEY(resource,window));
 CREATE TABLE IF NOT EXISTS cluster_allocations(node TEXT,resource TEXT,window TEXT,amount INTEGER NOT NULL,PRIMARY KEY(node,resource,window));";

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub known: BTreeMap<String, u64>,
    pub replenish: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credit {
    pub resource: String,
    pub window: String,
    pub amount: u64,
    pub unlimited: bool,
}
fn open(path: &Path) -> Result<Connection> {
    let db = Connection::open(path)?;
    db.busy_timeout(std::time::Duration::from_millis(500))?;
    db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL")?;
    db.execute_batch(SCHEMA)?;
    Ok(db)
}
pub fn enable_worker(root: &Path) -> Result<()> {
    std::fs::create_dir_all(root.join("protection"))?;
    for path in [
        root.join("llm-budget.sqlite3"),
        root.join("protection/reputation.sqlite3"),
    ] {
        open(&path)?.execute("INSERT OR IGNORE INTO cluster_wallet_mode VALUES(1)", [])?;
    }
    Ok(())
}
pub fn ceiling(db: &Connection, resource: &str, window: &str, maximum: u64) -> Result<u64> {
    let worker: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM cluster_wallet_mode)",
        [],
        |r| r.get(0),
    )?;
    if !worker {
        return Ok(maximum);
    }
    let amount: Option<(u64, bool)> = db
        .query_row(
            "SELECT amount,unlimited FROM cluster_wallet WHERE resource=?1 AND window=?2",
            params![resource, window],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    Ok(match amount {
        Some((_, true)) => maximum,
        Some((n, false)) => n.min(maximum),
        None => 0,
    })
}
fn allocate(
    db: &Connection,
    node: &str,
    resource: &str,
    window: &str,
    request: &Request,
    allowance: (u64, u64, u64),
) -> Result<(u64, u64)> {
    let (maximum, used, chunk) = allowance;
    let previous: u64 = db
        .query_row(
            "SELECT amount FROM cluster_allocations WHERE node=?1 AND resource=?2 AND window=?3",
            params![node, resource, window],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or(0);
    let known = request
        .known
        .get(&format!("{resource}:{window}"))
        .copied()
        .unwrap_or(0);
    let increment = if previous == known && request.replenish.iter().any(|r| r == resource) {
        chunk.min(maximum.saturating_sub(used))
    } else {
        0
    };
    let amount = previous
        .checked_add(increment)
        .ok_or_else(|| anyhow::anyhow!("credit overflow"))?;
    db.execute("INSERT INTO cluster_allocations VALUES(?1,?2,?3,?4) ON CONFLICT(node,resource,window) DO UPDATE SET amount=excluded.amount",params![node,resource,window,amount])?;
    Ok((amount, increment))
}
pub fn grant(
    config: &crate::config::Config,
    node: &str,
    request: &Request,
    now: i64,
) -> Result<Vec<Credit>> {
    ensure!(
        request.known.len() <= 10
            && request.replenish.len() <= 5
            && request.known.keys().all(|k| k.len() < 80),
        "Invalid budget request"
    );
    let mut result = Vec::new();
    if let Some(llm) = &config.llm {
        let _init = crate::llm::Budget::open(&config.data_dir.join("llm-budget.sqlite3"))?;
        let mut db = open(&config.data_dir.join("llm-budget.sqlite3"))?;
        let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let month: String =
            tx.query_row("SELECT strftime('%Y-%m',?1,'unixepoch')", [now], |r| {
                r.get(0)
            })?;
        let used: u64 = tx
            .query_row(
                "SELECT accounted FROM llm_months WHERE month=?1",
                [&month],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or(0);
        let (amount, increment) = allocate(
            &tx,
            node,
            "llm",
            &month,
            request,
            (llm.monthly_budget_micro_eur, used, 100_000),
        )?;
        tx.execute("INSERT INTO llm_months VALUES(?1,?2,0) ON CONFLICT(month) DO UPDATE SET accounted=accounted+excluded.accounted",params![month,increment])?;
        tx.commit()?;
        result.push(Credit {
            resource: "llm".into(),
            window: month,
            amount,
            unlimited: false,
        });
    }
    if let Some(settings) = &config.protection {
        let _init = crate::protection::providers::Client::new(settings, &config.data_dir)?;
        let mut db = open(&config.data_dir.join("protection/reputation.sqlite3"))?;
        for provider in [
            crate::protection::providers::Provider::Crdf,
            crate::protection::providers::Provider::Virustotal,
        ] {
            if (provider == crate::protection::providers::Provider::Crdf && !settings.policy.crdf)
                || (provider == crate::protection::providers::Provider::Virustotal
                    && !settings.policy.virustotal)
            {
                continue;
            }
            let quota = settings.quota(provider, &settings.policy);
            let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let (day, minute) = (now / 86400, now / 60);
            let old: Option<(i64, u64, i64, u64)> = tx
                .query_row(
                    "SELECT day,day_used,minute,minute_used FROM quota WHERE provider=?1",
                    [provider.name()],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .optional()?;
            let (mut du, mut mu) = old
                .map(|(d, du, m, mu)| {
                    (
                        if d == day { du } else { 0 },
                        if m == minute { mu } else { 0 },
                    )
                })
                .unwrap_or((0, 0));
            for (suffix, window, limit, used, chunk) in [
                ("day", day, quota.day, &mut du, 50),
                ("minute", minute, quota.minute, &mut mu, 1),
            ] {
                let resource = format!("{}-{suffix}", provider.name());
                let window = window.to_string();
                let (amount, increment) = if limit == 0 {
                    (0, 0)
                } else {
                    allocate(
                        &tx,
                        node,
                        &resource,
                        &window,
                        request,
                        (u64::from(limit), *used, chunk),
                    )?
                };
                *used = used.saturating_add(increment);
                result.push(Credit {
                    resource,
                    window,
                    amount,
                    unlimited: limit == 0,
                });
            }
            tx.execute(
                "INSERT OR REPLACE INTO quota VALUES(?1,?2,?3,?4,?5)",
                params![provider.name(), day, du, minute, mu],
            )?;
            tx.commit()?;
        }
    }
    prune(&config.data_dir, now)?;
    Ok(result)
}
pub fn install(root: &Path, credits: &[Credit], now: i64) -> Result<()> {
    ensure!(credits.len() <= 5, "Too many credits");
    for credit in credits {
        let path = if credit.resource == "llm" {
            root.join("llm-budget.sqlite3")
        } else {
            root.join("protection/reputation.sqlite3")
        };
        ensure!(
            [
                "llm",
                "crdf-day",
                "crdf-minute",
                "virustotal-day",
                "virustotal-minute"
            ]
            .contains(&credit.resource.as_str())
                && credit.amount <= 10_000_000_000
                && !(credit.resource == "llm" && credit.unlimited),
            "Invalid credit"
        );
        let db = open(&path)?;
        let current = if credit.resource == "llm" {
            db.query_row("SELECT strftime('%Y-%m',?1,'unixepoch')", [now], |r| {
                r.get::<_, String>(0)
            })?
        } else if credit.resource.ends_with("-day") {
            (now / 86400).to_string()
        } else {
            (now / 60).to_string()
        };
        if credit.window != current {
            continue;
        }
        db.execute("INSERT INTO cluster_wallet VALUES(?1,?2,?3,?4) ON CONFLICT(resource,window) DO UPDATE SET amount=MAX(amount,excluded.amount),unlimited=excluded.unlimited",params![credit.resource,credit.window,credit.amount,credit.unlimited])?;
    }
    prune(root, now)?;
    Ok(())
}
pub fn request(root: &Path, now: i64) -> Result<Request> {
    let mut out = Request::default();
    let db = open(&root.join("llm-budget.sqlite3"))?;
    let month: String = db.query_row("SELECT strftime('%Y-%m',?1,'unixepoch')", [now], |r| {
        r.get(0)
    })?;
    let mut needs = vec![("llm".to_owned(), month, 0u64, 10_000u64)];
    // Client initialization may not yet have created the ledger on the first handshake.
    if let Ok(used) = db.query_row(
        "SELECT accounted FROM llm_months WHERE month=?1",
        [&needs[0].1],
        |r| r.get::<_, u64>(0),
    ) {
        needs[0].2 = used;
    }
    drop(db);
    for p in ["crdf", "virustotal"] {
        let db = open(&root.join("protection/reputation.sqlite3"))?;
        let previous = db
            .query_row(
                "SELECT day,day_used,minute,minute_used FROM quota WHERE provider=?1",
                [p],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, u64>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, u64>(3)?,
                    ))
                },
            )
            .ok();
        needs.push((
            format!("{p}-day"),
            (now / 86400).to_string(),
            previous
                .map(|(d, n, _, _)| if d == now / 86400 { n } else { 0 })
                .unwrap_or(0),
            2,
        ));
        needs.push((
            format!("{p}-minute"),
            (now / 60).to_string(),
            previous
                .map(|(_, _, m, n)| if m == now / 60 { n } else { 0 })
                .unwrap_or(0),
            1,
        ));
    }
    for (resource, window, used, margin) in needs {
        let db = open(&root.join(if resource == "llm" {
            "llm-budget.sqlite3"
        } else {
            "protection/reputation.sqlite3"
        }))?;
        let (amount, unlimited) = db
            .query_row(
                "SELECT amount,unlimited FROM cluster_wallet WHERE resource=?1 AND window=?2",
                params![resource, window],
                |r| Ok((r.get::<_, u64>(0)?, r.get::<_, bool>(1)?)),
            )
            .optional()?
            .unwrap_or((0, false));
        out.known.insert(format!("{resource}:{window}"), amount);
        if !unlimited && amount.saturating_sub(used) < margin {
            out.replenish.push(resource);
        }
    }
    Ok(out)
}

fn prune(root: &Path, now: i64) -> Result<()> {
    for (file, llm) in [
        ("llm-budget.sqlite3", true),
        ("protection/reputation.sqlite3", false),
    ] {
        let path = root.join(file);
        if !path.exists() {
            continue;
        }
        let db = open(&path)?;
        if llm {
            let month: String = db.query_row(
                "SELECT strftime('%Y-%m',?1,'unixepoch')",
                [now - 62 * 86400],
                |r| r.get(0),
            )?;
            for table in ["cluster_wallet", "cluster_allocations"] {
                db.execute(
                    &format!("DELETE FROM {table} WHERE resource='llm' AND window<?1"),
                    [&month],
                )?;
            }
        } else {
            for table in ["cluster_wallet", "cluster_allocations"] {
                db.execute(&format!("DELETE FROM {table} WHERE (resource LIKE '%-day' AND CAST(window AS INTEGER)<?1) OR (resource LIKE '%-minute' AND CAST(window AS INTEGER)<?2)"), params![now/86400-2,now/60-10])?;
            }
        }
    }
    Ok(())
}
