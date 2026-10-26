//! Optional, independently versioned management component. No SMTP queue data.
use super::{MAX_CONNECTIONS, Record, View};
use anyhow::{Result, ensure};
use rusqlite::{OptionalExtension, Transaction, params};
const SQL: &str = include_str!("local.sql");
pub fn migrate(tx: &Transaction<'_>) -> Result<()> {
    tx.execute_batch("CREATE TABLE IF NOT EXISTS identity_connection_schema(id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL,sha256 TEXT NOT NULL)")?;
    let row: Option<(i64, String)> = tx
        .query_row(
            "SELECT version,sha256 FROM identity_connection_schema WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let hash = crate::message::digest(SQL.as_bytes());
    match row {
        Some((v, h)) => ensure!(
            v == 1 && h == hash,
            "Unsupported directory connection schema"
        ),
        None => {
            tx.execute_batch(SQL)?;
            tx.execute(
                "INSERT INTO identity_connection_schema VALUES(1,1,?1)",
                [hash],
            )?;
        }
    }
    Ok(())
}
pub(crate) fn authorize(tx: &Transaction<'_>, actor: &str, session: &str) -> Result<i64> {
    crate::control::identity::local_authorize(tx, actor, session)?;
    Ok(tx.query_row(
        "SELECT coalesce((SELECT version FROM console_user_versions WHERE username=?1),0)",
        [actor],
        |r| r.get(0),
    )?)
}
pub(crate) fn owner_current(tx: &Transaction<'_>, record: &Record) -> Result<bool> {
    Ok(tx.query_row("SELECT EXISTS(SELECT 1 FROM users u LEFT JOIN console_user_versions v ON v.username=u.username WHERE u.username=?1 AND u.admin=1 AND u.disabled=0 AND coalesce(v.version,0)=?2)",params![record.metadata.owner,record.metadata.owner_version],|r|r.get(0))?)
}
pub(crate) fn read(tx: &Transaction<'_>, source: &str) -> Result<Option<Record>> {
    tx.query_row(
        "SELECT record FROM identity_connections WHERE source_id=?1",
        [source],
        |r| r.get::<_, String>(0),
    )
    .optional()?
    .map(|s| Record::decode(&s, source, "sqlite"))
    .transpose()
}
pub fn save(
    tx: &Transaction<'_>,
    expected: Option<&str>,
    next: &Record,
    actor: &str,
    session: &str,
    now: i64,
) -> Result<()> {
    let version = authorize(tx, actor, session)?;
    migrate(tx)?;
    let old = read(tx, &next.metadata.source.id)?;
    super::replacement(old.as_ref(), expected, next, actor, version, "sqlite", now)?;
    if old.is_none() {
        let count: i64 = tx.query_row("SELECT count(*) FROM identity_connections", [], |r| {
            r.get(0)
        })?;
        ensure!(
            count < MAX_CONNECTIONS as i64,
            "Directory connection limit reached"
        );
    }
    if old
        .as_ref()
        .is_some_and(|p| p.metadata.generation == next.metadata.generation)
    {
        return Ok(());
    }
    tx.execute("INSERT INTO identity_connections(source_id,record) VALUES(?1,?2) ON CONFLICT(source_id) DO UPDATE SET record=excluded.record",params![next.metadata.source.id,next.encode()?])?;
    tx.execute("INSERT INTO audit(created,username,action,object_id) VALUES(?1,?2,'identity_connection_saved',?3)",params![now,actor,next.metadata.source.id])?;
    Ok(())
}
pub fn list(tx: &Transaction<'_>, actor: &str, session: &str, now: i64) -> Result<Vec<View>> {
    authorize(tx, actor, session)?;
    migrate(tx)?;
    let mut statement = tx
        .prepare("SELECT source_id,record FROM identity_connections ORDER BY source_id LIMIT 17")?;
    let rows = statement
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    ensure!(
        rows.len() <= MAX_CONNECTIONS,
        "Directory connection limit exceeded"
    );
    rows.into_iter()
        .map(|(id, raw)| {
            let record = Record::decode(&raw, &id, "sqlite")?;
            Ok(record.view(now, owner_current(tx, &record)?))
        })
        .collect()
}
pub fn get(
    tx: &Transaction<'_>,
    source: &str,
    generation: &str,
    actor: &str,
    session: &str,
    now: i64,
) -> Result<Record> {
    authorize(tx, actor, session)?;
    migrate(tx)?;
    let record =
        read(tx, source)?.ok_or_else(|| anyhow::anyhow!("Directory connection not found"))?;
    ensure!(
        record.metadata.generation == generation
            && owner_current(tx, &record)?
            && record.view(now, true).status == "configured",
        "Directory connection expired, revoked or authorization changed"
    );
    Ok(record)
}
pub fn revoke(
    tx: &Transaction<'_>,
    source: &str,
    expected: &str,
    actor: &str,
    session: &str,
    now: i64,
) -> Result<()> {
    authorize(tx, actor, session)?;
    migrate(tx)?;
    let old = read(tx, source)?.ok_or_else(|| anyhow::anyhow!("Directory connection not found"))?;
    let changed = old.revoked_at.is_none();
    let record = super::revoke(old, expected, now)?;
    if changed {
        tx.execute(
            "UPDATE identity_connections SET record=?1 WHERE source_id=?2",
            params![record.encode()?, source],
        )?;
        tx.execute("INSERT INTO audit(created,username,action,object_id) VALUES(?1,?2,'identity_connection_revoked',?3)",params![now,actor,source])?;
    }
    Ok(())
}
