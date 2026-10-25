use super::Grant;
use crate::identity::{
    connections::{self, Record, Reference, local as connections_db, vault::Key},
    sync::{self, Event, Outcome, Request},
};
use anyhow::{Context, Result, ensure};
use rusqlite::{Transaction, params};
fn write(tx: &Transaction<'_>, record: &Record) -> Result<()> {
    ensure!(
        tx.execute(
            "UPDATE identity_connections SET record=?1 WHERE source_id=?2",
            params![record.encode()?, record.metadata.source.id]
        )? == 1,
        "Directory connection disappeared"
    );
    Ok(())
}
fn audit(tx: &Transaction<'_>, actor: &str, action: &str, id: &str, now: i64) -> Result<()> {
    tx.execute(
        "INSERT INTO audit(created,username,action,object_id) VALUES(?1,?2,?3,?4)",
        params![now, actor, action, id],
    )?;
    Ok(())
}
#[allow(clippy::too_many_arguments)]
pub fn save(
    tx: &Transaction<'_>,
    reference: &Reference,
    expected: Option<&str>,
    grant: Grant,
    key: &Key,
    actor: &str,
    session: &str,
    now: i64,
) -> Result<()> {
    reference.validate()?;
    let version = connections_db::authorize(tx, actor, session)?;
    let mut record = connections_db::get(
        tx,
        &reference.source_id,
        &reference.generation,
        actor,
        session,
        now,
    )?;
    let signature = key.sign_schedule(&record.metadata, &grant)?;
    super::enable(&mut record, expected, grant, signature, actor, version, now)?;
    key.verify_schedule(&record)?;
    write(tx, &record)?;
    audit(
        tx,
        actor,
        "identity_schedule_saved",
        &record.metadata.source.id,
        now,
    )
}
pub fn stop(
    tx: &Transaction<'_>,
    reference: &Reference,
    expected: &str,
    actor: &str,
    session: &str,
    now: i64,
) -> Result<()> {
    reference.validate()?;
    connections_db::authorize(tx, actor, session)?;
    connections_db::migrate(tx)?;
    let mut record =
        connections_db::read(tx, &reference.source_id)?.context("Directory connection missing")?;
    ensure!(
        record.metadata.generation == reference.generation,
        "Directory connection changed"
    );
    let schedule = record.schedule.as_ref().context("No collection schedule")?;
    ensure!(schedule.grant.id == expected, "Collection schedule changed");
    let binding = schedule.binding(&record.metadata)?;
    let changed = schedule.revoked_at.is_none();
    super::disable(&mut record, &binding, now)?;
    if changed {
        write(tx, &record)?;
        audit(tx, actor, "identity_schedule_stopped", expected, now)?;
    }
    Ok(())
}
pub fn due(tx: &Transaction<'_>, now: i64, revision: i64) -> Result<Vec<Record>> {
    let exists:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='identity_connections')",[],|r|r.get(0))?;
    if !exists {
        return Ok(vec![]);
    }
    connections_db::migrate(tx)?;
    let mut q = tx
        .prepare("SELECT source_id,record FROM identity_connections ORDER BY source_id LIMIT 17")?;
    let rows = q
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    ensure!(
        rows.len() <= connections::MAX_CONNECTIONS,
        "Directory connection limit exceeded"
    );
    let mut result = Vec::new();
    for (id, raw) in rows {
        let record = Record::decode(&raw, &id, "sqlite")?;
        if record
            .view(now, connections_db::owner_current(tx, &record)?)
            .status
            == "configured"
            && record
                .schedule
                .as_ref()
                .is_some_and(|s| s.due(now, revision))
        {
            result.push(record);
        }
    }
    result.sort_by_key(|r| r.schedule.as_ref().map(|s| s.next_due));
    Ok(result)
}
pub fn authorized(tx: &Transaction<'_>, request: &Request, now: i64) -> Result<Record> {
    connections_db::migrate(tx)?;
    let record =
        connections_db::read(tx, &request.source_id)?.context("Directory connection missing")?;
    ensure!(
        connections_db::owner_current(tx, &record)?,
        "Collection owner authorization changed"
    );
    super::authorize(&record, request, now)?;
    Ok(record)
}
pub fn claim(tx: &Transaction<'_>, request: &Request, key: &Key, now: i64) -> Result<Record> {
    connections_db::migrate(tx)?;
    let mut record =
        connections_db::read(tx, &request.source_id)?.context("Directory connection missing")?;
    ensure!(
        connections_db::owner_current(tx, &record)?,
        "Collection owner authorization changed"
    );
    key.verify_schedule(&record)?;
    let raw = {
        let mut q=tx.prepare("SELECT object_id FROM audit WHERE action='identity_sync' AND created>=?1 ORDER BY id LIMIT 129")?;
        q.query_map([request.created - 3960], |r| r.get(0))?
            .collect::<rusqlite::Result<Vec<String>>>()?
    };
    sync::admit(&raw, request, now)?;
    super::claim(&mut record, request, now)?;
    write(tx, &record)?;
    audit(
        tx,
        &record.metadata.owner,
        sync::ACTION,
        &Event {
            request: request.clone(),
            outcome: Outcome::Running,
        }
        .encode()?,
        now,
    )?;
    Ok(record)
}
pub fn finish(tx: &Transaction<'_>, mut event: Event, actor: &str, now: i64) -> Result<()> {
    ensure!(
        event.request.scheduled.is_some(),
        "Scheduled receipt required"
    );
    connections_db::migrate(tx)?;
    let mut record = connections_db::read(tx, &event.request.source_id)?;
    if matches!(event.outcome, Outcome::Ready { .. })
        && authorized(tx, &event.request, now).is_err()
    {
        event.outcome = Outcome::Failed {
            reason: sync::Failure::Authorization,
        };
    }
    let raw = {
        let mut q=tx.prepare("SELECT object_id FROM audit WHERE action='identity_sync' AND object_id LIKE ?1 ORDER BY id LIMIT 129")?;
        q.query_map([format!("{};%", event.request.id)], |r| r.get(0))?
            .collect::<rusqlite::Result<Vec<String>>>()?
    };
    sync::finish(&raw, &event, now)?;
    if let Some(record) = record.as_mut()
        && super::completed(record, &event, now)?
    {
        write(tx, record)?;
    }
    audit(tx, actor, sync::ACTION, &event.encode()?, now)
}
