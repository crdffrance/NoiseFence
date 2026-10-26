use super::{
    Command, Inventory, Reply,
    database::{Cell, Database, Deadline, Param, Row},
    engine,
};
use crate::identity::{
    connections::{Record, Reference, local as connections, vault::Key},
    scim::access::{Access, UNAUTHORIZED},
};
use anyhow::{Result, ensure};
use rusqlite::{
    OptionalExtension, Transaction,
    types::{Value, ValueRef},
};
use std::{
    future::{Future, ready},
    path::Path,
};
const SQL: &str = include_str!("local.sql");
fn migrate(tx: &Transaction<'_>) -> Result<()> {
    tx.execute_batch("CREATE TABLE IF NOT EXISTS identity_scim_schema(id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL,sha256 TEXT NOT NULL)")?;
    let previous: Option<(i64, String)> = tx
        .query_row(
            "SELECT version,sha256 FROM identity_scim_schema WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let digest = crate::message::digest(SQL.as_bytes());
    if let Some((version, hash)) = previous {
        ensure!(
            version == 1 && hash == digest,
            "Unsupported SCIM component schema"
        );
    } else {
        tx.execute_batch(SQL)?;
        tx.execute("INSERT INTO identity_scim_schema VALUES(1,1,?1)", [digest])?;
    }
    Ok(())
}
struct Local<'a, 'tx> {
    tx: &'a Transaction<'tx>,
    deadline: Deadline,
}
fn values(params: &[Param]) -> Vec<Value> {
    params
        .iter()
        .map(|v| match v {
            Param::Text(Some(v)) => Value::Text(v.clone()),
            Param::Integer(Some(v)) => Value::Integer(*v),
            _ => Value::Null,
        })
        .collect()
}
impl Database for Local<'_, '_> {
    fn query<'a>(
        &'a mut self,
        sql: &'a str,
        params: &'a [Param],
    ) -> impl Future<Output = Result<Vec<Row>>> + Send + 'a {
        // Executes entirely on the dedicated SCIM blocking worker. The shared async
        // algorithm never moves a SQLite transaction onto an async worker.
        ready((|| {
            self.deadline.check()?;
            let values = values(params);
            let mut stmt = self.tx.prepare(sql)?;
            let columns = stmt.column_count();
            let mut rows = stmt.query(rusqlite::params_from_iter(values))?;
            let mut result = vec![];
            while let Some(row) = rows.next()? {
                let mut cells = Vec::with_capacity(columns);
                for i in 0..columns {
                    cells.push(match row.get_ref(i)? {
                        ValueRef::Text(v) => Cell::Text(std::str::from_utf8(v)?.into()),
                        ValueRef::Integer(v) => Cell::Integer(v),
                        ValueRef::Null => Cell::Null,
                        _ => anyhow::bail!("Unsupported SCIM column"),
                    });
                }
                result.push(Row(cells));
            }
            Ok(result)
        })())
    }
    fn execute<'a>(
        &'a mut self,
        sql: &'a str,
        params: &'a [Param],
    ) -> impl Future<Output = Result<u64>> + Send + 'a {
        ready((|| {
            self.deadline.check()?;
            Ok(self
                .tx
                .execute(sql, rusqlite::params_from_iter(values(params)))? as u64)
        })())
    }
}
fn authorized(tx: &Transaction<'_>, root: &Path, access: &Access) -> Result<Record> {
    connections::migrate(tx)?;
    let record = connections::read(tx, &access.source_id)?.ok_or(UNAUTHORIZED)?;
    let key = Key::load(root)?;
    access.bearer.verify(
        &record,
        &key,
        connections::owner_current(tx, &record)?,
        crate::now(),
    )?;
    Ok(record)
}
pub(super) fn request(
    tx: &Transaction<'_>,
    root: &Path,
    access: Access,
    command: Command,
    deadline: Deadline,
) -> Result<super::super::Result<Reply>> {
    let record = authorized(tx, root, &access)?;
    migrate(tx)?;
    let result = tokio::runtime::Handle::current().block_on(engine::execute(
        &mut Local { tx, deadline },
        &record,
        command,
        crate::now(),
    ))?;
    // Expiry can pass while a large group mutation is executing.
    authorized(tx, root, &access)?;
    Ok(result)
}
pub(super) fn inventory(
    tx: &Transaction<'_>,
    root: &Path,
    reference: &Reference,
    actor: &str,
    session: &str,
    deadline: Deadline,
) -> Result<Inventory> {
    reference.validate()?;
    let record = connections::get(
        tx,
        &reference.source_id,
        &reference.generation,
        actor,
        session,
        crate::now(),
    )?;
    ensure!(
        matches!(
            Key::load(root)?.open(&record, crate::now())?,
            crate::identity::connections::Credential::ScimBearerVerifier { .. }
        ),
        "Not a SCIM source"
    );
    migrate(tx)?;
    let result = tokio::runtime::Handle::current().block_on(engine::inventory(
        &mut Local { tx, deadline },
        &record,
        crate::now(),
    ))?;
    connections::get(
        tx,
        &reference.source_id,
        &reference.generation,
        actor,
        session,
        crate::now(),
    )?;
    Ok(result)
}

pub(super) fn preflight(
    tx: &Transaction<'_>,
    root: &Path,
    access: Access,
) -> Result<(Access, crate::identity::directory::Source)> {
    let source = authorized(tx, root, &access)?.metadata.source;
    Ok((access, source))
}
/// Dedicated SQLite connection: no provisioning work waits on the SMTP writer
/// mutex. The task keeps ownership until interrupted SQL has actually stopped.
pub(super) async fn run<T, F>(root: std::path::PathBuf, f: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(&mut rusqlite::Connection, &Path, Deadline) -> Result<T> + Send + 'static,
{
    tokio::spawn(async move {
        let deadline = Deadline::new();
        let (send, receive) = tokio::sync::oneshot::channel();
        let mut task = tokio::task::spawn_blocking(move || {
            let mut db = rusqlite::Connection::open_with_flags(
                root.join("state.sqlite3"),
                rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE,
            )?;
            db.busy_timeout(std::time::Duration::from_millis(250))?;
            let _ = send.send(db.get_interrupt_handle());
            db.execute_batch(
                "PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON;",
            )?;
            deadline.check()?;
            f(&mut db, &root, deadline)
        });
        match receive.await {
            Ok(interrupt) => tokio::select! {
                result = &mut task => result?,
                _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {
                    interrupt.interrupt();
                    task.await?
                }
            },
            Err(_) => task.await?,
        }
    })
    .await?
}

/// Called inside the same write transaction as a durable review receipt.
pub(crate) fn verify_review(
    tx: &Transaction<'_>,
    proof: &super::super::staging::Attestation,
    record: &Record,
) -> Result<()> {
    migrate(tx)?;
    let (digest, sequence): (String, i64) = tx.query_row(
        "SELECT source_sha256,sequence FROM identity_scim_sources WHERE source_id=?1",
        [&record.metadata.source.id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    ensure!(
        digest == proof.revision.source_sha256,
        "SCIM source changed"
    );
    proof.verify(&record.metadata.source, &super::revision(record, sequence)?)
}
