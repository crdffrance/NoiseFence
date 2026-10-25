use super::{
    Command, Inventory, Reply,
    database::{Cell, Database, Param, Row},
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
        // Executes entirely on Store::run's blocking worker. The shared async
        // algorithm never moves a SQLite transaction onto an async worker.
        ready((|| {
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
        ready(
            self.tx
                .execute(sql, rusqlite::params_from_iter(values(params)))
                .map(|n| n as u64)
                .map_err(Into::into),
        )
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
) -> Result<super::super::Result<Reply>> {
    let record = authorized(tx, root, &access)?;
    migrate(tx)?;
    let result = tokio::runtime::Handle::current().block_on(engine::execute(
        &mut Local { tx },
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
        &mut Local { tx },
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
