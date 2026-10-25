//! Durable SCIM requests share the management mutation lock with connection
//! revocation and administrator authorization changes. SMTP never uses it.
use super::{
    Central, admin::management_lock, database_error, identity_connections as connections,
    policies::approval,
};
use crate::identity::{
    connections::{Credential, Reference, vault::Key},
    scim::{
        access::{Access, UNAUTHORIZED},
        repository::{
            Command, Inventory, Reply,
            database::{Cell, Database, Deadline, Param, Row},
            engine,
        },
    },
};
use anyhow::{Context, Result, ensure};
use std::path::PathBuf;
use tokio_postgres::{
    Transaction,
    types::{ToSql, Type},
};
const SQL: &str = include_str!("../identity/scim/repository/postgres.sql");
pub(super) async fn migrate(tx: &Transaction<'_>) -> Result<()> {
    tx.batch_execute("CREATE TABLE IF NOT EXISTS noisefence.identity_scim_schema(id BIGINT PRIMARY KEY CHECK(id=1),version BIGINT NOT NULL,sha256 TEXT NOT NULL)").await.map_err(database_error)?;
    let digest = crate::message::digest(SQL.as_bytes());
    if let Some(row) = tx
        .query_opt(
            "SELECT version,sha256 FROM noisefence.identity_scim_schema WHERE id=1",
            &[],
        )
        .await
        .map_err(database_error)?
    {
        ensure!(
            row.get::<_, i64>(0) == 1 && row.get::<_, String>(1) == digest,
            "Unsupported SCIM component schema"
        );
    } else {
        tx.batch_execute(SQL).await.map_err(database_error)?;
        tx.execute(
            "INSERT INTO noisefence.identity_scim_schema VALUES(1,1,$1)",
            &[&digest],
        )
        .await
        .map_err(database_error)?;
    }
    Ok(())
}
pub(super) async fn check(tx: &Transaction<'_>) -> Result<()> {
    let row = tx
        .query_one(
            "SELECT version,sha256 FROM noisefence.identity_scim_schema WHERE id=1",
            &[],
        )
        .await
        .map_err(database_error)?;
    ensure!(
        row.get::<_, i64>(0) == 1
            && row.get::<_, String>(1) == crate::message::digest(SQL.as_bytes()),
        "SCIM component requires supported migration"
    );
    Ok(())
}
struct Postgres<'a, 'tx> {
    tx: &'a Transaction<'tx>,
    deadline: Deadline,
}
// SQL comes only from the private shared algorithm. Values are always bound,
// never interpolated. All returned numeric columns use BIGINT in this schema.
fn statement(sql: &str) -> String {
    sql.replace('?', "$")
        .replace("identity_scim_", "noisefence.identity_scim_")
}
fn values(params: &[Param]) -> Vec<&(dyn ToSql + Sync)> {
    params
        .iter()
        .map(|p| match p {
            Param::Text(v) => v as &(dyn ToSql + Sync),
            Param::Integer(v) => v as &(dyn ToSql + Sync),
        })
        .collect()
}
impl Database for Postgres<'_, '_> {
    async fn query<'a>(&'a mut self, sql: &'a str, params: &'a [Param]) -> Result<Vec<Row>> {
        self.deadline.check()?;
        let rows = self
            .tx
            .query(&statement(sql), &values(params))
            .await
            .map_err(database_error)?;
        rows.into_iter()
            .map(|row| {
                let mut cells = Vec::with_capacity(row.len());
                for (i, column) in row.columns().iter().enumerate() {
                    cells.push(match *column.type_() {
                        Type::INT8 => row
                            .try_get::<_, Option<i64>>(i)
                            .map_err(database_error)?
                            .map_or(Cell::Null, Cell::Integer),
                        Type::TEXT => row
                            .try_get::<_, Option<String>>(i)
                            .map_err(database_error)?
                            .map_or(Cell::Null, Cell::Text),
                        _ => anyhow::bail!("Unsupported SCIM column"),
                    });
                }
                Ok(Row(cells))
            })
            .collect()
    }
    async fn execute<'a>(&'a mut self, sql: &'a str, params: &'a [Param]) -> Result<u64> {
        self.deadline.check()?;
        self.tx
            .execute(&statement(sql), &values(params))
            .await
            .map_err(database_error)
    }
}
impl Central {
    pub async fn scim_request(
        &self,
        root: PathBuf,
        access: Access,
        command: Command,
    ) -> Result<Reply> {
        let deadline = Deadline::new();
        let key = tokio::task::spawn_blocking(move || Key::load(&root)).await??;
        let mut db = self
            .interactive
            .get()
            .await
            .context("SCIM management unavailable")?;
        let tx = db.transaction().await.map_err(database_error)?;
        management_lock(&tx).await?;
        connections::check(&tx).await?;
        let record = connections::read(
            &tx,
            &access.source_id,
            &self.directory_connection_authority(),
        )
        .await?
        .ok_or(UNAUTHORIZED)?;
        access.bearer.verify(
            &record,
            &key,
            connections::owner_current(&tx, &record).await?,
            crate::now(),
        )?;
        check(&tx).await?;
        let result = engine::execute(
            &mut Postgres { tx: &tx, deadline },
            &record,
            command,
            crate::now(),
        )
        .await?;
        let current = connections::read(
            &tx,
            &access.source_id,
            &self.directory_connection_authority(),
        )
        .await?
        .ok_or(UNAUTHORIZED)?;
        access.bearer.verify(
            &current,
            &key,
            connections::owner_current(&tx, &current).await?,
            crate::now(),
        )?;
        deadline.check()?;
        tx.commit().await.map_err(database_error)?;
        result.map_err(Into::into)
    }
    pub async fn scim_preflight(
        &self,
        root: PathBuf,
        access: Access,
    ) -> Result<(Access, crate::identity::directory::Source)> {
        let deadline = Deadline::new();
        let key = tokio::task::spawn_blocking(move || Key::load(&root)).await??;
        let mut db = self
            .interactive
            .get()
            .await
            .context("SCIM management unavailable")?;
        let tx = db.transaction().await.map_err(database_error)?;
        management_lock(&tx).await?;
        connections::check(&tx).await?;
        let record = connections::read(
            &tx,
            &access.source_id,
            &self.directory_connection_authority(),
        )
        .await?
        .ok_or(UNAUTHORIZED)?;
        access.bearer.verify(
            &record,
            &key,
            connections::owner_current(&tx, &record).await?,
            crate::now(),
        )?;
        deadline.check()?;
        tx.commit().await.map_err(database_error)?;
        Ok((access, record.metadata.source))
    }
    pub async fn scim_inventory(
        &self,
        root: PathBuf,
        reference: Reference,
        actor: &str,
        session: &str,
    ) -> Result<Inventory> {
        reference.validate()?;
        let deadline = Deadline::new();
        let key = tokio::task::spawn_blocking(move || Key::load(&root)).await??;
        let mut db = self
            .interactive
            .get()
            .await
            .context("SCIM management unavailable")?;
        let tx = db.transaction().await.map_err(database_error)?;
        management_lock(&tx).await?;
        approval(&tx, actor, session, None).await?;
        let record =
            connections::live(&tx, &reference, &self.directory_connection_authority()).await?;
        ensure!(
            matches!(
                key.open(&record, crate::now())?,
                Credential::ScimBearerVerifier { .. }
            ),
            "Not a SCIM source"
        );
        check(&tx).await?;
        let result =
            engine::inventory(&mut Postgres { tx: &tx, deadline }, &record, crate::now()).await?;
        approval(&tx, actor, session, None).await?;
        connections::live(&tx, &reference, &self.directory_connection_authority()).await?;
        deadline.check()?;
        tx.commit().await.map_err(database_error)?;
        Ok(result)
    }
}
