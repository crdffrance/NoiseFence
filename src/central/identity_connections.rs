//! Directory credentials use the selected authority, with a separate component
//! checksum. Its ciphertext is never returned by console status or node sync.
use super::{Central, admin::management_lock, database_error};
use crate::identity::connections::{self, MAX_CONNECTIONS, Record, View};
use anyhow::{Context, Result, ensure};
use tokio_postgres::Transaction;
const SQL: &str = include_str!("../identity/connections/postgres.sql");
pub(super) async fn migrate(tx: &Transaction<'_>) -> Result<()> {
    tx.batch_execute("CREATE TABLE IF NOT EXISTS noisefence.identity_connection_schema(id integer PRIMARY KEY CHECK(id=1),version integer NOT NULL,sha256 text NOT NULL)").await.map_err(database_error)?;
    let row = tx
        .query_opt(
            "SELECT version,sha256 FROM noisefence.identity_connection_schema WHERE id=1",
            &[],
        )
        .await
        .map_err(database_error)?;
    let hash = crate::message::digest(SQL.as_bytes());
    if let Some(row) = row {
        ensure!(
            row.get::<_, i32>(0) == 1 && row.get::<_, String>(1) == hash,
            "Unsupported directory connection schema"
        );
    } else {
        tx.batch_execute(SQL).await.map_err(database_error)?;
        tx.execute(
            "INSERT INTO noisefence.identity_connection_schema VALUES(1,1,$1)",
            &[&hash],
        )
        .await
        .map_err(database_error)?;
    }
    Ok(())
}
pub(crate) async fn check(tx: &Transaction<'_>) -> Result<()> {
    let row = tx
        .query_one(
            "SELECT version,sha256 FROM noisefence.identity_connection_schema WHERE id=1",
            &[],
        )
        .await
        .map_err(database_error)?;
    ensure!(
        row.get::<_, i32>(0) == 1
            && row.get::<_, String>(1) == crate::message::digest(SQL.as_bytes()),
        "Directory connection component requires a supported migration"
    );
    Ok(())
}
async fn owner_current(tx: &Transaction<'_>, record: &Record) -> Result<bool> {
    Ok(tx.query_one("SELECT EXISTS(SELECT 1 FROM noisefence.users WHERE username=$1 AND admin AND NOT disabled AND version=$2)",&[&record.metadata.owner,&record.metadata.owner_version]).await.map_err(database_error)?.get(0))
}
async fn read(tx: &Transaction<'_>, source: &str, authority: &str) -> Result<Option<Record>> {
    tx.query_opt(
        "SELECT record::text FROM noisefence.identity_connections WHERE source_id=$1",
        &[&source],
    )
    .await
    .map_err(database_error)?
    .map(|r| Record::decode(&r.get::<_, String>(0), source, authority))
    .transpose()
}
pub(crate) async fn live(
    tx: &Transaction<'_>,
    reference: &connections::Reference,
    authority: &str,
) -> Result<Record> {
    reference.validate()?;
    check(tx).await?;
    let record = read(tx, &reference.source_id, authority)
        .await?
        .context("Directory connection not found")?;
    ensure!(
        record.metadata.generation == reference.generation
            && owner_current(tx, &record).await?
            && record.view(crate::now(), true).status == "configured",
        "Directory connection expired, revoked or authorization changed"
    );
    // The caller checks its administrator session in this same transaction.
    Ok(record)
}
impl Central {
    pub async fn identity_connection_prepare(
        &self,
        root: std::path::PathBuf,
        actor: &str,
        session: &str,
    ) -> Result<(connections::vault::Key, i64)> {
        let mut db = self
            .interactive
            .get()
            .await
            .context("Directory credentials unavailable")?;
        let tx = db.transaction().await.map_err(database_error)?;
        management_lock(&tx).await?;
        let version = super::policies::approval(&tx, actor, session, None).await?;
        check(&tx).await?;
        let count: i64 = tx
            .query_one("SELECT count(*) FROM noisefence.identity_connections", &[])
            .await
            .map_err(database_error)?
            .get(0);
        let key = tokio::task::spawn_blocking(move || {
            connections::vault::Key::load_or_initialize(&root, count != 0)
        })
        .await??;
        tx.commit().await.map_err(database_error)?;
        Ok((key, version))
    }

    pub fn directory_connection_authority(&self) -> String {
        self.binding()
            .map(|b| format!("postgres:{}:{}", b.instance, b.source_digest))
            .unwrap_or_else(|| "postgres:unbound".into())
    }
    pub async fn identity_connection_save(
        &self,
        expected: Option<&str>,
        next: &Record,
        actor: &str,
        session: &str,
    ) -> Result<()> {
        let mut db = self
            .interactive
            .get()
            .await
            .context("Directory credentials unavailable")?;
        let tx = db.transaction().await.map_err(database_error)?;
        management_lock(&tx).await?;
        let version = super::policies::approval(&tx, actor, session, None).await?;
        check(&tx).await?;
        let authority = self.directory_connection_authority();
        let old = read(&tx, &next.metadata.source.id, &authority).await?;
        connections::replacement(
            old.as_ref(),
            expected,
            next,
            actor,
            version,
            &authority,
            crate::now(),
        )?;
        if old.is_none() {
            let count: i64 = tx
                .query_one("SELECT count(*) FROM noisefence.identity_connections", &[])
                .await
                .map_err(database_error)?
                .get(0);
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
        let value: serde_json::Value = serde_json::from_str(&next.encode()?)?;
        tx.execute("INSERT INTO noisefence.identity_connections(source_id,record) VALUES($1,$2) ON CONFLICT(source_id) DO UPDATE SET record=excluded.record",&[&next.metadata.source.id,&value]).await.map_err(database_error)?;
        tx.execute("INSERT INTO noisefence.audit(created,username,action,object_id) VALUES($1,$2,'identity_connection_saved',$3)",&[&crate::now(),&actor,&next.metadata.source.id]).await.map_err(database_error)?;
        tx.commit().await.map_err(database_error)?;
        Ok(())
    }
    pub async fn identity_connection_list(&self, actor: &str, session: &str) -> Result<Vec<View>> {
        let mut db = self
            .interactive
            .get()
            .await
            .context("Directory credentials unavailable")?;
        let tx = db.transaction().await.map_err(database_error)?;
        super::policies::approval(&tx, actor, session, None).await?;
        check(&tx).await?;
        let rows = tx.query("SELECT source_id,record::text FROM noisefence.identity_connections ORDER BY source_id LIMIT 17",&[]).await.map_err(database_error)?;
        ensure!(
            rows.len() <= MAX_CONNECTIONS,
            "Directory connection limit exceeded"
        );
        let mut result = Vec::new();
        let authority = self.directory_connection_authority();
        for row in rows {
            let record = Record::decode(
                &row.get::<_, String>(1),
                &row.get::<_, String>(0),
                &authority,
            )?;
            result.push(record.view(crate::now(), owner_current(&tx, &record).await?));
        }
        Ok(result)
    }
    pub async fn identity_connection_get(
        &self,
        source: &str,
        generation: &str,
        actor: &str,
        session: &str,
    ) -> Result<Record> {
        let mut db = self
            .interactive
            .get()
            .await
            .context("Directory credentials unavailable")?;
        let tx = db.transaction().await.map_err(database_error)?;
        super::policies::approval(&tx, actor, session, None).await?;
        check(&tx).await?;
        let record = read(&tx, source, &self.directory_connection_authority())
            .await?
            .context("Directory connection not found")?;
        ensure!(
            record.metadata.generation == generation
                && owner_current(&tx, &record).await?
                && record.view(crate::now(), true).status == "configured",
            "Directory connection expired, revoked or authorization changed"
        );
        Ok(record)
    }
    pub async fn identity_connection_revoke(
        &self,
        source: &str,
        expected: &str,
        actor: &str,
        session: &str,
    ) -> Result<()> {
        let mut db = self
            .interactive
            .get()
            .await
            .context("Directory credentials unavailable")?;
        let tx = db.transaction().await.map_err(database_error)?;
        management_lock(&tx).await?;
        super::policies::approval(&tx, actor, session, None).await?;
        check(&tx).await?;
        let old = read(&tx, source, &self.directory_connection_authority())
            .await?
            .context("Directory connection not found")?;
        let changed = old.revoked_at.is_none();
        let record = connections::revoke(old, expected, crate::now())?;
        if changed {
            let value: serde_json::Value = serde_json::from_str(&record.encode()?)?;
            tx.execute(
                "UPDATE noisefence.identity_connections SET record=$1 WHERE source_id=$2",
                &[&value, &source],
            )
            .await
            .map_err(database_error)?;
            tx.execute("INSERT INTO noisefence.audit(created,username,action,object_id) VALUES($1,$2,'identity_connection_revoked',$3)",&[&crate::now(),&actor,&source]).await.map_err(database_error)?;
        }
        tx.commit().await.map_err(database_error)?;
        Ok(())
    }
}
