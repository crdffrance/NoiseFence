//! Durable scheduled collection in the selected management authority.
use super::{
    Central, admin::management_lock, database_error, identity_connections as connections_db,
};
use crate::identity::{
    connections::{MAX_CONNECTIONS, Record, Reference, vault::Key},
    schedule::{self, Grant},
    sync::{self, Event, Outcome, Request},
};
use anyhow::{Context, Result, ensure};
use tokio_postgres::Transaction;
async fn write(tx: &Transaction<'_>, record: &Record) -> Result<()> {
    let value: serde_json::Value = serde_json::from_str(&record.encode()?)?;
    ensure!(
        tx.execute(
            "UPDATE noisefence.identity_connections SET record=$1 WHERE source_id=$2",
            &[&value, &record.metadata.source.id]
        )
        .await
        .map_err(database_error)?
            == 1,
        "Directory connection disappeared"
    );
    Ok(())
}
async fn audit(tx: &Transaction<'_>, actor: &str, action: &str, id: &str) -> Result<()> {
    tx.execute(
        "INSERT INTO noisefence.audit(created,username,action,object_id) VALUES($1,$2,$3,$4)",
        &[&crate::now(), &actor, &action, &id],
    )
    .await
    .map_err(database_error)?;
    Ok(())
}
pub(super) async fn authorized(
    tx: &Transaction<'_>,
    request: &Request,
    authority: &str,
) -> Result<Record> {
    connections_db::check(tx).await?;
    let record = connections_db::read(tx, &request.source_id, authority)
        .await?
        .context("Directory connection missing")?;
    ensure!(
        connections_db::owner_current(tx, &record).await?,
        "Collection owner authorization changed"
    );
    schedule::authorize(&record, request, crate::now())?;
    Ok(record)
}
impl Central {
    #[allow(clippy::too_many_arguments)]
    pub async fn identity_schedule_save(
        &self,
        reference: &Reference,
        expected: Option<&str>,
        grant: Grant,
        key: &Key,
        actor: &str,
        session: &str,
    ) -> Result<()> {
        let mut db = self
            .interactive
            .get()
            .await
            .context("Directory schedule unavailable")?;
        let tx = db.transaction().await.map_err(database_error)?;
        management_lock(&tx).await?;
        let version = super::policies::approval(&tx, actor, session, None).await?;
        let mut record =
            connections_db::live(&tx, reference, &self.directory_connection_authority()).await?;
        let signature = key.sign_schedule(&record.metadata, &grant)?;
        schedule::enable(
            &mut record,
            expected,
            grant,
            signature,
            actor,
            version,
            crate::now(),
        )?;
        key.verify_schedule(&record)?;
        write(&tx, &record).await?;
        audit(
            &tx,
            actor,
            "identity_schedule_saved",
            &record.metadata.source.id,
        )
        .await?;
        tx.commit().await.map_err(database_error)?;
        Ok(())
    }
    pub async fn identity_schedule_stop(
        &self,
        reference: &Reference,
        expected: &str,
        actor: &str,
        session: &str,
    ) -> Result<()> {
        reference.validate()?;
        let mut db = self
            .interactive
            .get()
            .await
            .context("Directory schedule unavailable")?;
        let tx = db.transaction().await.map_err(database_error)?;
        management_lock(&tx).await?;
        super::policies::approval(&tx, actor, session, None).await?;
        connections_db::check(&tx).await?;
        let mut record = connections_db::read(
            &tx,
            &reference.source_id,
            &self.directory_connection_authority(),
        )
        .await?
        .context("Directory connection missing")?;
        ensure!(
            record.metadata.generation == reference.generation,
            "Directory connection changed"
        );
        let schedule = record.schedule.as_ref().context("No collection schedule")?;
        ensure!(schedule.grant.id == expected, "Collection schedule changed");
        let binding = schedule.binding(&record.metadata)?;
        let changed = schedule.revoked_at.is_none();
        schedule::disable(&mut record, &binding, crate::now())?;
        if changed {
            write(&tx, &record).await?;
            audit(&tx, actor, "identity_schedule_stopped", expected).await?;
        }
        tx.commit().await.map_err(database_error)?;
        Ok(())
    }
    pub async fn identity_schedule_due(&self, revision: i64) -> Result<Vec<Record>> {
        let mut db = self
            .interactive
            .get()
            .await
            .context("Directory schedule unavailable")?;
        let tx = db.transaction().await.map_err(database_error)?;
        connections_db::check(&tx).await?;
        let rows=tx.query("SELECT source_id,record::text FROM noisefence.identity_connections ORDER BY source_id LIMIT 17",&[]).await.map_err(database_error)?;
        ensure!(
            rows.len() <= MAX_CONNECTIONS,
            "Directory connection limit exceeded"
        );
        let now = crate::now();
        let mut records = Vec::new();
        for row in rows {
            let record = Record::decode(
                &row.get::<_, String>(1),
                &row.get::<_, String>(0),
                &self.directory_connection_authority(),
            )?;
            if record
                .view(now, connections_db::owner_current(&tx, &record).await?)
                .status
                == "configured"
                && record
                    .schedule
                    .as_ref()
                    .is_some_and(|s| s.due(now, revision))
            {
                records.push(record);
            }
        }
        records.sort_by_key(|r| r.schedule.as_ref().map(|s| s.next_due));
        Ok(records)
    }
    pub async fn identity_schedule_claim(&self, request: &Request, key: &Key) -> Result<Record> {
        let mut db = self
            .interactive
            .get()
            .await
            .context("Directory schedule unavailable")?;
        let tx = db.transaction().await.map_err(database_error)?;
        management_lock(&tx).await?;
        connections_db::check(&tx).await?;
        let mut record = connections_db::read(
            &tx,
            &request.source_id,
            &self.directory_connection_authority(),
        )
        .await?
        .context("Directory connection missing")?;
        ensure!(
            connections_db::owner_current(&tx, &record).await?,
            "Collection owner authorization changed"
        );
        key.verify_schedule(&record)?;
        let raw:Vec<String>=tx.query("SELECT object_id FROM noisefence.audit WHERE action='identity_sync' AND created>=$1 ORDER BY id LIMIT 129",&[&(request.created-3960)]).await.map_err(database_error)?.iter().map(|r|r.get(0)).collect();
        sync::admit(&raw, request, crate::now())?;
        schedule::claim(&mut record, request, crate::now())?;
        write(&tx, &record).await?;
        audit(
            &tx,
            &record.metadata.owner,
            sync::ACTION,
            &Event {
                request: request.clone(),
                outcome: Outcome::Running,
            }
            .encode()?,
        )
        .await?;
        tx.commit().await.map_err(database_error)?;
        Ok(record)
    }
    pub async fn identity_schedule_authorized(&self, request: &Request) -> Result<()> {
        let mut db = self
            .interactive
            .get()
            .await
            .context("Directory schedule unavailable")?;
        let tx = db.transaction().await.map_err(database_error)?;
        authorized(&tx, request, &self.directory_connection_authority()).await?;
        Ok(())
    }
    pub async fn identity_schedule_finish(&self, event: &Event, actor: &str) -> Result<()> {
        ensure!(
            event.request.scheduled.is_some(),
            "Scheduled receipt required"
        );
        let mut event = event.clone();
        let mut db = self
            .interactive
            .get()
            .await
            .context("Directory schedule unavailable")?;
        let tx = db.transaction().await.map_err(database_error)?;
        management_lock(&tx).await?;
        connections_db::check(&tx).await?;
        let mut record = connections_db::read(
            &tx,
            &event.request.source_id,
            &self.directory_connection_authority(),
        )
        .await?;
        if matches!(event.outcome, Outcome::Ready { .. })
            && authorized(&tx, &event.request, &self.directory_connection_authority())
                .await
                .is_err()
        {
            event.outcome = Outcome::Failed {
                reason: sync::Failure::Authorization,
            };
        }
        let raw:Vec<String>=tx.query("SELECT object_id FROM noisefence.audit WHERE action='identity_sync' AND object_id LIKE $1 ORDER BY id LIMIT 129",&[&format!("{};%",event.request.id)]).await.map_err(database_error)?.iter().map(|r|r.get(0)).collect();
        sync::finish(&raw, &event, crate::now())?;
        if let Some(record) = record.as_mut()
            && schedule::completed(record, &event, crate::now())?
        {
            write(&tx, record).await?;
        }
        audit(&tx, actor, sync::ACTION, &event.encode()?).await?;
        tx.commit().await.map_err(database_error)?;
        Ok(())
    }
}
