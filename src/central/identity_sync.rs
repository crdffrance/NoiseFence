use super::{Central, admin::management_lock, database_error};
use crate::identity::sync::{self, Event, Outcome, Request};
use anyhow::{Context, Result};
impl Central {
    pub async fn identity_sync_begin(
        &self,
        request: &Request,
        actor: &str,
        session: &str,
    ) -> Result<()> {
        let mut db = self
            .interactive
            .get()
            .await
            .context("Directory journal unavailable")?;
        let tx = db.transaction().await.map_err(database_error)?;
        management_lock(&tx).await?;
        super::policies::approval(&tx, actor, session, None).await?;
        let rows=tx.query("SELECT object_id FROM noisefence.audit WHERE action='identity_sync' AND created>=$1 ORDER BY id LIMIT 129", &[&(request.created-3960)]).await.map_err(database_error)?;
        let raw: Vec<String> = rows.iter().map(|r| r.get(0)).collect();
        sync::admit(&raw, request, crate::now())?;
        let data = Event {
            request: request.clone(),
            outcome: Outcome::Running,
        }
        .encode()?;
        tx.execute("INSERT INTO noisefence.audit(created,username,action,object_id) VALUES($1,$2,'identity_sync',$3)",&[&request.created,&actor,&data]).await.map_err(database_error)?;
        tx.commit().await.map_err(database_error)?;
        Ok(())
    }
    pub async fn identity_sync_finish(&self, result: &Event, actor: &str) -> Result<()> {
        let mut db = self
            .interactive
            .get()
            .await
            .context("Directory journal unavailable")?;
        let tx = db.transaction().await.map_err(database_error)?;
        management_lock(&tx).await?;
        let pattern = format!("{};%", result.request.id);
        let rows=tx.query("SELECT object_id FROM noisefence.audit WHERE action='identity_sync' AND object_id LIKE $1 ORDER BY id LIMIT 129",&[&pattern]).await.map_err(database_error)?;
        let raw: Vec<String> = rows.iter().map(|r| r.get(0)).collect();
        sync::finish(&raw, result, crate::now())?;
        tx.execute("INSERT INTO noisefence.audit(created,username,action,object_id) VALUES($1,$2,'identity_sync',$3)",&[&crate::now(),&actor,&result.encode()?]).await.map_err(database_error)?;
        tx.commit().await.map_err(database_error)?;
        Ok(())
    }
    pub async fn identity_sync_read(
        &self,
        id: &str,
        actor: &str,
        session: &str,
    ) -> Result<Vec<String>> {
        let mut db = self
            .interactive
            .get()
            .await
            .context("Directory journal unavailable")?;
        let tx = db.transaction().await.map_err(database_error)?;
        super::policies::approval(&tx, actor, session, None).await?;
        let pattern = format!("{id};%");
        let rows=tx.query("SELECT object_id FROM noisefence.audit WHERE action='identity_sync' AND object_id LIKE $1 ORDER BY id LIMIT 129",&[&pattern]).await.map_err(database_error)?;
        Ok(rows.iter().map(|r| r.get(0)).collect())
    }
}
