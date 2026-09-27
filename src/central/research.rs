//! Durable management of research jobs. Job execution is outside SMTP.
use super::{Central, admin::management_lock, database_error};
use crate::{
    now,
    quality::workflow::{Request, validate_request},
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
async fn administrator(tx: &deadpool_postgres::Transaction<'_>, user: &str) -> Result<()> {
    ensure!(tx.query_opt("SELECT username FROM noisefence.users WHERE username=$1 AND admin AND NOT disabled FOR SHARE",&[&user]).await.map_err(database_error)?.is_some(),"Administrator access required");
    Ok(())
}
impl Central {
    pub async fn quality_enqueue(&self, user: &str, request: &Request) -> Result<String> {
        validate_request(request)?;
        let mut db = self
            .interactive
            .get()
            .await
            .context("Central research capacity unavailable")?;
        let tx = db.transaction().await.map_err(database_error)?;
        management_lock(&tx).await?;
        administrator(&tx, user).await?;
        let purpose:String=tx.query_opt("SELECT purpose FROM noisefence.quality_batches WHERE id=$1 AND username=$2 AND created>=$3",&[&request.batch,&user,&(now()-30*86400)]).await.map_err(database_error)?.context("Sample not found")?.get(0);
        ensure!(
            request.operation != "train" || purpose == "development",
            "Only development samples may be fitted"
        );
        if let Some(candidate) = &request.candidate {
            let ready:bool=tx.query_one("SELECT EXISTS(SELECT 1 FROM noisefence.quality_jobs WHERE id=$1 AND username=$2 AND operation='train' AND status='complete' AND model_sha256 IS NOT NULL AND created>=$3)",&[&candidate,&user,&(now()-30*86400)]).await.map_err(database_error)?.get(0);
            ensure!(ready, "Candidate not available");
        }
        let counts=tx.query_one("SELECT count(*) FILTER(WHERE status IN ('queued','running')),count(*) FROM noisefence.quality_jobs",&[]).await.map_err(database_error)?;
        ensure!(
            counts.get::<_, i64>(0) < 4 && counts.get::<_, i64>(1) < 100,
            "Research queue is full"
        );
        let duplicate:bool=tx.query_one("SELECT EXISTS(SELECT 1 FROM noisefence.quality_jobs WHERE batch_id=$1 AND operation=$2 AND status IN ('queued','running'))",&[&request.batch,&request.operation]).await.map_err(database_error)?.get(0);
        ensure!(!duplicate, "This sample already has a pending job");
        let id = uuid::Uuid::new_v4().to_string();
        tx.execute("INSERT INTO noisefence.quality_jobs(id,username,batch_id,operation,candidate_id,status,created) VALUES($1,$2,$3,$4,$5,'queued',$6)",&[&id,&user,&request.batch,&request.operation,&request.candidate,&now()]).await.map_err(database_error)?;
        tx.execute("INSERT INTO noisefence.audit(created,username,action,object_id) VALUES($1,$2,'quality_job',$3)",&[&now(),&user,&id]).await.map_err(database_error)?;
        tx.commit().await.map_err(database_error)?;
        Ok(id)
    }
    pub async fn quality_jobs(&self, user: &str) -> Result<Value> {
        let mut db = self
            .interactive
            .get()
            .await
            .context("Central research capacity unavailable")?;
        let tx = db
            .build_transaction()
            .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
            .start()
            .await
            .map_err(database_error)?;
        administrator(&tx, user).await?;
        let worker = tx
            .query_opt(
                "SELECT heartbeat,build FROM noisefence.quality_worker_status WHERE id=1",
                &[],
            )
            .await
            .map_err(database_error)?
            .map(|r| json!({"heartbeat":r.get::<_,i64>(0),"build":r.get::<_,String>(1)}));
        let jobs=tx.query("SELECT id,batch_id,operation,candidate_id,status,created,started,finished,report,model_sha256 FROM noisefence.quality_jobs WHERE username=$1 AND created>=$2 ORDER BY created DESC,id DESC LIMIT 100",&[&user,&(now()-30*86400)]).await.map_err(database_error)?;
        let jobs:Vec<_>=jobs.iter().map(|r|json!({"id":r.get::<_,String>(0),"batch":r.get::<_,String>(1),"operation":r.get::<_,String>(2),"candidate":r.get::<_,Option<String>>(3),"status":r.get::<_,String>(4),"created":r.get::<_,i64>(5),"started":r.get::<_,Option<i64>>(6),"finished":r.get::<_,Option<i64>>(7),"report":r.get::<_,Option<Value>>(8),"model_sha256":r.get::<_,Option<String>>(9)})).collect();
        Ok(json!({"jobs":jobs,"worker":worker,"observation_only":true}))
    }
    pub async fn quality_cancel(&self, user: &str, id: &str) -> Result<()> {
        let mut db = self
            .interactive
            .get()
            .await
            .context("Central research capacity unavailable")?;
        let tx = db.transaction().await.map_err(database_error)?;
        management_lock(&tx).await?;
        administrator(&tx, user).await?;
        ensure!(tx.execute("UPDATE noisefence.quality_jobs SET status='cancelled',finished=$3 WHERE id=$1 AND username=$2 AND status='queued'",&[&id,&user,&now()]).await.map_err(database_error)?==1,"Only queued jobs can be cancelled");
        tx.execute("INSERT INTO noisefence.audit(created,username,action,object_id) VALUES($1,$2,'quality_cancel',$3)",&[&now(),&user,&id]).await.map_err(database_error)?;
        tx.commit().await.map_err(database_error)?;
        Ok(())
    }
    pub async fn quality_candidate(&self, user: &str, id: &str) -> Result<Option<String>> {
        let mut db = self
            .interactive
            .get()
            .await
            .context("Central research capacity unavailable")?;
        let tx = db.transaction().await.map_err(database_error)?;
        administrator(&tx, user).await?;
        Ok(tx.query_opt("SELECT model_sha256 FROM noisefence.quality_jobs WHERE id=$1 AND username=$2 AND status='complete' AND operation='train' AND created>=$3",&[&id,&user,&(now()-30*86400)]).await.map_err(database_error)?.and_then(|r|r.get(0)))
    }
}
