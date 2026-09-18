//! Durable, administrator-owned research jobs. SMTP never runs a trainer.
use crate::{now, store::Store};
use anyhow::{Result, ensure};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub job: Option<String>,
    pub sha256: Option<String>,
}
impl Selection {
    pub fn path(&self, root: &Path) -> Result<Option<PathBuf>> {
        match (&self.job, &self.sha256) {
            (None, None) => Ok(None),
            (Some(id), Some(hash)) => {
                ensure!(
                    valid_id(id) && super::hash(hash),
                    "Invalid candidate reference"
                );
                Ok(Some(
                    root.join("calibration")
                        .join(id)
                        .join("candidate/model.json"),
                ))
            }
            _ => anyhow::bail!("Candidate reference requires an identifier and digest"),
        }
    }
}
pub fn valid_id(id: &str) -> bool {
    uuid::Uuid::parse_str(id).is_ok_and(|u| u.to_string() == id)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub batch: String,
    pub operation: String,
    pub candidate: Option<String>,
}
pub async fn enqueue(store: &Store, user: String, request: Request) -> Result<String> {
    ensure!(
        valid_id(&request.batch)
            && matches!(request.operation.as_str(), "train" | "compare" | "evaluate"),
        "Invalid research request"
    );
    ensure!(
        if request.operation == "evaluate" {
            request.candidate.as_deref().is_some_and(valid_id)
        } else {
            request.candidate.is_none()
        },
        "Evaluation requires a prepared candidate"
    );
    store.run(move|db| {
        let tx=db.transaction()?;
        let admin:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM users WHERE username=?1 AND admin=1 AND disabled=0)",[&user],|r|r.get(0))?;
        ensure!(admin,"Administrator access required");
        let purpose:Option<String>=tx.query_row("SELECT COALESCE(p.purpose,'regression') FROM quality_batches b LEFT JOIN quality_purposes p ON p.batch_id=b.id WHERE b.id=?1 AND b.username=?2 AND b.created>=?3",params![request.batch,user,now()-30*86400],|r|r.get(0)).optional()?;
        let purpose=purpose.ok_or_else(||anyhow::anyhow!("Sample not found"))?;
        ensure!(request.operation!="train" || purpose=="development","Only development samples may be fitted");
        if let Some(candidate)=&request.candidate {
            let ready:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM quality_jobs WHERE id=?1 AND username=?2 AND operation='train' AND status='complete' AND model_sha256 IS NOT NULL AND created>=?3)",params![candidate,user,now()-30*86400],|r|r.get(0))?;
            ensure!(ready,"Candidate not available");
        }
        let outstanding:usize=tx.query_row("SELECT COUNT(*) FROM quality_jobs WHERE status IN ('queued','running')",[],|r|r.get(0))?;
        let retained:usize=tx.query_row("SELECT COUNT(*) FROM quality_jobs",[],|r|r.get(0))?;
        ensure!(outstanding<4 && retained<100,"Research queue is full");
        let duplicate:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM quality_jobs WHERE batch_id=?1 AND operation=?2 AND status IN ('queued','running'))",params![request.batch,request.operation],|r|r.get(0))?;
        ensure!(!duplicate,"This sample already has a pending job");
        let id=uuid::Uuid::new_v4().to_string();
        tx.execute("INSERT INTO quality_jobs(id,username,batch_id,operation,candidate_id,status,created) VALUES(?1,?2,?3,?4,?5,'queued',?6)",params![id,user,request.batch,request.operation,request.candidate,now()])?;
        tx.execute("INSERT INTO audit(created,username,action,object_id) VALUES(?1,?2,'quality_job',?3)",params![now(),user,id])?;
        tx.commit()?;Ok(id)
    }).await
}
pub async fn list(store: &Store, user: String) -> Result<Value> {
    store.read(move|db|{
        let worker:Option<Value>=db.query_row("SELECT heartbeat,build FROM quality_worker_status WHERE id=1",[],|r|Ok(json!({"heartbeat":r.get::<_,i64>(0)?,"build":r.get::<_,String>(1)?}))).optional()?;
        let mut q=db.prepare("SELECT id,batch_id,operation,candidate_id,status,created,started,finished,report,model_sha256 FROM quality_jobs WHERE username=?1 AND created>=?2 ORDER BY created DESC,id DESC LIMIT 100")?;
        let jobs=q.query_map(params![user,now()-30*86400],|r|{
            let report:Option<String>=r.get(8)?;
            Ok(json!({"id":r.get::<_,String>(0)?,"batch":r.get::<_,String>(1)?,"operation":r.get::<_,String>(2)?,"candidate":r.get::<_,Option<String>>(3)?,"status":r.get::<_,String>(4)?,"created":r.get::<_,i64>(5)?,"started":r.get::<_,Option<i64>>(6)?,"finished":r.get::<_,Option<i64>>(7)?,"report":report.and_then(|s|serde_json::from_str::<Value>(&s).ok()),"model_sha256":r.get::<_,Option<String>>(9)?}))
        })?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(json!({"jobs":jobs,"worker":worker,"observation_only":true}))
    }).await
}
pub async fn cancel(store: &Store, user: String, id: String) -> Result<()> {
    store.run(move|db|{
        ensure!(db.execute("UPDATE quality_jobs SET status='cancelled',finished=?3 WHERE id=?1 AND username=?2 AND status='queued'",params![id,user,now()])?==1,"Only queued jobs can be cancelled");
        db.execute("INSERT INTO audit(created,username,action,object_id) VALUES(?1,?2,'quality_cancel',?3)",params![now(),user,id])?;Ok(())
    }).await
}
pub async fn candidate(store: &Store, root: &Path, user: String, id: String) -> Result<Selection> {
    ensure!(valid_id(&id), "Invalid candidate identifier");
    let key = id.clone();
    let sha=store.read(move|db|{
        Ok(db.query_row("SELECT model_sha256 FROM quality_jobs WHERE id=?1 AND username=?2 AND status='complete' AND operation='train' AND created>=?3",params![key,user,now()-30*86400],|r|r.get::<_,Option<String>>(0)).optional()?.flatten())
    }).await?.ok_or_else(||anyhow::anyhow!("Prepared candidate not found"))?;
    let selection = Selection {
        job: Some(id),
        sha256: Some(sha.clone()),
    };
    let path = selection.path(root)?.unwrap();
    let model = super::Model::load(&path)?;
    ensure!(
        model.schema == "noisefence-quality-model-2"
            && model.trained_at <= now()
            && now() - model.trained_at <= 30 * 86400,
        "Candidate expired or unversioned"
    );
    ensure!(
        crate::message::digest(&std::fs::read(path)?) == sha,
        "Candidate was modified"
    );
    Ok(selection)
}

pub async fn cohorts(store: &Store, user: String) -> Result<Value> {
    store.read(move|db|{
        let mut q=db.prepare("SELECT json_extract(m.scan,'$.quality.artifacts_sha256'),COUNT(*),MIN(m.created),MAX(m.created) FROM messages m WHERE m.is_dsn=0 AND m.created>=?2 AND json_extract(m.scan,'$.quality.protocol_sha256')=?3 AND EXISTS(SELECT 1 FROM deliveries d JOIN console_access a ON a.delivery_id=d.id WHERE d.message_id=m.id AND a.username=?1) GROUP BY 1 ORDER BY MAX(m.created) DESC LIMIT 100")?;
        let rows=q.query_map(params![user,now()-30*86400,super::protocol_hash()],|r|Ok(json!({"id":r.get::<_,String>(0)?,"messages":r.get::<_,usize>(1)?,"since":r.get::<_,i64>(2)?,"until":r.get::<_,i64>(3)?})))?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(json!(rows))
    }).await
}
