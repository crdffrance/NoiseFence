//! One dedicated database session owns the research runner. A lost connection
//! cannot publish a result; abandoned work is interrupted, never retrained.
use super::{Central, admin::management_lock, database_error};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Job {
    pub id: String,
    pub username: String,
    pub batch: String,
    pub operation: String,
    pub candidate: Option<String>,
    pub candidate_sha256: Option<String>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Outcome {
    pub status: String,
    pub report: Value,
    pub model_sha256: Option<String>,
}
impl Outcome {
    pub fn validate(&self, job: &Job) -> Result<()> {
        ensure!(
            matches!(
                self.status.as_str(),
                "complete" | "failed" | "insufficient_labels"
            ),
            "Invalid research outcome"
        );
        ensure!(
            self.report.is_object() && serde_json::to_vec(&self.report)?.len() <= 512 * 1024,
            "Invalid aggregate report"
        );
        ensure!(
            self.model_sha256
                .as_deref()
                .is_none_or(crate::compatibility::valid_hash),
            "Invalid model digest"
        );
        ensure!(
            self.model_sha256.is_some() == (self.status == "complete" && job.operation == "train"),
            "Inconsistent research model receipt"
        );
        Ok(())
    }
}
pub struct Worker {
    // Detached from the pool: Drop aborts the connection task, releasing its
    // session advisory lock. A locked connection is never recycled to callers.
    db: deadpool_postgres::ClientWrapper,
    build: String,
    current: Option<Job>,
}
impl Central {
    pub async fn research_worker(&self, build: &str) -> Result<Worker> {
        ensure!(
            !build.is_empty() && build.len() <= 200 && build.bytes().all(|b| b.is_ascii_graphic()),
            "Invalid research build"
        );
        let object = self
            .interactive
            .get()
            .await
            .context("Central research capacity unavailable")?;
        let mut db = deadpool_postgres::Object::take(object);
        let owned: bool = db
            .query_one("SELECT pg_try_advisory_lock(719021428125::bigint)", &[])
            .await
            .map_err(database_error)?
            .get(0);
        ensure!(owned, "Another research worker owns the database session");
        let tx = db.transaction().await.map_err(database_error)?;
        management_lock(&tx).await?;
        tx.execute("UPDATE noisefence.quality_jobs SET status='interrupted',finished=$1,model_sha256=NULL,report=$2 WHERE status='running'",&[&crate::now(),&json!({"status":"interrupted","may_activate":false,"observation_only":true})]).await.map_err(database_error)?;
        heartbeat(&tx, build).await?;
        tx.commit().await.map_err(database_error)?;
        Ok(Worker {
            db,
            build: build.into(),
            current: None,
        })
    }
}
async fn heartbeat(tx: &deadpool_postgres::Transaction<'_>, build: &str) -> Result<()> {
    tx.execute("INSERT INTO noisefence.quality_worker_status(id,heartbeat,build) VALUES(1,$1,$2) ON CONFLICT(id) DO UPDATE SET heartbeat=excluded.heartbeat,build=excluded.build",&[&crate::now(),&build]).await.map_err(database_error)?;
    Ok(())
}
impl Worker {
    pub async fn heartbeat(&mut self) -> Result<()> {
        let tx = self.db.transaction().await.map_err(database_error)?;
        heartbeat(&tx, &self.build).await?;
        tx.commit().await.map_err(database_error)?;
        Ok(())
    }
    pub async fn retained(&mut self) -> Result<Vec<String>> {
        let rows=self.db.query("SELECT id FROM noisefence.quality_jobs UNION SELECT settings#>>'{quality_candidate,job}' FROM noisefence.policy_revisions WHERE settings#>>'{quality_candidate,job}' IS NOT NULL LIMIT 10001",&[]).await.map_err(database_error)?;
        ensure!(rows.len() <= 10000, "Research retention exceeds capacity");
        let mut ids = BTreeSet::new();
        for r in rows {
            let id: String = r.get(0);
            ensure!(
                crate::quality::workflow::valid_id(&id),
                "Invalid retained candidate identifier"
            );
            ids.insert(id);
        }
        Ok(ids.into_iter().collect())
    }
    pub async fn claim(&mut self) -> Result<Option<Job>> {
        ensure!(
            self.current.is_none(),
            "Research session already owns a job"
        );
        let tx = self.db.transaction().await.map_err(database_error)?;
        management_lock(&tx).await?;
        heartbeat(&tx, &self.build).await?;
        // Revalidate the user, purpose and candidate at execution time, not just
        // when an administrator enqueued the request.
        tx.execute("UPDATE noisefence.quality_jobs j SET status='cancelled',finished=$1,model_sha256=NULL WHERE j.status='queued' AND (j.created<$2 OR NOT EXISTS(SELECT 1 FROM noisefence.users u WHERE u.username=j.username AND u.admin AND NOT u.disabled) OR NOT EXISTS(SELECT 1 FROM noisefence.quality_batches b WHERE b.id=j.batch_id AND b.username=j.username AND b.created>=$2 AND (j.operation!='train' OR b.purpose='development')) OR (j.operation='evaluate' AND NOT EXISTS(SELECT 1 FROM noisefence.quality_jobs c WHERE c.id=j.candidate_id AND c.username=j.username AND c.operation='train' AND c.status='complete' AND c.model_sha256 IS NOT NULL AND c.created>=$2)))",&[&crate::now(),&(crate::now()-30*86400)]).await.map_err(database_error)?;
        let row=tx.query_opt("SELECT j.id,j.username,j.batch_id,j.operation,j.candidate_id,c.model_sha256 FROM noisefence.quality_jobs j LEFT JOIN noisefence.quality_jobs c ON c.id=j.candidate_id WHERE j.status='queued' ORDER BY j.created,j.id LIMIT 1 FOR UPDATE OF j",&[]).await.map_err(database_error)?;
        let job = row.map(|r| Job {
            id: r.get(0),
            username: r.get(1),
            batch: r.get(2),
            operation: r.get(3),
            candidate: r.get(4),
            candidate_sha256: r.get(5),
        });
        if let Some(job) = &job {
            ensure!(
                crate::quality::workflow::valid_id(&job.id)
                    && crate::quality::workflow::valid_id(&job.batch),
                "Invalid research identifiers"
            );
            ensure!(
                job.operation != "evaluate"
                    || (job
                        .candidate
                        .as_deref()
                        .is_some_and(crate::quality::workflow::valid_id)
                        && job
                            .candidate_sha256
                            .as_deref()
                            .is_some_and(crate::compatibility::valid_hash)),
                "Invalid prepared candidate"
            );
            tx.execute("UPDATE noisefence.quality_jobs SET status='running',started=$2,finished=NULL WHERE id=$1 AND status='queued'",&[&job.id,&crate::now()]).await.map_err(database_error)?;
            tx.execute("INSERT INTO noisefence.audit(created,username,action,object_id) VALUES($1,$2,'quality_claim',$3)",&[&crate::now(),&job.username,&job.id]).await.map_err(database_error)?;
        }
        tx.commit().await.map_err(database_error)?;
        self.current = job.clone();
        Ok(job)
    }
    pub async fn finish(&mut self, job_id: &str, mut outcome: Outcome) -> Result<String> {
        let job = self
            .current
            .as_ref()
            .context("No research job owned by this session")?;
        ensure!(
            job.id == job_id,
            "Research job is not owned by this session"
        );
        outcome.validate(job)?;
        let tx = self.db.transaction().await.map_err(database_error)?;
        management_lock(&tx).await?;
        let active=tx.query_opt("SELECT username FROM noisefence.users WHERE username=$1 AND admin AND NOT disabled FOR SHARE",&[&job.username]).await.map_err(database_error)?.is_some();
        if !active {
            outcome.status = "cancelled".into();
            outcome.model_sha256 = None;
            outcome.report = json!({"status":"cancelled","reason":"administrator_revoked"});
        }
        outcome.report["may_activate"] = json!(false);
        outcome.report["observation_only"] = json!(true);
        ensure!(tx.execute("UPDATE noisefence.quality_jobs SET status=$2,finished=$3,report=$4,model_sha256=$5 WHERE id=$1 AND username=$6 AND status='running'",&[&job.id,&outcome.status,&crate::now(),&outcome.report,&outcome.model_sha256,&job.username]).await.map_err(database_error)?==1,"Research ownership no longer current");
        tx.execute("INSERT INTO noisefence.audit(created,username,action,object_id) VALUES($1,$2,'quality_result',$3)",&[&crate::now(),&job.username,&job.id]).await.map_err(database_error)?;
        heartbeat(&tx, &self.build).await?;
        tx.commit().await.map_err(database_error)?;
        self.current = None;
        Ok(outcome.status)
    }
}

#[derive(Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Retained {},
    Claim {},
    Heartbeat {},
    Finish { job: String, outcome: Outcome },
}
/// Private stdio protocol for the installed Python runner. No credentials or
/// arbitrary SQL cross this boundary. EOF closes the owning database session.
pub async fn serve<R: tokio::io::AsyncBufRead + Unpin, W: tokio::io::AsyncWrite + Unpin>(
    central: &Central,
    build: &str,
    mut input: R,
    mut output: W,
) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    let mut worker = central.research_worker(build).await?;
    output
        .write_all(b"{\"schema\":\"noisefence-research-worker-1\",\"ready\":true}\n")
        .await?;
    output.flush().await?;
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(15));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut packet = Vec::new();
    let mut commands = 0;
    loop {
        tokio::select! {
            _=interval.tick()=>worker.heartbeat().await?,
            buffer=input.fill_buf()=> {
                let buffer=buffer?;
                if buffer.is_empty() {ensure!(packet.is_empty(),"Truncated research request");return Ok(());}
                let newline=buffer.iter().position(|b|*b==b'\n');
                let consumed=newline.map_or(buffer.len(),|i|i+1);
                ensure!(packet.len()+consumed<=600*1024,"Research request exceeds capacity");
                packet.extend_from_slice(&buffer[..consumed]);input.consume(consumed);
                if newline.is_none(){continue;}
                commands+=1;ensure!(commands<=64,"Research session request limit exceeded");
                let request:Request=serde_json::from_slice(&packet).context("Invalid research request")?;packet.clear();
                let result=match request {
                    Request::Retained {}=>json!(worker.retained().await?),
                    Request::Claim {}=>json!(worker.claim().await?),
                    Request::Heartbeat {}=>{worker.heartbeat().await?;Value::Null},
                    Request::Finish{job,outcome}=>json!({"status":worker.finish(&job,outcome).await?}),
                };
                let mut bytes=serde_json::to_vec(&json!({"ok":true,"result":result}))?;
                ensure!(bytes.len()<=1024*1024,"Research reply exceeds capacity");bytes.push(b'\n');
                output.write_all(&bytes).await?;output.flush().await?;
            }
        }
    }
}
