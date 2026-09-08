use crate::{config::Recipient, engine::Scan, now};
use anyhow::{Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::{
        fs::{OpenOptionsExt, PermissionsExt},
        io::AsRawFd,
    },
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

#[derive(Clone)]
pub struct Store {
    pub root: PathBuf,
    db: Arc<Mutex<Connection>>,
    delivery_ready: Arc<tokio::sync::Notify>,
}
#[derive(Clone, Debug)]
pub struct Job {
    pub delivery_id: i64,
    pub message_id: String,
    pub created: i64,
    pub sender: String,
    pub destination: String,
    pub hosts: Vec<String>,
    pub attempts: u32,
    pub is_dsn: bool,
}
#[derive(Serialize)]
pub struct VisibleRecipient {
    pub address: String,
    pub status: String,
}
#[derive(Serialize)]
pub struct VisibleMail {
    pub id: String,
    pub created: i64,
    pub sender: String,
    pub subject: String,
    pub score: f64,
    pub tagged: bool,
    pub complete: bool,
    pub model: String,
    pub reasons: Vec<crate::engine::Signal>,
    pub recipients: Vec<VisibleRecipient>,
    pub feedback: Option<bool>,
    pub antivirus: crate::antivirus::AntivirusResult,
    pub signatures: crate::antivirus::AntivirusResult,
    pub llm: crate::llm::LlmResult,
    pub semantic: VisibleSemantic,
    pub smtp_policy: crate::smtp_policy::PolicyResult,
    pub vision: crate::vision::Summary,
    pub evidence: Option<crate::evidence::Evidence>,
    pub decision: crate::fusion::runtime::Decision,
    pub fusion: crate::fusion::runtime::Observation,
}
#[derive(Serialize)]
pub struct VisibleSemantic {
    pub status: crate::engine::SemanticStatus,
    pub model: String,
    pub encoder: String,
    pub elapsed_ms: u64,
}
impl From<crate::engine::SemanticResult> for VisibleSemantic {
    fn from(result: crate::engine::SemanticResult) -> Self {
        Self {
            status: result.status,
            model: result.model,
            encoder: result.encoder,
            elapsed_ms: result.elapsed_ms,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct User {
    pub username: String,
    pub admin: bool,
    pub csrf: String,
    pub addresses: Vec<String>,
}
impl Store {
    pub fn open(root: &Path) -> Result<Self> {
        fs::create_dir_all(root)?;
        fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
        fs::create_dir_all(root.join("spool"))?;
        fs::create_dir_all(root.join("incoming"))?;
        let mut db = Connection::open(root.join("state.sqlite3"))?;
        db.busy_timeout(std::time::Duration::from_secs(10))?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA secure_delete=ON;")?;
        let version: i64 = db.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        ensure!(version <= 1, "database is newer than this binary");
        if version == 0 {
            let tx = db.transaction()?;
            tx.execute_batch("CREATE TABLE messages(id TEXT PRIMARY KEY,created INTEGER NOT NULL,sender TEXT NOT NULL,scan TEXT NOT NULL,is_dsn INTEGER NOT NULL DEFAULT 0,raw_present INTEGER NOT NULL DEFAULT 1);
              CREATE TABLE deliveries(id INTEGER PRIMARY KEY,message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,address TEXT NOT NULL,destination TEXT NOT NULL,hosts TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pending',attempts INTEGER NOT NULL DEFAULT 0,next_attempt INTEGER NOT NULL,error TEXT,dsn_id TEXT,UNIQUE(message_id,address));
              CREATE INDEX delivery_due ON deliveries(status,next_attempt);
              CREATE INDEX delivery_destination ON deliveries(destination,message_id);
              CREATE TABLE users(username TEXT PRIMARY KEY,password TEXT NOT NULL,admin INTEGER NOT NULL DEFAULT 0,disabled INTEGER NOT NULL DEFAULT 0);
              CREATE TABLE grants(username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,address TEXT NOT NULL,PRIMARY KEY(username,address));
              CREATE TABLE sessions(token_hash TEXT PRIMARY KEY,username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,csrf TEXT NOT NULL,expires INTEGER NOT NULL);
              CREATE TABLE feedback(username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,spam INTEGER NOT NULL,created INTEGER NOT NULL,PRIMARY KEY(username,message_id));
              CREATE TABLE audit(id INTEGER PRIMARY KEY,created INTEGER NOT NULL,username TEXT NOT NULL,action TEXT NOT NULL,object_id TEXT NOT NULL);
              CREATE INDEX messages_created ON messages(created); PRAGMA user_version=1;")?;
            tx.commit()?;
        }
        Ok(Self {
            root: root.into(),
            db: Arc::new(Mutex::new(db)),
            delivery_ready: Arc::new(tokio::sync::Notify::new()),
        })
    }
    pub(crate) async fn wait_for_delivery(&self) {
        self.delivery_ready.notified().await;
    }
    pub fn daemon_lock(&self) -> Result<File> {
        let f = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(self.root.join("daemon.lock"))?;
        // SAFETY: flock receives the live descriptor owned by f. Keeping f alive holds the lock.
        ensure!(
            unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "another daemon already uses this spool"
        );
        Ok(f)
    }
    pub async fn run<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&mut Connection) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || {
            f(&mut *db
                .lock()
                .map_err(|_| anyhow::anyhow!("database lock poisoned"))?)
        })
        .await?
    }
    pub fn raw_path(&self, id: &str) -> PathBuf {
        self.root.join("spool").join(format!("{id}.eml"))
    }
    pub async fn recover(&self) -> Result<()> {
        self.run(|db| {
            db.execute(
                "UPDATE deliveries SET status='pending' WHERE status='sending'",
                [],
            )?;
            Ok(())
        })
        .await?;
        let ids = self
            .run(|db| {
                let mut q = db.prepare("SELECT id FROM messages WHERE raw_present=1")?;
                Ok(q.query_map([], |r| r.get::<_, String>(0))?
                    .collect::<rusqlite::Result<std::collections::HashSet<_>>>()?)
            })
            .await?;
        for id in &ids {
            ensure!(
                self.raw_path(id).is_file(),
                "durable queue corruption: missing message {id}; restore from backup before serving"
            );
        }
        for entry in fs::read_dir(self.root.join("incoming"))? {
            let p = entry?.path();
            if p.is_file() {
                fs::remove_file(p)?;
            }
        }
        for entry in fs::read_dir(self.root.join("spool"))? {
            let p = entry?.path();
            let id = p.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            if p.is_file() && !ids.contains(id) {
                fs::remove_file(p)?;
            }
        }
        Ok(())
    }
    pub async fn enqueue(
        &self,
        id: String,
        sender: String,
        recipients: Vec<Recipient>,
        scan: Scan,
        raw: Vec<u8>,
    ) -> Result<()> {
        let path = self.raw_path(&id);
        let directory = self.root.join("spool");
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)?;
            if let Err(e) = f
                .write_all(&raw)
                .and_then(|_| f.sync_all())
                .and_then(|_| File::open(directory)?.sync_all())
            {
                let _ = fs::remove_file(path);
                return Err(e.into());
            }
            Ok(())
        })
        .await??;
        let cleanup = self.raw_path(&id);
        let result=self.run(move|db| {
            let tx=db.transaction()?;
            tx.execute("INSERT INTO messages(id,created,sender,scan) VALUES(?1,?2,?3,?4)",params![id,now(),sender,serde_json::to_string(&scan)?])?;
            for r in recipients { tx.execute("INSERT INTO deliveries(message_id,address,destination,hosts,next_attempt) VALUES(?1,?2,?3,?4,?5)",params![id,r.address,r.destination,serde_json::to_string(&r.hosts)?,now()])?; }
            tx.commit()?;Ok(())
        }).await;
        if result.is_err() {
            let _ = fs::remove_file(cleanup);
        } else {
            // Notify only after both the spool and the SQLite transaction are durable.
            self.delivery_ready.notify_one();
        }
        result
    }
    pub async fn claim(&self) -> Result<Option<Job>> {
        self.run(|db| {
            let tx=db.transaction()?;
            let job=tx.query_row("SELECT d.id,m.id,m.created,m.sender,d.destination,d.hosts,d.attempts,m.is_dsn FROM deliveries d JOIN messages m ON m.id=d.message_id WHERE d.status='pending' AND d.next_attempt<=?1 ORDER BY d.next_attempt,d.id LIMIT 1",[now()],|r|Ok((r.get::<_,i64>(0)?,r.get::<_,String>(1)?,r.get::<_,i64>(2)?,r.get::<_,String>(3)?,r.get::<_,String>(4)?,r.get::<_,String>(5)?,r.get::<_,u32>(6)?,r.get::<_,bool>(7)?))).optional()?;
            let Some((delivery_id,message_id,created,sender,destination,hosts,attempts,is_dsn))=job else { return Ok(None); };
            let hosts=serde_json::from_str(&hosts)?;
            tx.execute("UPDATE deliveries SET status='sending',attempts=attempts+1 WHERE id=?1",[delivery_id])?;
            tx.commit()?;
            Ok(Some(Job{delivery_id,message_id,created,sender,destination,hosts,attempts:attempts+1,is_dsn}))
        }).await
    }
    pub async fn finish(&self, job: &Job, status: &str, error: &str, next: i64) -> Result<()> {
        let id = job.delivery_id;
        let status = status.to_string();
        let error = crate::message::safe_value(error);
        self.run(move |db| {
            db.execute(
                "UPDATE deliveries SET status=?2,error=?3,next_attempt=?4 WHERE id=?1",
                params![id, status, error, next],
            )?;
            Ok(())
        })
        .await
    }
    pub async fn failed(&self) -> Result<Vec<Job>> {
        self.run(|db| {
            let mut q=db.prepare("SELECT d.id,m.id,m.created,m.sender,d.destination,d.hosts,d.attempts,m.is_dsn FROM deliveries d JOIN messages m ON m.id=d.message_id WHERE d.status='failed' AND d.dsn_id IS NULL LIMIT 100")?;
            let rows=q.query_map([],|r|Ok((r.get::<_,i64>(0)?,r.get::<_,String>(1)?,r.get::<_,i64>(2)?,r.get::<_,String>(3)?,r.get::<_,String>(4)?,r.get::<_,String>(5)?,r.get::<_,u32>(6)?,r.get::<_,bool>(7)?)))?;
            let mut jobs=Vec::new();for r in rows {let (delivery_id,message_id,created,sender,destination,hosts,attempts,is_dsn)=r?;jobs.push(Job{delivery_id,message_id,created,sender,destination,hosts:serde_json::from_str(&hosts)?,attempts,is_dsn});}Ok(jobs)
        }).await
    }
    /// Link a durable DSN to its failure in the same SQLite transaction. The DSN's UUID
    /// is deterministic per failed delivery, so a crash before commit is retryable.
    pub async fn enqueue_dsn(&self, job: Job, raw: Vec<u8>, hosts: Vec<String>) -> Result<()> {
        let id = format!("dsn-{}", job.delivery_id);
        let path = self.raw_path(&id);
        let dir = self.root.join("spool");
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut f = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .mode(0o600)
                .open(path)?;
            f.write_all(&raw)?;
            f.sync_all()?;
            File::open(dir)?.sync_all()?;
            Ok(())
        })
        .await??;
        self.run(move|db| {
            let tx=db.transaction()?;
            let scan=Scan{complete:true,subject:"Delivery failure".into(),model:"dsn".into(),..Scan::default()};
            tx.execute("INSERT OR IGNORE INTO messages(id,created,sender,scan,is_dsn) VALUES(?1,?2,'',?3,1)",params![id,now(),serde_json::to_string(&scan)?])?;
            tx.execute("INSERT OR IGNORE INTO deliveries(message_id,address,destination,hosts,next_attempt) VALUES(?1,?2,?2,?3,?4)",params![id,job.sender,serde_json::to_string(&hosts)?,now()])?;
            tx.execute("UPDATE deliveries SET status='notified',dsn_id=?2 WHERE id=?1",params![job.delivery_id,id])?;
            tx.commit()?;Ok(())
        }).await
    }
    pub async fn cleanup(&self) -> Result<()> {
        let ids=self.run(|db| { let mut q=db.prepare("SELECT id FROM messages m WHERE raw_present=1 AND NOT EXISTS(SELECT 1 FROM deliveries d WHERE d.message_id=m.id AND d.status IN ('pending','sending','failed'))")?;Ok(q.query_map([],|r|r.get::<_,String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?) }).await?;
        for id in ids {
            // Commit tombstone first; a crash leaves an orphan file, removed by recovery.
            let key = id.clone();
            self.run(move |db| {
                db.execute("UPDATE messages SET raw_present=0 WHERE id=?1", [key])?;
                Ok(())
            })
            .await?;
            match fs::remove_file(self.raw_path(&id)) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        self.run(|db| {
            db.execute("DELETE FROM sessions WHERE expires<?1", [now()])?;
            db.execute(
                "DELETE FROM messages WHERE created<?1 AND raw_present=0",
                [now() - 30 * 86400],
            )?;
            db.execute("DELETE FROM audit WHERE created<?1", [now() - 30 * 86400])?;
            db.execute_batch("PRAGMA wal_checkpoint(PASSIVE)")?;
            Ok(())
        })
        .await
    }
    pub async fn list(
        &self,
        username: String,
        query: String,
        filter: String,
        offset: u32,
        threshold: f64,
    ) -> Result<Vec<VisibleMail>> {
        self.run(move|db| {
            let mut q=db.prepare("SELECT m.id,m.created,m.sender,m.scan,(SELECT spam FROM feedback f WHERE f.message_id=m.id AND f.username=?1) FROM messages m WHERE m.created>=?5 AND EXISTS(SELECT 1 FROM deliveries d JOIN grants g ON g.address=d.destination WHERE d.message_id=m.id AND g.username=?1) AND (?2='' OR instr(lower(m.sender),lower(?2))>0 OR instr(lower(json_extract(m.scan,'$.subject')),lower(?2))>0) AND (?3='all' OR (?3='spam' AND COALESCE(json_extract(m.scan,'$.decision.outcome')='unwanted',json_extract(m.scan,'$.complete')=1 AND json_extract(m.scan,'$.score')>=?6)) OR (?3='incomplete' AND json_extract(m.scan,'$.complete')=0)) ORDER BY m.created DESC,m.id DESC LIMIT 50 OFFSET ?4")?;
            let rows=q.query_map(params![username,query,filter,offset,now()-30*86400,threshold],|r|Ok((r.get::<_,String>(0)?,r.get::<_,i64>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,Option<bool>>(4)?)))?;
            let mut out=Vec::new();
            for row in rows {
                let (id,created,sender,scan,feedback)=row?;let s:Scan=serde_json::from_str(&scan)?;
                let decision=s.decision.clone().unwrap_or_else(|| crate::fusion::runtime::Decision::legacy(&s,threshold));
                let mut recipients=db.prepare("SELECT DISTINCT d.address,d.status FROM deliveries d JOIN grants g ON g.address=d.destination WHERE d.message_id=?1 AND g.username=?2")?;
                let recipients=recipients.query_map(params![id,username],|r|Ok(VisibleRecipient{address:r.get(0)?,status:r.get(1)?}))?.collect::<rusqlite::Result<Vec<_>>>()?;
                out.push(VisibleMail{id,created,sender,subject:s.subject,score:s.score,tagged:s.tagged,complete:s.complete,model:s.model,reasons:s.reasons,recipients,feedback,antivirus:s.antivirus,signatures:s.signatures,llm:s.llm,semantic:s.semantic.into(),smtp_policy:s.smtp_policy,vision:s.vision,evidence:s.evidence,decision,fusion:s.fusion});
            }Ok(out)
        }).await
    }
    pub async fn feedback(&self, user: String, id: String, spam: bool) -> Result<()> {
        self.run(move|db| {
            let tx=db.transaction()?;
            let allowed:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM deliveries d JOIN grants g ON g.address=d.destination JOIN messages m ON m.id=d.message_id WHERE d.message_id=?1 AND g.username=?2 AND m.created>=?3)",params![id,user,now()-30*86400],|r|r.get(0))?;
            ensure!(allowed,"message not found");
            tx.execute("INSERT INTO feedback(username,message_id,spam,created) VALUES(?1,?2,?3,?4) ON CONFLICT(username,message_id) DO UPDATE SET spam=excluded.spam,created=excluded.created",params![user,id,spam,now()])?;
            tx.execute("INSERT INTO audit(created,username,action,object_id) VALUES(?1,?2,'feedback',?3)",params![now(),user,id])?;
            tx.commit()?;Ok(())
        }).await
    }
}
pub fn available_bytes(path: &Path) -> Result<u64> {
    let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
    let mut info = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: NUL-terminated path and valid writable statvfs storage; only read on success.
    ensure!(
        unsafe { libc::statvfs(path.as_ptr(), info.as_mut_ptr()) } == 0,
        "cannot read free disk space"
    );
    let info = unsafe { info.assume_init() };
    // statvfs integer widths differ between macOS and Linux.
    Ok((u128::from(info.f_bavail) * u128::from(info.f_frsize)).min(u128::from(u64::MAX)) as u64)
}
