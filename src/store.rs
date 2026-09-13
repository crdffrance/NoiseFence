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

pub struct QueueVariant {
    pub id: String,
    pub scan: Scan,
    pub raw: Vec<u8>,
    pub recipients: Vec<(Recipient, Option<crate::custom_filtering::Assessment>)>,
}

#[derive(Clone)]
pub struct Store {
    pub root: PathBuf,
    db: Arc<Mutex<Connection>>,
    delivery_ready: Arc<tokio::sync::Notify>,
    console_reads: Arc<tokio::sync::Semaphore>,
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
    pub pending_command: Option<String>,
    pub filtering: Option<serde_json::Value>,
    pub held_until: Option<i64>,
    pub released_at: Option<i64>,
    pub action: Option<String>,
    pub address: String,
    pub status: String,
}
#[derive(Serialize)]
pub struct VisibleMail {
    pub node_id: Option<String>,
    pub node_updated_at: Option<i64>,
    pub delivery_classification: Option<crate::mailing::Category>,
    pub action: Option<crate::actions::Applied>,
    pub id: String,
    pub created: i64,
    pub sender: String,
    pub subject: String,
    pub score: f64,
    pub tagged: bool,
    pub pub_tagged: bool,
    pub category: crate::mailing::Category,
    pub complete: bool,
    pub model: String,
    pub reasons: Vec<crate::engine::Signal>,
    pub recipients: Vec<VisibleRecipient>,
    pub feedback: Option<bool>,
    pub feedback_category: Option<crate::mailing::FeedbackCategory>,
    pub antivirus: crate::antivirus::AntivirusResult,
    pub signatures: crate::antivirus::AntivirusResult,
    pub llm: crate::llm::LlmResult,
    pub semantic: VisibleSemantic,
    pub smtp_policy: crate::smtp_policy::PolicyResult,
    pub early_rbl: Option<crate::rbl::Report>,
    pub adaptive: Option<crate::adaptive::Report>,
    pub vision: crate::vision::Summary,
    pub protection: Option<crate::protection::Report>,
    pub mailing: Option<crate::mailing::Report>,
    pub evidence: Option<crate::evidence::Evidence>,
    pub decision: crate::fusion::runtime::Decision,
    pub arbitration: Option<crate::decision::Arbitration>,
    pub fusion: crate::fusion::runtime::Observation,
    pub quality: Option<serde_json::Value>,
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
        ensure!(version <= 4, "database is newer than this binary");
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
        let migration = db.transaction()?;
        migration.execute_batch(include_str!("control-schema.sql"))?;
        migration.execute_batch(include_str!("cluster-schema.sql"))?;
        if version <= 2 {
            migration.execute_batch("PRAGMA user_version=2")?;
        }
        crate::search::migrate(&migration)?;
        migration.execute_batch(crate::mfa::SCHEMA)?;
        migration.commit()?;
        Ok(Self {
            root: root.into(),
            db: Arc::new(Mutex::new(db)),
            delivery_ready: Arc::new(tokio::sync::Notify::new()),
            console_reads: Arc::new(tokio::sync::Semaphore::new(4)),
        })
    }
    pub(crate) fn notify_delivery(&self) {
        self.delivery_ready.notify_one();
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
    /// Bounded read-only WAL snapshots keep console searches off the durable writer mutex.
    pub async fn read<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&mut Connection) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let permit = self
            .console_reads
            .clone()
            .try_acquire_owned()
            .map_err(|_| anyhow::anyhow!("console read capacity occupied"))?;
        let path = self.root.join("state.sqlite3");
        // The timeout owner survives HTTP cancellation until SQLite is interrupted.
        tokio::spawn(async move {
            let (send, receive) = tokio::sync::oneshot::channel();
            let mut task = tokio::task::spawn_blocking(move || {
                let _permit = permit;
                let mut db =
                    Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
                db.busy_timeout(std::time::Duration::from_millis(250))?;
                let _ = send.send(db.get_interrupt_handle());
                db.execute_batch("BEGIN")?;
                f(&mut db)
            });
            let interrupt = receive.await?;
            tokio::select! {
                result = &mut task => result?,
                _ = tokio::time::sleep(std::time::Duration::from_secs(3)) => {
                    interrupt.interrupt(); task.await?
                }
            }
        })
        .await?
    }
    pub fn raw_path(&self, id: &str) -> PathBuf {
        self.root.join("spool").join(format!("{id}.eml"))
    }
    pub async fn recover(&self) -> Result<()> {
        self.run(|db| {
            db.execute(
                "UPDATE deliveries SET status='pending' WHERE status='sending' AND NOT EXISTS(SELECT 1 FROM cluster_origin WHERE message_id=deliveries.message_id)",
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
        self.enqueue_variants(
            sender,
            vec![QueueVariant {
                id,
                scan,
                raw,
                recipients: recipients.into_iter().map(|r| (r, None)).collect(),
            }],
        )
        .await
    }
    /// All files and all recipient policies commit as one SMTP acceptance unit.
    pub async fn enqueue_variants(
        &self,
        sender: String,
        variants: Vec<QueueVariant>,
    ) -> Result<()> {
        ensure!(
            !variants.is_empty() && variants.len() <= 6,
            "invalid queue batch"
        );
        for v in &variants {
            ensure!(
                !v.id.is_empty()
                    && v.id.len() <= 100
                    && v.id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b)),
                "invalid queue identifier"
            );
            for (_, a) in &v.recipients {
                let applied = a.as_ref().map(|a| &a.action).or(v.scan.action.as_ref());
                ensure!(
                    applied.is_none_or(|a| (1..=30).contains(&a.quarantine_days)),
                    "invalid quarantine retention"
                );
            }
        }
        let root = self.root.clone();
        let db = self.db.clone();
        // One owned blocking operation cannot be cancelled between persistence and commit.
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut written=Vec::new();
            let result=(|| -> Result<()> {
                for v in &variants {
                    let path=root.join("spool").join(format!("{}.eml",v.id));
                    let mut f=OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path)?;
                    written.push(path); f.write_all(&v.raw)?; f.sync_all()?;
                }
                File::open(root.join("spool"))?.sync_all()?;
                let mut db=db.lock().map_err(|_|anyhow::anyhow!("database lock poisoned"))?;
                let tx=db.transaction()?;
                for v in variants {
                    tx.execute("INSERT INTO messages(id,created,sender,scan) VALUES(?1,?2,?3,?4)",params![v.id,now(),sender,serde_json::to_string(&v.scan)?])?;
                    for (r,a) in v.recipients {
                        let applied=a.as_ref().map(|a|&a.action).or(v.scan.action.as_ref());
                        let action=applied.map(|a|a.effective).unwrap_or_default();
                        let days=applied.map(|a|a.quarantine_days).unwrap_or(14);
                        let (name,status)=match action {
                            crate::actions::Action::Deliver=>("deliver","pending"),
                            crate::actions::Action::Tag=>("tag","pending"),
                            crate::actions::Action::Quarantine=>("quarantine","quarantined"),
                        };
                        tx.execute("INSERT INTO deliveries(message_id,address,destination,hosts,next_attempt,status) VALUES(?1,?2,?3,?4,?5,?6)",params![v.id,r.address,r.destination,serde_json::to_string(&r.hosts)?,now(),status])?;
                        let delivery_id=tx.last_insert_rowid();
                        tx.execute("INSERT INTO delivery_policy(delivery_id,action,held_until) VALUES(?1,?2,?3)",params![delivery_id,name,(action==crate::actions::Action::Quarantine).then(||now()+i64::from(days)*86400)])?;
                        if let Some(a)=a { tx.execute("INSERT INTO delivery_filtering(delivery_id,assessment) VALUES(?1,?2)",params![delivery_id,serde_json::to_string(&a)?])?; }
                    }
                }
                tx.commit()?;Ok(())
            })();
            if result.is_err() { for path in written { let _=fs::remove_file(path); } }
            result
        }).await??;
        self.delivery_ready.notify_one();
        Ok(())
    }
    pub async fn claim(&self) -> Result<Option<Job>> {
        self.run(|db| {
            let tx=db.transaction()?;
            let job=tx.query_row("SELECT d.id,m.id,COALESCE(p.released_at,m.created),m.sender,d.destination,d.hosts,d.attempts,m.is_dsn FROM deliveries d JOIN messages m ON m.id=d.message_id LEFT JOIN delivery_policy p ON p.delivery_id=d.id WHERE d.status='pending' AND NOT EXISTS(SELECT 1 FROM cluster_origin WHERE message_id=m.id) AND d.next_attempt<=?1 ORDER BY d.next_attempt,d.id LIMIT 1",[now()],|r|Ok((r.get::<_,i64>(0)?,r.get::<_,String>(1)?,r.get::<_,i64>(2)?,r.get::<_,String>(3)?,r.get::<_,String>(4)?,r.get::<_,String>(5)?,r.get::<_,u32>(6)?,r.get::<_,bool>(7)?))).optional()?;
            let Some((delivery_id,message_id,created,sender,destination,hosts,attempts,is_dsn))=job else { return Ok(None); };
            let hosts=serde_json::from_str(&hosts)?;
            tx.execute("UPDATE deliveries SET status='sending',attempts=attempts+1 WHERE id=?1",[delivery_id])?;
            tx.commit()?;
            Ok(Some(Job{delivery_id,message_id,created,sender,destination,hosts,attempts:attempts+1,is_dsn}))
        }).await
    }
    pub async fn finish(&self, job: &Job, status: &str, error: &str, next: i64) -> Result<()> {
        self.finish_with_attempts(job, status, error, next, &[])
            .await
    }
    /// Commit the delivery result and its bounded transcript together. A lost
    /// final SMTP response can still cause a retry, as in ordinary SMTP.
    pub async fn finish_with_attempts(
        &self,
        job: &Job,
        status: &str,
        error: &str,
        next: i64,
        attempts: &[crate::delivery_log::Attempt],
    ) -> Result<()> {
        let id = job.delivery_id;
        let attempt = job.attempts;
        let status = status.to_string();
        let error = crate::delivery_log::sanitize_text(error);
        let mut attempts = attempts.iter().rev().take(50).cloned().collect::<Vec<_>>();
        attempts.reverse();
        let traces = attempts
            .iter_mut()
            .map(|trace| {
                trace.sanitize();
                serde_json::to_string(trace)
            })
            .collect::<serde_json::Result<Vec<_>>>()?;
        self.run(move |db| {
            let tx = db.transaction()?;
            tx.execute(
                "UPDATE deliveries SET status=?2,error=?3,next_attempt=?4 WHERE id=?1",
                params![id, status, error, next],
            )?;
            for trace in traces {
                tx.execute("INSERT INTO delivery_attempts(delivery_id,attempt,trace) VALUES(?1,?2,?3)",params![id,attempt,trace])?;
            }
            tx.execute("DELETE FROM delivery_attempts WHERE delivery_id=?1 AND id NOT IN (SELECT id FROM delivery_attempts WHERE delivery_id=?1 ORDER BY id DESC LIMIT 50)",[id])?;
            tx.commit()?;
            Ok(())
        })
        .await
    }
    pub async fn failed(&self) -> Result<Vec<Job>> {
        self.run(|db| {
            let mut q=db.prepare("SELECT d.id,m.id,m.created,m.sender,d.destination,d.hosts,d.attempts,m.is_dsn FROM deliveries d JOIN messages m ON m.id=d.message_id WHERE d.status='failed' AND d.dsn_id IS NULL AND NOT EXISTS(SELECT 1 FROM cluster_origin WHERE message_id=m.id) LIMIT 100")?;
            let rows=q.query_map([],|r|Ok((r.get::<_,i64>(0)?,r.get::<_,String>(1)?,r.get::<_,i64>(2)?,r.get::<_,String>(3)?,r.get::<_,String>(4)?,r.get::<_,String>(5)?,r.get::<_,u32>(6)?,r.get::<_,bool>(7)?)))?;
            let mut jobs=Vec::new();for r in rows {let (delivery_id,message_id,created,sender,destination,hosts,attempts,is_dsn)=r?;jobs.push(Job{delivery_id,message_id,created,sender,destination,hosts:serde_json::from_str(&hosts)?,attempts,is_dsn});}Ok(jobs)
        }).await
    }
    /// Link a durable DSN to its failure in the same SQLite transaction. Worker IDs
    /// include their node and original message, so queue counters cannot collide.
    pub async fn enqueue_dsn(&self, job: Job, raw: Vec<u8>, hosts: Vec<String>) -> Result<()> {
        let delivery_id = job.delivery_id;
        let original = job.message_id.clone();
        let id = self.read(move |db| {
            let node: Option<String> = db.query_row("SELECT value FROM cluster_state WHERE key='node_id' AND EXISTS(SELECT 1 FROM cluster_state WHERE key='role' AND value='worker')", [], |r| r.get(0)).optional()?;
            Ok(if let Some(node) = node {
                let hash = crate::message::digest(format!("noisefence-dsn:{node}:{original}:{delivery_id}").as_bytes());
                let mut bytes: [u8;16] = hex::decode(&hash[..32])?.try_into().expect("16 digest bytes");
                bytes[6] = (bytes[6] & 0x0f) | 0x80;
                bytes[8] = (bytes[8] & 0x3f) | 0x80;
                uuid::Uuid::from_bytes(bytes).to_string()
            } else { format!("dsn-{delivery_id}") })
        }).await?;
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
        self.run(|db| {
            let tx = db.transaction()?;
            tx.execute("INSERT INTO audit(created,username,action,object_id) SELECT ?1,'system','quarantine_expire',CAST(d.id AS TEXT) FROM deliveries d JOIN delivery_policy p ON p.delivery_id=d.id WHERE d.status='quarantined' AND p.held_until<=?1 AND NOT EXISTS(SELECT 1 FROM cluster_origin WHERE message_id=d.message_id)",[now()])?;
            tx.execute("UPDATE deliveries SET status='expired' WHERE status='quarantined' AND NOT EXISTS(SELECT 1 FROM cluster_origin WHERE message_id=deliveries.message_id) AND id IN (SELECT delivery_id FROM delivery_policy WHERE held_until<=?1)",[now()])?;
            tx.commit()?; Ok(())
        }).await?;
        let ids=self.run(|db| { let mut q=db.prepare("SELECT id FROM messages m WHERE raw_present=1 AND NOT EXISTS(SELECT 1 FROM deliveries d WHERE d.message_id=m.id AND d.status IN ('pending','sending','failed','quarantined'))")?;Ok(q.query_map([],|r|r.get::<_,String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?) }).await?;
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
                "DELETE FROM console_invitations WHERE expires<?1",
                [now() - 30 * 86400],
            )?;
            db.execute(
                "DELETE FROM messages WHERE created<?1 AND raw_present=0 AND NOT EXISTS(SELECT 1 FROM cluster_origin o WHERE o.message_id=messages.id AND o.raw_present=1)",
                [now() - 30 * 86400],
            )?;
            db.execute("DELETE FROM audit WHERE created<?1", [now() - 30 * 86400])?;
            db.execute(
                "DELETE FROM quality_batches WHERE created<?1",
                [now() - 30 * 86400],
            )?;
            db.execute(
                "DELETE FROM quality_labels WHERE created<?1",
                [now() - 30 * 86400],
            )?;
            db.execute(
                "DELETE FROM adaptive_labels WHERE created<?1",
                [now() - 30 * 86400],
            )?;
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
        self.list_scoped(username, query, filter, offset, threshold, String::new())
            .await
    }
    pub async fn list_scoped(
        &self,
        username: String,
        query: String,
        filter: String,
        offset: u32,
        threshold: f64,
        domain: String,
    ) -> Result<Vec<VisibleMail>> {
        Ok(self
            .search_messages(
                username,
                crate::search::Search {
                    q: query,
                    filter,
                    offset,
                    domain,
                    ..Default::default()
                },
                threshold,
            )
            .await?
            .messages)
    }
    pub async fn search_messages(
        &self,
        username: String,
        options: crate::search::Search,
        threshold: f64,
    ) -> Result<crate::search::Page> {
        let terms = options.validate()?;
        let crate::search::Search {
            filter,
            offset,
            domain,
            ..
        } = &options;
        let (filter, offset, domain) = (filter.clone(), *offset, domain.clone());
        let mut values = vec![
            username.clone().into(),
            filter.into(),
            offset.into(),
            (now() - 30 * 86400).into(),
            threshold.into(),
            domain.clone().into(),
        ];
        let search_sql = options.predicate(&terms, &mut values);
        self.read(move|db| {
            let predicate=format!(include_str!("search-filter.sql"), publicity=crate::mailing::PUBLICITY_SQL,signal=crate::mailing::SIGNAL_SQL,search=search_sql);
            let total=db.query_row(&format!("SELECT COUNT(*) FROM messages m WHERE {predicate} AND ?3>=0"),rusqlite::params_from_iter(&values),|r|r.get::<_,u64>(0))?;
            let sql=format!("SELECT m.id,m.created,m.sender,m.scan,(SELECT spam FROM feedback f WHERE f.message_id=m.id AND f.username=?1),(SELECT category FROM feedback_categories c WHERE c.message_id=m.id AND c.username=?1) FROM messages m WHERE {predicate} ORDER BY m.created DESC,m.id DESC LIMIT 50 OFFSET ?3");
            let mut q=db.prepare(&sql)?;
            let rows=q.query_map(rusqlite::params_from_iter(&values),|r|Ok((r.get::<_,String>(0)?,r.get::<_,i64>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,Option<bool>>(4)?,r.get::<_,Option<String>>(5)?)))?;
            let mut out=Vec::new();
            for row in rows {
                let (id,created,sender,scan,feedback,feedback_category)=row?;
                let feedback_category=feedback_category.as_deref().map(crate::mailing::FeedbackCategory::parse).transpose()?;let s:Scan=serde_json::from_str(&scan)?;
                let category=crate::mailing::category(&s,threshold);
                let decision=s.decision.clone().unwrap_or_else(|| crate::fusion::runtime::Decision::legacy(&s,threshold));
                let mut recipients=db.prepare("SELECT DISTINCT d.address,d.status,p.held_until,p.released_at,p.action,f.assessment,(SELECT c.id FROM cluster_commands c WHERE c.message_id=d.message_id AND c.recipient=d.address AND c.finished IS NULL AND c.expires>unixepoch()) FROM deliveries d JOIN console_access g ON g.delivery_id=d.id LEFT JOIN delivery_policy p ON p.delivery_id=d.id LEFT JOIN delivery_filtering f ON f.delivery_id=d.id WHERE d.message_id=?1 AND g.username=?2 AND (?3='' OR lower(substr(d.address,-length(?3)-1))='@'||lower(?3) OR lower(substr(d.destination,-length(?3)-1))='@'||lower(?3))")?;
                let recipients=recipients.query_map(params![id,username,domain],|r|Ok(VisibleRecipient{pending_command:r.get(6)?,filtering:r.get::<_,Option<String>>(5)?.and_then(|s|serde_json::from_str(&s).ok()),address:r.get(0)?,status:r.get(1)?,held_until:r.get(2)?,released_at:r.get(3)?,action:r.get(4)?}))?.collect::<rusqlite::Result<Vec<_>>>()?;
                let origin:Option<(String,i64)>=db.query_row("SELECT node_id,updated FROM cluster_origin WHERE message_id=?1",[&id],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
                out.push(VisibleMail{node_id:origin.as_ref().map(|o|o.0.clone()),node_updated_at:origin.map(|o|o.1),adaptive:s.native_filter.as_ref().and_then(|n|n.report.adaptive.clone()),delivery_classification:s.delivery_classification,quality:s.quality.as_ref().map(crate::quality::Report::public),action:s.action,id,created,sender,subject:s.subject,score:s.score,tagged:s.tagged,pub_tagged:s.pub_tagged,category,complete:s.complete,model:s.model,reasons:s.reasons,recipients,feedback,feedback_category,antivirus:s.antivirus,signatures:s.signatures,llm:s.llm,semantic:s.semantic.into(),smtp_policy:s.smtp_policy,early_rbl:s.early_rbl,vision:s.vision,protection:s.protection,mailing:s.mailing,evidence:s.evidence,decision,arbitration:s.arbitration,fusion:s.fusion});
            }Ok(crate::search::Page { has_more: u64::from(offset)+(out.len() as u64)<total, messages: out, total, offset })
        }).await
    }
    pub async fn feedback(&self, user: String, id: String, spam: bool) -> Result<()> {
        self.record_feedback(user, id, spam, None).await
    }
    pub async fn feedback_category(
        &self,
        user: String,
        id: String,
        category: crate::mailing::FeedbackCategory,
    ) -> Result<()> {
        self.record_feedback(
            user,
            id,
            category == crate::mailing::FeedbackCategory::Spam,
            Some(category),
        )
        .await
    }
    async fn record_feedback(
        &self,
        user: String,
        id: String,
        spam: bool,
        category: Option<crate::mailing::FeedbackCategory>,
    ) -> Result<()> {
        self.run(move|db| {
            let tx=db.transaction()?;
            let allowed:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM deliveries d JOIN console_access g ON g.delivery_id=d.id JOIN messages m ON m.id=d.message_id WHERE d.message_id=?1 AND g.username=?2 AND m.created>=?3)",params![id,user,now()-30*86400],|r|r.get(0))?;
            ensure!(allowed,"message not found");
            tx.execute("INSERT INTO feedback(username,message_id,spam,created) VALUES(?1,?2,?3,?4) ON CONFLICT(username,message_id) DO UPDATE SET spam=excluded.spam,created=excluded.created",params![user,id,spam,now()])?;
            if let Some(category) = category {
                tx.execute("INSERT INTO feedback_categories(username,message_id,category) VALUES(?1,?2,?3)",params![user,id,category.as_str()])?;
            }
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
