//! Temporary, private originals for R&D. Never a source of delivery or training decisions.
use anyhow::{Context, Result, ensure};
use rand::RngCore;
use ring::aead;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, RwLock},
};

const MIB: u64 = 1024 * 1024;
const MAX_CONTEXT: usize = 4 * 1024 * 1024;
const MAGIC: &[u8] = b"NF-RD-1\0";
const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS entries(id TEXT PRIMARY KEY,created INTEGER NOT NULL,expires INTEGER NOT NULL,raw_bytes INTEGER NOT NULL,stored_bytes INTEGER NOT NULL,ids TEXT NOT NULL,final INTEGER NOT NULL DEFAULT 0); CREATE INDEX IF NOT EXISTS expiry ON entries(expires); CREATE TABLE IF NOT EXISTS counters(name TEXT PRIMARY KEY,value INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,created INTEGER NOT NULL,actor TEXT NOT NULL,action TEXT NOT NULL,object_id TEXT NOT NULL);";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub enabled: bool,
    /// Absolute deadline. Restarting or resaving a policy never extends it.
    pub collect_until: i64,
    pub retention_days: u32,
    pub quota_mib: u64,
    pub max_message_bytes: usize,
    pub domains: Vec<String>,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            enabled: false,
            collect_until: 0,
            retention_days: 30,
            quota_mib: 5120,
            max_message_bytes: 25 * 1024 * 1024,
            domains: vec![],
        }
    }
}
impl Settings {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (1..=90).contains(&self.retention_days),
            "Archive retention must be 1–90 days."
        );
        ensure!(
            (64..=102400).contains(&self.quota_mib),
            "Archive quota must be 64–102400 MiB per MX."
        );
        ensure!(
            (1024..=25 * 1024 * 1024).contains(&self.max_message_bytes),
            "Archive size limit must be 1 KiB–25 MiB."
        );
        ensure!(
            self.collect_until >= 0
                && self.collect_until <= crate::now().saturating_add(90 * 86400),
            "Invalid archive collection deadline."
        );
        ensure!(
            !self.enabled || self.collect_until > 0,
            "Temporary collection requires an absolute stop date."
        );
        ensure!(
            self.domains.len() <= 100
                && self
                    .domains
                    .iter()
                    .all(|d| crate::config::valid_domain(d) && d == &d.to_ascii_lowercase()),
            "Invalid archive domain scope."
        );
        Ok(())
    }
    pub fn collecting(&self, now: i64) -> bool {
        self.enabled && now < self.collect_until
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContextRecord {
    pub format: u32,
    pub id: String,
    pub created: i64,
    pub expires: i64,
    pub hostname: String,
    pub build: String,
    pub peer_ip: String,
    pub helo: String,
    pub sender: String,
    pub recipients: Vec<String>,
    pub encrypted_transport: bool,
    pub raw_sha256: String,
    pub configuration_sha256: String,
    pub message_ids: Vec<String>,
    pub observations: Vec<serde_json::Value>,
    pub observations_updated_at: i64,
    pub observations_final: bool,
}

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Status {
    pub collecting: bool,
    pub collect_until: i64,
    pub retention_days: u32,
    pub quota_mib: u64,
    pub messages: u64,
    pub stored_bytes: u64,
    pub pending_observations: u64,
    pub pending_writes: usize,
    pub counters: BTreeMap<String, u64>,
    pub checked_at: i64,
}

pub struct Runtime {
    root: PathBuf,
    settings: RwLock<Settings>,
    io: Mutex<()>,
    jobs: Arc<tokio::sync::Semaphore>,
    memory: Arc<tokio::sync::Semaphore>,
    skipped: Mutex<BTreeMap<String, u64>>,
    recovered: std::sync::atomic::AtomicBool,
}
impl Runtime {
    pub fn new(data: &Path) -> Self {
        Self {
            root: data.join("research-archive"),
            settings: RwLock::new(Settings::default()),
            io: Mutex::new(()),
            jobs: Arc::new(tokio::sync::Semaphore::new(8)),
            memory: Arc::new(tokio::sync::Semaphore::new(64 * 1024 * 1024)),
            skipped: Mutex::new(BTreeMap::new()),
            recovered: std::sync::atomic::AtomicBool::new(false),
        }
    }
    #[cfg(test)]
    pub(crate) fn pause_for_test(&self) -> std::sync::MutexGuard<'_, ()> {
        self.io.lock().unwrap()
    }
    pub fn configure(&self, settings: Settings) {
        *self.settings.write().unwrap() = settings;
    }
    pub fn collecting(&self) -> bool {
        self.settings.read().unwrap().collecting(crate::now())
    }
    fn skipped(&self, reason: &str) {
        *self
            .skipped
            .lock()
            .unwrap()
            .entry(reason.into())
            .or_default() += 1;
    }
    /// Transfers the existing original buffer after durable enqueue; no additional raw copy.
    /// A saturated or failed research archive cannot delay SMTP or hold a delivered body.
    pub fn capture(self: &Arc<Self>, raw: Vec<u8>, context: ContextRecord, reserve: u64) {
        let settings = self.settings.read().unwrap().clone();
        if !settings.collecting(crate::now()) {
            return;
        }
        // Mixed-domain transactions are excluded as a whole, preserving original bytes and Bcc privacy.
        if !settings.domains.is_empty()
            && context.recipients.iter().any(|r| {
                r.rsplit_once('@').is_none_or(|(_, d)| {
                    !settings.domains.iter().any(|v| v.eq_ignore_ascii_case(d))
                })
            })
        {
            self.skipped("domain_scope");
            return;
        }
        if raw.len() > settings.max_message_bytes {
            self.skipped("oversize");
            return;
        }
        let Ok(job) = self.jobs.clone().try_acquire_owned() else {
            self.skipped("busy");
            return;
        };
        let Ok(memory) = self
            .memory
            .clone()
            .try_acquire_many_owned(raw.len().saturating_add(MAX_CONTEXT).max(1) as u32)
        else {
            self.skipped("busy");
            return;
        };
        let runtime = self.clone();
        tokio::task::spawn_blocking(move || {
            let (_job, _memory) = (job, memory);
            if runtime.persist(raw, context, reserve).is_err() {
                runtime.skipped("write_error");
                tracing::warn!(
                    "Temporary research archive write failed; delivery remains independent"
                );
            }
        });
    }
    fn database(&self) -> Result<Connection> {
        private_dir(&self.root)?;
        private_dir(&self.root.join("objects"))?;
        let path = self.root.join("index.sqlite3");
        if path.exists() {
            regular(&path)?;
        }
        let db = Connection::open(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        db.busy_timeout(std::time::Duration::from_secs(2))?;
        db.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON;",
        )?;
        db.execute_batch(SCHEMA)?;
        Ok(db)
    }
    fn persist(&self, raw: Vec<u8>, mut context: ContextRecord, reserve: u64) -> Result<()> {
        let _lock = self.io.lock().unwrap();
        let settings = self.settings.read().unwrap().clone();
        let now = crate::now();
        if !settings.collecting(now) {
            self.skipped("stopped_before_write");
            return Ok(());
        }
        ensure!(
            uuid::Uuid::parse_str(&context.id)?.to_string() == context.id,
            "Invalid archive ID"
        );
        ensure!(
            context.created <= now && context.created > 0 && context.message_ids.len() <= 8,
            "Invalid archive context"
        );
        if raw.len() > settings.max_message_bytes {
            self.skipped("oversize");
            return Ok(());
        }
        if !settings.domains.is_empty()
            && context.recipients.iter().any(|r| {
                r.rsplit_once('@').is_none_or(|(_, d)| {
                    !settings.domains.iter().any(|v| v.eq_ignore_ascii_case(d))
                })
            })
        {
            self.skipped("domain_scope");
            return Ok(());
        }
        context.expires = context.created + i64::from(settings.retention_days) * 86400;
        context.raw_sha256 = crate::message::digest(&raw);
        let metadata = serde_json::to_vec(&context)?;
        ensure!(
            metadata.len() <= MAX_CONTEXT,
            "Archive context exceeds limit"
        );
        let mut db = self.database()?;
        self.purge_expired(&mut db, now)?;
        let used: u64 = db.query_row(
            "SELECT COALESCE(SUM(stored_bytes),0) FROM entries",
            [],
            |r| r.get(0),
        )?;
        // Shrinking a quota never silently evicts unexpired examples.
        let required = (raw.len() + metadata.len() + 2 * (MAGIC.len() + 28)) as u64;
        if used.saturating_add(required) > settings.quota_mib * MIB {
            increment(&db, "quota_full", 1)?;
            return Ok(());
        }
        let free = crate::store::available_bytes(&self.root)?;
        if free
            < reserve
                .max(2 * 1024 * MIB)
                .saturating_add(required)
                .saturating_add(64 * MIB)
        {
            increment(&db, "disk_reserve", 1)?;
            return Ok(());
        }
        let entries: u64 = db.query_row("SELECT COUNT(*) FROM entries", [], |r| r.get(0))?;
        if entries >= 100000 {
            increment(&db, "entry_limit", 1)?;
            return Ok(());
        }
        ensure!(
            entries == 0 || self.root.join("archive.key").exists(),
            "Archive key missing for existing originals"
        );
        let key = key(&self.root, true)?;
        let folder = self.root.join("objects").join(&context.id);
        ensure!(!folder.exists(), "Archive ID already exists");
        private_dir(&folder)?;
        let result = (|| -> Result<()> {
            write_sealed(
                &folder.join("message.enc"),
                &raw,
                &key,
                &format!("{}:original", context.id),
            )?;
            write_sealed(
                &folder.join("context.enc"),
                &metadata,
                &key,
                &format!("{}:context", context.id),
            )?;
            let tx = db.transaction()?;
            tx.execute("INSERT INTO entries(id,created,expires,raw_bytes,stored_bytes,ids,final) VALUES(?1,?2,?3,?4,?5,?6,?7)", params![context.id,context.created,context.expires,raw.len() as u64,required,serde_json::to_string(&context.message_ids)?,context.observations_final])?;
            increment(&tx, "archived", 1)?;
            File::open(self.root.join("objects"))?.sync_all()?;
            tx.commit()?;
            Ok(())
        })();
        if result.is_err()
            && db
                .query_row("SELECT 1 FROM entries WHERE id=?1", [&context.id], |r| {
                    r.get::<_, u8>(0)
                })
                .optional()?
                .is_none()
        {
            let _ = fs::remove_dir_all(&folder);
        }
        result
    }
    fn purge_expired(&self, db: &mut Connection, now: i64) -> Result<()> {
        let rows: Vec<String> = db
            .prepare("SELECT id FROM entries WHERE expires<=?1 LIMIT 1000")?
            .query_map([now], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        for id in rows {
            ensure!(
                uuid::Uuid::parse_str(&id)?.to_string() == id,
                "Invalid archive index"
            );
            let folder = self.root.join("objects").join(&id);
            if folder.exists() {
                ensure!(
                    !folder.symlink_metadata()?.file_type().is_symlink(),
                    "Invalid archive directory"
                );
                fs::remove_dir_all(folder)?;
            }
            db.execute("DELETE FROM entries WHERE id=?1", [id])?;
            increment(db, "expired", 1)?;
        }
        Ok(())
    }
    pub fn status(&self) -> Result<Status> {
        let settings = self.settings.read().unwrap().clone();
        let mut status = Status {
            collecting: settings.collecting(crate::now()),
            collect_until: settings.collect_until,
            retention_days: settings.retention_days,
            quota_mib: settings.quota_mib,
            pending_writes: 8 - self.jobs.available_permits(),
            checked_at: crate::now(),
            ..Default::default()
        };
        let _lock = self.io.lock().unwrap();
        if self.root.exists() {
            let db = self.database()?;
            (status.messages,status.stored_bytes,status.pending_observations)=db.query_row("SELECT COUNT(*),COALESCE(SUM(stored_bytes),0),COALESCE(SUM(final=0),0) FROM entries WHERE expires>?1",[crate::now()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;
            status.counters = db
                .prepare("SELECT name,value FROM counters")?
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<rusqlite::Result<_>>()?;
        }
        for (k, v) in self.skipped.lock().unwrap().iter() {
            *status.counters.entry(k.clone()).or_default() += v;
        }
        Ok(status)
    }
    /// Called even after collection stops. Reconciles crash orphans and expires originals.
    pub async fn maintain(self: &Arc<Self>, store: &crate::store::Store) -> Result<()> {
        let runtime = self.clone();
        let pending=tokio::task::spawn_blocking(move || -> Result<Vec<(String,Vec<String>)>> {
            let _lock=runtime.io.lock().unwrap();
            if !runtime.root.exists() && !runtime.collecting() && runtime.skipped.lock().unwrap().is_empty() { return Ok(vec![]); }
            let mut db=runtime.database()?;
            runtime.purge_expired(&mut db,crate::now())?;
            db.execute("DELETE FROM events WHERE created<?1",[crate::now()-30*86400])?;
            let counters=std::mem::take(&mut *runtime.skipped.lock().unwrap());
            for (name,value) in counters { increment(&db,&name,value)?; }
            // A process crash between object persistence and index commit leaves only ciphertext.
            if !runtime.recovered.load(std::sync::atomic::Ordering::Relaxed) {
            for entry in fs::read_dir(runtime.root.join("objects"))? {
                let entry=entry?;let id=entry.file_name().to_string_lossy().into_owned();
                if uuid::Uuid::parse_str(&id).is_err() { continue; }
                if !entry.file_type()?.is_dir() { continue; }
                if db.query_row("SELECT 1 FROM entries WHERE id=?1",[&id],|r|r.get::<_,u8>(0)).optional()?.is_none() {
                    fs::remove_dir_all(entry.path())?;increment(&db,"recovered_orphans",1)?;
                } else {
                    // Repair a crash after an atomic context replacement but before its index update.
                    let mut stored=0u64;
                    for name in ["message.enc","context.enc"] {let path=entry.path().join(name);regular(&path)?;stored=stored.saturating_add(path.metadata()?.len());}
                    db.execute("UPDATE entries SET stored_bytes=?2 WHERE id=?1",params![id,stored])?;
                    for temporary in fs::read_dir(entry.path())? {
                        let temporary=temporary?;
                        if temporary.file_name().to_string_lossy().starts_with(".write-") && temporary.file_type()?.is_file() {fs::remove_file(temporary.path())?;}
                    }
                }
            }
            runtime.recovered.store(true,std::sync::atomic::Ordering::Relaxed);
            }
            if !runtime.collecting() && db.query_row("SELECT COUNT(*) FROM entries",[],|r|r.get::<_,u64>(0))?==0 && runtime.root.join("archive.key").exists() {fs::remove_file(runtime.root.join("archive.key"))?;File::open(&runtime.root)?.sync_all()?;}
            let rows=db.prepare("SELECT id,ids FROM entries WHERE final=0 AND expires>?1 ORDER BY created LIMIT 100")?.query_map([crate::now()],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
            rows.into_iter().map(|(id,ids)|Ok((id,serde_json::from_str(&ids)?))).collect()
        }).await??;
        for (id, ids) in pending {
            let observations=store.read(move |db| {
                ids.into_iter().map(|id| Ok(db.query_row("SELECT scan FROM messages WHERE id=?1 AND NOT EXISTS(SELECT 1 FROM cluster_origin WHERE message_id=messages.id)",[id],|r|r.get::<_,String>(0)).optional()?.map(|s|serde_json::from_str::<serde_json::Value>(&s)).transpose()?)).collect::<Result<Vec<_>>>()
            }).await?;
            let runtime = self.clone();
            tokio::task::spawn_blocking(move || runtime.refresh(&id, observations)).await??;
        }
        Ok(())
    }
    fn refresh(&self, id: &str, observations: Vec<Option<serde_json::Value>>) -> Result<()> {
        let _lock = self.io.lock().unwrap();
        let db = self.database()?;
        if db
            .query_row(
                "SELECT 1 FROM entries WHERE id=?1 AND expires>?2",
                params![id, crate::now()],
                |r| r.get::<_, u8>(0),
            )
            .optional()?
            .is_none()
        {
            return Ok(());
        }
        let key = key(&self.root, false)?;
        let path = self.root.join("objects").join(id).join("context.enc");
        let mut record: ContextRecord = serde_json::from_slice(&read_sealed(
            &path,
            &key,
            &format!("{id}:context"),
            MAX_CONTEXT,
        )?)?;
        if observations.iter().all(Option::is_some) {
            record.observations = observations.into_iter().flatten().collect();
            record.observations_final = record.observations.iter().all(|s| {
                s.pointer("/rspamd/status")
                    .and_then(serde_json::Value::as_str)
                    != Some("pending")
            });
            // A missing final comparator result is recorded as interrupted after its own deadline.
            for scan in &mut record.observations {
                if scan
                    .pointer("/rspamd/status")
                    .and_then(serde_json::Value::as_str)
                    == Some("pending")
                    && scan
                        .pointer("/rspamd/expires_at")
                        .and_then(serde_json::Value::as_i64)
                        .is_some_and(|t| t < crate::now())
                {
                    scan["rspamd"]["status"] = serde_json::json!("interrupted");
                }
            }
            record.observations_final = record.observations.iter().all(|s| {
                s.pointer("/rspamd/status")
                    .and_then(serde_json::Value::as_str)
                    != Some("pending")
            });
        } else {
            record.observations_final = true;
        }
        record.observations_updated_at = crate::now();
        let bytes = serde_json::to_vec(&record)?;
        ensure!(bytes.len() <= MAX_CONTEXT, "Archive observations too large");
        let previous = path.metadata()?.len();
        let next = (bytes.len() + MAGIC.len() + 28) as u64;
        let used: u64 = db.query_row(
            "SELECT COALESCE(SUM(stored_bytes),0) FROM entries",
            [],
            |r| r.get(0),
        )?;
        if used.saturating_sub(previous).saturating_add(next)
            > self.settings.read().unwrap().quota_mib * MIB
            || crate::store::available_bytes(&self.root)? < 2 * 1024 * MIB + next + 64 * MIB
        {
            increment(&db, "observation_capacity", 1)?;
            return Ok(());
        }
        write_sealed(&path, &bytes, &key, &format!("{id}:context"))?;
        db.execute(
            "UPDATE entries SET final=?2,stored_bytes=stored_bytes-?3+?4 WHERE id=?1",
            params![id, record.observations_final, previous, next],
        )?;
        Ok(())
    }
    pub fn list(&self) -> Result<Vec<serde_json::Value>> {
        let _lock = self.io.lock().unwrap();
        if !self.root.exists() {
            return Ok(vec![]);
        }
        let db = self.database()?;
        let rows=db.prepare("SELECT id,created,expires,raw_bytes,final FROM entries WHERE expires>?1 ORDER BY created DESC LIMIT 100")?.query_map([crate::now()],|r|Ok(serde_json::json!({"id":r.get::<_,String>(0)?,"created":r.get::<_,i64>(1)?,"expires":r.get::<_,i64>(2)?,"raw_bytes":r.get::<_,u64>(3)?,"observations_final":r.get::<_,bool>(4)?})))?.collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }
    /// Local operator export only. The Web never renders or exposes archived message bodies.
    pub fn export(&self, id: &str, destination: &Path) -> Result<()> {
        ensure!(
            uuid::Uuid::parse_str(id)?.to_string() == id,
            "Invalid archive ID"
        );
        ensure!(!destination.exists(), "Export destination must not exist");
        let _lock = self.io.lock().unwrap();
        let db = self.database()?;
        audit(&db, "export_attempt", id)?;
        ensure!(
            db.query_row(
                "SELECT 1 FROM entries WHERE id=?1 AND expires>?2",
                params![id, crate::now()],
                |r| r.get::<_, u8>(0)
            )
            .optional()?
            .is_some(),
            "Archive unavailable or expired"
        );
        let key = key(&self.root, false)?;
        let folder = self.root.join("objects").join(id);
        let context = read_sealed(
            &folder.join("context.enc"),
            &key,
            &format!("{id}:context"),
            MAX_CONTEXT,
        )?;
        let record: ContextRecord = serde_json::from_slice(&context)?;
        let raw = read_sealed(
            &folder.join("message.enc"),
            &key,
            &format!("{id}:original"),
            25 * 1024 * 1024,
        )?;
        ensure!(
            record.id == id
                && record.expires > crate::now()
                && record.raw_sha256 == crate::message::digest(&raw),
            "Archive integrity or expiry check failed"
        );
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(destination)?;
        let result = (|| -> Result<()> {
            private_write(&destination.join("message.eml"), &raw)?;
            private_write(&destination.join("context.json"), &context)?;
            increment(&db, "exports", 1)?;
            audit(&db, "exported", id)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(destination);
        }
        result
    }
}
fn audit(db: &Connection, action: &str, id: &str) -> Result<()> {
    // OS identity is recorded, not a caller-supplied label.
    let actor = format!("uid:{}", unsafe { libc::geteuid() });
    db.execute(
        "INSERT INTO events(created,actor,action,object_id) VALUES(?1,?2,?3,?4)",
        params![crate::now(), actor, action, id],
    )?;
    Ok(())
}
fn increment(db: &Connection, name: &str, count: u64) -> Result<()> {
    db.execute("INSERT INTO counters(name,value) VALUES(?1,?2) ON CONFLICT(name) DO UPDATE SET value=value+excluded.value",params![name,count])?;
    Ok(())
}
fn private_dir(path: &Path) -> Result<()> {
    if path.exists() {
        ensure!(
            path.symlink_metadata()?.file_type().is_dir(),
            "Private archive directory required"
        );
    } else {
        fs::create_dir_all(path)?;
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}
fn regular(path: &Path) -> Result<()> {
    let m = path.symlink_metadata()?;
    ensure!(
        m.is_file() && !m.file_type().is_symlink(),
        "Private regular archive file required"
    );
    Ok(())
}
fn private_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("Missing archive parent")?;
    let tmp = parent.join(format!(".write-{}", uuid::Uuid::new_v4()));
    let result = (|| -> Result<()> {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        fs::rename(&tmp, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(tmp);
    }
    result
}
fn key(root: &Path, create: bool) -> Result<[u8; 32]> {
    let path = root.join("archive.key");
    if !path.exists() {
        ensure!(create, "Archive key missing");
        let mut k = [0; 32];
        rand::rngs::OsRng.fill_bytes(&mut k);
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)?;
        f.write_all(&k)?;
        f.sync_all()?;
        File::open(root)?.sync_all()?;
    }
    regular(&path)?;
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    ensure!(
        f.metadata()?.len() == 32 && f.metadata()?.permissions().mode() & 0o077 == 0,
        "Private 32-byte archive key required"
    );
    let mut k = [0; 32];
    f.read_exact(&mut k)?;
    Ok(k)
}
fn cipher(key: &[u8; 32]) -> Result<aead::LessSafeKey> {
    Ok(aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_256_GCM, key)
            .map_err(|_| anyhow::anyhow!("Archive encryption unavailable"))?,
    ))
}
fn write_sealed(path: &Path, bytes: &[u8], key: &[u8; 32], aad: &str) -> Result<()> {
    let mut nonce = [0; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let mut body = bytes.to_vec();
    cipher(key)?
        .seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(aad.as_bytes()),
            &mut body,
        )
        .map_err(|_| anyhow::anyhow!("Archive encryption failed"))?;
    let mut sealed = Vec::with_capacity(MAGIC.len() + 12 + body.len());
    sealed.extend_from_slice(MAGIC);
    sealed.extend_from_slice(&nonce);
    sealed.extend(body);
    private_write(path, &sealed)
}
fn read_sealed(path: &Path, key: &[u8; 32], aad: &str, max: usize) -> Result<Vec<u8>> {
    regular(path)?;
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    ensure!(
        f.metadata()?.len() <= (max + MAGIC.len() + 28) as u64,
        "Oversized encrypted archive"
    );
    let mut bytes = vec![];
    f.take((max + MAGIC.len() + 29) as u64)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.starts_with(MAGIC) && bytes.len() >= MAGIC.len() + 28,
        "Invalid encrypted archive"
    );
    let nonce = bytes[MAGIC.len()..MAGIC.len() + 12].try_into()?;
    let mut body = bytes[MAGIC.len() + 12..].to_vec();
    Ok(cipher(key)?
        .open_in_place(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(aad.as_bytes()),
            &mut body,
        )
        .map_err(|_| anyhow::anyhow!("Archive authentication failed"))?
        .to_vec())
}
#[cfg(test)]
mod tests;

/// Separate maintenance loop: archive disk I/O and observation updates never occupy the relay loop.
pub async fn run(store: crate::store::Store, mut stop: tokio::sync::watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
    loop {
        tokio::select! {
            _=stop.changed()=>break,
            _=interval.tick()=>{if store.archive.maintain(&store).await.is_err(){tracing::warn!("Temporary archive maintenance failed; mail service remains independent");}}
        }
    }
    // Bounded drain during a normal service stop. A crash can lose pending research writes.
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        store.archive.jobs.clone().acquire_many_owned(8),
    )
    .await;
}
