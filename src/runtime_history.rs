//! Short-lived, private detector input cache. Never authorizes console access.
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OpenFlags, params};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    os::{
        fd::AsRawFd,
        unix::fs::{OpenOptionsExt, PermissionsExt},
    },
    path::Path,
    time::Duration,
};
pub const PROTOCOL: &str = "noisefence-runtime-history-1";
pub const MAX_BYTES: usize = 64 * 1024 * 1024;
pub const TTL: i64 = 60;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Vote {
    pub actor: String,
    pub spam: bool,
    pub created: i64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Row {
    pub id: String,
    pub created: i64,
    pub is_dsn: bool,
    pub fingerprint: String,
    pub simhash: Option<String>,
    pub raw_sha256: Option<String>,
    pub feature_count: usize,
    pub native: Option<crate::native_filter::input::Features>,
    pub sender_key: Option<String>,
    pub behavior: Option<crate::quality::behavior::Sample>,
    pub domains: Vec<String>,
    pub votes: Vec<Vote>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub protocol: String,
    pub generation: i64,
    pub created: i64,
    pub rows: Vec<Row>,
}
impl Snapshot {
    pub fn validate(&self) -> Result<()> {
        let now = crate::now();
        ensure!(
            self.protocol == PROTOCOL
                && self.generation > 0
                && self.created <= now + 5
                && self.created > now - TTL,
            "Runtime history is stale or incompatible"
        );
        ensure!(
            self.rows.len() <= 50000,
            "Runtime history exceeds row capacity"
        );
        let mut ids = std::collections::HashSet::new();
        for row in &self.rows {
            ensure!(
                crate::ha::replica::valid_id(&row.id)
                    && (!row.id.starts_with("dsn-") || row.is_dsn)
                    && ids.insert(&row.id)
                    && row.created > 0
                    && row.created <= now + 5,
                "Invalid runtime history identity"
            );
            ensure!(
                (row.fingerprint.is_empty() || crate::compatibility::valid_hash(&row.fingerprint))
                    && row
                        .sender_key
                        .as_deref()
                        .is_none_or(crate::compatibility::valid_hash)
                    && row
                        .raw_sha256
                        .as_deref()
                        .is_none_or(crate::compatibility::valid_hash),
                "Invalid runtime history digest"
            );
            ensure!(
                row.simhash
                    .as_deref()
                    .is_none_or(|s| s.len() == 16 && s.bytes().all(|b| b.is_ascii_hexdigit()))
                    && row.feature_count <= 80,
                "Invalid runtime campaign features"
            );
            if let Some(native) = &row.native {
                native.validate()?;
            }
            ensure!(
                row.behavior.as_ref().is_none_or(|s| s.valid())
                    && row.domains.len() <= 100
                    && row
                        .domains
                        .iter()
                        .all(|d| crate::config::valid_domain(d) && d == &d.to_ascii_lowercase()),
                "Invalid runtime scope"
            );
            ensure!(
                row.votes.len() <= 1000
                    && row
                        .votes
                        .iter()
                        .all(|v| crate::compatibility::valid_hash(&v.actor)
                            && v.created > 0
                            && v.created <= now + 5),
                "Invalid runtime annotation"
            );
        }
        ensure!(
            serde_json::to_vec(self)?.len() <= MAX_BYTES,
            "Runtime history exceeds byte capacity"
        );
        Ok(())
    }
}
/// Selection is durable; absence of the cache must never reopen old local truth.
pub async fn require(store: &crate::store::Store) -> Result<()> {
    store.run(|db| {
        use rusqlite::OptionalExtension;
        let tx=db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let previous:Option<String>=tx.query_row("SELECT value FROM cluster_state WHERE key='runtime_history_protocol'",[],|r|r.get(0)).optional()?;
        ensure!(previous.as_deref().is_none_or(|value|value==PROTOCOL),"Unknown runtime history authority");
        tx.execute("INSERT OR IGNORE INTO cluster_state(key,value) VALUES('runtime_history_protocol',?1)",[PROTOCOL])?;
        tx.commit()?;Ok(())
    }).await
}

pub fn open(root: &Path) -> Result<Connection> {
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let db = Connection::open_with_flags(root.join("state.sqlite3"), flags)?;
    db.busy_timeout(Duration::from_millis(30))?;
    let format: i64 = db.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if format >= crate::central::selection::FORMAT {
        ensure!(
            crate::central::selection::Selection::read(&db)?.is_some(),
            "Selected runtime history authority is missing"
        );
    }
    let clustered: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='cluster_state')",
        [],
        |r| r.get(0),
    )?;
    let central = if clustered {
        let mut query=db.prepare("SELECT key,value FROM cluster_state WHERE key IN ('runtime_history_protocol','management_transport')")?;
        let values = query
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        for (key, value) in &values {
            ensure!(
                value
                    == if key == "runtime_history_protocol" {
                        PROTOCOL
                    } else {
                        crate::central::transport::PROTOCOL
                    },
                "Unknown runtime history authority"
            );
        }
        !values.is_empty()
    } else {
        false
    };
    if !central {
        return Ok(db);
    }
    drop(db);
    let db = Connection::open_with_flags(root.join("runtime-history.sqlite3"), flags)?;
    db.busy_timeout(Duration::from_millis(30))?;
    db.execute_batch("BEGIN")?;
    let (protocol, created): (String, i64) = db.query_row(
        "SELECT protocol,created FROM snapshot WHERE id=1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    ensure!(
        protocol == PROTOCOL && created <= crate::now() + 5 && created > crate::now() - TTL,
        "Runtime history unavailable or expired"
    );
    Ok(db)
}
struct Temporary(std::path::PathBuf);
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
pub async fn install(root: &Path, snapshot: Snapshot) -> Result<()> {
    let root = root.to_owned();
    tokio::task::spawn_blocking(move ||->Result<()> {
        snapshot.validate()?;
        let path=root.join(format!(".runtime-history-{}.sqlite3",uuid::Uuid::new_v4()));
        let file=OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path)?;drop(file);
        let temporary=Temporary(path);let mut db=Connection::open(&temporary.0)?;
        db.execute_batch("PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF; CREATE TABLE snapshot(id INTEGER PRIMARY KEY,protocol TEXT,generation INTEGER,created INTEGER); CREATE TABLE messages(id TEXT PRIMARY KEY,created INTEGER,is_dsn INTEGER,scan TEXT); CREATE INDEX history_date ON messages(created DESC); CREATE INDEX sender_key ON messages(json_extract(scan,'$.sender_history.key'),created); CREATE TABLE users(username TEXT PRIMARY KEY,admin INTEGER,disabled INTEGER); CREATE TABLE training_feedback(username TEXT,message_id TEXT,spam INTEGER,created INTEGER,PRIMARY KEY(username,message_id)); CREATE INDEX vote_message ON training_feedback(message_id); CREATE TABLE deliveries(id INTEGER PRIMARY KEY,message_id TEXT,destination TEXT); CREATE INDEX delivery_message ON deliveries(message_id); CREATE VIEW console_access AS SELECT u.username,d.id AS delivery_id FROM users u CROSS JOIN deliveries d;")?;
        let tx=db.transaction()?;
        tx.execute("INSERT INTO snapshot VALUES(1,?1,?2,?3)",params![snapshot.protocol,snapshot.generation,snapshot.created])?;
        for row in &snapshot.rows {
            let scan=serde_json::json!({"fingerprint":row.fingerprint,"campaign_simhash":row.simhash,"raw_sha256":row.raw_sha256,"features":vec![(0,0.0);row.feature_count],"native_filter":{"features":row.native},"sender_history":{"key":row.sender_key,"behavior":{"sample":row.behavior}}});
            tx.execute("INSERT INTO messages VALUES(?1,?2,?3,?4)",params![row.id,row.created,row.is_dsn,serde_json::to_string(&scan)?])?;
            for vote in &row.votes {
                tx.execute("INSERT OR IGNORE INTO users VALUES(?1,1,0)",[&vote.actor])?;
                tx.execute("INSERT INTO training_feedback VALUES(?1,?2,?3,?4)",params![vote.actor,row.id,vote.spam,vote.created])?;
            }
            for domain in &row.domains {tx.execute("INSERT INTO deliveries(message_id,destination) VALUES(?1,?2)",params![row.id,format!("cache@{domain}")])?;}
        }
        tx.commit()?;drop(db);File::open(&temporary.0)?.sync_all()?;
        let lock=OpenOptions::new().write(true).create(true).truncate(false).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(root.join("runtime-history.lock"))?;
        // This advisory lock serializes only cache publication, not SMTP queues.
        ensure!(unsafe{libc::flock(lock.as_raw_fd(),libc::LOCK_EX|libc::LOCK_NB)}==0,"Runtime history publication busy");
        let target=root.join("runtime-history.sqlite3");
        if target.exists() {
            let previous=Connection::open_with_flags(&target,OpenFlags::SQLITE_OPEN_READ_ONLY).and_then(|db|db.query_row("SELECT protocol,generation,created FROM snapshot WHERE id=1",[],|r|Ok((r.get::<_,String>(0)?,r.get::<_,i64>(1)?,r.get::<_,i64>(2)?))));
            // This cache is disposable. A corrupt file can be replaced by a
            // fresh validated snapshot; fresh generations may not go backwards.
            if let Ok((protocol,generation,created))=previous {
                ensure!(protocol==PROTOCOL,"Unknown runtime history format");
                ensure!(snapshot.generation>generation || (created<=crate::now()-TTL && snapshot.created>created),"Stale runtime history generation");
            }
        }
        snapshot.validate()?;fs::rename(&temporary.0,&target)?;fs::set_permissions(&target,fs::Permissions::from_mode(0o600))?;File::open(root)?.sync_all()?;Ok(())
    }).await.context("Runtime history writer unavailable")?
}
