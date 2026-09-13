//! Two durable copies before SMTP acceptance. Replicas never own delivery leases.
pub mod recovery;
pub mod replica;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, sync::Arc, time::Duration};

pub const PROTOCOL: &str = "noisefence-replica-1";
pub const SCHEMA: &str = include_str!("ha-schema.sql");

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub peer_id: String,
    pub peer_url: String,
    pub credential_file: PathBuf,
    #[serde(default = "timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "capacity")]
    pub max_replica_bytes: u64,
    #[serde(default)]
    pub allow_loopback_http: bool,
}
fn timeout() -> u64 {
    30
}
fn capacity() -> u64 {
    10 * 1024 * 1024 * 1024
}
impl Settings {
    pub fn validate(&self) -> Result<()> {
        let url = reqwest::Url::parse(&self.peer_url)?;
        ensure!(
            crate::cluster::valid_id(&self.peer_id),
            "Invalid replica peer"
        );
        ensure!(
            url.scheme() == "https"
                || (self.allow_loopback_http
                    && url.scheme() == "http"
                    && matches!(url.host_str(), Some("127.0.0.1" | "[::1]"))),
            "Replica requires HTTPS"
        );
        ensure!(
            !self.allow_loopback_http
                || (url.scheme() == "http"
                    && matches!(url.host_str(), Some("127.0.0.1" | "[::1]"))),
            "Test exemption is restricted to HTTP loopback"
        );
        ensure!(
            url.username().is_empty()
                && url.password().is_none()
                && url.path() == "/"
                && url.query().is_none()
                && url.fragment().is_none(),
            "Replica URL must be an origin"
        );
        ensure!(
            self.credential_file.is_absolute()
                && (5..=120).contains(&self.timeout_seconds)
                && (64 * 1024 * 1024..=1024_u64.pow(4)).contains(&self.max_replica_bytes),
            "Invalid replication limits"
        );
        Ok(())
    }
}

pub struct Runtime {
    pub last_peer_seen: std::sync::atomic::AtomicI64,
    pub settings: Settings,
    pub node_id: String,
    pub machine: String,
    pub key: String,
    pub http: reqwest::Client,
    pub capacity: Arc<tokio::sync::Semaphore>,
    pub serial: Arc<tokio::sync::Mutex<()>>,
    pub receivers: Arc<tokio::sync::Semaphore>,
    pub max_message_bytes: u64,
    pub minimum_free_bytes: u64,
}
impl Runtime {
    pub fn new(config: &crate::config::Config) -> Result<Self> {
        let settings = config.replication.clone().context("Replication disabled")?;
        settings.validate()?;
        let node_id = config
            .cluster
            .as_ref()
            .context("Replication requires a node identity")?
            .node_id
            .clone();
        ensure!(
            node_id != settings.peer_id,
            "Replica must be a different node"
        );
        let machine = match std::fs::read("/etc/machine-id") {
            Ok(bytes) => crate::message::digest(&bytes),
            Err(_) if settings.allow_loopback_http => "test-machine".into(),
            Err(e) => return Err(e).context("Linux machine identity required for replication"),
        };
        let key = crate::cluster::protocol::credential(&settings.credential_file)?;
        let http = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(settings.timeout_seconds))
            .build()?;
        Ok(Self {
            last_peer_seen: std::sync::atomic::AtomicI64::new(0),
            settings,
            node_id,
            machine,
            key,
            http,
            capacity: Arc::new(tokio::sync::Semaphore::new(2)),
            serial: Arc::new(tokio::sync::Mutex::new(())),
            receivers: Arc::new(tokio::sync::Semaphore::new(4)),
            max_message_bytes: config.smtp.max_message_bytes as u64 + 256 * 1024,
            minimum_free_bytes: config.smtp.minimum_free_bytes,
        })
    }
}

pub fn ready(store: &crate::store::Store) -> bool {
    store.replication.get().is_none_or(|runtime| {
        let seen = runtime
            .last_peer_seen
            .load(std::sync::atomic::Ordering::Relaxed);
        let age = crate::now().saturating_sub(seen);
        seen > 0 && (0..=15).contains(&age)
    })
}
pub async fn initialize(store: &crate::store::Store, config: &crate::config::Config) -> Result<()> {
    if config.replication.is_some() {
        let runtime = Arc::new(Runtime::new(config)?);
        let directory = store.root.join("replicas").join(&runtime.settings.peer_id);
        std::fs::create_dir_all(&directory)?;
        use std::os::unix::fs::PermissionsExt;
        for path in [&directory, directory.parent().unwrap(), &store.root] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
            std::fs::File::open(path)?.sync_all()?;
        }
        if store.replication.get().is_none() {
            store
                .replication
                .set(runtime)
                .map_err(|_| anyhow::anyhow!("Replication initialized concurrently"))?;
        }
        store.run(|db| {
            let tx = db.transaction()?;
            tx.execute("INSERT OR REPLACE INTO cluster_state VALUES('ha_required','1')", [])?;
            tx.execute("INSERT OR IGNORE INTO ha_local(message_id,generation,acked) SELECT id,1,0 FROM messages WHERE raw_present=1 AND NOT EXISTS(SELECT 1 FROM cluster_origin WHERE message_id=messages.id)", [])?;
            tx.execute_batch("PRAGMA user_version=5")?;
            tx.commit()?; Ok(())
        }).await?;
    } else {
        store
            .read(|db| {
                ensure!(
                    !db.query_row(
                        "SELECT EXISTS(SELECT 1 FROM cluster_state WHERE key='ha_required')",
                        [],
                        |r| r.get::<_, bool>(0)
                    )?,
                    "This queue requires replication; use the documented fenced recovery procedure"
                );
                Ok(())
            })
            .await?;
    }
    Ok(())
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Status {
    pub required: bool,
    pub peer_id: Option<String>,
    pub unprotected: u64,
    pub pending_updates: u64,
    pub remote_messages: u64,
    pub remote_bytes: u64,
    pub last_success: Option<i64>,
    pub last_error: Option<String>,
}
pub async fn status(store: &crate::store::Store) -> Result<Status> {
    let peer_id = store.replication.get().map(|r| r.settings.peer_id.clone());
    store.read(move |db| {
        use rusqlite::OptionalExtension;
        Ok(Status {
            required: peer_id.is_some(), peer_id,
            unprotected: db.query_row("SELECT COUNT(*) FROM ha_local WHERE acked=0", [], |r| r.get(0))?,
            pending_updates: db.query_row("SELECT COUNT(*) FROM ha_local WHERE acked<generation", [], |r| r.get(0))?,
            remote_messages: db.query_row("SELECT COUNT(*) FROM ha_remote WHERE body_present=1", [], |r| r.get(0))?,
            remote_bytes: db.query_row("SELECT COALESCE(SUM(body_bytes),0) FROM ha_remote WHERE body_present=1", [], |r| r.get(0))?,
            last_success: db.query_row("SELECT CAST(value AS INTEGER) FROM cluster_state WHERE key='ha_last_success'", [], |r| r.get(0)).optional()?,
            last_error: db.query_row("SELECT value FROM cluster_state WHERE key='ha_last_error'", [], |r| r.get(0)).optional()?,
        })
    }).await
}

/// Finish pending replication with the daemon stopped. No SMTP or relay is started.
pub async fn flush(store: &crate::store::Store, config: &crate::config::Config) -> Result<Status> {
    ensure!(
        config.replication.is_some(),
        "Strict replication is not configured"
    );
    let _lock = store.daemon_lock()?;
    crate::cluster::prepare(config, store).await?;
    initialize(store, config).await?;
    tokio::time::timeout(Duration::from_secs(180), async {
        loop {
            replica::synchronize(store).await?;
            let result = status(store).await?;
            if result.pending_updates == 0 && result.unprotected == 0 {
                return Ok(result);
            }
        }
    })
    .await
    .context("Replica flush deadline exceeded")?
}

pub async fn run(
    store: crate::store::Store,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let mut timer = tokio::time::interval(Duration::from_secs(2));
    loop {
        tokio::select! { _ = stop.changed() => break, _ = timer.tick() => {} }
        if *stop.borrow() {
            break;
        }
        if store.replication.get().is_none() {
            continue;
        }
        if let Err(error) = replica::synchronize(&store).await {
            if let Some(runtime) = store.replication.get() {
                runtime
                    .last_peer_seen
                    .store(0, std::sync::atomic::Ordering::Relaxed);
            }
            let error = crate::delivery_log::sanitize(&error.to_string(), 240).0;
            tracing::warn!(%error, "durable replication unavailable; strict acceptance remains required");
            let _ = store
                .run(move |db| {
                    db.execute(
                        "INSERT OR REPLACE INTO cluster_state VALUES('ha_last_error',?1)",
                        [error],
                    )?;
                    Ok(())
                })
                .await;
        }
    }
    Ok(())
}
