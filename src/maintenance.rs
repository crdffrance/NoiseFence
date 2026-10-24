//! Bounded candidate-runtime validation behind an external maintenance reservation.
//! Only authenticated probes are served. No SMTP, relay, policy driver, retention,
//! command consumption or browser API is started by this entry point.
use crate::{
    central::{binding::Binding, outbox::Identity, selection::Selection},
    cluster::activation::{Epoch, participant::Local},
    config::Config,
    control::Controller,
    store::Store,
};
use anyhow::{Context, Result, ensure};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs::OpenOptions,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

pub const PROTOCOL: &str = "noisefence-maintenance-validation-1";
const REPLICA_PATH: &str = "/api/v1/replication/v1/validation";
const POLICY_PATH: &str = "/api/v1/cluster/v3/validation";
const FRESH: Duration = Duration::from_secs(15);

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Peer {
    pub identity: Identity,
    pub binary_sha256: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub protocol: String,
    pub operation: String,
    pub selection: Selection,
    pub policy: Epoch,
    pub peer: Peer,
    pub config_sha256: String,
    pub binary_sha256: String,
    pub expires_at: i64,
}
fn canonical_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|v| v.to_string() == value)
}
impl Plan {
    pub fn validate(&self, now: i64) -> Result<()> {
        self.selection.validate()?;
        self.policy.validate()?;
        ensure!(
            self.protocol == PROTOCOL && canonical_uuid(&self.operation),
            "Invalid maintenance operation"
        );
        ensure!(
            self.expires_at > now && self.expires_at <= now.saturating_add(3600),
            "Maintenance authorization expired or exceeds one hour"
        );
        ensure!(
            crate::cluster::valid_id(&self.peer.identity.node)
                && canonical_uuid(&self.peer.identity.epoch)
                && self.peer.identity.node != self.selection.node.node,
            "Invalid maintenance peer"
        );
        for digest in [
            &self.peer.binary_sha256,
            &self.config_sha256,
            &self.binary_sha256,
        ] {
            ensure!(
                crate::compatibility::valid_hash(digest),
                "Invalid maintenance checksum"
            );
        }
        ensure!(
            self.policy.sequence > self.selection.baseline.sequence
                || self.policy == self.selection.baseline,
            "Maintenance policy predates selected authority"
        );
        Ok(())
    }
}

/// This is a root authorization, not a message/API-supplied path. Check all
/// ancestors and use O_NOFOLLOW/O_NONBLOCK so links and FIFOs cannot supply it.
fn protected_file(path: &Path, maximum: u64) -> Result<std::fs::File> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "Physical absolute maintenance path required"
    );
    for parent in path.ancestors().skip(1) {
        let info = std::fs::symlink_metadata(parent)?;
        ensure!(
            info.is_dir() && info.uid() == 0 && info.mode() & 0o022 == 0,
            "Maintenance path ancestors must be protected by root"
        );
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let info = file.metadata()?;
    ensure!(
        info.is_file()
            && info.uid() == 0
            && info.nlink() == 1
            && info.mode() & 0o022 == 0
            && info.len() <= maximum,
        "Unsafe maintenance file"
    );
    Ok(file)
}
fn digest_file(file: std::fs::File) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    let mut file = file;
    let mut block = [0u8; 65536];
    loop {
        let count = file.read(&mut block)?;
        if count == 0 {
            break;
        }
        digest.update(&block[..count]);
    }
    Ok(hex::encode(digest.finalize()))
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Probe {
    protocol: String,
    operation: String,
    node: Identity,
    database: Binding,
    policy: Epoch,
    version: String,
    binary_sha256: String,
    machine: String,
    nonce: String,
}
struct Session {
    plan: Plan,
    config: Arc<Config>,
    store: Store,
    // Keep the actual verified engine/models resident throughout validation.
    control: Arc<Controller>,
    replica: crate::ha::Runtime,
    started: Instant,
    lifetime: Duration,
    replica_seen: AtomicU64,
    policy_seen: AtomicU64,
    capacity: Arc<tokio::sync::Semaphore>,
}
impl Session {
    fn live(&self) -> Result<()> {
        ensure!(
            crate::now() < self.plan.expires_at && self.started.elapsed() < self.lifetime,
            "Maintenance authorization expired"
        );
        Ok(())
    }
    fn seen(&self, cell: &AtomicU64) {
        cell.store(
            self.started.elapsed().as_millis() as u64 + 1,
            Ordering::Release,
        );
    }
    fn fresh(&self, cell: &AtomicU64) -> bool {
        let seen = cell.load(Ordering::Acquire);
        let now = self.started.elapsed().as_millis() as u64 + 1;
        seen > 0 && seen <= now && now - seen <= FRESH.as_millis() as u64
    }
    fn probe(&self, nonce: String) -> Probe {
        Probe {
            protocol: PROTOCOL.into(),
            operation: self.plan.operation.clone(),
            node: self.plan.selection.node.clone(),
            database: self.plan.selection.database.clone(),
            policy: self.plan.policy.clone(),
            version: env!("CARGO_PKG_VERSION").into(),
            binary_sha256: self.plan.binary_sha256.clone(),
            machine: self.replica.machine.clone(),
            nonce,
        }
    }
    fn check_probe(&self, probe: &Probe, nonce: Option<&str>) -> Result<()> {
        self.live()?;
        ensure!(
            probe.protocol == PROTOCOL
                && probe.operation == self.plan.operation
                && probe.node == self.plan.peer.identity
                && probe.database == self.plan.selection.database
                && probe.policy == self.plan.policy
                && probe.version == env!("CARGO_PKG_VERSION")
                && probe.binary_sha256 == self.plan.peer.binary_sha256
                && canonical_uuid(&probe.nonce)
                && nonce.is_none_or(|n| n == probe.nonce),
            "Maintenance peer binding mismatch"
        );
        ensure!(
            self.replica.settings.allow_loopback_http
                || (crate::compatibility::valid_hash(&probe.machine)
                    && probe.machine != self.replica.machine),
            "Maintenance replica requires an independent machine"
        );
        Ok(())
    }
    async fn local(&self) -> Result<()> {
        self.live()?;
        let selection = self.plan.selection.clone();
        let epoch = self.plan.policy.clone();
        self.store
            .read(move |db| {
                ensure!(
                    Selection::read(db)?.as_ref() == Some(&selection),
                    "Selected maintenance authority changed"
                );
                let local = Local::read(db)?.context("Maintenance participant missing")?;
                ensure!(
                    local.authority().released()
                        && local.installed_epoch() == &epoch
                        && local.authority().current_epoch() == epoch,
                    "Maintenance policy is pending or changed"
                );
                Ok(())
            })
            .await?;
        let snapshot = self.control.snapshot();
        ensure!(
            snapshot.activation_epoch.as_ref() == Some(&self.plan.policy)
                && self.control.cluster_digest() == self.plan.policy.digest,
            "Loaded maintenance runtime differs"
        );
        if let Some(central) = self.store.management() {
            central
                .validate_maintenance_policy(
                    &self.plan.selection.node,
                    &self.plan.peer.identity,
                    &self.plan.policy,
                    None,
                )
                .await?;
        }
        // A database wait must not extend the root authorization.
        self.live()
    }
    async fn replica_probe(&self) -> Result<()> {
        let challenge = self.probe(uuid::Uuid::new_v4().to_string());
        let response = self
            .replica
            .http
            .post(format!(
                "{}{}",
                self.replica.settings.peer_url.trim_end_matches('/'),
                REPLICA_PATH
            ))
            .bearer_auth(&self.replica.key)
            .json(&challenge)
            .timeout(Duration::from_secs(5))
            .send()
            .await?;
        let reply: Probe = crate::cluster::worker::bounded_json(response, 4096).await?;
        self.check_probe(&reply, Some(&challenge.nonce))?;
        self.seen(&self.replica_seen);
        Ok(())
    }
    async fn policy_probe(&self) -> Result<()> {
        let settings = self.config.cluster.as_ref().context("Cluster missing")?;
        let key = crate::cluster::protocol::credential(
            settings
                .credential_file
                .as_deref()
                .context("Worker credential missing")?,
        )?;
        let challenge = self.probe(uuid::Uuid::new_v4().to_string());
        let request = self
            .replica
            .http
            .post(format!(
                "{}{}",
                settings
                    .coordinator_url
                    .as_deref()
                    .context("Coordinator missing")?
                    .trim_end_matches('/'),
                POLICY_PATH
            ))
            .bearer_auth(key)
            .header("x-noisefence-node", &self.plan.selection.node.node)
            .json(&challenge)
            .timeout(Duration::from_secs(5));
        let response =
            crate::central::binding::request(request, Some(&self.plan.selection.database))?
                .send()
                .await?;
        crate::central::binding::check_headers(
            response.headers(),
            Some(&self.plan.selection.database),
        )?;
        let reply: Probe = crate::cluster::worker::bounded_json(response, 4096).await?;
        self.check_probe(&reply, Some(&challenge.nonce))?;
        self.seen(&self.policy_seen);
        Ok(())
    }
    async fn observe(self: Arc<Self>, mut stop: tokio::sync::watch::Receiver<bool>) -> Result<()> {
        loop {
            self.live()?;
            let check = async {
                self.local().await?;
                let replica = self.replica_probe();
                let policy = async {
                    if crate::cluster::is_worker(&self.config) {
                        self.policy_probe().await
                    } else {
                        Ok(())
                    }
                };
                let (r, p) = tokio::join!(replica, policy);
                if r.is_err() {
                    self.replica_seen.store(0, Ordering::Release);
                }
                if p.is_err() {
                    self.policy_seen.store(0, Ordering::Release);
                }
                r.and(p)
            };
            tokio::select! {
                _ = stop.changed() => return Ok(()),
                result = check => if let Err(error) = result {
                    // Never retain a previous ready observation across a failed check.
                    self.replica_seen.store(0, Ordering::Release);
                    self.policy_seen.store(0, Ordering::Release);
                    tracing::warn!(error=%crate::delivery_log::sanitize(&error.to_string(),240).0, "maintenance validation incomplete");
                }
            }
            tokio::select! { _ = stop.changed() => return Ok(()), _ = tokio::time::sleep(Duration::from_secs(2)) => {} }
        }
    }
}
fn secret(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("authorization")?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}
fn same_secret(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0, |x, (a, b)| x | (a ^ b)) == 0
}
fn unavailable() -> Response {
    (StatusCode::SERVICE_UNAVAILABLE, [("retry-after", "5")], Json(json!({"error":"Maintenance validation: SMTP, delivery and administration are disabled."}))).into_response()
}
fn refused(error: anyhow::Error) -> Response {
    tracing::warn!(error=%crate::delivery_log::sanitize(&error.to_string(),240).0, "maintenance probe refused");
    (
        StatusCode::CONFLICT,
        Json(json!({"error":"Maintenance validation binding refused."})),
    )
        .into_response()
}
async fn guard(State(s): State<Arc<Session>>, request: Request, next: Next) -> Response {
    let Ok(_permit) = s.capacity.clone().try_acquire_owned() else {
        return unavailable();
    };
    if s.live().is_err() {
        return unavailable();
    }
    match tokio::time::timeout(Duration::from_secs(5), next.run(request)).await {
        Ok(response) if s.live().is_ok() => response,
        _ => unavailable(),
    }
}
async fn health(State(s): State<Arc<Session>>) -> Json<Value> {
    let local = s.local().await.is_ok();
    Json(
        json!({"status":"maintenance_validation","smtp_ready":false,"delivery_enabled":false,
        "administration_enabled":false,"validation_ready":local && s.fresh(&s.replica_seen) && s.fresh(&s.policy_seen),
        "operation":s.plan.operation,"node":s.plan.selection.node.node,"version":env!("CARGO_PKG_VERSION"),
        "binary_sha256":s.plan.binary_sha256,"local_runtime_valid":local,
        "replica_probe_fresh":s.fresh(&s.replica_seen),"policy_probe_fresh":s.fresh(&s.policy_seen),
        "checked_at":crate::now(),"expires_at":s.plan.expires_at}),
    )
}
async fn replica_probe(
    State(s): State<Arc<Session>>,
    headers: HeaderMap,
    Json(probe): Json<Probe>,
) -> Response {
    if !secret(&headers).is_some_and(|key| same_secret(key, &s.replica.key)) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let check = async {
        s.check_probe(&probe, None)?;
        s.local().await
    };
    match check.await {
        Ok(()) => Json(s.probe(probe.nonce)).into_response(),
        Err(error) => refused(error),
    }
}
async fn policy_probe(
    State(s): State<Arc<Session>>,
    headers: HeaderMap,
    Json(probe): Json<Probe>,
) -> Response {
    let Some(central) = s.store.management() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let check = async {
        crate::central::binding::check_headers(&headers, Some(&s.plan.selection.database))?;
        s.check_probe(&probe, None)?;
        ensure!(
            headers
                .get("x-noisefence-node")
                .and_then(|v| v.to_str().ok())
                == Some(probe.node.node.as_str()),
            "Worker header mismatch"
        );
        let key = secret(&headers).context("Worker credential required")?;
        ensure!(
            key.len() == 64 && key.bytes().all(|b| b.is_ascii_hexdigit()),
            "Invalid worker credential"
        );
        let node = central
            .authenticate_node(&probe.node.node, &crate::message::digest(key.as_bytes()))
            .await?
            .context("Worker credential refused")?;
        ensure!(
            node.identity() == &s.plan.peer.identity,
            "Worker epoch mismatch"
        );
        s.local().await?;
        central
            .validate_maintenance_policy(
                &s.plan.selection.node,
                &s.plan.peer.identity,
                &s.plan.policy,
                Some(&node),
            )
            .await?;
        Ok::<_, anyhow::Error>(())
    };
    match check.await {
        Ok(()) => {
            s.seen(&s.policy_seen);
            let mut response = Json(s.probe(probe.nonce)).into_response();
            if let Ok(Some(value)) =
                crate::central::binding::header_value(Some(&s.plan.selection.database))
            {
                response
                    .headers_mut()
                    .insert(crate::central::binding::HEADER, value);
            }
            response
        }
        Err(error) => refused(error),
    }
}
fn router(s: Arc<Session>) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route(REPLICA_PATH, post(replica_probe))
        .route(POLICY_PATH, post(policy_probe))
        .fallback(|| async { unavailable() })
        .layer(DefaultBodyLimit::max(4096))
        .layer(middleware::from_fn_with_state(s.clone(), guard))
        .with_state(s)
}

/// Explicit, temporary daemon mode; root's reservation remains responsible for
/// keeping the normal service and timers stopped. This mode never removes it.
pub async fn serve(config_path: &Path, plan_path: &Path) -> Result<()> {
    let plan: Plan = serde_json::from_reader(protected_file(plan_path, 16384)?)?;
    let authorized_at = crate::now();
    plan.validate(authorized_at)?;
    let started = Instant::now();
    let lifetime = Duration::from_secs((plan.expires_at - authorized_at) as u64);
    ensure!(
        digest_file(protected_file(config_path, 1024 * 1024)?)? == plan.config_sha256,
        "Authorized configuration differs"
    );
    let executable = std::env::current_exe()?.canonicalize()?;
    ensure!(
        digest_file(protected_file(&executable, 2 * 1024 * 1024 * 1024)?)? == plan.binary_sha256,
        "Authorized binary differs"
    );
    let config = Arc::new(Config::load(config_path)?);
    ensure!(
        config.management.is_some()
            && config.replication.is_some()
            && config.web.listen.ip().is_loopback(),
        "Validation requires a selected replicated native MX and loopback API"
    );
    let cluster = config
        .cluster
        .as_ref()
        .context("Cluster identity missing")?;
    ensure!(
        cluster.node_id == plan.selection.node.node
            && cluster.role == plan.selection.role
            && config.replication.as_ref().unwrap().peer_id == plan.peer.identity.node,
        "Validation plan names another node"
    );
    // Acquire before opening the writable store: do not run schema initialization
    // beside the normal daemon just because the requested listener differs.
    let _lock = Store::daemon_lock_at(&config.data_dir)?;
    let store =
        crate::central::bootstrap::open(&config, crate::central::bootstrap::Purpose::Runtime)?;
    let expected = plan.selection.clone();
    let epoch = plan.policy.clone();
    store
        .read(move |db| {
            ensure!(
                Selection::read(db)?.as_ref() == Some(&expected),
                "Maintenance selection differs"
            );
            let local = Local::read(db)?.context("Maintenance participant missing")?;
            ensure!(
                local.authority().released()
                    && local.installed_epoch() == &epoch
                    && local.authority().current_epoch() == epoch,
                "Resolve pending policy activation before validation"
            );
            Ok(())
        })
        .await?;
    let control = Controller::load(config.clone(), store.clone()).await?;
    let s = Arc::new(Session {
        replica: crate::ha::Runtime::new(&config)?,
        plan,
        config,
        store,
        control,
        started,
        lifetime,
        replica_seen: AtomicU64::new(0),
        policy_seen: AtomicU64::new(0),
        capacity: Arc::new(tokio::sync::Semaphore::new(4)),
    });
    s.local().await?;
    let listener = tokio::net::TcpListener::bind(s.config.web.listen).await?;
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let (stop, rx) = tokio::sync::watch::channel(false);
    let mut api = tokio::spawn(
        axum::serve(listener, router(s.clone()))
            .with_graceful_shutdown(async move {
                let mut rx = rx;
                let _ = rx.changed().await;
            })
            .into_future(),
    );
    let mut observer = tokio::spawn(s.clone().observe(stop.subscribe()));
    tracing::info!(operation=%s.plan.operation,node=%s.plan.selection.node.node,"maintenance validation started; SMTP and administrative APIs disabled");
    let result = tokio::select! {
        _ = term.recv() => Ok(()), _ = tokio::signal::ctrl_c() => Ok(()),
        _ = tokio::time::sleep(s.lifetime.saturating_sub(s.started.elapsed())) => Err(anyhow::anyhow!("Maintenance validation authorization expired")),
        result = &mut api => match result {
            Ok(Err(error)) => Err(error.into()),
            Err(error) => Err(error.into()),
            Ok(Ok(())) => Err(anyhow::anyhow!("Maintenance API stopped unexpectedly")),
        },
        result = &mut observer => match result {
            Ok(Err(error)) => Err(error),
            Err(error) => Err(error.into()),
            Ok(Ok(())) => Err(anyhow::anyhow!("Maintenance observer stopped unexpectedly")),
        },
    };
    let _ = stop.send(true);
    // Only await unfinished handles; polling a completed JoinHandle again panics.
    if !api.is_finished() {
        let _ = tokio::time::timeout(Duration::from_secs(6), &mut api).await;
    }
    if !observer.is_finished() {
        let _ = tokio::time::timeout(Duration::from_secs(6), &mut observer).await;
    }
    api.abort();
    observer.abort();
    result
}

#[cfg(test)]
mod tests;
