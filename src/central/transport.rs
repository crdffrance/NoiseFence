//! Bounded, authenticated worker metadata transport. Bodies stay on the MX pair.
use super::{
    history, logs,
    outbox::{Entry, Identity},
};
use serde::{Deserialize, Serialize};
pub const PROTOCOL: &str = "noisefence-management-1";
pub const REPLY_LIMIT: usize = 64 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Batch<T> {
    pub protocol: String,
    pub epoch: String,
    pub events: Vec<T>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt<T> {
    pub protocol: String,
    pub identity: Identity,
    pub receipts: Vec<T>,
}
pub type History = Batch<history::Event>;
pub type Logs = Batch<logs::Event>;
pub type HistoryReceipt = Receipt<Entry>;
pub type LogReceipt = Receipt<logs::Receipt>;

/// Each call transfers at most one bounded batch on each independent journal.
/// The HTTP client must already pin TLS/authentication to the coordinator origin.
pub async fn synchronize_metadata_once(
    store: &crate::store::Store,
    http: &reqwest::Client,
    url: &str,
) -> anyhow::Result<usize> {
    use anyhow::ensure;
    let (identity, events) = history::export(store).await?;
    let mut count = 0;
    if !events.is_empty() {
        let request = Batch {
            protocol: PROTOCOL.into(),
            epoch: identity.epoch.clone(),
            events,
        };
        let response = http
            .post(format!("{url}/api/v1/cluster/v3/history"))
            .json(&request)
            .timeout(std::time::Duration::from_secs(20))
            .send()
            .await?;
        let receipt: HistoryReceipt =
            crate::cluster::worker::bounded_json(response, REPLY_LIMIT).await?;
        ensure!(
            receipt.protocol == PROTOCOL && receipt.identity == identity,
            "Metadata acknowledgement authority mismatch"
        );
        ensure!(
            receipt.receipts.len() <= request.events.len()
                && receipt
                    .receipts
                    .iter()
                    .all(|r| request.events.iter().any(|e| e.receipt == *r)),
            "Unexpected metadata acknowledgement"
        );
        count += receipt.receipts.len();
        let acknowledged = receipt.receipts;
        store
            .run(move |db| super::outbox::acknowledge(db, &identity, &acknowledged))
            .await?;
    }
    let (identity, events) = logs::export(store).await?;
    if !events.is_empty() {
        let request = Batch {
            protocol: PROTOCOL.into(),
            epoch: identity.epoch.clone(),
            events,
        };
        let response = http
            .post(format!("{url}/api/v1/cluster/v3/logs"))
            .json(&request)
            .timeout(std::time::Duration::from_secs(20))
            .send()
            .await?;
        let receipt: LogReceipt =
            crate::cluster::worker::bounded_json(response, REPLY_LIMIT).await?;
        ensure!(
            receipt.protocol == PROTOCOL && receipt.identity == identity,
            "Transcript acknowledgement authority mismatch"
        );
        ensure!(
            receipt.receipts.len() <= request.events.len()
                && receipt
                    .receipts
                    .iter()
                    .all(|r| request.events.iter().any(|e| e.receipt == *r)),
            "Unexpected transcript acknowledgement"
        );
        count += receipt.receipts.len();
        logs::acknowledge(store, identity, receipt.receipts).await?;
    }
    Ok(count)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandPoll {
    pub protocol: String,
    pub epoch: String,
    pub receipts: Vec<crate::cluster::history::CommandResult>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandReply {
    pub protocol: String,
    pub identity: Identity,
    pub receipts: Vec<crate::cluster::history::CommandResult>,
    pub commands: Vec<crate::cluster::history::Command>,
}
/// Executions and receipts share the same local transaction. A failed network
/// acknowledgement is retried from disk before fetching further work.
pub async fn synchronize_commands_once(
    store: &crate::store::Store,
    http: &reqwest::Client,
    url: &str,
) -> anyhow::Result<usize> {
    use anyhow::ensure;
    let identity = store.read(|db| super::outbox::identity(db)).await?;
    let request = CommandPoll {
        protocol: PROTOCOL.into(),
        epoch: identity.epoch.clone(),
        receipts: super::commands::pending_receipts(store, &identity).await?,
    };
    let response = http
        .post(format!("{url}/api/v1/cluster/v3/commands"))
        .json(&request)
        .timeout(std::time::Duration::from_secs(20))
        .send()
        .await?;
    let reply: CommandReply = crate::cluster::worker::bounded_json(response, REPLY_LIMIT).await?;
    ensure!(
        reply.protocol == PROTOCOL && reply.identity == identity,
        "Command acknowledgement authority mismatch"
    );
    ensure!(
        reply.receipts.len() <= request.receipts.len()
            && reply.receipts.iter().all(|r| request
                .receipts
                .iter()
                .any(|e| e.id == r.id && e.result == r.result)),
        "Unexpected command acknowledgement"
    );
    let acknowledged = reply.receipts.len();
    super::commands::acknowledge_receipts(store, identity.clone(), reply.receipts).await?;
    let executed = super::commands::execute(store, identity, reply.commands).await?;
    Ok(acknowledged + executed.len())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyPoll {
    pub protocol: String,
    pub epoch: String,
    pub request: crate::cluster::activation::transport::Request,
}
/// The installer selects this transport only after epoch enrollment and backend
/// fencing. Absence means the existing SQLite protocol, never automatic fallback.
pub async fn remote_enabled(store: &crate::store::Store) -> anyhow::Result<bool> {
    use anyhow::ensure;
    use rusqlite::OptionalExtension;
    store
        .read(|db| {
            let value: Option<String> = db
                .query_row(
                    "SELECT value FROM cluster_state WHERE key='management_transport'",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            if let Some(value) = value {
                ensure!(value == PROTOCOL, "Unknown management transport");
                super::outbox::identity(db)?;
                Ok(true)
            } else {
                Ok(false)
            }
        })
        .await
}
pub async fn run_remote(
    store: crate::store::Store,
    http: reqwest::Client,
    url: String,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    loop {
        for commands in [true, false] {
            tokio::select! {
                _=stop.changed()=>return Ok(()),
                result=async {if commands {synchronize_commands_once(&store,&http,&url).await} else {synchronize_metadata_once(&store,&http,&url).await}}=> {
                    if let Err(error)=result {tracing::warn!(error=%crate::delivery_log::sanitize(&error.to_string(),400).0,"central management synchronization pending");}
                }
            }
        }
        tokio::select! {_=stop.changed()=>return Ok(()),_=tokio::time::sleep(std::time::Duration::from_secs(2))=>{}}
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyReply {
    pub protocol: String,
    pub identity: Identity,
    pub reply: crate::cluster::activation::transport::Reply,
}
pub async fn run_local(
    store: crate::store::Store,
    central: super::Central,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    loop {
        for commands in [true, false] {
            tokio::select! {
                _=stop.changed()=>return Ok(()),
                result=async {if commands {central.synchronize_commands_once(&store).await} else {central.synchronize_once(&store).await}}=> {
                    if let Err(error)=result {tracing::warn!(error=%crate::delivery_log::sanitize(&error.to_string(),400).0,"central management synchronization pending");}
                }
            }
        }
        tokio::select! {_=stop.changed()=>return Ok(()),_=tokio::time::sleep(std::time::Duration::from_secs(2))=>{}}
    }
}
