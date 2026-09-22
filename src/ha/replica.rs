use super::{PROTOCOL, Runtime};
use crate::{
    now,
    store::{QueueVariant, Store},
};
use anyhow::{Context, Result, ensure};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, path::PathBuf, sync::Arc};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Delivery {
    pub address: String,
    pub destination: String,
    pub hosts: Vec<String>,
    pub status: String,
    pub attempts: u32,
    pub next_attempt: i64,
    pub error: Option<String>,
    pub dsn_id: Option<String>,
    pub action: String,
    pub held_until: Option<i64>,
    pub released_at: Option<i64>,
    pub filtering: Option<serde_json::Value>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub protocol: String,
    pub owner: String,
    pub id: String,
    pub generation: i64,
    pub confirmed: bool,
    pub created: i64,
    pub sender: String,
    pub scan: serde_json::Value,
    pub is_dsn: bool,
    pub body_hash: Option<String>,
    pub body_bytes: u64,
    pub deliveries: Vec<Delivery>,
}
pub fn valid_id(id: &str) -> bool {
    uuid::Uuid::parse_str(id).is_ok_and(|v| v.to_string() == id)
        || id
            .strip_prefix("dsn-")
            .is_some_and(|n| n.parse::<i64>().is_ok_and(|v| v > 0 && v.to_string() == n))
}
impl Manifest {
    pub fn validate(&self, runtime: &Runtime) -> Result<()> {
        ensure!(
            self.protocol == PROTOCOL
                && self.owner == runtime.settings.peer_id
                && valid_id(&self.id),
            "Invalid replica identity"
        );
        ensure!(
            (0..=1_000_000_000_000_000).contains(&self.generation)
                && self.confirmed == (self.generation > 0),
            "Invalid replica generation"
        );
        ensure!(
            self.created >= 0
                && self.created <= now() + 300
                && (self.sender.is_empty() || crate::config::valid_address(&self.sender)),
            "Invalid envelope"
        );
        ensure!(
            !self.id.starts_with("dsn-") || (self.is_dsn && self.sender.is_empty()),
            "Legacy identifier reserved for local notifications"
        );
        ensure!(
            !self.deliveries.is_empty() && self.deliveries.len() <= 100,
            "Invalid recipient count"
        );
        ensure!(
            self.body_bytes <= runtime.max_message_bytes
                && self
                    .body_hash
                    .as_ref()
                    .is_none_or(|h| crate::compatibility::valid_hash(h)),
            "Invalid body manifest"
        );
        ensure!(
            self.body_hash.is_some() || (self.confirmed && self.body_bytes == 0 && self.resolved()),
            "Unresolved replica needs a body"
        );
        let scan: crate::engine::Scan = serde_json::from_value(self.scan.clone())?;
        ensure!(
            scan.score.is_finite() && (0.0..=100.0).contains(&scan.score),
            "Invalid score"
        );
        let mut addresses = BTreeSet::new();
        for d in &self.deliveries {
            ensure!(
                crate::config::valid_address(&d.address)
                    && crate::config::valid_address(&d.destination)
                    && addresses.insert(&d.address),
                "Invalid recipient"
            );
            ensure!(
                !d.hosts.is_empty()
                    && d.hosts.len() <= 20
                    && d.hosts
                        .iter()
                        .all(|h| crate::config::endpoint(h, 25).is_some()),
                "Invalid relay route"
            );
            ensure!(
                [
                    "pending",
                    "sending",
                    "delivered",
                    "failed",
                    "notified",
                    "dsn_suppressed",
                    "quarantined",
                    "discarded",
                    "expired"
                ]
                .contains(&d.status.as_str()),
                "Invalid delivery state"
            );
            ensure!(
                ["deliver", "tag", "quarantine"].contains(&d.action.as_str())
                    && d.error.as_ref().is_none_or(|s| s.len() <= 8192),
                "Invalid delivery policy"
            );
            ensure!(
                d.dsn_id.as_ref().is_none_or(|id| valid_id(id)),
                "Invalid linked notification"
            );
        }
        ensure!(
            serde_json::to_vec(self)?.len() <= 3 * 1024 * 1024,
            "Replica metadata too large"
        );
        Ok(())
    }
    pub fn resolved(&self) -> bool {
        self.deliveries
            .iter()
            .all(|d| !["pending", "sending", "failed", "quarantined"].contains(&d.status.as_str()))
    }
    pub(crate) fn identity(&self) -> BTreeSet<(&str, &str, &Vec<String>)> {
        self.deliveries
            .iter()
            .map(|d| (d.address.as_str(), d.destination.as_str(), &d.hosts))
            .collect()
    }
}

#[derive(Serialize, Deserialize)]
pub struct Receipt {
    pub protocol: String,
    pub node_id: String,
    pub machine: String,
    pub id: String,
    pub generation: i64,
}
pub fn receipt(runtime: &Runtime, id: String, generation: i64) -> Receipt {
    Receipt {
        protocol: PROTOCOL.into(),
        node_id: runtime.node_id.clone(),
        machine: runtime.machine.clone(),
        id,
        generation,
    }
}
pub fn body_path(store: &Store, owner: &str, id: &str) -> PathBuf {
    store
        .root
        .join("replicas")
        .join(owner)
        .join(format!("{id}.eml"))
}
pub fn request(runtime: &Runtime, path: &str) -> reqwest::RequestBuilder {
    runtime
        .http
        .post(format!(
            "{}/api/v1/replication/v1/{path}",
            runtime.settings.peer_url.trim_end_matches('/')
        ))
        .bearer_auth(&runtime.key)
        .header("x-noisefence-node", &runtime.node_id)
        .header("x-noisefence-machine", &runtime.machine)
}
async fn acknowledged(
    runtime: &Runtime,
    mut response: reqwest::Response,
    id: &str,
    generation: i64,
) -> Result<()> {
    ensure!(
        response.status().is_success(),
        "Replica HTTP {}",
        response.status().as_u16()
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            bytes.len() + chunk.len() <= 4096,
            "Oversized replica receipt"
        );
        bytes.extend_from_slice(&chunk);
    }
    let r: Receipt = serde_json::from_slice(&bytes)?;
    ensure!(
        r.protocol == PROTOCOL
            && r.node_id == runtime.settings.peer_id
            && r.id == id
            && r.generation == generation,
        "Mismatched durable receipt"
    );
    ensure!(
        runtime.settings.allow_loopback_http || r.machine != runtime.machine,
        "Replica resides on the same machine"
    );
    runtime
        .last_peer_seen
        .store(now(), std::sync::atomic::Ordering::Relaxed);
    Ok(())
}
async fn upload(
    runtime: &Runtime,
    id: &str,
    hash: &str,
    body: reqwest::Body,
    bytes: u64,
) -> Result<()> {
    let response = request(runtime, &format!("body/{id}"))
        .header("x-noisefence-sha256", hash)
        .header("x-noisefence-bytes", bytes)
        .body(body)
        .send()
        .await?;
    acknowledged(runtime, response, id, 0).await
}
async fn update(runtime: &Runtime, manifest: &Manifest) -> Result<()> {
    let response = request(runtime, "manifest").json(manifest).send().await?;
    acknowledged(runtime, response, &manifest.id, manifest.generation).await
}

/// Remote candidates are inert, including when the owner fails before local commit.
pub async fn prepare(store: &Store, sender: &str, variants: &[QueueVariant]) -> Result<()> {
    let Some(runtime) = store.replication.get() else {
        return Ok(());
    };
    let _permit = runtime
        .capacity
        .clone()
        .try_acquire_owned()
        .context("Replication busy; retry SMTP")?;
    let batch = async {
        for v in variants {
            ensure!(
                valid_id(&v.id) && v.raw.len() as u64 <= runtime.max_message_bytes,
                "Invalid replica body"
            );
            let hash = v.raw.digest();
            let deliveries = v
                .recipients
                .iter()
                .map(|(r, a)| {
                    let applied = a.as_ref().map(|a| &a.action).or(v.scan.action.as_ref());
                    let action = applied.map(|a| a.effective).unwrap_or_default();
                    let held = action == crate::actions::Action::Quarantine;
                    Ok(Delivery {
                        address: r.address.clone(),
                        destination: r.destination.clone(),
                        hosts: r.hosts.clone(),
                        status: if held { "quarantined" } else { "pending" }.into(),
                        attempts: 0,
                        next_attempt: now(),
                        error: None,
                        dsn_id: None,
                        action: match action {
                            crate::actions::Action::Deliver => "deliver",
                            crate::actions::Action::Tag => "tag",
                            crate::actions::Action::Quarantine => "quarantine",
                        }
                        .into(),
                        held_until: held.then(|| {
                            now() + 86400 * i64::from(applied.map_or(14, |a| a.quarantine_days))
                        }),
                        released_at: None,
                        filtering: a.as_ref().map(serde_json::to_value).transpose()?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            let manifest = Manifest {
                protocol: PROTOCOL.into(),
                owner: runtime.node_id.clone(),
                id: v.id.clone(),
                generation: 0,
                confirmed: false,
                created: now(),
                sender: sender.into(),
                scan: serde_json::to_value(&v.scan)?,
                is_dsn: false,
                body_hash: Some(hash.clone()),
                body_bytes: v.raw.len() as u64,
                deliveries,
            };
            upload(runtime, &v.id, &hash, v.raw.http_body(), v.raw.len() as u64).await?;
            update(runtime, &manifest).await?;
        }
        Ok::<_, anyhow::Error>(())
    };
    tokio::time::timeout(
        std::time::Duration::from_secs(runtime.settings.timeout_seconds),
        batch,
    )
    .await
    .context("Replica batch deadline exceeded; retry SMTP")?
}

pub(crate) fn read_deliveries(db: &rusqlite::Connection, id: &str) -> Result<Vec<Delivery>> {
    let mut q=db.prepare("SELECT d.address,d.destination,d.hosts,d.status,d.attempts,d.next_attempt,d.error,d.dsn_id,COALESCE(p.action,'deliver'),p.held_until,p.released_at,f.assessment FROM deliveries d LEFT JOIN delivery_policy p ON p.delivery_id=d.id LEFT JOIN delivery_filtering f ON f.delivery_id=d.id WHERE d.message_id=?1 ORDER BY d.id")?;
    let mut rows = q.query([id])?;
    let mut deliveries = Vec::new();
    while let Some(r) = rows.next()? {
        deliveries.push(Delivery {
            address: r.get(0)?,
            destination: r.get(1)?,
            hosts: serde_json::from_str(&r.get::<_, String>(2)?)?,
            status: r.get(3)?,
            attempts: r.get(4)?,
            next_attempt: r.get(5)?,
            error: r.get(6)?,
            dsn_id: r.get(7)?,
            action: r.get(8)?,
            held_until: r.get(9)?,
            released_at: r.get(10)?,
            filtering: r
                .get::<_, Option<String>>(11)?
                .map(|s| serde_json::from_str(&s))
                .transpose()?,
        });
    }
    Ok(deliveries)
}

pub async fn export(store: &Store, id: String) -> Result<Manifest> {
    let node = store
        .replication
        .get()
        .context("Replication unavailable")?
        .node_id
        .clone();
    let root = store.root.clone();
    store.read(move |db| {
        let (generation,created,sender,scan,is_dsn,present):(i64,i64,String,String,bool,bool) = db.query_row("SELECT h.generation,m.created,m.sender,m.scan,m.is_dsn,m.raw_present FROM ha_local h JOIN messages m ON m.id=h.message_id WHERE m.id=?1 AND NOT EXISTS(SELECT 1 FROM cluster_origin WHERE message_id=m.id)",[&id],|r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?)))?;
        let deliveries=read_deliveries(db,&id)?;
        let (body_bytes,body_hash)=if present { let (n,h)=crate::cluster::artifacts::file_digest(&root.join("spool").join(format!("{id}.eml")))?;(n,Some(h)) } else {(0,None)};
        Ok(Manifest{protocol:PROTOCOL.into(),owner:node,id,generation,confirmed:true,created,sender,scan:serde_json::from_str(&scan)?,is_dsn,body_hash,body_bytes,deliveries})
    }).await
}

pub async fn synchronize_message(store: &Store, id: String) -> Result<()> {
    let Some(runtime) = store.replication.get() else {
        return Ok(());
    };
    let _permit = runtime
        .capacity
        .clone()
        .try_acquire_owned()
        .context("Replication capacity occupied")?;
    let manifest = export(store, id.clone()).await?;
    if let Some(hash) = &manifest.body_hash {
        let file = tokio::fs::File::open(store.raw_path(&id)).await?;
        upload(
            runtime,
            &id,
            hash,
            reqwest::Body::wrap_stream(tokio_util::io::ReaderStream::new(file)),
            manifest.body_bytes,
        )
        .await?;
    }
    update(runtime, &manifest).await?;
    store
        .run(move |db| {
            let tx = db.transaction()?;
            tx.execute(
                "UPDATE ha_local SET acked=MAX(acked,?2) WHERE message_id=?1",
                params![id, manifest.generation],
            )?;
            tx.execute(
                "INSERT OR REPLACE INTO cluster_state VALUES('ha_last_success',?1)",
                [now().to_string()],
            )?;
            tx.execute("DELETE FROM cluster_state WHERE key='ha_last_error'", [])?;
            tx.commit()?;
            Ok(())
        })
        .await
}
pub async fn synchronize(store: &Store) -> Result<()> {
    cleanup(store).await?;
    if let Some(runtime) = store.replication.get() {
        let response = request(runtime, "ping").send().await?;
        acknowledged(runtime, response, "ping", 0).await?;
        store
            .run(|db| {
                db.execute(
                    "INSERT OR REPLACE INTO cluster_state VALUES('ha_last_success',?1)",
                    [now().to_string()],
                )?;
                db.execute("DELETE FROM cluster_state WHERE key='ha_last_error'", [])?;
                Ok(())
            })
            .await?;
    }
    let ids=store.read(|db| Ok(db.prepare("SELECT message_id FROM ha_local WHERE generation>acked ORDER BY CASE WHEN acked=0 THEN 0 ELSE 1 END,generation LIMIT 12")?.query_map([],|r|r.get::<_,String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?)).await?;
    for id in ids {
        synchronize_message(store, id).await?;
    }
    Ok(())
}

/// Candidates with a manifest are retained until an operator resolves ownership.
/// Only unreferenced uploads and acknowledged terminal tombstones can be pruned.
pub async fn cleanup(store: &Store) -> Result<()> {
    let Some(runtime) = store.replication.get() else {
        return Ok(());
    };
    let Ok(_guard) = runtime.serial.clone().try_lock_owned() else {
        return Ok(());
    };
    let rows=store.read(|db|Ok(db.prepare("SELECT b.owner,b.id FROM ha_blobs b WHERE b.present=0 OR EXISTS(SELECT 1 FROM ha_remote r WHERE r.owner=b.owner AND r.id=b.id AND r.body_present=0) OR (b.updated<?1 AND NOT EXISTS(SELECT 1 FROM ha_remote r WHERE r.owner=b.owner AND r.id=b.id)) LIMIT 128")?.query_map([now()-86400],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?)))?.collect::<rusqlite::Result<Vec<_>>>()?)).await?;
    for (owner, id) in rows {
        ensure!(
            crate::cluster::valid_id(&owner) && valid_id(&id),
            "Invalid replica catalog path"
        );
        match tokio::fs::remove_file(body_path(store, &owner, &id)).await {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        store
            .run(move |db| {
                db.execute(
                    "DELETE FROM ha_blobs WHERE owner=?1 AND id=?2",
                    params![owner, id],
                )?;
                Ok(())
            })
            .await?;
    }
    store
        .run(|db| {
            db.execute(
                "DELETE FROM ha_remote WHERE body_present=0 AND updated<?1",
                [now() - 30 * 86400],
            )?;
            Ok(())
        })
        .await
}

pub async fn ingest(store: &Store, runtime: Arc<Runtime>, manifest: Manifest) -> Result<Receipt> {
    manifest.validate(&runtime)?;
    let owner = manifest.owner.clone();
    let id = manifest.id.clone();
    let generation = manifest.generation;
    let root = store.root.clone();
    store.run(move |db| {
        let tx=db.transaction()?;
        let previous:Option<String>=tx.query_row("SELECT manifest FROM ha_remote WHERE owner=?1 AND id=?2",params![manifest.owner,manifest.id],|r|r.get(0)).optional()?;
        if let Some(raw)=previous {
            let old:Manifest=serde_json::from_str(&raw)?;
            // Initial candidate timestamps can precede the actual queue transaction.
            ensure!(old.sender==manifest.sender && old.is_dsn==manifest.is_dsn && old.identity()==manifest.identity() && (!old.confirmed || old.created==manifest.created), "Replica envelope changed");
            if old.generation>=manifest.generation {
                ensure!(old.generation!=manifest.generation || serde_json::to_value(&old)?==serde_json::to_value(&manifest)?, "Conflicting replica generation");
                ensure!(old.generation==manifest.generation,"Stale replica generation");
                return Ok(());
            }
            ensure!(old.body_hash.is_none() || manifest.body_hash.is_none() || old.body_hash==manifest.body_hash, "Replica body changed");
            ensure!(old.body_hash.is_some() || manifest.body_hash.is_none(), "Retired replica cannot be resurrected");
        }
        if let Some(hash)=&manifest.body_hash {
            let blob:Option<(String,u64,bool)>=tx.query_row("SELECT hash,bytes,present FROM ha_blobs WHERE owner=?1 AND id=?2",params![manifest.owner,manifest.id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
            ensure!(blob==Some((hash.clone(),manifest.body_bytes,true)),"Durable replica body missing or mismatched");
            ensure!(root.join("replicas").join(&manifest.owner).join(format!("{}.eml",manifest.id)).is_file(),"Replica file missing");
        }
        tx.execute("INSERT INTO ha_remote(owner,id,generation,manifest,body_hash,body_bytes,body_present,updated) VALUES(?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(owner,id) DO UPDATE SET generation=excluded.generation,manifest=excluded.manifest,body_present=excluded.body_present,updated=excluded.updated",params![manifest.owner,manifest.id,manifest.generation,serde_json::to_string(&manifest)?,manifest.body_hash,manifest.body_bytes,manifest.body_hash.is_some(),now()])?;
        if manifest.body_hash.is_none() {tx.execute("UPDATE ha_blobs SET present=0,updated=?3 WHERE owner=?1 AND id=?2",params![manifest.owner,manifest.id,now()])?;}
        tx.commit()?;Ok(())
    }).await?;
    // A durable tombstone precedes deletion. Startup housekeeping removes an orphan.
    let retired = store
        .read({
            let owner = owner.clone();
            let id = id.clone();
            move |db| {
                Ok(db.query_row(
                    "SELECT body_present=0 FROM ha_remote WHERE owner=?1 AND id=?2",
                    params![owner, id],
                    |r| r.get::<_, bool>(0),
                )?)
            }
        })
        .await?;
    if retired {
        match tokio::fs::remove_file(body_path(store, &owner, &id)).await {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(receipt(&runtime, id, generation))
}
