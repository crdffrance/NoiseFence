use super::{artifacts, budget, history, protocol};
use anyhow::{Context, Result, ensure};
use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use std::{path::Path, sync::Arc, time::Duration};
use tokio::io::AsyncWriteExt;

async fn bounded_json<T: DeserializeOwned>(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<T> {
    ensure!(
        response.status().is_success(),
        "Coordinator HTTP {}",
        response.status().as_u16()
    );
    ensure!(
        response.content_length().is_none_or(|n| n <= limit as u64),
        "Oversized cluster reply"
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            bytes.len() + chunk.len() <= limit,
            "Oversized cluster reply"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(serde_json::from_slice(&bytes)?)
}
struct PartialFile(std::path::PathBuf);
impl Drop for PartialFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
async fn download(
    http: &reqwest::Client,
    url: &str,
    root: &Path,
    bundle: &artifacts::Bundle,
    minimum_free: u64,
) -> Result<()> {
    bundle.validate()?;
    let dir = artifacts::directory(root, bundle);
    for (name, artifact) in &bundle.files {
        let path = dir.join(name);
        // Completed immutable files were verified before rename. Full verification is repeated on activation/restart.
        if path.is_file() {
            let existing = path.clone();
            let expected = artifact.clone();
            if tokio::task::spawn_blocking(move || {
                artifacts::file_digest(&existing)
                    .is_ok_and(|(n, h)| n == expected.size && h == expected.sha256)
            })
            .await?
            {
                continue;
            }
        }
        ensure!(
            crate::store::available_bytes(root)? > artifact.size.saturating_add(minimum_free),
            "Espace disque insuffisant pour les modèles et la file SMTP."
        );
        tokio::fs::create_dir_all(path.parent().unwrap()).await?;
        let temporary = path.with_extension(format!("partial-{}", uuid::Uuid::new_v4()));
        let _partial = PartialFile(temporary.clone());
        let result = async {
            let mut response = http
                .get(format!(
                    "{url}/api/v1/cluster/v1/artifacts/{}",
                    artifact.sha256
                ))
                .timeout(Duration::from_secs(180))
                .send()
                .await?;
            ensure!(
                response.status().is_success(),
                "Model HTTP {}",
                response.status().as_u16()
            );
            let mut output = tokio::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&temporary)
                .await?;
            let mut count = 0u64;
            let mut digest = Sha256::new();
            while let Some(chunk) = response.chunk().await? {
                count += chunk.len() as u64;
                ensure!(count <= artifact.size, "Model exceeds manifest");
                digest.update(&chunk);
                output.write_all(&chunk).await?;
            }
            ensure!(
                count == artifact.size && hex::encode(digest.finalize()) == artifact.sha256,
                "Model checksum mismatch"
            );
            output.sync_all().await?;
            drop(output);
            tokio::fs::rename(&temporary, &path).await?;
            std::fs::File::open(path.parent().unwrap())?.sync_all()?;
            Ok::<_, anyhow::Error>(())
        }
        .await;
        if result.is_err() {
            let _ = tokio::fs::remove_file(&temporary).await;
        }
        result?;
    }
    Ok(())
}
async fn poll(
    control: &Arc<crate::control::Controller>,
    http: &reqwest::Client,
    url: &str,
    last_error: Option<String>,
    results: Vec<history::CommandResult>,
) -> Result<Vec<history::CommandResult>> {
    let snapshot = control.snapshot();
    let root = control.base.data_dir.clone();
    let wallet =
        tokio::task::spawn_blocking(move || budget::request(&root, crate::now())).await??;
    // Metadata incidents must not prevent policy renewal or credit synchronization.
    let (records, last_error) = match history::export(&control.store).await {
        Ok(records) => (records, last_error),
        Err(error) => (
            Vec::new(),
            Some(format!(
                "Historique non synchronisé : {}",
                crate::delivery_log::sanitize(&error.to_string(), 280).0
            )),
        ),
    };
    let free_bytes = crate::store::available_bytes(&control.base.data_dir)?;
    let status = control
        .store
        .read(move |db| {
            let queued = db.query_row(
                "SELECT COUNT(*) FROM deliveries WHERE status IN ('pending','sending','failed')",
                [],
                |r| r.get(0),
            )?;
            let quarantined = db.query_row(
                "SELECT COUNT(*) FROM deliveries WHERE status='quarantined'",
                [],
                |r| r.get(0),
            )?;
            let pending_metadata =
                db.query_row("SELECT COUNT(*) FROM cluster_dirty", [], |r| r.get(0))?;
            Ok(protocol::NodeStatus {
                hostname: snapshot.config.hostname.clone(),
                poll_seconds: snapshot
                    .config
                    .cluster
                    .as_ref()
                    .map_or(10, |c| c.poll_seconds),
                queued,
                quarantined,
                pending_metadata,
                free_bytes,
                last_error,
            })
        })
        .await?;
    let request = protocol::Poll {
        build: env!("CARGO_PKG_VERSION").into(),
        revision: control.snapshot().revision,
        digest: control.cluster_digest(),
        budget: wallet,
        records,
        results,
        status,
    };
    let response = http
        .post(format!("{url}/api/v1/cluster/v1/sync"))
        .json(&request)
        .send()
        .await?;
    let reply: protocol::Reply = bounded_json(response, 1024 * 1024).await?;
    let settings = control
        .base
        .cluster
        .as_ref()
        .context("Worker settings missing")?;
    ensure!(
        reply.protocol == "noisefence-cluster-1"
            && reply.node_id == settings.node_id
            && (reply.server_time - crate::now()).abs() <= 300,
        "Invalid authority reply or unsynchronized clocks"
    );
    // Acknowledge only generations this poll actually submitted, never a newer local update.
    ensure!(
        reply.receipts.iter().all(|a| request
            .records
            .iter()
            .any(|r| r.id == a.id && r.generation == a.generation)),
        "Unexpected metadata acknowledgement"
    );
    history::acknowledge(&control.store, reply.receipts).await?;
    let root = control.base.data_dir.clone();
    let secrets = reply.secrets;
    let credits = reply.credits;
    let key_hash = tokio::task::spawn_blocking(move || -> Result<String> {
        budget::install(&root, &credits, crate::now())?;
        protocol::install_secrets(&root, &secrets)
    })
    .await??;
    let previous = control
        .store
        .read(|db| {
            use rusqlite::OptionalExtension;
            let raw: Option<String> = db
                .query_row(
                    "SELECT value FROM cluster_state WHERE key='bundle'",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            raw.map(|v| serde_json::from_str::<artifacts::Bundle>(&v).map_err(Into::into))
                .transpose()
        })
        .await?;
    if control.cluster_digest() != reply.bundle.digest {
        download(
            http,
            url,
            &control.base.data_dir,
            &reply.bundle,
            control.base.smtp.minimum_free_bytes,
        )
        .await?;
    }
    control
        .apply_cluster(reply.bundle.clone(), key_hash, reply.server_time)
        .await?;
    let root = control.base.data_dir.clone();
    tokio::task::spawn_blocking(move || {
        artifacts::prune_models(&root, &reply.bundle, previous.as_ref())
    })
    .await??;
    history::execute(&control.store, reply.commands).await
}
pub async fn run(
    control: Arc<crate::control::Controller>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let settings = control
        .base
        .cluster
        .as_ref()
        .context("Worker settings missing")?
        .clone();
    let url = settings
        .coordinator_url
        .as_deref()
        .context("Coordinator missing")?
        .trim_end_matches('/');
    let key = protocol::credential(
        settings
            .credential_file
            .as_deref()
            .context("Credential missing")?,
    )?;
    let mut headers = HeaderMap::new();
    let mut authorization = HeaderValue::from_str(&format!("Bearer {key}"))?;
    authorization.set_sensitive(true);
    headers.insert(AUTHORIZATION, authorization);
    headers.insert(
        "x-noisefence-node",
        HeaderValue::from_str(&settings.node_id)?,
    );
    let _ = rustls::crypto::ring::default_provider().install_default();
    let http = reqwest::Client::builder()
        .default_headers(headers)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .retry(reqwest::retry::never())
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(20))
        .build()?;
    let mut last_error = None;
    let mut results = Vec::new();
    loop {
        tokio::select! {
            _=stop.changed()=>return Ok(()),
            response=poll(&control,&http,url,last_error.clone(),results.clone())=>match response {
                Ok(ack)=>{results=ack;last_error=None;},
                Err(error)=>{let safe=crate::delivery_log::sanitize(&error.to_string(),400).0;tracing::warn!(error=%safe,"cluster synchronization incomplete");last_error=Some(safe);}
            }
        }
        tokio::select! {_=stop.changed()=>return Ok(()),_=tokio::time::sleep(Duration::from_secs(settings.poll_seconds))=>{}}
    }
}
