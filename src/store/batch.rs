//! Atomic persistence of recipient variants from one SMTP acceptance.
//! Variants are ordinary messages afterwards: relay, recovery, access checks and
//! retention operate on their own recipients and wire bytes. No shared scan may
//! disclose another variant's decision or authenticated correspondent history.
use super::Store;
use crate::{actions::Action, config::Recipient, engine::Scan, now};
use anyhow::{Result, ensure};
use rusqlite::params;
use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

pub const MAX_VARIANTS: usize = 2;
pub const SCHEMA_SQL: &str = "CREATE TABLE IF NOT EXISTS queue_batches(
 message_id TEXT PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,
 queue_id TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS queue_batch_receipt ON queue_batches(queue_id);";

/// Only the trusted engine/caller constructs queue entries. These are never
/// deserialized from HTTP or SMTP client fields, and raw bytes are never logged.
#[derive(Clone)]
pub struct Message {
    pub id: String,
    pub recipients: Vec<Recipient>,
    pub scan: Scan,
    pub raw: Vec<u8>,
}
impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QueuedVariant")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

fn safe_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
}

struct Prepared {
    message: Message,
    sandbox: Option<crate::sandbox_pipeline::Plan>,
    challenge: Option<crate::challenge::VerifiedSmtpFrom>,
    action: Action,
    held_days: u16,
}

/// Delete only files created by this invocation. An existing path which made
/// create_new fail belongs to an earlier operation and must never be removed.
fn remove_created(paths: &[PathBuf], directory: &Path) {
    for path in paths {
        let _ = fs::remove_file(path);
    }
    let _ = File::open(directory).and_then(|f| f.sync_all());
}

impl Store {
    /// All wire files and all rows are durable before this returns success.
    /// The first variant owns the SMTP queue receipt. The internal relation is
    /// not returned by recipient-facing APIs; no root ID or sibling is disclosed.
    /// At most two variants bound amplification from a single received message.
    pub async fn enqueue_batch(
        &self,
        queue_id: String,
        sender: String,
        messages: Vec<Message>,
    ) -> Result<()> {
        ensure!(
            (1..=MAX_VARIANTS).contains(&messages.len()),
            "invalid number of queue variants"
        );
        ensure!(
            safe_id(&queue_id) && messages[0].id == queue_id,
            "invalid queue receipt"
        );
        if messages.len() > 1 {
            let first = &messages[0];
            let hash = first
                .scan
                .raw_sha256
                .as_deref()
                .filter(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()));
            ensure!(
                hash.is_some(),
                "recipient variants require original message identity"
            );
            let body = crate::message::fields(&first.raw)?.1;
            for other in &messages[1..] {
                ensure!(
                    other.scan.raw_sha256.as_deref() == hash
                        && crate::message::fields(&other.raw)?.1 == body,
                    "recipient variants must preserve the same original body"
                );
            }
        }
        let epochs: Vec<_> = messages
            .iter()
            .filter_map(|m| m.scan.sender_history_projection.as_ref()?.active_epoch())
            .collect();
        let mut ids = HashSet::new();
        let mut recipients = HashSet::new();
        let mut prepared = Vec::with_capacity(messages.len());
        for message in messages {
            ensure!(
                message.scan.delivery_variants.is_empty(),
                "nested queue variants are not supported"
            );
            ensure!(
                safe_id(&message.id) && ids.insert(message.id.clone()),
                "invalid or duplicate queue id"
            );
            ensure!(
                !message.recipients.is_empty(),
                "queue variant has no recipients"
            );
            for recipient in &message.recipients {
                ensure!(
                    recipients.insert(recipient.address.clone()),
                    "recipient repeated across queue variants"
                );
            }
            let mut sandbox = message.scan.sandbox_pipeline_plan.clone();
            if let Some(plan) = &mut sandbox {
                plan.bind_queued(&message.raw)?;
            }
            let mut challenge = message.scan.challenge_identity.clone();
            if let Some(proof) = &mut challenge {
                proof.bind_queued(&message.raw);
            }
            let action = message
                .scan
                .action
                .as_ref()
                .map(|a| a.effective)
                .unwrap_or_default();
            let held_days = message
                .scan
                .action
                .as_ref()
                .map(|a| a.quarantine_days)
                .unwrap_or(14);
            ensure!(
                action != Action::Quarantine || (1..=30).contains(&held_days),
                "invalid quarantine retention"
            );
            prepared.push(Prepared {
                message,
                sandbox,
                challenge,
                action,
                held_days,
            });
        }
        // Move, rather than clone, the potentially large wire buffers. Only the
        // ordinary metadata and opaque prepared proofs remain for the SQLite tx.
        let files: Vec<_> = prepared
            .iter_mut()
            .map(|item| {
                (
                    self.raw_path(&item.message.id),
                    std::mem::take(&mut item.message.raw),
                )
            })
            .collect();
        let paths: Vec<_> = files.iter().map(|(path, _)| path.clone()).collect();
        let directory = self.root.join("spool");
        let write_directory = directory.clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut created = Vec::with_capacity(files.len());
            let result = (|| -> Result<()> {
                for (path, raw) in files {
                    let mut file = OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(&path)?;
                    created.push(path);
                    file.write_all(&raw)?;
                    file.sync_all()?;
                }
                File::open(&write_directory)?.sync_all()?;
                Ok(())
            })();
            if result.is_err() {
                remove_created(&created, &write_directory);
            }
            result
        })
        .await??;
        let log_ids: Vec<_> = prepared.iter().map(|p| p.message.id.clone()).collect();
        let receipt = queue_id.clone();
        let result = self.run(move |db| {
            let tx = db.transaction()?;
            let time = now();
            for epoch in &epochs { epoch.validate(&tx,time)?; }
            for item in prepared {
                let Message { id, recipients, scan, .. } = item.message;
                tx.execute("INSERT INTO messages(id,created,sender,scan) VALUES(?1,?2,?3,?4)",params![id,time,sender,serde_json::to_string(&scan)?])?;
                tx.execute("INSERT INTO queue_batches(message_id,queue_id) VALUES(?1,?2)",params![id,queue_id])?;
                let (action,status) = match item.action {
                    Action::Deliver => ("deliver","pending"),
                    Action::Tag => ("tag","pending"),
                    Action::Quarantine => ("quarantine","quarantined"),
                };
                for r in recipients {
                    tx.execute("INSERT INTO deliveries(message_id,address,destination,hosts,next_attempt,status) VALUES(?1,?2,?3,?4,?5,?6)",params![id,r.address,r.destination,serde_json::to_string(&r.hosts)?,time,status])?;
                    tx.execute("INSERT INTO delivery_policy(delivery_id,action,held_until) VALUES(?1,?2,?3)",params![tx.last_insert_rowid(),action,(item.action==Action::Quarantine).then(||time+i64::from(item.held_days)*86400)])?;
                }
                if let Some(receipt) = &scan.sender_history_receipt { crate::sender_history::record_prepared(&tx,&id,&scan,receipt)?; }
                if let Some(projection) = &scan.sender_history_projection { crate::sender_history::record_projection(&tx,&id,&scan,projection)?; }
                if let Some(proof) = &item.challenge { proof.record(&tx,&id,&scan)?; }
                if let Some(plan) = &item.sandbox { crate::sandbox_pipeline::record(&tx,&id,&scan,plan)?; }
            }
            for epoch in &epochs { epoch.validate(&tx,now())?; }
            tx.commit()?;
            Ok(())
        }).await;
        if result.is_err() {
            remove_created(&paths, &directory);
        } else {
            self.notify_delivery();
            for id in log_ids {
                tracing::info!(%id,queue_id=%receipt,"queue batch member persisted");
            }
        }
        result
    }
}
