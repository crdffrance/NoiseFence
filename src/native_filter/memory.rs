//! Recipient-domain scoped fuzzy memory. Only current authorized human feedback.
use super::{
    Status,
    input::{Features, similarity},
};
use rusqlite::{Connection, OpenFlags, params};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, path::Path, time::Duration};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Report {
    pub status: Status,
    pub matches: usize,
    pub spam_examples: usize,
    pub legitimate_examples: usize,
    pub structural_matches: usize,
    pub conflict: bool,
    pub corroborated_spam: bool,
}
impl Default for Report {
    fn default() -> Self {
        Self {
            status: Status::NotRun,
            matches: 0,
            spam_examples: 0,
            legitimate_examples: 0,
            structural_matches: 0,
            conflict: false,
            corroborated_spam: false,
        }
    }
}
pub async fn inspect(
    root: &Path,
    features: &Features,
    scopes: &[String],
    raw_sha256: &str,
) -> Report {
    inspect_with_permit(root, features, scopes, raw_sha256, None).await
}
pub(super) async fn inspect_with_permit(
    root: &Path,
    features: &Features,
    scopes: &[String],
    raw_sha256: &str,
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
) -> Report {
    if scopes.len() != 1 || features.text_shingles < 24 {
        return Report::default();
    }
    let path = root.join("state.sqlite3");
    let features = features.clone();
    let domain = scopes[0].clone();
    let original = raw_sha256.to_owned();
    let (send, receive) = tokio::sync::oneshot::channel();
    let task = tokio::task::spawn_blocking(move || -> anyhow::Result<Report> {
        let _permit = permit;
        let deadline = std::time::Instant::now() + Duration::from_millis(180);
        let db = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        db.busy_timeout(Duration::from_millis(30))?;
        if send.send(db.get_interrupt_handle()).is_err() {
            anyhow::bail!("cancelled fuzzy lookup");
        }
        let now = crate::now();
        let mut query = db.prepare(
            "SELECT m.scan,MIN(f.spam),MAX(f.spam) FROM messages m
          JOIN feedback f ON f.message_id=m.id JOIN users u ON u.username=f.username
          WHERE m.created>=?1 AND m.created<?2 AND f.created>=?1 AND f.created<?2
          AND m.is_dsn=0 AND u.admin=1 AND u.disabled=0 AND json_valid(m.scan)
          AND json_type(m.scan,'$.native_filter.features')='object'
          AND EXISTS(SELECT 1 FROM deliveries d JOIN console_access g ON g.delivery_id=d.id
            WHERE d.message_id=m.id AND g.username=f.username
            AND lower(substr(d.destination,instr(d.destination,'@')+1))=?3)
          GROUP BY m.id ORDER BY m.created DESC LIMIT 1001",
        )?;
        let rows = query.query_map(params![now - 30 * 86400, now, domain], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })?;
        let mut result = Report {
            status: Status::Complete,
            ..Default::default()
        };
        let mut spam = BTreeSet::new();
        let mut ham = BTreeSet::new();
        for (index, row) in rows.enumerate() {
            if index == 1000 || std::time::Instant::now() >= deadline {
                result.status = Status::Limited;
                result.corroborated_spam = false;
                return Ok(result);
            }
            let (scan, min, max) = row?;
            anyhow::ensure!(
                (0..=1).contains(&min) && (0..=1).contains(&max),
                "invalid fuzzy human label"
            );
            let scan: crate::engine::Scan = serde_json::from_str(&scan)?;
            let Some(hash) = scan.raw_sha256.filter(|h| h != &original) else {
                continue;
            };
            let Some(old) = scan.native_filter.and_then(|o| o.features) else {
                continue;
            };
            if old.validate().is_err() || old.text_shingles < 24 {
                continue;
            }
            let text_match = similarity(&features.text, &old.text).is_some_and(|s| s >= 0.875);
            let html_match = features.html_shingles >= 12
                && old.html_shingles >= 12
                && similarity(&features.html, &old.html).is_some_and(|s| s >= 0.9375);
            if html_match {
                result.structural_matches += 1;
            }
            // Template reuse alone cannot constitute evidence of spam.
            if !text_match {
                continue;
            }
            if max == 1 {
                spam.insert(hash.clone());
            }
            if min == 0 {
                ham.insert(hash);
            }
        }
        result.spam_examples = spam.len();
        result.legitimate_examples = ham.len();
        result.matches = spam.union(&ham).count();
        result.conflict = !spam.is_empty() && !ham.is_empty();
        result.corroborated_spam = spam.len() >= 2 && ham.is_empty();
        Ok(result)
    });
    struct Interrupt(Option<rusqlite::InterruptHandle>);
    impl Drop for Interrupt {
        fn drop(&mut self) {
            if let Some(h) = &self.0 {
                h.interrupt();
            }
        }
    }
    let work = async {
        let _interrupt = Interrupt(receive.await.ok());
        task.await
    };
    match tokio::time::timeout(Duration::from_millis(200), work).await {
        Ok(Ok(Ok(result))) => result,
        _ => Report {
            status: Status::Unavailable,
            ..Default::default()
        },
    }
}
