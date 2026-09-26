//! Durable, bounded accounting before private export bytes can leave the store.
//! Campaign hashes are research metadata, never sender or recipient identities.
use anyhow::{Result, ensure};
use rusqlite::{Connection, params};
use serde::Serialize;
use serde_json::Value;
use std::collections::{HashMap, HashSet};

pub const SCHEMA: &str = "noisefence-quality-exposure-1";
const LIMIT: usize = 50_000;
const WORK_LIMIT: usize = 1_000_000;

#[derive(Serialize)]
pub struct Exposure {
    pub schema: &'static str,
    pub candidate_sha256: Option<String>,
    pub tracking_since: i64,
    pub previously_exported: bool,
    pub related_campaign_seen: bool,
}

struct Index {
    exact: HashSet<String>,
    buckets: HashMap<(u8, u16), Vec<u64>>,
    work: usize,
}
impl Index {
    fn new() -> Self {
        Self {
            exact: HashSet::new(),
            buckets: HashMap::new(),
            work: 0,
        }
    }
    fn add(&mut self, fingerprint: String, simhash: Option<u64>) {
        self.exact.insert(fingerprint);
        if let Some(hash) = simhash {
            for part in 0..4u8 {
                self.buckets
                    .entry((part, (hash >> (part * 16)) as u16))
                    .or_default()
                    .push(hash);
            }
        }
    }
    fn contains(&mut self, fingerprint: &str, hash: Option<u64>) -> Result<bool> {
        if self.exact.contains(fingerprint) {
            return Ok(true);
        }
        if let Some(hash) = hash {
            // <=3 changed bits leave at least one of four 16-bit blocks equal.
            let mut checked = HashSet::new();
            for part in 0..4u8 {
                if let Some(candidates) = self.buckets.get(&(part, (hash >> (part * 16)) as u16)) {
                    for previous in candidates {
                        self.work += 1;
                        ensure!(
                            self.work <= WORK_LIMIT,
                            "Research exposure comparison exceeds capacity"
                        );
                        if checked.insert(*previous) && (previous ^ hash).count_ones() <= 3 {
                            return Ok(true);
                        }
                    }
                }
            }
        }
        Ok(false)
    }
}
fn simhash(value: &str) -> Option<u64> {
    (value.len() == 16 && value.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| u64::from_str_radix(value, 16).ok())
        .flatten()
}

/// Caller owns an IMMEDIATE transaction and commits before writing an export.
/// A later write failure remains consumed: the process may already have inspected it.
pub fn record(db: &Connection, batch: &str, rows: &[Value], now: i64) -> Result<Exposure> {
    ensure!(
        !db.is_autocommit(),
        "Research exposure requires a transaction"
    );
    let tracking_since = db.query_row(
        "SELECT tracking_since FROM quality_exposure_state WHERE id=1",
        [],
        |r| r.get(0),
    )?;
    let previously_exported = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM quality_export_batches WHERE batch_id=?1)",
        [batch],
        |r| r.get(0),
    )?;
    db.execute(
        "DELETE FROM quality_export_campaigns WHERE exposed_at<?1",
        [now - 30 * 86400],
    )?;
    db.execute(
        "DELETE FROM quality_export_batches WHERE exposed_at<?1",
        [now - 30 * 86400],
    )?;
    let mut q =
        db.prepare("SELECT fingerprint,simhash FROM quality_export_campaigns LIMIT 50001")?;
    let history = q
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    ensure!(
        history.len() <= LIMIT,
        "Research exposure history exceeds capacity"
    );
    let mut index = Index::new();
    for (fingerprint, hash) in history {
        index.add(fingerprint, simhash(&hash));
    }
    let mut related_campaign_seen = false;
    let mut incoming = HashSet::new();
    for row in rows {
        if let Some(fingerprint) = row["fingerprint"].as_str().filter(|s| super::hash(s)) {
            let hash = row["simhash"]
                .as_str()
                .filter(|s| simhash(s).is_some())
                .unwrap_or("");
            if !related_campaign_seen {
                related_campaign_seen = index.contains(fingerprint, simhash(hash))?;
            }
            incoming.insert((fingerprint.to_owned(), hash.to_owned()));
        }
    }
    // Check only the previously exported population, not other rows in this draw.
    for (fingerprint, hash) in incoming {
        db.execute("INSERT INTO quality_export_campaigns(fingerprint,simhash,exposed_at) VALUES(?1,?2,?3) ON CONFLICT(fingerprint,simhash) DO UPDATE SET exposed_at=excluded.exposed_at",params![fingerprint,hash,now])?;
    }
    let retained: usize =
        db.query_row("SELECT COUNT(*) FROM quality_export_campaigns", [], |r| {
            r.get(0)
        })?;
    ensure!(
        retained <= LIMIT,
        "Research exposure history exceeds capacity"
    );
    db.execute("INSERT INTO quality_export_batches(batch_id,exposed_at) VALUES(?1,?2) ON CONFLICT(batch_id) DO UPDATE SET exposed_at=excluded.exposed_at",params![batch,now])?;
    Ok(Exposure {
        schema: SCHEMA,
        candidate_sha256: None,
        tracking_since,
        previously_exported,
        related_campaign_seen,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn block_index_matches_three_bit_distance_without_quadratic_scan() {
        let mut index = Index::new();
        let hash = 0x123456789abcdef0;
        index.add("first".into(), Some(hash));
        assert!(
            index
                .contains("different", Some(hash ^ (1 << 3) ^ (1 << 22) ^ (1 << 57)))
                .unwrap()
        );
        assert!(!index.contains("different", Some(hash ^ 0xf)).unwrap());
        assert!(index.contains("first", None).unwrap());
        assert!(!index.contains("different", None).unwrap());
        index.work = WORK_LIMIT;
        assert!(index.contains("different", Some(hash)).is_err());
    }
}
