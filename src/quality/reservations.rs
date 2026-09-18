//! Protected evaluation campaigns are never fed to periodic content trainers.
use anyhow::{Result, ensure};
use rusqlite::Connection;
use std::collections::HashSet;
pub struct Reserved {
    exact: HashSet<String>,
    hashes: Vec<u64>,
}
impl Reserved {
    pub fn load(db: &Connection) -> Result<Self> {
        let mut query=db.prepare("SELECT DISTINCT json_extract(m.scan,'$.fingerprint'),json_extract(m.scan,'$.campaign_simhash') FROM messages m JOIN quality_protected_messages p ON p.message_id=m.id WHERE m.created>=?1 LIMIT 5001")?;
        let rows = query
            .query_map([crate::now() - 30 * 86400], |r| {
                Ok((
                    r.get::<_, Option<String>>(0)?,
                    r.get::<_, Option<String>>(1)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        ensure!(rows.len() <= 5000, "Protected campaign capacity exceeded");
        let mut exact = HashSet::new();
        let mut hashes = Vec::new();
        for (fingerprint, simhash) in rows {
            if let Some(fingerprint) = fingerprint.filter(|s| super::hash(s)) {
                exact.insert(fingerprint);
            }
            if let Some(hash) = simhash.and_then(|s| u64::from_str_radix(&s, 16).ok()) {
                hashes.push(hash);
            }
        }
        Ok(Self { exact, hashes })
    }
    pub fn contains(&self, scan: &crate::engine::Scan) -> bool {
        self.exact.contains(&scan.fingerprint)
            || scan
                .campaign_simhash
                .as_deref()
                .and_then(|s| u64::from_str_radix(s, 16).ok())
                .is_some_and(|hash| self.hashes.iter().any(|s| (s ^ hash).count_ones() <= 3))
    }
}
