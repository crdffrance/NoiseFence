//! Explicit v2 exchange: legacy synchronization is never a preparation receipt.
use super::{Acknowledgement, Journal};
use crate::cluster::protocol;
use anyhow::{Result, ensure};
use rusqlite::{OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};

pub const PROTOCOL: &str = "noisefence-activation-1";
pub const REPLY_LIMIT: usize = 6 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub protocol: String,
    pub poll: protocol::Poll,
    pub acknowledgement: Option<Acknowledgement>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reply {
    pub protocol: String,
    pub data: protocol::Reply,
    pub activation: Option<Journal>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Peer {
    pub seen: i64,
    pub build: String,
    pub revision: i64,
    pub digest: String,
    pub credential: String,
}
impl Peer {
    pub fn read(tx: &Transaction<'_>, id: &str) -> Result<Option<Self>> {
        let raw: Option<String> = tx
            .query_row(
                "SELECT value FROM cluster_state WHERE key=?1",
                [format!("activation_peer:{id}")],
                |r| r.get(0),
            )
            .optional()?;
        raw.map(|s| {
            ensure!(s.len() <= 1024, "Oversized activation capability record");
            Ok(serde_json::from_str(&s)?)
        })
        .transpose()
    }
    pub fn save(&self, tx: &Transaction<'_>, id: &str) -> Result<()> {
        ensure!(crate::cluster::valid_id(id), "Invalid activation peer");
        tx.execute(
            "INSERT OR REPLACE INTO cluster_state VALUES(?1,?2)",
            params![
                format!("activation_peer:{id}"),
                serde_json::to_string(self)?
            ],
        )?;
        Ok(())
    }
}
