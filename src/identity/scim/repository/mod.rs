//! Source-scoped durable staging, shared transaction algorithm, two adapters.
pub(crate) mod database;
pub(crate) mod engine;
pub(crate) mod local;
mod store;
use super::{ListQuery, Resource, ResourceType, Revision};
use crate::identity::{connections::Record, directory::Source};
use serde::Serialize;

/// Body bytes remain private; no Debug/Serialize implementation can log them.
pub enum Command {
    Authenticate,
    Get {
        kind: ResourceType,
        id: String,
    },
    List {
        kind: ResourceType,
        query: ListQuery,
    },
    Create {
        kind: ResourceType,
        body: Vec<u8>,
    },
    Replace {
        kind: ResourceType,
        id: String,
        body: Vec<u8>,
        expected: Option<String>,
    },
    Patch {
        kind: ResourceType,
        id: String,
        body: Vec<u8>,
        expected: Option<String>,
    },
    Delete {
        kind: ResourceType,
        id: String,
        expected: Option<String>,
    },
}
pub enum Reply {
    Status(Stage),
    Resource(Box<Resource>),
    List(serde_json::Value),
    Deleted,
}
#[derive(Clone, Debug, Serialize)]
pub struct Stage {
    pub revision: Revision,
    pub users: usize,
    pub groups: usize,
    pub memberships: usize,
    /// Conservative storage reservation: exact base bytes plus128 per edge.
    pub reserved_bytes: usize,
    pub modified: i64,
}
pub struct Inventory {
    pub source: Source,
    pub stage: Stage,
    pub resources: Vec<Resource>,
}
pub(super) const MAX_BYTES: usize = 64 * 1024 * 1024;
pub(super) const EDGE_BYTES: usize = 128;
pub(super) const REQUESTS_PER_MINUTE: i64 = 600;
pub(super) fn revision(record: &Record, sequence: i64) -> anyhow::Result<Revision> {
    anyhow::ensure!(sequence >= 0, "Invalid SCIM sequence");
    Ok(Revision::new(
        &record.metadata.source,
        record.metadata.generation.clone(),
        sequence as u64,
    )?)
}
