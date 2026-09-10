pub mod antivirus;
pub mod api;
pub mod challenge;
pub mod config;
pub mod confirmation;
pub mod content_inspection;
pub mod corpus;
pub mod decision;
pub mod delivery_log;
pub mod diagnostics;
pub mod engine;
pub mod evidence;
pub mod features;
pub mod fusion;
pub mod heuristics;
pub mod learning;
pub mod llm;
pub mod mailing;
pub mod message;
pub mod population;
pub mod protection;
pub mod relay;
pub mod research;
pub mod research_engines;
pub mod sandbox;
pub mod sandbox_pipeline;
pub mod sandbox_service;
#[cfg(feature = "semantic")]
pub mod semantic;
pub mod sender_history;
pub mod smtp;
pub mod smtp_admission;
pub mod smtp_policy;
pub mod store;

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
pub mod vision;

pub mod control;

pub mod actions;
pub mod quarantine;
pub mod rules;
