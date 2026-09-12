pub mod antivirus;
pub mod api;
pub mod compatibility;
pub mod config;
pub mod confirmation;
pub mod corpus;
pub mod decision;
pub mod delivery_log;
pub mod detection_diagnostics;
pub mod diagnostics;
pub mod engine;
pub mod evidence;
pub mod features;
pub mod fusion;
pub mod learning;
pub mod llm;
pub mod mailing;
pub mod message;
pub mod native_filter;
pub mod population;
pub mod protection;
pub mod quality;
pub mod relay;
pub mod research;
#[cfg(feature = "semantic")]
pub mod semantic;
pub mod smtp;
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

pub mod custom_filtering;

pub mod reliability;
