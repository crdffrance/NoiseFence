pub mod antivirus;
pub mod api;
pub mod config;
pub mod corpus;
pub mod engine;
pub mod evidence;
pub mod features;
pub mod fusion;
pub mod learning;
pub mod llm;
pub mod message;
pub mod population;
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
