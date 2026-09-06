pub mod antivirus;
pub mod api;
pub mod config;
pub mod corpus;
pub mod engine;
pub mod llm;
pub mod message;
pub mod relay;
pub mod smtp;
pub mod store;

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
