//! Release metadata is retained, while compatibility binds executable behavior.
pub const DETECTOR_BUILD_SHA256: &str = env!("NOISEFENCE_DETECTOR_BUILD_SHA256");

pub fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
