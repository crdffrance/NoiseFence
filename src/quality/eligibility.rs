//! Shared dataset-readiness checks, not campaign independence or qualification.
use serde::{Deserialize, Serialize};

// Both readers select a bounded observation, not the entire message/scan. The
// literal sentinel fails parsing and counts as invalid; it never means usable.
pub(super) const OBSERVATION_SQL: &str = "CASE WHEN length(CAST(json_extract(m.scan,'$.quality') AS BLOB))<=131072 THEN json_extract(m.scan,'$.quality') WHEN json_type(m.scan,'$.quality') IS NULL OR json_type(m.scan,'$.quality')='null' THEN NULL ELSE '{}' END";
pub(super) const COHORT_SQL: &str = "CASE WHEN length(json_extract(m.scan,'$.quality.artifacts_sha256'))=64 THEN json_extract(m.scan,'$.quality.artifacts_sha256') ELSE '' END";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Exclusion {
    MissingObservation,
    InvalidObservation,
    UnsupportedProtocol,
    NonSmtpObservation,
    IncompleteExtraction,
    InvalidProvenance,
    InvalidFeatures,
    MissingCampaignIdentity,
}

#[derive(Deserialize)]
struct Observation {
    schema: String,
    protocol_sha256: String,
    artifacts_sha256: String,
    source: String,
    availability_profile: String,
    complete_features: bool,
    values: Vec<f64>,
}

pub(super) fn cohort(value: &str) -> String {
    if super::hash(value) {
        value.into()
    } else {
        "unrecorded".into()
    }
}

pub(super) fn inspect(
    encoded: Option<&str>,
    artifact: &str,
    fingerprint: Option<&str>,
    simhash: Option<&str>,
) -> Result<(), Exclusion> {
    let encoded = encoded.ok_or(Exclusion::MissingObservation)?;
    if encoded == "null" {
        return Err(Exclusion::MissingObservation);
    }
    let q: Observation =
        serde_json::from_str(encoded).map_err(|_| Exclusion::InvalidObservation)?;
    if q.schema != "noisefence-quality-observation-1" {
        return Err(Exclusion::InvalidObservation);
    }
    if q.protocol_sha256 != super::protocol_hash() {
        return Err(Exclusion::UnsupportedProtocol);
    }
    if q.source != "smtp_session" {
        return Err(Exclusion::NonSmtpObservation);
    }
    if !q.complete_features {
        return Err(Exclusion::IncompleteExtraction);
    }
    if !super::hash(artifact)
        || q.artifacts_sha256 != artifact
        || q.availability_profile.is_empty()
        || q.availability_profile.len() > 1024
        || !q
            .availability_profile
            .bytes()
            .all(|b| b.is_ascii_lowercase() || matches!(b, b'/' | b'_'))
    {
        return Err(Exclusion::InvalidProvenance);
    }
    super::validate_values(&q.values).map_err(|_| Exclusion::InvalidFeatures)?;
    if !fingerprint.is_some_and(super::hash)
        || !simhash.is_some_and(|s| {
            s.len() == 16
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
    {
        return Err(Exclusion::MissingCampaignIdentity);
    }
    Ok(())
}
