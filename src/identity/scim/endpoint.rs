//! Public URLs use only operator configuration, never Host or forwarded headers.
use super::{Error, Result};
pub fn source_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 100
        && id.as_bytes()[0].is_ascii_alphanumeric()
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
pub fn base(origin: &str, id: &str, loopback_development: bool) -> Result<String> {
    let invalid = Error::new(503, "", "Provisioning origin is not configured safely.");
    if !source_id(id) {
        return Err(invalid);
    }
    let url = reqwest::Url::parse(origin).map_err(|_| invalid)?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
        || url.host_str().is_none()
        || url.origin().ascii_serialization() != origin
        || !(url.scheme() == "https"
            || (loopback_development
                && url.scheme() == "http"
                && url.host_str() == Some("127.0.0.1")))
    {
        return Err(invalid);
    }
    Ok(format!("{origin}/scim/{id}/v2"))
}
