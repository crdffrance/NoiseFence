//! Tenant-scoped directory and relationship evidence. Directory membership is
//! neither mailbox authorization nor proof that a message is legitimate.
//! Connectors and publication run outside the SMTP path.
pub mod connections;
pub mod connectors;
pub mod detection;
pub mod directory;
pub mod learning;
pub mod management;
pub mod protection;
pub mod relationships;
pub mod runtime;
pub mod sync;

use anyhow::{Result, ensure};

/// Preserve local-part case and syntax. Domain case/IDNA alone is canonicalized;
/// plus tags, dots and provider-specific alias equivalences are never invented.
pub fn mailbox(value: &str) -> Result<String> {
    ensure!(
        value.len() <= 320 && !value.chars().any(char::is_control),
        "Invalid identity mailbox"
    );
    let (local, domain) = value
        .rsplit_once('@')
        .ok_or_else(|| anyhow::anyhow!("Invalid identity mailbox"))?;
    let domain = idna::domain_to_ascii_strict(domain)?.to_ascii_lowercase();
    let address = format!("{local}@{domain}");
    ensure!(
        crate::config::valid_address(&address) && address.len() <= 320,
        "Invalid identity mailbox"
    );
    Ok(address)
}

pub(crate) fn text(value: &str, maximum: usize) -> bool {
    !value.trim().is_empty()
        && value.len() <= maximum
        && !value.chars().any(|c| {
            c.is_control() || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
}

/// Deliberately conservative. Homonyms stay ambiguous; accents and script
/// differences are not silently collapsed into the same identity.
pub fn name_key(value: &str) -> Option<String> {
    text(value, 200).then(|| {
        value
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase()
    })
}

pub(crate) fn scope(value: &str) -> bool {
    value.contains('.') && crate::config::valid_domain(value) && value == value.to_ascii_lowercase()
}
