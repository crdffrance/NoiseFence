//! Shared validation of account grants against the active mail policy.
use crate::config::Config;
use anyhow::{Result, ensure};

pub fn grants(cfg: &Config, username: &str, addresses: &mut Vec<String>) -> Result<()> {
    ensure!(
        !username.is_empty()
            && username.len() <= 100
            && username
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-@".contains(&b)),
        "Invalid account ID."
    );
    ensure!(addresses.len() <= 1000, "Too many access grants.");
    for address in addresses.iter_mut() {
        let (local, domain) = address
            .rsplit_once('@')
            .ok_or_else(|| anyhow::anyhow!("Invalid address."))?;
        ensure!(
            cfg.domains
                .iter()
                .any(|d| d.name.eq_ignore_ascii_case(domain)),
            "Domain not configured."
        );
        *address = if local == "*" {
            format!("*@{}", domain.to_ascii_lowercase())
        } else {
            cfg.recipient(address)
                .ok_or_else(|| anyhow::anyhow!("Recipient not configured."))?
                .destination
        };
    }
    addresses.sort();
    addresses.dedup();
    Ok(())
}
