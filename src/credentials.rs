//! Provider credentials belong to a resident runtime, never to a mutable lookup
//! performed halfway through analysis. This memory-only snapshot is deliberately
//! excluded from configuration serialization and redacted from Debug output.
use crate::config::Config;
use anyhow::{Result, ensure};
use std::{collections::BTreeMap, sync::Arc};

#[derive(Clone, Default)]
pub struct Snapshot(BTreeMap<String, String>);
impl std::fmt::Debug for Snapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProviderCredentials([REDACTED])")
    }
}
impl Snapshot {
    pub fn capture(config: &Config) -> Result<Self> {
        if let Some(snapshot) = &config.provider_credentials {
            return Ok((**snapshot).clone());
        }
        Ok(Self(crate::cluster::protocol::secrets(config)?))
    }
    pub fn from_map(keys: BTreeMap<String, String>) -> Result<Self> {
        ensure!(keys.len() <= 4, "Too many provider credentials");
        for (name, key) in &keys {
            ensure!(
                ["crdf", "virustotal", "scaleway", "spamhaus"].contains(&name.as_str())
                    && (16..=256).contains(&key.len())
                    && key.bytes().all(|b| if name == "spamhaus" {
                        b.is_ascii_alphanumeric()
                    } else {
                        b.is_ascii_graphic()
                    }),
                "Invalid provider credential set"
            );
        }
        Ok(Self(keys))
    }
    pub fn fingerprint(&self) -> String {
        crate::message::digest(&serde_json::to_vec(&self.0).expect("provider key map"))
    }
    pub fn get(&self, provider: &str) -> Option<&str> {
        self.0.get(provider).map(String::as_str)
    }
    /// Only authenticated node exchange may serialize this map; Web settings,
    /// status, receipts, model bundles and logs must not include it.
    pub(crate) fn export(&self) -> BTreeMap<String, String> {
        self.0.clone()
    }
    pub(crate) fn protection(root: &std::path::Path) -> Self {
        use crate::protection::providers::{Provider, read_key};
        Self(
            [Provider::Crdf, Provider::Virustotal]
                .into_iter()
                .filter_map(|p| read_key(root, p).ok().map(|key| (p.name().into(), key)))
                .collect(),
        )
    }
}

/// Preserve an explicitly empty snapshot: absent credentials never fall through
/// to environment variables or files belonging to another runtime generation.
pub fn pin(config: Arc<Config>) -> Result<Arc<Config>> {
    if config.provider_credentials.is_some() {
        return Ok(config);
    }
    let snapshot = Arc::new(Snapshot::capture(&config)?);
    let mut config = (*config).clone();
    config.provider_credentials = Some(snapshot);
    Ok(Arc::new(config))
}
