use super::{artifacts::Bundle, budget, history};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};

/// Explicitly audited wire-identical releases for a coordinator-first rollout.
/// A future release must review its typed policies before extending this window.
pub fn compatible_build(build: &str) -> bool {
    build == env!("CARGO_PKG_VERSION")
        || (env!("CARGO_PKG_VERSION") == "0.15.1" && matches!(build, "0.14.0" | "0.15.0"))
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Poll {
    pub build: String,
    pub revision: i64,
    pub digest: String,
    pub budget: budget::Request,
    pub records: Vec<history::Record>,
    pub results: Vec<history::CommandResult>,
    pub status: NodeStatus,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NodeStatus {
    pub hostname: String,
    pub poll_seconds: u64,
    pub queued: u64,
    pub quarantined: u64,
    pub pending_metadata: u64,
    pub free_bytes: u64,
    pub last_error: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reply {
    pub protocol: String,
    pub node_id: String,
    pub server_time: i64,
    pub bundle: Bundle,
    pub receipts: Vec<history::Receipt>,
    pub commands: Vec<history::Command>,
    pub credits: Vec<budget::Credit>,
    pub secrets: BTreeMap<String, String>,
}
pub fn private_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("Missing parent")?;
    std::fs::create_dir_all(parent)?;
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    let temporary = parent.join(format!(".cluster-{}", uuid::Uuid::new_v4()));
    let result = (|| -> Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)?;
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temporary);
    }
    result
}
pub fn credential(path: &Path) -> Result<String> {
    use std::io::Read;
    let file = std::fs::File::open(path)?;
    ensure!(
        file.metadata()?.permissions().mode() & 0o077 == 0,
        "L’identité du nœud doit être privée (0600)."
    );
    let mut value = String::new();
    file.take(66).read_to_string(&mut value)?;
    let value = value.trim();
    ensure!(
        value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()),
        "Identité de nœud invalide."
    );
    Ok(value.into())
}
pub fn secrets(config: &crate::config::Config) -> Result<BTreeMap<String, String>> {
    let mut secrets = BTreeMap::new();
    for provider in [
        crate::protection::providers::Provider::Crdf,
        crate::protection::providers::Provider::Virustotal,
    ] {
        if let Ok(key) = crate::protection::providers::read_key(&config.data_dir, provider) {
            secrets.insert(provider.name().into(), key);
        }
    }
    if let Some(c) = &config.llm {
        let key = crate::management::read_key(&config.data_dir, "scaleway")?
            .or_else(|| std::env::var(&c.api_key_env).ok());
        if let Some(key) = key {
            secrets.insert("scaleway".into(), key);
        }
    }
    if let Some(key) = crate::management::dqs_key(config)? {
        secrets.insert("spamhaus".into(), key);
    }
    Ok(secrets)
}
pub fn install_secrets(root: &Path, secrets: &BTreeMap<String, String>) -> Result<String> {
    ensure!(secrets.len() <= 4, "Too many credentials");
    for (name, key) in secrets {
        ensure!(
            ["crdf", "virustotal", "scaleway", "spamhaus"].contains(&name.as_str()),
            "Unrecognized credential"
        );
        match name.as_str() {
            "crdf" | "virustotal" => {
                let provider = crate::protection::providers::Provider::parse(name)?;
                if crate::protection::providers::read_key(root, provider)
                    .ok()
                    .as_ref()
                    != Some(key)
                {
                    crate::protection::providers::save_key(root, provider, key)?;
                }
            }
            _ => {
                if crate::management::read_key(root, name)?.as_ref() != Some(key) {
                    crate::management::save_key(root, name, key)?;
                }
            }
        }
    }
    Ok(crate::message::digest(&serde_json::to_vec(secrets)?))
}
