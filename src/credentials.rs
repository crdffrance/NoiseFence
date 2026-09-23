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
    pub fn replacing(&self, provider: String, key: Option<String>) -> Result<Self> {
        ensure!(
            ["crdf", "virustotal", "scaleway", "spamhaus"].contains(&provider.as_str()),
            "Unknown provider"
        );
        let mut next = self.export();
        if let Some(key) = key {
            next.insert(provider, key);
        } else {
            next.remove(&provider);
        }
        Self::from_map(next)
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

/// Immutable private generations, independent of mutable installation key files.
/// Only the fingerprint may be referenced from a policy/model bundle.
pub mod generations {
    use super::*;
    use anyhow::Context;
    use std::{
        fs,
        io::{Read, Write},
        os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
        path::{Path, PathBuf},
    };
    const LIMIT: u64 = 4096;
    fn directory(root: &Path) -> PathBuf {
        root.join("cluster/credentials")
    }
    fn path(root: &Path, digest: &str) -> Result<PathBuf> {
        ensure!(
            crate::compatibility::valid_hash(digest),
            "Invalid credential generation"
        );
        Ok(directory(root).join(format!("{digest}.json")))
    }
    pub fn load(root: &Path, digest: &str) -> Result<Snapshot> {
        let dir = directory(root);
        let metadata = fs::symlink_metadata(&dir)?;
        ensure!(
            metadata.is_dir() && metadata.permissions().mode() & 0o077 == 0,
            "Unsafe credential directory"
        );
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path(root, digest)?)?;
        let meta = file.metadata()?;
        ensure!(
            meta.is_file() && meta.len() <= LIMIT && meta.permissions().mode() & 0o077 == 0,
            "Unsafe credential generation"
        );
        let mut raw = Vec::new();
        file.take(LIMIT + 1).read_to_end(&mut raw)?;
        ensure!(raw.len() as u64 <= LIMIT, "Oversized credential generation");
        let values = serde_json::from_slice(&raw)
            .map_err(|_| anyhow::anyhow!("Invalid credential generation data"))?;
        let snapshot = Snapshot::from_map(values)?;
        ensure!(
            snapshot.fingerprint() == digest,
            "Credential generation checksum mismatch"
        );
        Ok(snapshot)
    }
    pub fn freeze(root: &Path, keys: &Snapshot) -> Result<String> {
        // Validate the entire map before any filesystem mutation.
        Snapshot::from_map(keys.export())?;
        let digest = keys.fingerprint();
        let destination = path(root, &digest)?;
        let dir = directory(root);
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)?;
        let meta = fs::symlink_metadata(&dir)?;
        ensure!(
            meta.is_dir() && meta.permissions().mode() & 0o077 == 0,
            "Unsafe credential directory"
        );
        if destination.try_exists()? {
            load(root, &digest)?;
            fs::File::open(&destination)?.sync_all()?;
            fs::File::open(&dir)?.sync_all()?;
            fs::File::open(dir.parent().context("Missing credential parent")?)?.sync_all()?;
            fs::File::open(root)?.sync_all()?;
            return Ok(digest);
        }
        let raw = serde_json::to_vec(&keys.export())?;
        ensure!(raw.len() as u64 <= LIMIT, "Oversized credential generation");
        let temp = dir.join(format!(".stage-{}", uuid::Uuid::new_v4()));
        let result = (|| -> Result<()> {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temp)?;
            file.write_all(&raw)?;
            file.sync_all()?;
            // A concurrent writer cannot overwrite an existing immutable generation.
            match fs::hard_link(&temp, &destination) {
                Ok(()) => (),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    load(root, &digest)?;
                }
                Err(e) => return Err(e.into()),
            }
            fs::File::open(&dir)?.sync_all()?;
            fs::File::open(dir.parent().context("Missing credential parent")?)?.sync_all()?;
            fs::File::open(root)?.sync_all()?;
            Ok(())
        })();
        let _ = fs::remove_file(temp);
        result?;
        Ok(digest)
    }
    pub fn retain(root: &Path, hashes: &std::collections::BTreeSet<String>) -> Result<()> {
        // Do not collect when reading an old, unbound journal. Verify every
        // retained generation before removing any unreachable one.
        if hashes.is_empty() {
            return Ok(());
        }
        for hash in hashes {
            load(root, hash)?;
        }
        let dir = directory(root);
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(hash) = name.to_str().and_then(|s| s.strip_suffix(".json")) else {
                continue;
            };
            if crate::compatibility::valid_hash(hash)
                && entry.file_type()?.is_file()
                && !hashes.contains(hash)
            {
                fs::remove_file(entry.path())?;
            }
        }
        fs::File::open(dir)?.sync_all()?;
        Ok(())
    }
}
