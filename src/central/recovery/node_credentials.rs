//! Durable replacement worker tokens. Never overwrite a previous operation's keys.
use crate::central::binding::Binding;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Tokens {
    protocol: String,
    operation: String,
    database: Binding,
    pub workers: BTreeMap<String, Worker>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Worker {
    pub epoch: String,
    pub token: String,
}
impl Tokens {
    fn validate(
        &self,
        binding: &Binding,
        operation: &str,
        workers: &BTreeMap<String, String>,
    ) -> Result<()> {
        ensure!(
            self.protocol == "noisefence-recovery-worker-credentials-1"
                && &self.database == binding
                && self.operation == operation,
            "Worker recovery credential authority mismatch"
        );
        ensure!(
            self.workers.len() == workers.len()
                && self
                    .workers
                    .iter()
                    .all(|(node, key)| workers.get(node) == Some(&key.epoch)
                        && key.token.len() == 64
                        && key.token.bytes().all(|b| b.is_ascii_hexdigit())),
            "Worker recovery credential source mismatch"
        );
        ensure!(
            self.workers
                .values()
                .map(|v| &v.token)
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == self.workers.len(),
            "Recovery worker credentials must be distinct"
        );
        Ok(())
    }
    pub fn hashes(&self) -> BTreeMap<String, String> {
        self.workers
            .iter()
            .map(|(node, key)| (node.clone(), crate::message::digest(key.token.as_bytes())))
            .collect()
    }
}

pub(super) fn read(
    path: &Path,
    binding: &Binding,
    operation: &str,
    workers: &BTreeMap<String, String>,
) -> Result<Option<Tokens>> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(v) => v,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let meta = file.metadata()?;
    // SAFETY: geteuid only reads the process identity.
    ensure!(
        meta.is_file()
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.permissions().mode() & 0o077 == 0
            && meta.len() <= 32768,
        "Worker recovery credentials must be a bounded owner-private regular file"
    );
    let mut raw = Vec::new();
    file.take(32769).read_to_end(&mut raw)?;
    ensure!(
        raw.len() <= 32768,
        "Worker recovery credentials exceed limit"
    );
    let keys: Tokens = serde_json::from_slice(&raw)
        .map_err(|_| anyhow::anyhow!("Invalid worker recovery credential file"))?;
    keys.validate(binding, operation, workers)?;
    Ok(Some(keys))
}

pub(super) fn prepare(
    path: &Path,
    binding: &Binding,
    operation: &str,
    workers: &BTreeMap<String, String>,
) -> Result<Tokens> {
    binding.validate()?;
    ensure!(
        uuid::Uuid::parse_str(operation).is_ok_and(|id| id.to_string() == operation)
            && workers.len() <= 63
            && workers
                .iter()
                .all(|(node, epoch)| crate::cluster::valid_id(node)
                    && uuid::Uuid::parse_str(epoch).is_ok_and(|id| id.to_string() == *epoch)),
        "Invalid worker recovery operation or source set"
    );
    let parent = path
        .parent()
        .context("Worker credential directory missing")?;
    let meta = std::fs::symlink_metadata(parent)?;
    // SAFETY: geteuid only reads the process identity.
    ensure!(
        path.is_absolute()
            && parent.canonicalize()? == parent
            && meta.is_dir()
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.permissions().mode() & 0o077 == 0,
        "Worker credentials require a physical owner-private directory"
    );
    if let Some(keys) = read(path, binding, operation, workers)? {
        return Ok(keys);
    }
    let keys = Tokens {
        protocol: "noisefence-recovery-worker-credentials-1".into(),
        operation: operation.into(),
        database: binding.clone(),
        workers: workers
            .iter()
            .map(|(node, epoch)| {
                (
                    node.clone(),
                    Worker {
                        epoch: epoch.clone(),
                        token: crate::api::random_token(),
                    },
                )
            })
            .collect(),
    };
    keys.validate(binding, operation, workers)?;
    let temporary = parent.join(format!(".recovery-worker-{}", uuid::Uuid::new_v4()));
    let result = (|| -> Result<Tokens> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(&serde_json::to_vec(&keys)?)?;
        file.sync_all()?;
        match std::fs::hard_link(&temporary, path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
        File::open(parent)?.sync_all()?;
        read(path, binding, operation, workers)?.context("Published worker credentials missing")
    })();
    if temporary.exists() {
        std::fs::remove_file(&temporary)?;
        File::open(parent)?.sync_all()?;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn worker_secrets_are_durable_distinct_private_and_bound_to_one_operation() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.join("workers.json");
        let binding = Binding {
            instance: uuid::Uuid::new_v4().to_string(),
            source_digest: "a".repeat(64),
        };
        let operation = uuid::Uuid::new_v4().to_string();
        let workers = BTreeMap::from([
            ("mx2".into(), uuid::Uuid::new_v4().to_string()),
            ("mx3".into(), uuid::Uuid::new_v4().to_string()),
        ]);
        let first = prepare(&path, &binding, &operation, &workers).unwrap();
        assert_ne!(first.workers["mx2"].token, first.workers["mx3"].token);
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            prepare(&path, &binding, &operation, &workers)
                .unwrap()
                .hashes(),
            first.hashes()
        );
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert!(prepare(&path, &binding, &uuid::Uuid::new_v4().to_string(), &workers).is_err());
        let mut changed = binding.clone();
        changed.instance = uuid::Uuid::new_v4().to_string();
        assert!(prepare(&path, &changed, &operation, &workers).is_err());
        let mut wrong = workers.clone();
        wrong.insert("mx2".into(), uuid::Uuid::new_v4().to_string());
        assert!(prepare(&path, &binding, &operation, &wrong).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        let linked = root.join("linked.json");
        std::os::unix::fs::symlink(&path, &linked).unwrap();
        assert!(prepare(&linked, &binding, &operation, &workers).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(prepare(&path, &binding, &operation, &workers).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut corrupt: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        corrupt["workers"]["mx3"]["token"] = corrupt["workers"]["mx2"]["token"].clone();
        std::fs::write(&path, serde_json::to_vec(&corrupt).unwrap()).unwrap();
        assert!(prepare(&path, &binding, &operation, &workers).is_err());
    }
}
