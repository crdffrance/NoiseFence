//! Private installation key shared by participating MXs. Never part of a policy,
//! database projection or public export. Loading does not create or rotate keys.
use anyhow::{Context, Result, ensure};
use rand::RngCore;
use ring::hmac;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

pub struct Key {
    id: String,
    hmac: hmac::Key,
}
fn private(meta: &fs::Metadata) -> bool {
    // SAFETY: geteuid only reads the current process identity.
    meta.uid() == unsafe { libc::geteuid() } && meta.permissions().mode() & 0o077 == 0
}
fn directory(root: &Path) -> Result<PathBuf> {
    ensure!(
        fs::symlink_metadata(root)?.is_dir(),
        "Memory root must be a physical directory"
    );
    let path = root.join("contact-memory");
    let meta = fs::symlink_metadata(&path)?;
    ensure!(
        meta.is_dir() && private(&meta),
        "Memory key directory must be owner-private"
    );
    Ok(path)
}
fn bytes(path: &Path, length: usize) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file() && private(&meta) && meta.nlink() == 1 && meta.len() == length as u64,
        "Memory key file must be private, regular, single-link and the expected size"
    );
    let mut bytes = vec![0; length];
    file.read_exact(&mut bytes)?;
    Ok(bytes)
}
fn publish(dir: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let temporary = dir.join(format!(".new-{}", uuid::Uuid::new_v4()));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        match fs::hard_link(&temporary, dir.join(name)) {
            Ok(()) => (),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(e) => return Err(e.into()),
        }
        fs::remove_file(&temporary)?;
        File::open(dir)?.sync_all()?;
        Ok(())
    })();
    if temporary.try_exists().unwrap_or(false) {
        let _ = fs::remove_file(temporary);
    }
    result
}
impl Key {
    fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            id: crate::message::digest(bytes),
            hmac: hmac::Key::new(hmac::HMAC_SHA256, bytes),
        }
    }
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn token(&self, purpose: &str, parts: &[&str]) -> String {
        let mut context = hmac::Context::with_key(&self.hmac);
        for part in std::iter::once("noisefence-private-contact-2")
            .chain(std::iter::once(purpose))
            .chain(parts.iter().copied())
        {
            context.update(&(part.len() as u64).to_be_bytes());
            context.update(part.as_bytes());
        }
        hex::encode(context.sign().as_ref())
    }
    pub fn load(root: &Path) -> Result<Self> {
        let dir = directory(root)?;
        let key = Self::from_bytes(&bytes(&dir.join("key"), 32)?);
        ensure!(
            bytes(&dir.join("key-id"), 64)? == key.id.as_bytes(),
            "Memory key identity differs; restore the matching key"
        );
        Ok(key)
    }
    pub fn matching(root: &Path, expected: Option<&str>) -> Result<Self> {
        let expected =
            expected.context("Install a memory key and select its ID before enabling memory")?;
        let key = Self::load(root)?;
        ensure!(
            key.id == expected,
            "Memory key does not match the reviewed policy"
        );
        Ok(key)
    }
    /// Explicit operator installation. Existing material is never overwritten.
    /// Restoring a lost key requires an exact matching private backup file.
    pub fn install(root: &Path, source: Option<&Path>) -> Result<Self> {
        ensure!(
            fs::symlink_metadata(root)?.is_dir(),
            "Memory root must be a physical directory"
        );
        let path = root.join("contact-memory");
        match fs::DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => File::open(root)?.sync_all()?,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(e) => return Err(e.into()),
        }
        let dir = directory(root)?;
        let expected = match bytes(&dir.join("key-id"), 64) {
            Ok(v) => Some(v),
            Err(e)
                if e.downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
            {
                None
            }
            Err(e) => return Err(e),
        };
        let candidate = match source {
            Some(source) => bytes(source, 32)?,
            None => match bytes(&dir.join("key"), 32) {
                Ok(v) => v,
                Err(e)
                    if e.downcast_ref::<std::io::Error>()
                        .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
                {
                    ensure!(
                        expected.is_none(),
                        "Memory key lost; restore its matching private backup"
                    );
                    let mut v = vec![0; 32];
                    rand::rngs::OsRng.fill_bytes(&mut v);
                    v
                }
                Err(e) => return Err(e),
            },
        };
        let candidate_id = crate::message::digest(&candidate);
        ensure!(
            expected
                .as_ref()
                .is_none_or(|id| id == candidate_id.as_bytes()),
            "Restore key does not match installation identity"
        );
        publish(&dir, "key", &candidate)?;
        let installed = Self::from_bytes(&bytes(&dir.join("key"), 32)?);
        ensure!(
            source.is_none() || installed.id == candidate_id,
            "Another memory key is already installed"
        );
        publish(&dir, "key-id", installed.id.as_bytes())?;
        Self::load(root)
    }
}

#[cfg(test)]
mod tests;
