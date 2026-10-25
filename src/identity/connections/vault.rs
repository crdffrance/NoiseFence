//! Installation-local encryption key. Loading never creates a replacement key.
//! A lost key requires restoring that key or explicitly replacing connections.
use super::{Credential, Metadata, Record};
use anyhow::{Context, Result, ensure};
use rand::RngCore;
use ring::aead;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
const MAX_PLAINTEXT: usize = 12000;
pub const MAX_SEALED_BYTES: usize = 12 + MAX_PLAINTEXT + 16;
pub struct Key([u8; 32]);
fn owner(meta: &fs::Metadata) -> bool {
    // SAFETY: geteuid only reads the process identity.
    meta.uid() == unsafe { libc::geteuid() } && meta.permissions().mode() & 0o077 == 0
}
fn folder(root: &Path) -> Result<PathBuf> {
    ensure!(
        fs::symlink_metadata(root)?.is_dir(),
        "Directory vault root is not a physical directory"
    );
    let path = root.join("directory-vault");
    let meta = fs::symlink_metadata(&path)?;
    ensure!(
        meta.is_dir() && owner(&meta),
        "Directory vault requires an owner-private physical directory"
    );
    Ok(path)
}
impl Key {
    pub(crate) fn load_or_initialize(root: &Path, has_connections: bool) -> Result<Self> {
        match fs::symlink_metadata(root.join("directory-vault/key")) {
            Ok(_) => Self::load(root),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                ensure!(
                    !has_connections,
                    "Directory vault key missing; restore the original key"
                );
                Self::initialize(root)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Explicit initialization only. Callers must prove there are no existing
    /// connections before initializing an installation with a missing key.
    pub fn initialize(root: &Path) -> Result<Self> {
        ensure!(
            fs::symlink_metadata(root)?.is_dir(),
            "Directory vault root is not a physical directory"
        );
        let path = root.join("directory-vault");
        match fs::DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => File::open(root)?.sync_all()?,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(e) => return Err(e.into()),
        }
        let dir = folder(root)?;
        let mut bytes = [0; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let temporary = dir.join(format!(".key-{}", uuid::Uuid::new_v4()));
        let result = (|| -> Result<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            // Publish a complete, synced key without replacing an existing one.
            match fs::hard_link(&temporary, dir.join("key")) {
                Ok(()) => (),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
                Err(e) => return Err(e.into()),
            }
            fs::remove_file(&temporary)?;
            File::open(&dir)?.sync_all()?;
            Ok(())
        })();
        if temporary.try_exists().unwrap_or(false) {
            let _ = fs::remove_file(temporary);
        }
        result?;
        Self::load(root)
    }
    pub fn load(root: &Path) -> Result<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(folder(root)?.join("key"))?;
        let meta = file.metadata()?;
        ensure!(
            meta.is_file() && owner(&meta) && meta.len() == 32 && meta.nlink() == 1,
            "Directory vault key must be a private single-link regular 32-byte file"
        );
        let mut bytes = [0; 32];
        file.read_exact(&mut bytes)?;
        Ok(Self(bytes))
    }
    pub fn sign_schedule(
        &self,
        metadata: &Metadata,
        grant: &crate::identity::schedule::Grant,
    ) -> Result<String> {
        ensure!(metadata.key_id == self.id(), "Directory vault key mismatch");
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &self.0);
        Ok(hex::encode(
            ring::hmac::sign(&key, &grant.signed_bytes(metadata)?).as_ref(),
        ))
    }
    pub fn verify_schedule(&self, record: &Record) -> Result<()> {
        record.validate()?;
        ensure!(
            record.metadata.key_id == self.id(),
            "Directory vault key mismatch"
        );
        let schedule = record.schedule.as_ref().context("No collection grant")?;
        ring::hmac::verify(
            &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &self.0),
            &schedule.grant.signed_bytes(&record.metadata)?,
            &hex::decode(&schedule.signature)?,
        )
        .map_err(|_| anyhow::anyhow!("Collection grant authentication failed"))
    }
    pub fn id(&self) -> String {
        crate::message::digest(&self.0)
    }
    fn cipher(&self) -> Result<aead::LessSafeKey> {
        Ok(aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_256_GCM, &self.0)
                .map_err(|_| anyhow::anyhow!("Directory vault unavailable"))?,
        ))
    }
    pub fn seal(&self, metadata: Metadata, credential: &Credential) -> Result<Record> {
        metadata.validate()?;
        ensure!(metadata.key_id == self.id(), "Directory vault key mismatch");
        credential.validate(&metadata.source, metadata.created, metadata.expires)?;
        let mut data = credential.plaintext()?;
        ensure!(
            data.len() <= MAX_PLAINTEXT,
            "Directory credential too large"
        );
        let mut nonce = [0; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        self.cipher()?
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(metadata.aad()?),
                &mut data,
            )
            .map_err(|_| anyhow::anyhow!("Directory credential encryption failed"))?;
        let mut sealed = nonce.to_vec();
        sealed.extend(data);
        let record = Record {
            metadata,
            schedule: None,
            sealed: Some(sealed),
            revoked_at: None,
        };
        record.validate()?;
        Ok(record)
    }
    /// Callers also verify the selected authority, generation and owner version
    /// inside its repository transaction before using decrypted credentials.
    pub fn open(&self, record: &Record, now: i64) -> Result<Credential> {
        record.validate()?;
        ensure!(
            record.revoked_at.is_none()
                && record.metadata.key_id == self.id()
                && now >= record.metadata.created
                && now < record.metadata.expires,
            "Directory credential is revoked, expired or bound to another key"
        );
        let sealed = record
            .sealed
            .as_ref()
            .context("Directory credential revoked")?;
        let nonce: [u8; 12] = sealed[..12].try_into()?;
        let mut data = sealed[12..].to_vec();
        let plain = self
            .cipher()?
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(record.metadata.aad()?),
                &mut data,
            )
            .map_err(|_| anyhow::anyhow!("Directory credential decryption refused"))?;
        let value: Credential = serde_json::from_slice(plain)
            .map_err(|_| anyhow::anyhow!("Invalid encrypted directory credential"))?;
        value.validate(
            &record.metadata.source,
            record.metadata.created,
            record.metadata.expires,
        )?;
        Ok(value)
    }
}
#[cfg(test)]
mod tests;
