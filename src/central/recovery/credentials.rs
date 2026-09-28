//! Credentials are published durably before revocation, never returned in reports.
use crate::central::binding::Binding;
use anyhow::{Context, Result, ensure};
use argon2::PasswordVerifier;
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Credentials {
    protocol: String,
    operation: String,
    database: Binding,
    pub username: String,
    password: String,
    pub password_hash: String,
}

impl Credentials {
    fn validate(&self, database: &Binding, operation: &str) -> Result<()> {
        ensure!(
            self.protocol == "noisefence-recovery-access-1"
                && self.operation == operation
                && &self.database == database,
            "Recovery credential authority or operation mismatch"
        );
        crate::operator::AccountChange::Create {
            password_hash: self.password_hash.clone(),
            admin: true,
            addresses: Vec::new(),
        }
        .validate(&self.username)?;
        ensure!(
            self.username.starts_with("recovery-")
                && self.password.len() == 64
                && self.password.bytes().all(|c| c.is_ascii_hexdigit()),
            "Invalid recovery credentials"
        );
        let hash = argon2::PasswordHash::new(&self.password_hash)
            .map_err(|_| anyhow::anyhow!("Invalid recovery password hash"))?;
        let params = argon2::Params::default();
        ensure!(
            hash.params.get_decimal("m") == Some(params.m_cost())
                && hash.params.get_decimal("t") == Some(params.t_cost())
                && hash.params.get_decimal("p") == Some(params.p_cost()),
            "Unexpected recovery password hashing parameters"
        );
        ensure!(
            argon2::Argon2::default()
                .verify_password(self.password.as_bytes(), &hash)
                .is_ok(),
            "Recovery password does not match its saved hash"
        );
        Ok(())
    }
}

fn read(path: &Path, database: &Binding, operation: &str) -> Result<Option<Credentials>> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let meta = file.metadata()?;
    // SAFETY: geteuid only reads this process's effective identity.
    ensure!(
        meta.is_file()
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.permissions().mode() & 0o077 == 0
            && meta.len() <= 8192,
        "Recovery credentials must be an owner-private regular file"
    );
    let mut bytes = Vec::new();
    file.take(8193).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 8192,
        "Recovery credentials exceed size limit"
    );
    // Do not attach serialized values to errors: they contain the password.
    let value: Credentials = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("Invalid recovery credentials file"))?;
    value.validate(database, operation)?;
    Ok(Some(value))
}

pub(super) fn prepare(path: &Path, database: &Binding, operation: &str) -> Result<Credentials> {
    database.validate()?;
    ensure!(
        uuid::Uuid::parse_str(operation).is_ok_and(|id| id.to_string() == operation),
        "Invalid recovery operation"
    );
    let parent = path
        .parent()
        .context("Recovery credential parent missing")?;
    let meta = std::fs::symlink_metadata(parent)?;
    // SAFETY: geteuid only reads this process's effective identity.
    ensure!(
        path.is_absolute()
            && parent.canonicalize()? == parent
            && meta.is_dir()
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.permissions().mode() & 0o077 == 0,
        "Recovery credentials require an existing physical owner-private directory"
    );
    if let Some(value) = read(path, database, operation)? {
        return Ok(value);
    }
    let password = crate::api::random_token();
    let value = Credentials {
        protocol: "noisefence-recovery-access-1".into(),
        operation: operation.into(),
        database: database.clone(),
        username: format!("recovery-{}", uuid::Uuid::new_v4().simple()),
        password_hash: crate::api::hash_password(&password)?,
        password,
    };
    let temp = parent.join(format!(".recovery-{}", uuid::Uuid::new_v4()));
    let result = (|| -> Result<Credentials> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        file.write_all(&serde_json::to_vec(&value)?)?;
        file.sync_all()?;
        // Publish a complete file without ever replacing an existing credential.
        match std::fs::hard_link(&temp, path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
        File::open(parent)?.sync_all()?;
        read(path, database, operation)?.context("Published recovery credentials missing")
    })();
    if temp.exists() {
        std::fs::remove_file(&temp)?;
        File::open(parent)?.sync_all()?;
    }
    result
}
