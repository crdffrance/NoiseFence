use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs::OpenOptions,
    io::Read,
    net::IpAddr,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::PathBuf,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    /// Absolute Unix socket directory, or a certificate-verified server hostname.
    pub host: String,
    #[serde(default = "port")]
    pub port: u16,
    pub database: String,
    pub username: String,
    /// Passwords never enter TOML, the Web API, CLI arguments or a DSN.
    pub password_file: Option<PathBuf>,
    pub ca_file: Option<PathBuf>,
    #[serde(default = "connections")]
    pub max_connections: usize,
    /// Restricted to numeric loopback addresses for isolated integration tests.
    #[serde(default)]
    pub allow_loopback_plaintext: bool,
}

fn port() -> u16 {
    5432
}
fn connections() -> usize {
    4
}
impl Settings {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.host.is_empty()
                && self.host.len() <= 255
                && !self.host.chars().any(char::is_control),
            "Invalid database host"
        );
        ensure!(
            self.port > 0 && (1..=16).contains(&self.max_connections),
            "Invalid database pool limits"
        );
        for name in [&self.database, &self.username] {
            ensure!(
                !name.is_empty()
                    && name.len() <= 63
                    && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'),
                "Invalid database or role name"
            );
        }
        ensure!(
            !self.allow_loopback_plaintext
                || self.host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback()),
            "Plaintext database connections are restricted to explicit numeric loopback addresses"
        );
        for path in [&self.password_file, &self.ca_file].into_iter().flatten() {
            ensure!(
                path.is_absolute(),
                "Database credential paths must be absolute"
            );
        }
        ensure!(
            self.host.starts_with('/') || self.password_file.is_some(),
            "TCP database connections require a private password file"
        );
        Ok(())
    }
    pub(super) fn password(&self) -> Result<Option<String>> {
        let Some(path) = &self.password_file else {
            return Ok(None);
        };
        let mut f = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        let metadata = f.metadata()?;
        ensure!(
            metadata.is_file()
                && metadata.len() <= 4096
                && metadata.permissions().mode() & 0o027 == 0,
            "Database password must be a private regular file of at most 4096 bytes"
        );
        let mut value = String::new();
        (&mut f).take(4097).read_to_string(&mut value)?;
        ensure!(value.len() <= 4096, "Database password exceeds size limit");
        let value = value.trim_end_matches(['\r', '\n']).to_owned();
        ensure!(
            !value.is_empty() && !value.contains(['\0', '\r', '\n']),
            "Invalid database password file"
        );
        Ok(Some(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn settings(path: PathBuf) -> Settings {
        Settings {
            host: "127.0.0.1".into(),
            port: 5432,
            database: "test".into(),
            username: "test".into(),
            password_file: Some(path),
            ca_file: None,
            max_connections: 4,
            allow_loopback_plaintext: true,
        }
    }
    #[test]
    fn credentials_are_bounded_private_regular_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("password");
        std::fs::write(&path, "synthetic-test-password\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let config = settings(path.clone());
        assert_eq!(
            config.password().unwrap().as_deref(),
            Some("synthetic-test-password")
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(config.password().is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&path, "x".repeat(4097)).unwrap();
        assert!(config.password().is_err());
        std::fs::write(&path, "one\ntwo").unwrap();
        assert!(config.password().is_err());
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(settings(link).password().is_err());
    }
    #[test]
    fn plaintext_cannot_extend_beyond_numeric_loopback() {
        let mut config = settings("/private/credential".into());
        for host in ["127.0.0.1", "::1"] {
            config.host = host.into();
            assert!(config.validate().is_ok());
        }
        for host in [
            "localhost",
            "db.example.test",
            "192.0.2.1",
            "/run/postgresql",
        ] {
            config.host = host.into();
            assert!(config.validate().is_err());
        }
        config.allow_loopback_plaintext = false;
        config.host = "db.example.test".into();
        assert!(config.validate().is_ok());
        config.password_file = None;
        assert!(config.validate().is_err());
        config.host = "/run/postgresql".into();
        assert!(config.validate().is_ok());
    }
}
