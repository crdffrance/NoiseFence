//! Private directory connection material. Kept out of runtime policy bundles,
//! SMTP replicas, public configuration, synchronization receipts and logs.
pub(crate) mod local;
mod repository;
pub mod vault;
use super::{
    connectors,
    directory::{Provider, Source},
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
pub const MAX_CONNECTIONS: usize = 16;
pub const MAX_RECORD_BYTES: usize = 65536;
pub const PROTOCOL: &str = "identity-connection-1";

/// Typed secret. Neither Debug nor Serialize: only the private vault encoder
/// may turn it into plaintext bytes, never an API response or diagnostic.
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Credential {
    EntraApplication {
        client_id: String,
        client_secret: String,
    },
    GoogleAccessToken {
        access_token: String,
    },
    OktaAccessToken {
        access_token: String,
    },
}
impl Credential {
    fn plaintext(&self) -> Result<Vec<u8>> {
        #[derive(Serialize)]
        #[serde(tag = "kind", rename_all = "snake_case")]
        enum Wire<'a> {
            EntraApplication {
                client_id: &'a str,
                client_secret: &'a str,
            },
            GoogleAccessToken {
                access_token: &'a str,
            },
            OktaAccessToken {
                access_token: &'a str,
            },
        }
        let wire = match self {
            Self::EntraApplication {
                client_id,
                client_secret,
            } => Wire::EntraApplication {
                client_id,
                client_secret,
            },
            Self::GoogleAccessToken { access_token } => Wire::GoogleAccessToken { access_token },
            Self::OktaAccessToken { access_token } => Wire::OktaAccessToken { access_token },
        };
        serde_json::to_vec(&wire).map_err(|_| anyhow::anyhow!("Invalid directory credential"))
    }
    pub fn validate(&self, source: &Source, created: i64, expires: i64) -> Result<()> {
        source.validate()?;
        ensure!(
            created > 0 && expires > created,
            "Invalid directory credential lifetime"
        );
        let maximum = match self {
            Self::EntraApplication {
                client_id,
                client_secret,
            } => {
                ensure!(
                    source.provider == Provider::Entra,
                    "Credential provider mismatch"
                );
                connectors::entra::Credentials::new(
                    &source.authority,
                    client_id,
                    client_secret.clone(),
                )?;
                90 * 86400
            }
            Self::GoogleAccessToken { access_token } => {
                ensure!(
                    source.provider == Provider::Google,
                    "Credential provider mismatch"
                );
                connectors::google::Credentials::new(&source.authority, access_token.clone())?;
                3600
            }
            Self::OktaAccessToken { access_token } => {
                ensure!(
                    source.provider == Provider::Okta,
                    "Credential provider mismatch"
                );
                connectors::okta::Credentials::new(&source.authority, access_token.clone())?;
                3600
            }
        };
        ensure!(
            expires.checked_sub(created).is_some_and(|n| n <= maximum),
            "Directory credential lifetime exceeds its bound"
        );
        Ok(())
    }
}
/// The complete metadata is authenticated as additional encryption data, so a
/// database edit cannot move credentials to a different source, owner or lease.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    pub protocol: String,
    pub source: Source,
    pub generation: String,
    pub supersedes: Option<String>,
    pub authority: String,
    pub key_id: String,
    pub owner: String,
    pub owner_version: i64,
    pub created: i64,
    pub expires: i64,
}
impl Metadata {
    pub fn validate(&self) -> Result<()> {
        self.source.validate()?;
        ensure!(
            self.protocol == PROTOCOL
                && uuid::Uuid::parse_str(&self.generation)
                    .is_ok_and(|u| u.to_string() == self.generation)
                && self
                    .supersedes
                    .as_deref()
                    .is_none_or(
                        |s| uuid::Uuid::parse_str(s).is_ok_and(|u| u.to_string() == s)
                            && s != self.generation
                    )
                && super::text(&self.authority, 200)
                && crate::compatibility::valid_hash(&self.key_id)
                && super::text(&self.owner, 100)
                && self.owner_version >= 0
                && self.created > 0
                && self.expires > self.created
                && self
                    .expires
                    .checked_sub(self.created)
                    .is_some_and(|n| n <= 90 * 86400),
            "Invalid directory connection metadata"
        );
        ensure!(
            matches!(
                self.source.provider,
                Provider::Entra | Provider::Google | Provider::Okta
            ),
            "Unsupported stored directory provider"
        );
        if self.source.provider != Provider::Entra {
            ensure!(
                self.expires - self.created <= 3600,
                "Stored access token lifetime exceeds one hour"
            );
        }
        Ok(())
    }
    pub fn aad(&self) -> Result<Vec<u8>> {
        self.validate()?;
        Ok(serde_json::to_vec(self)?)
    }
}
/// Storage representation. Its ciphertext is deliberately not part of View.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub metadata: Metadata,
    pub sealed: Option<Vec<u8>>,
    pub revoked_at: Option<i64>,
}
impl Record {
    pub fn validate(&self) -> Result<()> {
        self.metadata.validate()?;
        ensure!(
            match (&self.sealed, self.revoked_at) {
                (Some(s), None) => (29..=vault::MAX_SEALED_BYTES).contains(&s.len()),
                (None, Some(t)) => t >= self.metadata.created,
                _ => false,
            },
            "Invalid directory credential state"
        );
        Ok(())
    }
    pub fn encode(&self) -> Result<String> {
        self.validate()?;
        let data = serde_json::to_string(self)?;
        ensure!(
            data.len() <= MAX_RECORD_BYTES,
            "Directory credential record too large"
        );
        Ok(data)
    }
    pub fn decode(value: &str, source_id: &str, authority: &str) -> Result<Self> {
        ensure!(
            value.len() <= MAX_RECORD_BYTES,
            "Directory credential record too large"
        );
        let record: Self = serde_json::from_str(value)
            .map_err(|_| anyhow::anyhow!("Invalid directory credential record"))?;
        record.validate()?;
        ensure!(
            record.metadata.source.id == source_id && record.metadata.authority == authority,
            "Directory credential authority mismatch"
        );
        Ok(record)
    }
    pub fn view(&self, now: i64, owner_current: bool) -> View {
        View {
            metadata: self.metadata.clone(),
            status: if self.revoked_at.is_some() {
                "revoked"
            } else if !owner_current {
                "authorization_changed"
            } else if now >= self.metadata.expires {
                "expired"
            } else if now < self.metadata.created {
                "not_yet_valid"
            } else {
                "configured"
            }
            .into(),
        }
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct View {
    pub metadata: Metadata,
    pub status: String,
}

/// Shared CAS rules. Rotation cannot silently reassign the source or resurrect
/// an old generation after a revoke. Callers authorize inside the transaction.
pub(crate) fn replacement(
    previous: Option<&Record>,
    expected: Option<&str>,
    next: &Record,
    actor: &str,
    version: i64,
    authority: &str,
    now: i64,
) -> Result<()> {
    next.validate()?;
    ensure!(
        next.sealed.is_some()
            && next.revoked_at.is_none()
            && next.metadata.owner == actor
            && next.metadata.owner_version == version
            && next.metadata.authority == authority
            && next.metadata.supersedes.as_deref() == expected,
        "Directory credential authorization or lifetime changed"
    );
    if let Some(old) = previous
        && old.metadata.generation == next.metadata.generation
    {
        ensure!(
            old.encode()? == next.encode()?,
            "Directory credential generation already used"
        );
        return Ok(());
    }
    ensure!(
        (now - 30..=now + 5).contains(&next.metadata.created) && next.metadata.expires > now,
        "Directory credential lifetime changed"
    );
    ensure!(
        previous.map(|p| p.metadata.generation.as_str()) == expected,
        "Directory connection changed; reload before saving"
    );
    if let Some(old) = previous {
        ensure!(
            old.metadata.source == next.metadata.source
                && old.metadata.generation != next.metadata.generation,
            "Directory credential rotation cannot change its source or reuse a generation"
        );
    }
    Ok(())
}
pub(crate) fn revoke(mut record: Record, expected: &str, now: i64) -> Result<Record> {
    ensure!(
        record.metadata.generation == expected,
        "Directory connection changed; reload before revoking"
    );
    if record.revoked_at.is_none() {
        record.sealed = None;
        record.revoked_at = Some(now);
    }
    record.validate()?;
    Ok(record)
}
