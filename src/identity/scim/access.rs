//! High-entropy inbound capability. Neither bearer values nor their verifier
//! are included in public connection views, audit entries or policy bundles.
use super::{Error, Result, resource};
use crate::identity::{
    connections::{Credential, Record, vault::Key},
    directory::Provider,
};
use rand::RngCore;
use ring::hmac;
const DOMAIN: &[u8] = b"NoiseFence SCIM bearer verifier v1";
pub(crate) const UNAUTHORIZED: Error = Error::new(401, "", "Invalid provisioning authorization.");
/// Intentionally not Clone, Debug or Serialize. The token is returned only by
/// explicit enrollment; HTTP headers must also be marked sensitive by callers.
pub struct Bearer {
    generation: String,
    value: String,
}
impl Bearer {
    pub fn issue(generation: &str) -> Result<(Self, String)> {
        if !resource::id(generation) {
            return Err(super::INVALID);
        }
        let mut bytes = [0; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let value = format!("nfscim1_{generation}_{}", hex::encode(bytes));
        let verifier = hex::encode(
            hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, DOMAIN), value.as_bytes()).as_ref(),
        );
        Ok((
            Self {
                generation: generation.into(),
                value,
            },
            verifier,
        ))
    }
    pub fn parse(value: String) -> Result<Self> {
        if value.len() != 109 || !value.is_ascii() {
            return Err(UNAUTHORIZED);
        }
        let rest = value.strip_prefix("nfscim1_").ok_or(UNAUTHORIZED)?;
        let (generation, secret) = rest.split_once('_').ok_or(UNAUTHORIZED)?;
        if !resource::id(generation)
            || secret.len() != 64
            || !secret
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(UNAUTHORIZED);
        }
        Ok(Self {
            generation: generation.into(),
            value,
        })
    }
    pub fn into_value(self) -> String {
        self.value
    }
    pub(crate) fn verify(
        &self,
        record: &Record,
        key: &Key,
        owner_current: bool,
        now: i64,
    ) -> Result<()> {
        if !owner_current
            || record.metadata.source.provider != Provider::Scim
            || record.metadata.generation != self.generation
            || record.view(now, true).status != "configured"
        {
            return Err(UNAUTHORIZED);
        }
        let Credential::ScimBearerVerifier { verifier } =
            key.open(record, now).map_err(|_| UNAUTHORIZED)?
        else {
            return Err(UNAUTHORIZED);
        };
        let digest = hex::decode(verifier).map_err(|_| UNAUTHORIZED)?;
        // The domain-separator key is public. Security comes from the uniformly
        // random 256-bit bearer; HMAC verification supplies constant-time compare.
        hmac::verify(
            &hmac::Key::new(hmac::HMAC_SHA256, DOMAIN),
            self.value.as_bytes(),
            &digest,
        )
        .map_err(|_| UNAUTHORIZED)
    }
}
pub struct Access {
    pub(crate) source_id: String,
    pub(crate) bearer: Bearer,
}
impl Access {
    pub fn new(source_id: String, token: String) -> Result<Self> {
        if !crate::identity::text(&source_id, 100) {
            return Err(UNAUTHORIZED);
        }
        Ok(Self {
            source_id,
            bearer: Bearer::parse(token)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{
        connections::{Metadata, PROTOCOL},
        directory::Source,
        schedule::Grant,
    };
    fn credential(key: &Key, created: i64, expires: i64) -> (Bearer, Record) {
        let generation = uuid::Uuid::new_v4().to_string();
        let (token, verifier) = Bearer::issue(&generation).unwrap();
        let record = key
            .seal(
                Metadata {
                    protocol: PROTOCOL.into(),
                    source: Source {
                        id: "scim-test".into(),
                        label: "Fixture".into(),
                        provider: Provider::Scim,
                        authority: "synthetic".into(),
                        scopes: ["example.test".into()].into(),
                        stale_after_seconds: 86400,
                    },
                    generation,
                    supersedes: None,
                    authority: "sqlite".into(),
                    key_id: key.id(),
                    owner: "admin".into(),
                    owner_version: 0,
                    created,
                    expires,
                },
                &Credential::ScimBearerVerifier { verifier },
            )
            .unwrap();
        (token, record)
    }
    #[test]
    fn inbound_capabilities_expire_and_owner_rights_are_required() {
        let root = tempfile::tempdir().unwrap();
        let key = Key::initialize(root.path()).unwrap();
        let (token, record) = credential(&key, 1000, 1100);
        assert!(token.verify(&record, &key, true, 1000).is_ok());
        for time in [999, 1100, 1200] {
            assert!(token.verify(&record, &key, true, time).is_err());
        }
        assert!(token.verify(&record, &key, false, 1050).is_err());
    }
    #[test]
    fn token_format_and_generation_cannot_be_substituted() {
        let root = tempfile::tempdir().unwrap();
        let key = Key::initialize(root.path()).unwrap();
        let (token, record) = credential(&key, 1000, 1100);
        let (other, _) = credential(&key, 1000, 1100);
        assert!(other.verify(&record, &key, true, 1050).is_err());
        let raw = token.into_value();
        for bad in [
            String::new(),
            format!("{raw} "),
            format!("Bearer {raw}"),
            raw.to_uppercase(),
            "x".repeat(109),
        ] {
            assert!(Bearer::parse(bad).is_err());
        }
        let mut wrong = raw.into_bytes();
        let last = wrong.last_mut().unwrap();
        *last = if *last == b'0' { b'1' } else { b'0' };
        assert!(
            Bearer::parse(String::from_utf8(wrong).unwrap())
                .unwrap()
                .verify(&record, &key, true, 1050)
                .is_err()
        );
    }
    #[test]
    fn encrypted_verifier_binds_source_key_and_revocation() {
        let root = tempfile::tempdir().unwrap();
        let key = Key::initialize(root.path()).unwrap();
        let (token, record) = credential(&key, 1000, 1100);
        let mut changed = record.clone();
        changed.metadata.source.authority = "another".into();
        assert!(token.verify(&changed, &key, true, 1050).is_err());
        let mut revoked = record.clone();
        revoked.revoked_at = Some(1040);
        revoked.sealed = None;
        assert!(token.verify(&revoked, &key, true, 1050).is_err());
        let other = tempfile::tempdir().unwrap();
        let other_key = Key::initialize(other.path()).unwrap();
        assert!(token.verify(&record, &other_key, true, 1050).is_err());
    }
    #[test]
    fn provisioning_capability_never_authorizes_a_pull_schedule() {
        let root = tempfile::tempdir().unwrap();
        let key = Key::initialize(root.path()).unwrap();
        let (_token, record) = credential(&key, 1000, 10000);
        let grant = Grant {
            protocol: crate::identity::schedule::PROTOCOL.into(),
            id: uuid::Uuid::new_v4().to_string(),
            connection: crate::identity::connections::Reference {
                source_id: record.metadata.source.id.clone(),
                generation: record.metadata.generation.clone(),
            },
            created: 1000,
            expires: 9000,
            interval_seconds: 900,
        };
        assert!(grant.validate(&record.metadata).is_err());
    }
}
