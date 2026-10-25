//! Enrollment creates provisioning access only. It never publishes a directory.
use super::Controller;
use crate::identity::{
    connections::{self, Credential, Metadata},
    directory::{Provider, Source},
    scim::{self, access::Bearer},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Enroll {
    pub revision: i64,
    pub catalog_sha256: Option<String>,
    pub expected_generation: Option<String>,
    pub source: Source,
    pub expires: i64,
}
/// The only response containing the bearer. Not Clone or Debug and never saved.
#[derive(Serialize)]
pub struct Enrolled {
    pub source: Source,
    pub generation: String,
    pub expires: i64,
    pub base_url: String,
    pub bearer: String,
}
impl Controller {
    pub async fn enroll_scim(
        &self,
        input: Enroll,
        actor: String,
        session: String,
    ) -> Result<Enrolled> {
        self.directory_authorize(actor.clone(), session.clone())
            .await?;
        let _permit = self
            .applying
            .clone()
            .try_acquire_owned()
            .context("A policy operation is already in progress")?;
        ensure!(
            input.source.provider == Provider::Scim,
            "SCIM source required"
        );
        let base_url = scim::endpoint::base(
            &self.base.web.public_origin,
            &input.source.id,
            !self.base.web.secure_cookies && self.base.web.listen.ip().is_loopback(),
        )?;
        self.directory_context(input.revision, input.catalog_sha256, &input.source)
            .await?;
        let now = crate::now();
        ensure!(
            input.expires > now && input.expires <= now + 90 * 86400,
            "SCIM access expires within 90 days"
        );
        // A client does not choose token entropy, verifier or enrollment UUID.
        let generation = uuid::Uuid::new_v4().to_string();
        let (bearer, verifier) = Bearer::issue(&generation)?;
        let (key, version) = self
            .store
            .identity_connection_prepare(actor.clone(), session.clone())
            .await?;
        let record = key.seal(
            Metadata {
                protocol: connections::PROTOCOL.into(),
                source: input.source.clone(),
                generation: generation.clone(),
                supersedes: input.expected_generation.clone(),
                authority: self.store.directory_connection_authority(),
                key_id: key.id(),
                owner: actor.clone(),
                owner_version: version,
                created: now,
                expires: input.expires,
            },
            &Credential::ScimBearerVerifier { verifier },
        )?;
        self.store
            .identity_connection_save(
                input.expected_generation,
                record,
                actor.clone(),
                session.clone(),
            )
            .await?;
        self.directory_authorize(actor, session).await?;
        Ok(Enrolled {
            source: input.source,
            generation,
            expires: input.expires,
            base_url,
            bearer: bearer.into_value(),
        })
    }
}
