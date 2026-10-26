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

#[derive(Serialize)]
pub struct InventoryView {
    pub revision: i64,
    pub catalog_sha256: Option<String>,
    pub stage: scim::repository::Stage,
    pub draft: Option<crate::identity::management::Draft>,
    pub inventory_sha256: Option<String>,
    pub problem: Option<&'static str>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attest {
    pub operation: String,
    pub revision: i64,
    pub catalog_sha256: Option<String>,
    pub connection: connections::Reference,
    pub staged_revision: scim::Revision,
    pub inventory_sha256: String,
    pub complete_inventory: bool,
}
impl Controller {
    pub async fn scim_inventory_view(
        &self,
        reference: connections::Reference,
        actor: String,
        session: String,
    ) -> Result<InventoryView> {
        self.directory_authorize(actor.clone(), session.clone())
            .await?;
        let inventory = self
            .store
            .scim_inventory(reference, actor.clone(), session.clone())
            .await?;
        let current = self.snapshot();
        let hash = current.config.identity.as_ref().map(|s| s.sha256.clone());
        self.directory_context(current.revision, hash.clone(), &inventory.source)
            .await?;
        let stage = inventory.stage;
        let staged_revision = stage.revision.clone();
        let projection = tokio::task::spawn_blocking(move || {
            scim::Candidate::inspect(
                inventory.source,
                staged_revision,
                &inventory.resources,
                crate::now(),
            )
        })
        .await?;
        self.directory_authorize(actor, session).await?;
        let (draft, inventory_sha256, problem) = match projection {
            Ok((draft, hash)) => (Some(draft), Some(hash), None),
            Err(_) => (
                None,
                None,
                Some(
                    "The staged graph is incomplete or invalid. Finish provisioning and reload before attesting.",
                ),
            ),
        };
        Ok(InventoryView {
            revision: current.revision,
            catalog_sha256: hash,
            stage,
            draft,
            inventory_sha256,
            problem,
        })
    }
    /// Explicit human completeness attestation, then immutable preparation. The
    /// same enrollment/sequence is checked transactionally at intent and Ready.
    /// Later provisioning is not included in the prepared artifact.
    pub async fn attest_scim(
        self: &std::sync::Arc<Self>,
        input: Attest,
        actor: String,
        session: String,
    ) -> Result<crate::identity::sync::Request> {
        ensure!(
            input.complete_inventory,
            "Explicit inventory completeness attestation required"
        );
        ensure!(
            crate::compatibility::valid_hash(&input.inventory_sha256),
            "Invalid inventory digest"
        );
        self.directory_authorize(actor.clone(), session.clone())
            .await?;
        let inventory = self
            .store
            .scim_inventory(input.connection.clone(), actor.clone(), session.clone())
            .await?;
        ensure!(
            inventory.stage.revision == input.staged_revision,
            "Inventory changed; reload and review"
        );
        let (_, _, generation) = self
            .directory_context(
                input.revision,
                input.catalog_sha256.clone(),
                &inventory.source,
            )
            .await?;
        let source = inventory.source.clone();
        let candidate = tokio::task::spawn_blocking(move || {
            let now = crate::now();
            scim::Candidate::prepare(
                inventory.source,
                inventory.stage.revision,
                generation,
                &inventory.resources,
                now,
                now,
            )
        })
        .await??;
        ensure!(
            candidate.inventory_sha256() == input.inventory_sha256,
            "Inventory changed; reload and review"
        );
        self.start_directory_sync(
            input.operation,
            input.revision,
            input.catalog_sha256,
            source,
            super::identity_sync::Collector::Scim(Box::new(candidate)),
            actor,
            session,
            Some(input.connection),
        )
        .await
    }
}
