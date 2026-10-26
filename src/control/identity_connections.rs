//! Administrative connection lifecycle. Credential persistence is separate from
//! directory snapshot approval and never authorizes background use implicitly.
use super::Controller;
use crate::identity::{
    connections::{self, Credential, Metadata, Reference, vault::Key},
    directory::Source,
    runtime,
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, sync::Arc};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Save {
    pub operation: String,
    pub revision: i64,
    pub catalog_sha256: Option<String>,
    pub expected_generation: Option<String>,
    pub source: Source,
    pub expires: i64,
    pub credential: Credential,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Collect {
    pub operation: String,
    pub revision: i64,
    pub catalog_sha256: Option<String>,
    pub connection: Reference,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdUpload {
    pub revision: i64,
    pub catalog_sha256: Option<String>,
    pub connection: Reference,
    pub envelope: Option<crate::identity::connectors::ad::Envelope>,
}
#[derive(Serialize)]
pub struct ConnectionView {
    pub schedule: Option<crate::identity::schedule::View>,
    pub source: Source,
    pub generation: String,
    pub owner: String,
    pub created: i64,
    pub expires: i64,
    pub status: String,
}
#[derive(Serialize)]
pub struct ConnectionsView {
    pub revision: i64,
    pub catalog_sha256: Option<String>,
    pub vault: String,
    pub connections: Vec<ConnectionView>,
}
// One immutable catalog read serves the entire status list, even at the source
// limit. Do not parse a 64 MiB catalog once per credential on an HTTP request.
fn source_generation(
    previous: &runtime::Document,
    source: &Source,
    scopes: &BTreeSet<String>,
) -> Result<u64> {
    ensure!(
        source.scopes.iter().all(|s| scopes.contains(s)),
        "Source scope is not a configured receiving domain"
    );
    let old = previous.sources.iter().find(|s| s.source.id == source.id);
    ensure!(
        old.is_none_or(|s| s.source == *source),
        "Source configuration changed; use a new ID for a different authority"
    );
    ensure!(
        old.is_some() || previous.sources.len() < 16,
        "Directory source limit reached"
    );
    old.map_or(Ok(1), |s| {
        s.generation
            .checked_add(1)
            .context("Source generation exhausted")
    })
}
impl Controller {
    pub(super) async fn directory_context(
        &self,
        revision: i64,
        expected: Option<String>,
        source: &Source,
    ) -> Result<(runtime::Document, BTreeSet<String>, u64)> {
        ensure!(
            !crate::cluster::is_worker(&self.base),
            "Use the management instance for directory connections"
        );
        source.validate()?;
        let current = self.snapshot();
        ensure!(
            revision == current.revision
                && expected == current.config.identity.as_ref().map(|s| s.sha256.clone()),
            "Directory changed; reload before continuing"
        );
        let scopes: BTreeSet<_> = current
            .config
            .domains
            .iter()
            .map(|d| d.name.clone())
            .collect();
        ensure!(
            source.scopes.iter().all(|s| scopes.contains(s)),
            "Source scope is not a configured receiving domain"
        );
        let settings = current.config.identity.clone();
        let previous = tokio::task::spawn_blocking(move || match settings {
            Some(s) => runtime::read_document(&s, crate::now()),
            None => Ok(runtime::Document {
                schema: runtime::SCHEMA.into(),
                sources: vec![],
            }),
        })
        .await??;
        let generation = source_generation(&previous, source, &scopes)?;
        Ok((previous, scopes, generation))
    }
    pub async fn directory_connections(
        &self,
        actor: String,
        session: String,
    ) -> Result<ConnectionsView> {
        ensure!(
            !crate::cluster::is_worker(&self.base),
            "Use the management instance for directory connections"
        );
        let records = self
            .store
            .identity_connection_list(actor.clone(), session.clone())
            .await?;
        let root = self.base.data_dir.clone();
        let (key_id, uninitialized) = tokio::task::spawn_blocking(move || {
            let absent = std::fs::symlink_metadata(root.join("directory-vault"))
                .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound);
            (Key::load(&root).ok().map(|k| k.id()), absent)
        })
        .await?;
        let snapshot = self.snapshot();
        let settings = snapshot.config.identity.clone();
        let scopes = snapshot
            .config
            .domains
            .iter()
            .map(|d| d.name.clone())
            .collect();
        let document = tokio::task::spawn_blocking(move || match settings {
            Some(s) => runtime::read_document(&s, crate::now()),
            None => Ok(runtime::Document {
                schema: runtime::SCHEMA.into(),
                sources: vec![],
            }),
        })
        .await?;
        let mut connections = Vec::new();
        for view in records {
            let mut status = view.status;
            if status == "configured" {
                if key_id.as_deref() != Some(&view.metadata.key_id) {
                    status = "key_unavailable".into();
                } else if document.is_err() {
                    status = "directory_unavailable".into();
                } else if document.as_ref().is_ok_and(|doc| {
                    source_generation(doc, &view.metadata.source, &scopes).is_err()
                }) {
                    status = "configuration_changed".into();
                }
            }
            let mut schedule = view.schedule;
            if let Some(s) = schedule.as_mut() {
                if !matches!(s.state.as_str(), "stopped" | "expired") && status != "configured" {
                    s.state = "access_unavailable".into();
                } else if s.state == "awaiting_review"
                    && s.last_run
                        .as_ref()
                        .is_some_and(|r| r.request.revision != snapshot.revision)
                {
                    s.state = "scheduled".into();
                }
            }
            connections.push(ConnectionView {
                schedule,
                source: view.metadata.source,
                generation: view.metadata.generation,
                owner: view.metadata.owner,
                created: view.metadata.created,
                expires: view.metadata.expires,
                status,
            });
        }
        self.directory_authorize(actor, session).await?;
        Ok(ConnectionsView {
            revision: snapshot.revision,
            catalog_sha256: snapshot.config.identity.as_ref().map(|s| s.sha256.clone()),
            vault: if key_id.is_some() {
                "ready"
            } else if connections.is_empty() && uninitialized {
                "not_initialized"
            } else {
                "unavailable"
            }
            .into(),
            connections,
        })
    }
    pub async fn save_directory_connection(
        &self,
        input: Save,
        actor: String,
        session: String,
    ) -> Result<ConnectionsView> {
        self.directory_authorize(actor.clone(), session.clone())
            .await?;
        let _permit = self
            .applying
            .clone()
            .try_acquire_owned()
            .context("A policy operation is already in progress")?;
        Reference {
            source_id: input.source.id.clone(),
            generation: input.operation.clone(),
        }
        .validate()?;
        ensure!(
            input.source.provider != crate::identity::directory::Provider::Scim,
            "Use explicit server-generated SCIM enrollment"
        );
        self.directory_context(input.revision, input.catalog_sha256.clone(), &input.source)
            .await?;
        input
            .credential
            .validate(&input.source, crate::now(), input.expires)?;
        let (key, version) = self
            .store
            .identity_connection_prepare(actor.clone(), session.clone())
            .await?;
        // The operation UUID is the receipt/generation. After a lost reply the
        // caller reads status by this ID, never silently resubmits a secret.
        let record = key.seal(
            Metadata {
                protocol: connections::PROTOCOL.into(),
                source: input.source,
                generation: input.operation,
                supersedes: input.expected_generation.clone(),
                authority: self.store.directory_connection_authority(),
                key_id: key.id(),
                owner: actor.clone(),
                owner_version: version,
                created: crate::now(),
                expires: input.expires,
            },
            &input.credential,
        )?;
        self.store
            .identity_connection_save(
                input.expected_generation,
                record,
                actor.clone(),
                session.clone(),
            )
            .await?;
        self.directory_connections(actor, session).await
    }
    pub async fn revoke_directory_connection(
        &self,
        reference: Reference,
        actor: String,
        session: String,
    ) -> Result<ConnectionsView> {
        ensure!(
            !crate::cluster::is_worker(&self.base),
            "Use the management instance for directory connections"
        );
        reference.validate()?;
        self.store
            .identity_connection_revoke(
                reference.source_id,
                reference.generation,
                actor.clone(),
                session.clone(),
            )
            .await?;
        self.directory_connections(actor, session).await
    }
    pub(super) async fn directory_connection_live(
        &self,
        reference: &Reference,
        actor: &str,
        session: &str,
    ) -> Result<()> {
        reference.validate()?;
        self.store
            .identity_connection_get(
                reference.source_id.clone(),
                reference.generation.clone(),
                actor.into(),
                session.into(),
            )
            .await?;
        Ok(())
    }
    pub async fn upload_ad_directory(
        self: &Arc<Self>,
        mut input: AdUpload,
        actor: String,
        session: String,
    ) -> Result<crate::identity::sync::Request> {
        input.connection.validate()?;
        let record = self
            .store
            .identity_connection_get(
                input.connection.source_id.clone(),
                input.connection.generation.clone(),
                actor.clone(),
                session.clone(),
            )
            .await?;
        let source = record.metadata.source.clone();
        self.directory_context(input.revision, input.catalog_sha256.clone(), &source)
            .await?;
        let envelope = input
            .envelope
            .take()
            .context("Signed AD envelope required")?;
        let root = self.base.data_dir.clone();
        let verified_source = source.clone();
        let export = tokio::task::spawn_blocking(move || -> Result<_> {
            let key = Key::load(&root)?;
            let Credential::AdCollectorPublicKey { public_key } =
                key.open(&record, crate::now())?
            else {
                anyhow::bail!("AD public-key enrollment required")
            };
            crate::identity::connectors::ad::PublicKey::new(
                &verified_source.authority,
                &public_key,
            )?
            .verify(&verified_source, envelope, crate::now())
        })
        .await??;
        self.start_ad_directory_sync(input, source, export, actor, session)
            .await
    }
    pub async fn collect_directory_connection(
        self: &Arc<Self>,
        input: Collect,
        actor: String,
        session: String,
    ) -> Result<crate::identity::sync::Request> {
        input.connection.validate()?;
        let record = self
            .store
            .identity_connection_get(
                input.connection.source_id.clone(),
                input.connection.generation.clone(),
                actor.clone(),
                session.clone(),
            )
            .await?;
        let root = self.base.data_dir.clone();
        let source = record.metadata.source.clone();
        self.directory_context(input.revision, input.catalog_sha256.clone(), &source)
            .await?;
        let credential =
            tokio::task::spawn_blocking(move || Key::load(&root)?.open(&record, crate::now()))
                .await??;
        self.start_stored_directory_sync(input, source, credential, actor, session)
            .await
    }
}
