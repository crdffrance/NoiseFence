//! Explicit one-shot provider collection. Long network work is detached from
//! HTTP and never holds the policy activation lock. Results still require review.
use super::{
    Controller,
    identity::{PreparedDirectory, local_authorize},
};
use crate::identity::{
    connectors::{entra, okta},
    directory::{Provider, Source},
    management, runtime,
    sync::{self, Event, Failure, Outcome, Request},
};
use anyhow::{Context, Result, ensure};
use rusqlite::params;
use serde::Serialize;
use std::{collections::BTreeSet, sync::Arc};
enum Collector {
    Entra(entra::Credentials),
    Okta(okta::Credentials),
}
#[derive(Serialize)]
pub struct SyncView {
    pub id: String,
    pub source_id: String,
    pub started_at: i64,
    pub deadline: i64,
    pub state: String,
    pub reason: Option<Failure>,
    pub stale: bool,
    pub installed: bool,
    pub prepared: Option<PreparedDirectory>,
}
impl Controller {
    pub async fn identity_sync_status(
        &self,
        id: String,
        actor: String,
        session: String,
    ) -> Result<SyncView> {
        ensure!(
            uuid::Uuid::parse_str(&id).is_ok() && id.len() == 36,
            "Invalid synchronization ID"
        );
        self.directory_authorize(actor.clone(), session.clone())
            .await?;
        let raw = if let Some(c) = self.store.management() {
            c.identity_sync_read(&id, &actor, &session).await?
        } else {
            let id = id.clone();
            self.store.read(move|db| {
                let mut q=db.prepare("SELECT object_id FROM audit WHERE action='identity_sync' AND object_id LIKE ?1 ORDER BY id LIMIT 129")?;
                Ok(q.query_map([format!("{id};%")],|r|r.get(0))?.collect::<rusqlite::Result<Vec<String>>>()?)
            }).await?
        };
        let job = sync::latest(&raw)?
            .remove(&id)
            .context("Synchronization not found")?;
        let current = self.snapshot();
        let stale = current.revision != job.request.revision
            || current.config.identity.as_ref().map(|s| s.sha256.clone())
                != job.request.catalog_sha256;
        let (state, reason, prepared) = match job.outcome {
            Outcome::Running
                if crate::now() > job.request.deadline
                    || job.request.runner != self.identity_sync_runner =>
            {
                ("outcome_unknown", None, None)
            }
            Outcome::Running => ("running", None, None),
            Outcome::Failed { reason } => ("failed", Some(reason), None),
            Outcome::Ready { prepared } => ("ready", None, Some(*prepared)),
        };
        let installed = prepared.as_ref().is_some_and(|p| {
            p.selection.sha256.as_deref()
                == current.config.identity.as_ref().map(|s| s.sha256.as_str())
        });
        self.directory_authorize(actor, session).await?;
        Ok(SyncView {
            id,
            source_id: job.request.source_id,
            started_at: job.request.created,
            deadline: job.request.deadline,
            state: state.into(),
            reason,
            stale,
            installed,
            prepared,
        })
    }
    /// The credential is used for this bounded invocation only and is never
    /// serialized in a receipt, configuration, queue or response.
    pub async fn synchronize_entra(
        self: &Arc<Self>,
        input: sync::EntraInput,
        actor: String,
        session: String,
    ) -> Result<Request> {
        let sync::EntraInput {
            operation,
            revision,
            catalog_sha256: expected,
            source,
            client_id,
            client_secret: secret,
        } = input;
        ensure!(
            source.provider == Provider::Entra,
            "Expected an Entra source"
        );
        let credentials = entra::Credentials::new(&source.authority, &client_id, secret)?;
        self.start_directory_sync(
            operation,
            revision,
            expected,
            source,
            Collector::Entra(credentials),
            actor,
            session,
        )
        .await
    }
    pub async fn synchronize_okta(
        self: &Arc<Self>,
        input: sync::OktaInput,
        actor: String,
        session: String,
    ) -> Result<Request> {
        let sync::OktaInput {
            operation,
            revision,
            catalog_sha256,
            source,
            access_token,
        } = input;
        ensure!(source.provider == Provider::Okta, "Expected an Okta source");
        let credentials = okta::Credentials::new(&source.authority, access_token)?;
        self.start_directory_sync(
            operation,
            revision,
            catalog_sha256,
            source,
            Collector::Okta(credentials),
            actor,
            session,
        )
        .await
    }
    #[allow(clippy::too_many_arguments)]
    async fn start_directory_sync(
        self: &Arc<Self>,
        operation: String,
        revision: i64,
        expected: Option<String>,
        source: Source,
        collector: Collector,
        actor: String,
        session: String,
    ) -> Result<Request> {
        ensure!(
            uuid::Uuid::parse_str(&operation).is_ok() && operation.len() == 36,
            "Invalid synchronization ID"
        );
        ensure!(
            !crate::cluster::is_worker(&self.base),
            "Use the management instance for directory synchronization"
        );
        self.directory_authorize(actor.clone(), session.clone())
            .await?;
        source.validate()?;
        let current = self.snapshot();
        ensure!(
            revision == current.revision
                && expected == current.config.identity.as_ref().map(|s| s.sha256.clone()),
            "Directory changed; reload before synchronization"
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
        let old = previous.sources.iter().find(|s| s.source.id == source.id);
        ensure!(
            old.is_none_or(|s| s.source == source),
            "Source configuration changed; use a new ID for a different authority"
        );
        ensure!(
            old.is_some() || previous.sources.len() < 16,
            "Directory source limit reached"
        );
        let generation = old.map_or(Ok(1), |s| {
            s.generation
                .checked_add(1)
                .context("Source generation exhausted")
        })?;
        let now = crate::now();
        let request = Request {
            id: operation,
            runner: self.identity_sync_runner.clone(),
            source_id: source.id.clone(),
            revision,
            catalog_sha256: expected,
            created: now,
            deadline: now + 360,
        };
        self.identity_sync_begin(&request, actor.clone(), session.clone())
            .await?;
        let this = self.clone();
        let receipt = request.clone();
        tokio::spawn(async move {
            let result = tokio::time::timeout(std::time::Duration::from_secs(350), async {
                let collected = match collector {
                    Collector::Entra(credentials) => {
                        entra::synchronize(
                            &source,
                            generation,
                            &credentials,
                            entra::Limits::default(),
                        )
                        .await
                    }
                    Collector::Okta(credentials) => {
                        okta::synchronize(
                            &source,
                            generation,
                            &credentials,
                            okta::Limits::default(),
                        )
                        .await
                    }
                }
                .map_err(|_| Failure::Collection)?;
                this.prepare_collected_directory(
                    &receipt,
                    previous,
                    collected.snapshot,
                    scopes,
                    actor.clone(),
                    session,
                )
                .await
            })
            .await
            .unwrap_or(Err(Failure::Deadline));
            let outcome = match result {
                Ok(prepared) => Outcome::Ready {
                    prepared: Box::new(prepared),
                },
                Err(reason) => Outcome::Failed { reason },
            };
            if this
                .identity_sync_finish(
                    Event {
                        request: receipt.clone(),
                        outcome,
                    },
                    actor,
                )
                .await
                .is_err()
            {
                // No provider response, secret or directory data in logs.
                tracing::warn!(job=%receipt.id,"Directory synchronization outcome was not recorded; inspect the receipt before retrying");
            }
        });
        Ok(request)
    }
    async fn prepare_collected_directory(
        &self,
        request: &Request,
        previous: runtime::Document,
        collected: crate::identity::directory::Snapshot,
        scopes: BTreeSet<String>,
        actor: String,
        session: String,
    ) -> Result<PreparedDirectory, Failure> {
        let _permit = self
            .applying
            .clone()
            .try_acquire_owned()
            .map_err(|_| Failure::Stale)?;
        self.directory_authorize(actor.clone(), session.clone())
            .await
            .map_err(|_| Failure::Authorization)?;
        let current = self.snapshot();
        if request.revision != current.revision
            || request.catalog_sha256 != current.config.identity.as_ref().map(|s| s.sha256.clone())
        {
            return Err(Failure::Stale);
        }
        let candidate = tokio::task::spawn_blocking(move || {
            management::preview_collected(&previous, collected, &scopes, crate::now())
        })
        .await
        .map_err(|_| Failure::Preparation)?
        .map_err(|_| Failure::Preparation)?;
        let root = self.base.data_dir.clone();
        let reserve = self.base.smtp.minimum_free_bytes;
        let bytes = serde_json::to_vec(&candidate.document).map_err(|_| Failure::Preparation)?;
        let mut selection = if let Some(c) = self.store.management() {
            c.prepare_identity_directory(root, bytes, reserve, &actor, &session)
                .await
                .map_err(|_| Failure::Preparation)?
        } else {
            // The durable sync intent already records authorization; artifact
            // creation never activates it, and the result is journalled below.
            tokio::task::spawn_blocking(move || {
                runtime::prepare(&root, &bytes, crate::now(), reserve)
            })
            .await
            .map_err(|_| Failure::Preparation)?
            .map_err(|_| Failure::Preparation)?
        };
        self.directory_authorize(actor, session)
            .await
            .map_err(|_| Failure::Authorization)?;
        selection.reviewed_from = request.catalog_sha256.clone();
        Ok(PreparedDirectory {
            revision: request.revision,
            selection,
            review: candidate.review,
            active: false,
        })
    }
    pub(crate) async fn identity_sync_begin(
        &self,
        request: &Request,
        actor: String,
        session: String,
    ) -> Result<()> {
        if let Some(c) = self.store.management() {
            return c.identity_sync_begin(request, &actor, &session).await;
        }
        let request = request.clone();
        self.store.run(move|db| {
            let tx=db.transaction()?;local_authorize(&tx,&actor,&session)?;
            let raw={let mut q=tx.prepare("SELECT object_id FROM audit WHERE action='identity_sync' AND created>=?1 ORDER BY id LIMIT 129")?;q.query_map([request.created-3960],|r|r.get(0))?.collect::<rusqlite::Result<Vec<String>>>()?};
            sync::admit(&raw,&request,crate::now())?;
            let data=Event{request:request.clone(),outcome:Outcome::Running}.encode()?;
            tx.execute("INSERT INTO audit(created,username,action,object_id) VALUES(?1,?2,'identity_sync',?3)",params![crate::now(),actor,data])?;
            tx.commit()?;Ok(())
        }).await
    }
    pub(crate) async fn identity_sync_finish(&self, event: Event, actor: String) -> Result<()> {
        if let Some(c) = self.store.management() {
            return c.identity_sync_finish(&event, &actor).await;
        }
        self.store.run(move|db| {
            let tx=db.transaction()?;
            let raw={let mut q=tx.prepare("SELECT object_id FROM audit WHERE action='identity_sync' AND object_id LIKE ?1 ORDER BY id LIMIT 129")?;q.query_map([format!("{};%",event.request.id)],|r|r.get(0))?.collect::<rusqlite::Result<Vec<String>>>()?};
            sync::finish(&raw,&event,crate::now())?;
            tx.execute("INSERT INTO audit(created,username,action,object_id) VALUES(?1,?2,'identity_sync',?3)",params![crate::now(),actor,event.encode()?])?;
            tx.commit()?;Ok(())
        }).await
    }
}

#[cfg(test)]
mod tests;
