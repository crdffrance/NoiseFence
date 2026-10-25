//! Directory artifacts use the selected management authority for authorization
//! and durable audit, and the normal policy revision for their later activation.
use super::Controller;
use crate::identity::{management, runtime};
use anyhow::{Context, Result, ensure};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, sync::Arc};

#[derive(Serialize)]
pub struct DirectoryView {
    pub revision: i64,
    pub catalog_sha256: Option<String>,
    pub observation_only: bool,
    pub sources: Vec<management::SourceStatus>,
    pub draft: Option<management::Draft>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreparedDirectory {
    pub revision: i64,
    pub selection: runtime::Selection,
    pub review: management::Review,
    pub active: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collection: Option<crate::identity::sync::CollectionSummary>,
}
impl Controller {
    pub(super) async fn directory_authorize(&self, actor: String, session: String) -> Result<()> {
        if let Some(central) = self.store.management() {
            central.policy_approval(&actor, &session, None).await?;
        } else {
            self.store
                .run(move |db| {
                    let tx = db.transaction()?;
                    local_authorize(&tx, &actor, &session)
                })
                .await?;
        }
        Ok(())
    }
    pub async fn identity_directory(
        &self,
        actor: String,
        session: String,
        source: Option<String>,
    ) -> Result<DirectoryView> {
        self.directory_authorize(actor.clone(), session.clone())
            .await?;
        ensure!(
            source
                .as_ref()
                .is_none_or(|s| crate::identity::text(s, 100)),
            "Invalid source identifier"
        );
        let snapshot = self.snapshot();
        let settings = snapshot.config.identity.clone();
        let hash = settings.as_ref().map(|s| s.sha256.clone());
        let (sources, draft) = tokio::task::spawn_blocking(move || -> Result<_> {
            let document = match settings {
                Some(s) => runtime::read_document(&s, crate::now())?,
                None => runtime::Document {
                    schema: runtime::SCHEMA.into(),
                    sources: vec![],
                },
            };
            let draft = source
                .map(|id| {
                    document
                        .sources
                        .iter()
                        .find(|s| s.source.id == id)
                        .cloned()
                        .map(management::Draft::from)
                        .context("Source not found")
                })
                .transpose()?;
            Ok((
                document
                    .sources
                    .iter()
                    .map(|s| management::SourceStatus::new(s, crate::now()))
                    .collect(),
                draft,
            ))
        })
        .await??;
        self.directory_authorize(actor, session).await?;
        Ok(DirectoryView {
            revision: snapshot.revision,
            catalog_sha256: hash,
            observation_only: true,
            sources,
            draft,
        })
    }
    pub async fn prepare_identity_directory(
        self: &Arc<Self>,
        revision: i64,
        expected: Option<String>,
        edit: management::Edit,
        actor: String,
        session: String,
    ) -> Result<PreparedDirectory> {
        ensure!(
            !crate::cluster::is_worker(&self.base),
            "Prepare directory changes on the management instance"
        );
        let permit = self
            .applying
            .clone()
            .try_acquire_owned()
            .context("A policy operation is already in progress")?;
        let this = self.clone();
        tokio::spawn(async move {
            let _permit=permit;
            this.directory_authorize(actor.clone(),session.clone()).await?;
            let current=this.snapshot();
            ensure!(revision==current.revision && expected==current.config.identity.as_ref().map(|s|s.sha256.clone()),"Directory changed; reload and review the current snapshot");
            let settings=current.config.identity.clone();
            let scopes:BTreeSet<_>=current.config.domains.iter().map(|d|d.name.clone()).collect();
            let candidate=tokio::task::spawn_blocking(move|| -> Result<_> {
                let previous=match settings {Some(s)=>runtime::read_document(&s,crate::now())?,None=>runtime::Document{schema:runtime::SCHEMA.into(),sources:vec![]}};
                management::preview(&previous,edit,&scopes,crate::now()).map_err(|e|management::InvalidEdit(e.to_string()).into())
            }).await??;
            let bytes=serde_json::to_vec(&candidate.document)?;
            let hash=crate::message::digest(&bytes);
            let root=this.base.data_dir.clone();
            let reserve=this.base.smtp.minimum_free_bytes;
            let mut selection=if let Some(central)=this.store.management() {
                central.prepare_identity_directory(root,bytes,reserve,&actor,&session).await?
            } else {
                let object=format!("{}:{hash}",uuid::Uuid::new_v4());
                let a=actor.clone();let t=session.clone();let o=object.clone();
                this.directory_authorize(a.clone(),t.clone()).await?;
                this.store.run(move|db| {
                    let tx=db.transaction()?;
                    local_authorize(&tx,&a,&t)?;
                    tx.execute("INSERT INTO audit(created,username,action,object_id) VALUES(?1,?2,'identity_prepare_started',?3)",params![crate::now(),a,o])?;
                    tx.commit()?;Ok(())
                }).await?;
                let outcome=tokio::task::spawn_blocking(move||runtime::prepare(&root,&bytes,crate::now(),reserve)).await.context("Directory preparation interrupted").and_then(|r|r);
                let action=if outcome.is_ok(){"identity_prepare_completed"}else{"identity_prepare_failed"};
                let a=actor.clone();
                this.store.run(move|db| {
                    db.execute("INSERT INTO audit(created,username,action,object_id) VALUES(?1,?2,?3,?4)",params![crate::now(),a,action,object])?;Ok(())
                }).await.context("Directory outcome not recorded; reload before retrying")?;
                outcome?
            };
            selection.reviewed_from=expected;
            // Preparation grants no activation; a later settings save rechecks
            // the session, administrator role, base revision and both digests.
            this.directory_authorize(actor,session).await?;
            Ok(PreparedDirectory{revision,selection,review:candidate.review,active:false,collection:None})
        }).await?
    }
}

pub(crate) fn local_authorize(
    tx: &rusqlite::Transaction<'_>,
    actor: &str,
    session: &str,
) -> Result<()> {
    super::activation_authority::admin(tx, actor, session)?;
    let allowed: bool = tx.query_row(
        "SELECT NOT EXISTS(SELECT 1 FROM mfa_credentials WHERE username=?1 AND enabled=1) OR EXISTS(SELECT 1 FROM mfa_sessions WHERE token_hash=?2)",
        params![actor, session], |r| r.get(0),
    )?;
    ensure!(allowed, "A verified administrator session is required");
    Ok(())
}
