//! Authority orchestration, separate from the local participant driver. Durable
//! preparation is an approved job; account/privilege changes invalidate its commit.
use super::{Controller, Settings};
use crate::cluster::{
    Role,
    activation::{Epoch, Journal, Phase, Progress, transport::Peer},
    artifacts,
};
use anyhow::{Context, Result, ensure};
use rusqlite::{OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum ActivationProblem {
    ApprovalChanged,
    MembershipChanged,
    RuntimePreparationFailed,
    RuntimeGenerationBusy,
}
impl std::fmt::Display for ActivationProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::ApprovalChanged => "Activation approval is no longer valid",
            Self::MembershipChanged => "Activation membership changed",
            Self::RuntimePreparationFailed => {
                "The local runtime could not prepare or install the policy"
            }
            Self::RuntimeGenerationBusy => {
                "Waiting for previous analyses to release runtime generations"
            }
        })
    }
}
impl std::error::Error for ActivationProblem {}

#[derive(Default)]
struct Selection {
    scope: Option<String>,
    models_sha256: Option<String>,
    credential: Option<(String, Option<String>)>,
}
const PROPOSAL: &str = "activation_proposal";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Proposal {
    epoch: Epoch,
    actor: String,
    actor_version: i64,
    #[serde(default)]
    scope: Option<String>,
}
fn approval(
    tx: &Transaction<'_>,
    actor: &str,
    token: Option<&str>,
    scope: Option<&str>,
) -> Result<i64> {
    let (is_admin, version): (bool, i64) = tx.query_row(
        "SELECT u.admin,COALESCE(v.version,0) FROM users u LEFT JOIN console_user_versions v ON v.username=u.username WHERE u.username=?1 AND u.disabled=0",
        [actor], |r| Ok((r.get(0)?, r.get(1)?)),
    ).optional()?.context("Approving account disabled or removed")?;
    if let Some(token) = token {
        let valid: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM sessions WHERE username=?1 AND token_hash=?2 AND expires>?3)", params![actor, token, crate::now()], |r| r.get(0))?;
        ensure!(valid, "Approving session expired or revoked");
    }
    if let Some(scope) = scope {
        let grants = tx
            .prepare("SELECT address FROM grants WHERE username=?1")?
            .query_map([actor], |r| r.get(0))?
            .collect::<rusqlite::Result<Vec<String>>>()?;
        ensure!(
            crate::preferences::permitted(scope, is_admin, &grants),
            "Preference address is no longer authorized"
        );
    } else {
        ensure!(is_admin, "Administrator rights required");
    }
    Ok(version)
}
fn admin(tx: &Transaction<'_>, actor: &str, token: &str) -> Result<i64> {
    approval(tx, actor, Some(token), None)
}
/// A delegated proposal can change exactly one mailbox entry, never its limits,
/// global settings, other recipients, model bindings or administrator rules.
fn scoped_delta(base: &Settings, next: &Settings, scope: &str) -> Result<()> {
    ensure!(
        base.preferences.enabled,
        "Customization disabled by the administrator"
    );
    let mut expected = base.clone();
    if let Some(p) = next.preferences.mailboxes.get(scope) {
        expected
            .preferences
            .mailboxes
            .insert(scope.to_owned(), p.clone());
    } else {
        expected.preferences.mailboxes.remove(scope);
    }
    ensure!(
        &expected == next,
        "Preference proposal changes settings outside its authorized scope"
    );
    Ok(())
}
fn save_proposal(
    tx: &Transaction<'_>,
    journal: &Journal,
    actor: String,
    actor_version: i64,
    scope: Option<String>,
) -> Result<()> {
    let epoch = journal
        .rollout()
        .context("Missing staged rollout")?
        .epoch()
        .clone();
    tx.execute(
        "INSERT OR REPLACE INTO cluster_state VALUES(?1,?2)",
        params![
            PROPOSAL,
            serde_json::to_string(&Proposal {
                epoch: epoch.clone(),
                actor: actor.clone(),
                actor_version,
                scope,
            })?
        ],
    )?;
    tx.execute("INSERT INTO audit(created,username,action,object_id) VALUES(?1,?2,'configuration_staged',?3)",params![crate::now(),actor,epoch.sequence.to_string()])?;
    Ok(())
}
fn nodes(tx: &Transaction<'_>, owner: &str) -> Result<Vec<String>> {
    let mut ids = tx
        .prepare("SELECT id FROM cluster_nodes WHERE enabled=1 ORDER BY id")?
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    ensure!(
        !ids.iter().any(|n| n == owner),
        "Authority cannot also be a registered worker"
    );
    ids.push(owner.into());
    ids.sort();
    Ok(ids)
}
fn membership(tx: &Transaction<'_>, journal: &Journal) -> Result<()> {
    let r = journal.rollout().context("Missing rollout")?;
    ensure!(
        nodes(tx, journal.owner())?
            .iter()
            .eq(r.participants().keys()),
        "Activation membership changed or a participant was revoked; resolve without bypassing its fence"
    );
    Ok(())
}
impl Controller {
    pub async fn activation_journal(&self) -> Result<Option<Journal>> {
        self.store
            .run(|db| {
                let tx = db.transaction()?;
                Journal::read(&tx)
            })
            .await
    }
    /// Projection for the Web console. Personal viewers never receive bundles,
    /// other recipients, actor identities, topology or model fingerprints.
    pub async fn activation_view(
        &self,
        actor: String,
        administrator: bool,
    ) -> Result<serde_json::Value> {
        // Status must remain readable while a preparation drains SMTP writes.
        // This is observed progress, never an authorization to mutate state.
        let installed = self.snapshot().revision;
        let ready = self.cluster_ready();
        let coordinator = self
            .base
            .cluster
            .as_ref()
            .is_some_and(|c| c.role == Role::Coordinator);
        self.store.run(move |db| {
            let tx = db.transaction()?;
            let live: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM users WHERE username=?1 AND disabled=0 AND (?2=0 OR admin=1))", params![actor, administrator], |r|r.get(0))?;
            ensure!(live, "Account privileges changed; reload the console");
            let journal = Journal::read(&tx)?;
            let rollout = journal.as_ref().and_then(|j| j.rollout());
            let pending = journal.as_ref().is_some_and(|j| !j.released() || !ready);
            let proposal: Option<String> = tx.query_row("SELECT value FROM cluster_state WHERE key=?1",[PROPOSAL],|r|r.get(0)).optional()?;
            let proposal = proposal.filter(|p|p.len()<=4096).map(|p|serde_json::from_str::<Proposal>(&p)).transpose()?;
            let own = proposal.as_ref().filter(|p| p.actor==actor && rollout.is_some_and(|r| *r.epoch()==p.epoch))
                .filter(|p| p.scope.as_ref().is_some_and(|scope| approval(&tx,&actor,None,Some(scope)).is_ok()));
            let incident: Option<String> = tx.query_row("SELECT value FROM cluster_state WHERE key='activation_incident'",[],|r|r.get(0)).optional()?;
            let incident = incident.filter(|s|s.len()<=4096).map(|s|serde_json::from_str::<serde_json::Value>(&s)).transpose()?
                .filter(|v| rollout.is_some_and(|r| serde_json::to_value(r.epoch()).ok().as_ref()==v.get("epoch")))
                .map(|v| serde_json::json!({"at":v["at"],"code":v["code"]}));
            Ok(serde_json::json!({
                "coordinator":coordinator, "coordinated":journal.is_some(), "pending":pending,
                "installed_revision":installed, "smtp_ready":ready,
                "phase":rollout.map(|r|r.phase()),
                "committed_revision":if administrator {journal.as_ref().map(|j|j.current().revision)} else {None},
                "epoch":if administrator {rollout.map(|r|r.epoch())} else {None},
                "participants":if administrator {rollout.map(|r|r.participants())} else {None},
                "abortable":administrator && rollout.is_some_and(|r|r.abortable()),
                "recoverable":administrator && rollout.is_some_and(|r|r.phase()==Phase::Committed && r.recovery_of().is_none()),
                "personal_change":own.map(|p|serde_json::json!({"scope":p.scope,"revision":p.epoch.revision,"phase":rollout.unwrap().phase()})),
                "incident":if administrator || own.is_some() {incident} else {None},
            }))
        }).await
    }
    fn authority_id(&self) -> Result<String> {
        let c = self
            .base
            .cluster
            .as_ref()
            .context("Cluster is not configured")?;
        ensure!(c.role == Role::Coordinator, "Not an activation authority");
        Ok(c.node_id.clone())
    }
    /// Stages an explicit administrator-approved rollout. Existing legacy Web
    /// saves never enroll a cluster as a side effect.
    pub async fn stage_activation_session(
        self: &Arc<Self>,
        revision: i64,
        settings: Settings,
        actor: String,
        token_hash: String,
    ) -> Result<Journal> {
        self.stage_authorized(revision, settings, actor, token_hash, Selection::default())
            .await
    }
    /// Explicit selection requires the digest returned by a draft preview.
    /// Settings-only and personal saves always retain installed model slots.
    pub async fn stage_installation_models_session(
        self: &Arc<Self>,
        revision: i64,
        settings: Settings,
        actor: String,
        token_hash: String,
        models_sha256: String,
    ) -> Result<Journal> {
        ensure!(
            crate::compatibility::valid_hash(&models_sha256),
            "Invalid model selection digest"
        );
        self.stage_authorized(
            revision,
            settings,
            actor,
            token_hash,
            Selection {
                models_sha256: Some(models_sha256),
                ..Default::default()
            },
        )
        .await
    }
    pub async fn stage_credential_session(
        self: &Arc<Self>,
        revision: i64,
        provider: String,
        key: Option<String>,
        actor: String,
        token_hash: String,
    ) -> Result<Journal> {
        ensure!(
            self.activation_journal().await?.is_some(),
            "Enroll coordinated activation before staging provider keys"
        );
        let settings = self.snapshot().settings.clone();
        self.stage_authorized(
            revision,
            settings,
            actor,
            token_hash,
            Selection {
                credential: Some((provider, key)),
                ..Default::default()
            },
        )
        .await
    }
    pub async fn effective_settings(&self, settings: &Settings) -> Result<crate::config::Config> {
        if self.activation_journal().await?.is_some() {
            let publication = self.publication().await?;
            settings.effective_installed(&self.base, &publication.bundle)
        } else {
            settings.effective(&self.base)
        }
    }
    pub async fn preview_installation_models(
        self: &Arc<Self>,
        revision: i64,
        mut settings: Settings,
    ) -> Result<serde_json::Value> {
        self.authority_id()?;
        let permit = self
            .applying
            .clone()
            .try_acquire_owned()
            .context("A policy operation is already in progress")?;
        let this = self.clone();
        tokio::spawn(async move {
            ensure!(
                this.snapshot().revision == revision,
                "Configuration changed; reload before selecting models"
            );
            settings.hydrate(&this.base);
            let current = this.publication().await?;
            let mut base = (*this.base).clone();
            base.provider_credentials = current.config.provider_credentials.clone();
            base.credential_generation = current.config.credential_generation.clone();
            tokio::task::spawn_blocking(move || {
                // Keep the expensive-preview slot until owned hashing finishes,
                // including when the HTTP client disconnects.
                let _permit = permit;
                let config = settings.effective(&base)?;
                let candidate = artifacts::capture(&config, settings, revision)?;
                Ok(serde_json::json!({"revision":revision,
                    "installed_sha256":artifacts::model_digest(&current.bundle)?,
                    "installation_sha256":artifacts::model_digest(&candidate.bundle)?,
                    "installed":artifacts::model_manifest(&current.bundle)?,
                    "installation":artifacts::model_manifest(&candidate.bundle)?,
                    "qualification":"not_evaluated"}))
            })
            .await?
        })
        .await?
    }
    pub async fn stage_preferences_session(
        self: &Arc<Self>,
        revision: i64,
        scope: String,
        preference: Option<crate::preferences::Preference>,
        actor: String,
        token_hash: String,
    ) -> Result<Journal> {
        let mut settings = self.snapshot().settings.clone();
        if let Some(p) = preference {
            settings.preferences.mailboxes.insert(scope.clone(), p);
        } else {
            settings.preferences.mailboxes.remove(&scope);
        }
        self.stage_authorized(
            revision,
            settings,
            actor,
            token_hash,
            Selection {
                scope: Some(scope),
                ..Default::default()
            },
        )
        .await
    }
    async fn stage_authorized(
        self: &Arc<Self>,
        revision: i64,
        mut settings: Settings,
        actor: String,
        token_hash: String,
        selection: Selection,
    ) -> Result<Journal> {
        let Selection {
            scope,
            models_sha256,
            credential,
        } = selection;
        let owner = self.authority_id()?;
        let this = self.clone();
        tokio::spawn(async move {
            let _serial=this.activation_serial.clone().lock_owned().await;
            let _applying=this.applying.clone().acquire_owned().await?;
            let a=actor.clone();let t=token_hash.clone();let grant=scope.clone();
            this.store.run(move|db| {let tx=db.transaction()?;approval(&tx,&a,Some(&t),grant.as_deref())}).await?;
            let current=this.snapshot();
            ensure!(current.revision==revision, "Configuration changed; reload before staging");
            settings.hydrate(&this.base);
            if let Some(scope)=&scope { scoped_delta(&current.settings, &settings, scope)?; }
            ensure!(serde_json::to_vec(&settings)?.len()<=128*1024, "Configuration exceeds its size limit");
            let publication=this.publication().await?;
            let next_revision=revision.checked_add(1).context("Revision exhausted")?;
            let root=this.base.data_dir.clone(); let reserve=this.base.smtp.minimum_free_bytes;
            let source=artifacts::bind_credentials((*publication).clone())?;
            let mut base=(*this.base).clone();
            base.provider_credentials=source.config.provider_credentials.clone();
            base.credential_generation=source.config.credential_generation.clone();
            let (candidate, bound_source)=tokio::task::spawn_blocking(move|| {
                artifacts::freeze(&root,&source,reserve)?;
                let mut config=if models_sha256.is_some() {settings.effective(&base)?}
                    else {settings.effective_installed(&base,&source.bundle)?};
                let mut keys=crate::credentials::Snapshot::capture(&source.config)?;
                if let Some((provider,key))=credential { keys=keys.replacing(provider,key)?; }
                config.credential_generation=Some(keys.fingerprint());
                config.provider_credentials=Some(Arc::new(keys));
                let next=artifacts::capture(&config,settings,next_revision)?;
                if let Some(expected)=models_sha256 {
                    ensure!(artifacts::model_digest(&next.bundle)?==expected, "Installation models changed after preview; review and select them again");
                }
                artifacts::freeze(&root,&next,reserve)?;
                Ok::<_,anyhow::Error>((next.bundle, source.bundle))
            }).await??;
            let stale=crate::now()-this.base.cluster.as_ref().unwrap().max_stale_seconds;
            this.store.run(move|db| {
                let tx=db.transaction()?;
                let actor_version=approval(&tx,&actor,Some(&token_hash),scope.as_deref())?;
                let latest:i64=tx.query_row("SELECT COALESCE(MAX(id),0) FROM console_revisions",[],|r|r.get(0))?;
                ensure!(latest==revision, "Configuration changed while staging");
                let existing=Journal::read(&tx)?;
                if let Some(j)=&existing {
                    ensure!(j.released() && j.current().digest==publication.bundle.digest, "Previous activation is unresolved or differs from the resident runtime");
                    membership(&tx,j)?;
                }
                let participants=nodes(&tx,&owner)?;
                for id in participants.iter().filter(|id| *id!=&owner) {
                    let peer=Peer::read(&tx,id)?.context("Every enabled MX must report activation support first")?;
                    let credential:String=tx.query_row("SELECT token_hash FROM cluster_nodes WHERE id=?1",[id],|r|r.get(0))?;
                    ensure!(peer.seen>=stale && peer.protocol==crate::cluster::activation::transport::PROTOCOL && peer.build==env!("CARGO_PKG_VERSION") && peer.credential==credential
                        && peer.revision==revision && peer.digest==publication.bundle.digest,
                        "Every enabled MX must freshly report the exact base policy and activation protocol");
                }
                if existing.is_none() {Journal::initialize(&tx,&owner,bound_source)?;}
                let journal=Journal::begin(&tx,candidate,participants,crate::now())?;
                save_proposal(&tx,&journal,actor,actor_version,scope)?;
                tx.commit()?;Ok(journal)
            }).await
        }).await?
    }
    pub async fn abort_activation_session(
        self: &Arc<Self>,
        epoch: Epoch,
        actor: String,
        token_hash: String,
    ) -> Result<Journal> {
        self.authority_id()?;
        let this = self.clone();
        tokio::spawn(async move {
            let _serial=this.activation_serial.clone().lock_owned().await;
            this.store.run(move|db| {
                let tx=db.transaction()?;admin(&tx,&actor,&token_hash)?;
                let journal=Journal::abort(&tx,&epoch,crate::now())?;
                tx.execute("INSERT INTO audit(created,username,action,object_id) VALUES(?1,?2,'configuration_aborted',?3)",params![crate::now(),actor,epoch.sequence.to_string()])?;
                tx.commit()?;Ok(journal)
            }).await
        }).await?
    }
    pub async fn recover_activation_session(
        self: &Arc<Self>,
        epoch: Epoch,
        actor: String,
        token_hash: String,
    ) -> Result<Journal> {
        self.authority_id()?;
        let this = self.clone();
        tokio::spawn(async move {
            let _serial = this.activation_serial.clone().lock_owned().await;
            this.store
                .run(move |db| {
                    let tx = db.transaction()?;
                    let version = admin(&tx, &actor, &token_hash)?;
                    let previous = Journal::read(&tx)?.context("No activation to recover")?;
                    membership(&tx, &previous)?;
                    let mut rollback = previous
                        .rollout()
                        .context("Missing rollout")?
                        .base()
                        .clone();
                    rollback.revision = previous
                        .current()
                        .revision
                        .checked_add(1)
                        .context("Revision exhausted")?;
                    rollback.digest = rollback.hash()?;
                    let journal = Journal::recover_previous(&tx, &epoch, rollback, crate::now())?;
                    save_proposal(&tx, &journal, actor, version, None)?;
                    tx.commit()?;
                    Ok(journal)
                })
                .await
        })
        .await?
    }
    /// One owned authority step. The next poll repeats it after a lost response or
    /// restart. Network receipts only advance the journal, never the live engine.
    pub async fn advance_activation(self: &Arc<Self>) -> Result<Option<Journal>> {
        self.authority_id()?;
        let this = self.clone();
        tokio::spawn(async move {
            let _serial = this.activation_serial.clone().lock_owned().await;
            let result = this.advance_activation_step().await;
            let failed = result.is_err();
            let code = result.as_ref().err().and_then(|e| e.downcast_ref::<ActivationProblem>()).copied()
                .map(serde_json::to_value).transpose()?.unwrap_or(serde_json::json!("activation_step_failed"));
            // Persist a bounded, non-sensitive incident. Detailed errors remain
            // in server logs; model/provider errors can contain private data.
            this.store.run(move |db| {
                let tx = db.transaction()?;
                if failed {
                    if let Some(j) = Journal::read(&tx)? && let Some(r) = j.rollout() {
                        let incident = serde_json::json!({"epoch":r.epoch(),"at":crate::now(),"code":code});
                        tx.execute("INSERT OR REPLACE INTO cluster_state VALUES('activation_incident',?1)",[incident.to_string()])?;
                    }
                } else { tx.execute("DELETE FROM cluster_state WHERE key='activation_incident'",[])?; }
                tx.commit()?; Ok(())
            }).await?;
            result
        }).await?
    }
    async fn advance_activation_step(self: &Arc<Self>) -> Result<Option<Journal>> {
        let owner = self.authority_id()?;
        let this = self.clone();
        tokio::spawn(async move {
            let Some(journal)=this.activation_journal().await? else {return Ok(None)};
            let rollout=journal.rollout().context("Missing activation rollout")?;
            let selected=if rollout.phase()==Phase::Aborted {rollout.base()} else {rollout.candidate()};
            let base=this.base.clone();let selected=selected.clone();
            let keys=tokio::task::spawn_blocking(move|| ->Result<crate::credentials::Snapshot> {
                let config=artifacts::materialize(&base,&selected,false)?;
                crate::credentials::Snapshot::capture(&config)
            }).await??;
            let acknowledgement=this.synchronize_activation(journal,keys,crate::now()).await.map_err(|error| {
                let problem=if error.downcast_ref::<crate::engine::RuntimeGenerationBusy>().is_some() {
                    ActivationProblem::RuntimeGenerationBusy
                } else { ActivationProblem::RuntimePreparationFailed };
                error.context(problem)
            })?;
            let updated=this.store.run(move|db| {
                let tx=db.transaction()?;
                let mut j=Journal::read(&tx)?.context("Missing activation state")?;
                membership(&tx,&j).context(ActivationProblem::MembershipChanged)?;
                if let Some(ack)=acknowledgement {j=Journal::acknowledge(&tx,&owner,&ack,crate::now())?;}
                let r=j.rollout().unwrap();
                let epoch=r.epoch().clone();
                if r.phase()==Phase::Preparing && r.participants().values().all(|p| *p>=Progress::Prepared) {
                    let raw:String=tx.query_row("SELECT value FROM cluster_state WHERE key=?1",[PROPOSAL],|r|r.get(0))?;
                    ensure!(raw.len()<=4096,"Oversized activation proposal");
                    let proposal:Proposal=serde_json::from_str(&raw)?;
                    ensure!(proposal.epoch==epoch,"Proposal epoch mismatch");
                    let version=approval(&tx,&proposal.actor,None,proposal.scope.as_deref()).context(ActivationProblem::ApprovalChanged)?;
                    ensure!(version==proposal.actor_version,ActivationProblem::ApprovalChanged);
                    if let Some(scope)=&proposal.scope { scoped_delta(&r.base().settings,&r.candidate().settings,scope)?; }
                    let latest:i64=tx.query_row("SELECT COALESCE(MAX(id),0) FROM console_revisions",[],|r|r.get(0))?;
                    ensure!(latest==r.base().revision,"Console revision changed outside activation");
                    tx.execute("INSERT INTO console_revisions(id,created,username,settings) VALUES(?1,?2,?3,?4)",params![r.candidate().revision,crate::now(),proposal.actor,serde_json::to_string(&r.candidate().settings)?])?;
                    tx.execute("INSERT INTO audit(created,username,action,object_id) VALUES(?1,?2,'configuration',?3)",params![crate::now(),proposal.actor,r.candidate().revision.to_string()])?;
                    j=Journal::commit(&tx,&epoch,crate::now())?;
                    tx.execute("DELETE FROM console_revisions WHERE id NOT IN (SELECT id FROM console_revisions ORDER BY id DESC LIMIT 100)",[])?;
                } else if r.phase()==Phase::Committed && r.participants().values().all(|p| *p==Progress::Applied) {
                    j=Journal::release(&tx,&epoch,crate::now())?;
                }
                tx.commit()?;Ok(j)
            }).await?;
            let retained=updated.clone();let root=this.base.data_dir.clone();
            tokio::task::spawn_blocking(move||artifacts::prune_retained(&root,&retained.bundles())).await??;
            Ok(Some(updated))
        }).await?
    }
}
