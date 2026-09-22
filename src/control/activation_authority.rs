//! Authority orchestration, separate from the local participant driver. Durable
//! preparation is an approved job; account/privilege changes invalidate its commit.
use super::{Controller, Settings};
use crate::cluster::{
    Role,
    activation::{Epoch, Journal, Phase, Progress, transport::Peer},
    artifacts, protocol,
};
use anyhow::{Context, Result, ensure};
use rusqlite::{OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

const PROPOSAL: &str = "activation_proposal";
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Proposal {
    epoch: Epoch,
    actor: String,
    actor_version: i64,
}
fn admin(tx: &Transaction<'_>, actor: &str, token: &str) -> Result<i64> {
    tx.query_row("SELECT COALESCE(v.version,0) FROM users u JOIN sessions s ON s.username=u.username LEFT JOIN console_user_versions v ON v.username=u.username WHERE u.username=?1 AND u.admin=1 AND u.disabled=0 AND s.token_hash=?2 AND s.expires>?3", params![actor,token,crate::now()], |r|r.get(0)).optional()?.context("Administrator session expired or revoked")
}
fn save_proposal(
    tx: &Transaction<'_>,
    journal: &Journal,
    actor: String,
    actor_version: i64,
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
                actor_version
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
        mut settings: Settings,
        actor: String,
        token_hash: String,
    ) -> Result<Journal> {
        let owner = self.authority_id()?;
        let this = self.clone();
        tokio::spawn(async move {
            let _serial=this.activation_serial.clone().lock_owned().await;
            let _applying=this.applying.clone().acquire_owned().await?;
            let a=actor.clone();let t=token_hash.clone();
            this.store.run(move|db| {let tx=db.transaction()?;admin(&tx,&a,&t)}).await?;
            let current=this.snapshot();
            ensure!(current.revision==revision, "Configuration changed; reload before staging");
            settings.hydrate(&this.base);
            ensure!(serde_json::to_vec(&settings)?.len()<=128*1024, "Configuration exceeds its size limit");
            let config=settings.effective(&this.base)?;
            let publication=this.publication().await?;
            let next_revision=revision.checked_add(1).context("Revision exhausted")?;
            let root=this.base.data_dir.clone(); let reserve=this.base.smtp.minimum_free_bytes;
            let source=publication.clone();
            let candidate=tokio::task::spawn_blocking(move|| {
                artifacts::freeze(&root,&source,reserve)?;
                let next=artifacts::capture(&config,settings,next_revision)?;
                artifacts::freeze(&root,&next,reserve)?;
                Ok::<_,anyhow::Error>(next.bundle)
            }).await??;
            let stale=crate::now()-this.base.cluster.as_ref().unwrap().max_stale_seconds;
            this.store.run(move|db| {
                let tx=db.transaction()?;
                let actor_version=admin(&tx,&actor,&token_hash)?;
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
                    ensure!(peer.seen>=stale && peer.build==env!("CARGO_PKG_VERSION") && peer.credential==credential
                        && peer.revision==revision && peer.digest==publication.bundle.digest,
                        "Every enabled MX must freshly report the exact base policy and activation protocol");
                }
                if existing.is_none() {Journal::initialize(&tx,&owner,publication.bundle.clone())?;}
                let journal=Journal::begin(&tx,candidate,participants,crate::now())?;
                save_proposal(&tx,&journal,actor,actor_version)?;
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
                    save_proposal(&tx, &journal, actor, version)?;
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
        let owner = self.authority_id()?;
        let this = self.clone();
        tokio::spawn(async move {
            let _serial=this.activation_serial.clone().lock_owned().await;
            let Some(journal)=this.activation_journal().await? else {return Ok(None)};
            let rollout=journal.rollout().context("Missing activation rollout")?;
            let selected=if rollout.phase()==Phase::Aborted {rollout.base()} else {rollout.candidate()};
            let base=this.base.clone();let selected=selected.clone();
            let keys=tokio::task::spawn_blocking(move|| ->Result<String> {
                let config=artifacts::materialize(&base,&selected,false)?;
                Ok(crate::message::digest(&serde_json::to_vec(&protocol::secrets(&config)?)?))
            }).await??;
            let acknowledgement=this.synchronize_activation(journal,keys,crate::now()).await?;
            let updated=this.store.run(move|db| {
                let tx=db.transaction()?;
                let mut j=Journal::read(&tx)?.context("Missing activation state")?;
                membership(&tx,&j)?;
                if let Some(ack)=acknowledgement {j=Journal::acknowledge(&tx,&owner,&ack,crate::now())?;}
                let r=j.rollout().unwrap();
                let epoch=r.epoch().clone();
                if r.phase()==Phase::Preparing && r.participants().values().all(|p| *p>=Progress::Prepared) {
                    let raw:String=tx.query_row("SELECT value FROM cluster_state WHERE key=?1",[PROPOSAL],|r|r.get(0))?;
                    ensure!(raw.len()<=4096,"Oversized activation proposal");
                    let proposal:Proposal=serde_json::from_str(&raw)?;
                    ensure!(proposal.epoch==epoch,"Proposal epoch mismatch");
                    let version:Option<i64>=tx.query_row("SELECT COALESCE(v.version,0) FROM users u LEFT JOIN console_user_versions v ON v.username=u.username WHERE u.username=?1 AND u.admin=1 AND u.disabled=0",[&proposal.actor],|r|r.get(0)).optional()?;
                    ensure!(version==Some(proposal.actor_version),"Staging administrator privileges changed; abort or reauthorize the proposal");
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
