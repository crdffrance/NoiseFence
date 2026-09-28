//! Central policy authority. The policy head and the commit barrier change in
//! one PostgreSQL transaction; participant admission fences remain local.
use super::{Central, admin::management_lock, database_error, outbox::Identity};
use crate::cluster::{
    activation::{Acknowledgement, Epoch, Journal, Phase},
    artifacts::Bundle,
};
use anyhow::{Context, Result, ensure};
use deadpool_postgres::Transaction;
use serde_json::Value;
use std::collections::BTreeMap;

pub struct Proposal<'a> {
    pub revision: i64,
    pub base_digest: String,
    pub candidate: Bundle,
    pub actor: &'a str,
    pub session_hash: &'a str,
    pub scope: Option<&'a str>,
    pub max_stale_seconds: i64,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusProjection {
    current: Epoch,
    rollout: Option<RolloutStatus>,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RolloutStatus {
    epoch: Epoch,
    phase: Phase,
    participants: BTreeMap<String, crate::cluster::activation::Progress>,
    recovery_of: Option<Epoch>,
}
impl StatusProjection {
    fn validate(&self) -> Result<()> {
        self.current.validate()?;
        if let Some(r) = &self.rollout {
            r.epoch.validate()?;
            if let Some(recovery) = &r.recovery_of {
                recovery.validate()?;
            }
            ensure!(
                (1..=64).contains(&r.participants.len())
                    && r.participants
                        .keys()
                        .all(|node| crate::cluster::valid_id(node)),
                "Invalid activation participants"
            );
        }
        Ok(())
    }
}

struct Authority {
    journal: Journal,
    membership: BTreeMap<String, String>,
    actor: Option<String>,
    actor_version: Option<i64>,
    session: Option<String>,
    scope: Option<String>,
}
async fn membership(tx: &Transaction<'_>) -> Result<BTreeMap<String, String>> {
    let rows = tx
        .query(
            "SELECT node,epoch FROM noisefence.sources WHERE enabled ORDER BY node FOR SHARE",
            &[],
        )
        .await
        .map_err(database_error)?;
    ensure!(
        (1..=64).contains(&rows.len()),
        "Invalid policy membership size"
    );
    Ok(rows.into_iter().map(|r| (r.get(0), r.get(1))).collect())
}
async fn read(tx: &Transaction<'_>, identity: Option<&Identity>) -> Result<Authority> {
    let r=tx.query_opt("SELECT node,epoch,journal,membership,actor,actor_version,session_hash,scope FROM noisefence.policy_authority WHERE id=1 FOR UPDATE", &[]).await.map_err(database_error)?.context("Central policy authority is not initialized")?;
    if let Some(identity) = identity {
        ensure!(
            r.get::<_, String>(0) == identity.node && r.get::<_, String>(1) == identity.epoch,
            "Policy authority identity mismatch"
        );
    }
    let journal: Journal = serde_json::from_value(r.get(2))?;
    journal.validate()?;
    ensure!(
        journal.owner() == r.get::<_, String>(0),
        "Invalid policy journal owner"
    );
    let a = Authority {
        journal,
        membership: serde_json::from_value(r.get(3))?,
        actor: r.get(4),
        actor_version: r.get(5),
        session: r.get(6),
        scope: r.get(7),
    };
    let current = membership(tx).await?;
    ensure!(
        current == a.membership,
        "Policy membership changed; reconcile the authority before continuing"
    );
    Ok(a)
}
async fn save(tx: &Transaction<'_>, journal: &Journal) -> Result<()> {
    journal.validate()?;
    let raw = serde_json::to_vec(journal)?;
    ensure!(raw.len() <= 4 * 1024 * 1024, "Activation journal too large");
    tx.execute(
        "UPDATE noisefence.policy_authority SET journal=$1,incident=CASE WHEN incident->'epoch'=$2 THEN incident ELSE NULL END WHERE id=1",
        &[&serde_json::to_value(journal)?,&journal.rollout().map(|r|serde_json::to_value(r.epoch())).transpose()?],
    )
    .await
    .map_err(database_error)?;
    Ok(())
}
pub(super) async fn approval(
    tx: &Transaction<'_>,
    actor: &str,
    session: &str,
    scope: Option<&str>,
) -> Result<i64> {
    ensure!(
        super::mfa::allowed(tx, actor, session, None).await?,
        "Approving session expired or revoked"
    );
    let r = tx
        .query_one(
            "SELECT admin,version FROM noisefence.users WHERE username=$1 AND NOT disabled",
            &[&actor],
        )
        .await
        .map_err(database_error)?;
    let administrator: bool = r.get(0);
    if let Some(scope) = scope {
        let grants: Vec<String> = tx
            .query(
                "SELECT address FROM noisefence.grants WHERE username=$1 ORDER BY address",
                &[&actor],
            )
            .await
            .map_err(database_error)?
            .into_iter()
            .map(|r| r.get(0))
            .collect();
        ensure!(
            crate::preferences::permitted(scope, administrator, &grants),
            "Preference address is no longer authorized"
        );
    } else {
        ensure!(administrator, "Administrator rights required");
    }
    Ok(r.get(1))
}
fn scoped_delta(base: &Bundle, next: &Bundle, scope: &str) -> Result<()> {
    ensure!(
        base.settings.preferences.enabled,
        "Customization disabled by the administrator"
    );
    let mut expected = base.settings.clone();
    if let Some(p) = next.settings.preferences.mailboxes.get(scope) {
        expected
            .preferences
            .mailboxes
            .insert(scope.to_owned(), p.clone());
    } else {
        expected.preferences.mailboxes.remove(scope);
    }
    ensure!(
        expected == next.settings
            && base.shared == next.shared
            && serde_json::to_value(&base.files)? == serde_json::to_value(&next.files)?
            && base.credential_generation == next.credential_generation
            && base.protocol == next.protocol
            && base.build == next.build,
        "Preference proposal changes settings outside its authorized scope"
    );
    Ok(())
}
async fn audit(tx: &Transaction<'_>, actor: &str, action: &str, epoch: &Epoch) -> Result<()> {
    tx.execute(
        "INSERT INTO noisefence.audit(created,username,action,object_id) VALUES($1,$2,$3,$4)",
        &[&crate::now(), &actor, &action, &epoch.sequence.to_string()],
    )
    .await
    .map_err(database_error)?;
    Ok(())
}
async fn revision(tx: &Transaction<'_>, bundle: &Bundle, actor: &str) -> Result<()> {
    let settings = serde_json::to_value(&bundle.settings)?;
    let hash = crate::message::digest(&serde_json::to_vec(&bundle.settings)?);
    tx.execute("INSERT INTO noisefence.policy_revisions(id,created,username,settings,sha256) VALUES($1,$2,$3,$4,$5)", &[&bundle.revision,&crate::now(),&actor,&settings,&hash]).await.map_err(database_error)?;
    Ok(())
}
impl Central {
    pub async fn policy_revisions(&self, actor: &str) -> Result<Vec<Value>> {
        let db = self
            .interactive
            .get()
            .await
            .context("Central policy capacity unavailable")?;
        let rows = db.query("SELECT id,created,username FROM noisefence.policy_revisions WHERE EXISTS(SELECT 1 FROM noisefence.users WHERE username=$1 AND admin AND NOT disabled) ORDER BY id DESC LIMIT 100", &[&actor]).await.map_err(database_error)?;
        Ok(rows.iter().map(|r| serde_json::json!({"id":r.get::<_,i64>(0),"created":r.get::<_,i64>(1),"username":r.get::<_,String>(2)})).collect())
    }
    pub async fn policy_revision(&self, actor: &str, revision: i64) -> Result<Option<Value>> {
        let db = self
            .interactive
            .get()
            .await
            .context("Central policy capacity unavailable")?;
        Ok(db.query_opt("SELECT settings FROM noisefence.policy_revisions WHERE id=$2 AND EXISTS(SELECT 1 FROM noisefence.users WHERE username=$1 AND admin AND NOT disabled)", &[&actor,&revision]).await.map_err(database_error)?.map(|r|r.get(0)))
    }
    pub async fn policy_approval(
        &self,
        actor: &str,
        session: &str,
        scope: Option<&str>,
    ) -> Result<i64> {
        let mut db = self
            .interactive
            .get()
            .await
            .context("Central policy capacity unavailable")?;
        let tx = db.transaction().await.map_err(database_error)?;
        management_lock(&tx).await?;
        approval(&tx, actor, session, scope).await
    }
    /// Installer/import operation. The caller must freeze and validate the
    /// referenced artifacts before enrolling the central authority.
    pub async fn initialize_policy(&self, owner: &Identity, active: Bundle) -> Result<Journal> {
        let journal = Journal::initial(&owner.node, active)?;
        ensure!(
            serde_json::to_vec(&journal)?.len() <= 4 * 1024 * 1024,
            "Activation journal too large"
        );
        let mut db = self
            .interactive
            .get()
            .await
            .context("Central policy capacity unavailable")?;
        let tx = db.transaction().await.map_err(database_error)?;
        management_lock(&tx).await?;
        let members = membership(&tx).await?;
        ensure!(
            members.get(&owner.node) == Some(&owner.epoch),
            "Unregistered policy authority"
        );
        if tx
            .query_opt("SELECT id FROM noisefence.policy_authority WHERE id=1", &[])
            .await
            .map_err(database_error)?
            .is_some()
        {
            let existing = read(&tx, Some(owner)).await?;
            ensure!(
                serde_json::to_value(&existing.journal)? == serde_json::to_value(&journal)?,
                "Policy authority already initialized with another state"
            );
            return Ok(existing.journal);
        }
        revision(&tx, journal.current(), "migration").await?;
        tx.execute("INSERT INTO noisefence.policy_head(id,revision,activated_at,activation_epoch) VALUES(1,$1,$2,$3)", &[&journal.current().revision,&crate::now(),&serde_json::to_value(journal.current_epoch())?]).await.map_err(database_error)?;
        tx.execute("INSERT INTO noisefence.policy_authority(id,node,epoch,journal,membership) VALUES(1,$1,$2,$3,$4)", &[&owner.node,&owner.epoch,&serde_json::to_value(&journal)?,&serde_json::to_value(members)?]).await.map_err(database_error)?;
        tx.commit().await.map_err(database_error)?;
        Ok(journal)
    }
    /// Identity is supplied by authenticated transport, never a JSON node claim.
    pub async fn report_policy_peer(
        &self,
        identity: &Identity,
        protocol: &str,
        build: &str,
        revision: i64,
        digest: &str,
    ) -> Result<()> {
        ensure!(
            protocol.len() <= 100
                && build.len() <= 100
                && revision >= 0
                && crate::compatibility::valid_hash(digest),
            "Invalid policy peer report"
        );
        let mut db = self
            .interactive
            .get()
            .await
            .context("Central policy capacity unavailable")?;
        let tx = db.transaction().await.map_err(database_error)?;
        management_lock(&tx).await?;
        let members = membership(&tx).await?;
        ensure!(
            members.get(&identity.node) == Some(&identity.epoch),
            "Unregistered policy peer"
        );
        tx.execute("INSERT INTO noisefence.policy_peers(node,epoch,seen,protocol,build,revision,digest) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(node) DO UPDATE SET epoch=excluded.epoch,seen=excluded.seen,protocol=excluded.protocol,build=excluded.build,revision=excluded.revision,digest=excluded.digest", &[&identity.node,&identity.epoch,&crate::now(),&protocol,&build,&revision,&digest]).await.map_err(database_error)?;
        tx.commit().await.map_err(database_error)?;
        Ok(())
    }
    /// Policy/status exchange is authenticated again within the transaction.
    /// An older receipt after a lost response is harmless; a future epoch is not.
    pub async fn exchange_policy(
        &self,
        node: &super::nodes::Authenticated,
        request: &crate::cluster::activation::transport::Request,
    ) -> Result<Journal> {
        let poll = &request.poll;
        ensure!(
            request.protocol == crate::cluster::activation::transport::PROTOCOL
                && poll.build == env!("CARGO_PKG_VERSION")
                && poll.revision >= 0
                && (poll.digest.is_empty() || crate::compatibility::valid_hash(&poll.digest))
                && poll.records.is_empty()
                && poll.results.is_empty(),
            "Invalid central policy poll"
        );
        ensure!(
            crate::config::valid_domain(&poll.status.hostname)
                && (2..=300).contains(&poll.status.poll_seconds)
                && serde_json::to_vec(&poll.status)?.len() <= 16384,
            "Invalid node status"
        );
        let mut db = self
            .interactive
            .get()
            .await
            .context("Central policy capacity unavailable")?;
        let tx = db.transaction().await.map_err(database_error)?;
        management_lock(&tx).await?;
        let a = read(&tx, None).await?;
        node.check(&tx).await?;
        ensure!(
            a.membership.get(&node.identity().node) == Some(&node.identity().epoch)
                && a.journal.owner() != node.identity().node,
            "Node is not a registered policy participant"
        );
        let mut journal = a.journal;
        if let Some(ack) = &request.acknowledgement {
            let r = journal
                .rollout()
                .context("Previously enrolled node cannot lose its activation state")?;
            ensure!(
                r.participants().contains_key(&node.identity().node),
                "Node is not an activation participant"
            );
            if r.epoch() == &ack.epoch {
                if r.phase() != Phase::Aborted {
                    journal = journal.acknowledged(&node.identity().node, ack, crate::now())?;
                    save(&tx, &journal).await?;
                }
            } else {
                ensure!(
                    ack.epoch.sequence < r.epoch().sequence,
                    "Unknown activation receipt"
                );
            }
        }
        let mut status = poll.status.clone();
        status.build = Some(poll.build.clone());
        status.last_error = status
            .last_error
            .map(|e| crate::delivery_log::sanitize(&e, 400).0);
        tx.execute("UPDATE noisefence.cluster_nodes SET last_seen=$2,applied_revision=$3,applied_digest=$4,status=$5 WHERE node=$1", &[&node.identity().node,&crate::now(),&poll.revision,&poll.digest,&serde_json::to_value(status)?]).await.map_err(database_error)?;
        tx.execute("INSERT INTO noisefence.policy_peers(node,epoch,seen,protocol,build,revision,digest) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(node) DO UPDATE SET epoch=excluded.epoch,seen=excluded.seen,protocol=excluded.protocol,build=excluded.build,revision=excluded.revision,digest=excluded.digest", &[&node.identity().node,&node.identity().epoch,&crate::now(),&request.protocol,&poll.build,&poll.revision,&poll.digest]).await.map_err(database_error)?;
        tx.commit().await.map_err(database_error)?;
        Ok(journal)
    }
    pub async fn policy_journal(&self, owner: &Identity) -> Result<Journal> {
        let mut db = self
            .interactive
            .get()
            .await
            .context("Central policy capacity unavailable")?;
        let tx = db.transaction().await.map_err(database_error)?;
        management_lock(&tx).await?;
        Ok(read(&tx, Some(owner)).await?.journal)
    }
    /// Capture the exact rollout before an authority step, even when membership
    /// needs reconciliation. This method grants no permission to advance it.
    pub async fn policy_incident_epoch(&self, owner: &Identity) -> Result<Option<Epoch>> {
        let db = self
            .interactive
            .get()
            .await
            .context("Central policy capacity unavailable")?;
        let row = db.query_opt("SELECT journal#>'{rollout,epoch}' FROM noisefence.policy_authority WHERE id=1 AND node=$1 AND epoch=$2 AND journal->>'owner'=node", &[&owner.node,&owner.epoch]).await.map_err(database_error)?.context("Policy authority identity mismatch")?;
        let raw: Option<Value> = row.get(0);
        let epoch: Option<Epoch> = raw.map(serde_json::from_value).transpose()?;
        if let Some(epoch) = &epoch {
            epoch.validate()?;
        }
        Ok(epoch)
    }
    pub async fn record_policy_incident(
        &self,
        owner: &Identity,
        epoch: &Epoch,
        code: Option<&str>,
    ) -> Result<bool> {
        epoch.validate()?;
        ensure!(
            code.is_none_or(|code| matches!(
                code,
                "approval_changed"
                    | "membership_changed"
                    | "runtime_preparation_failed"
                    | "runtime_generation_busy"
                    | "activation_step_failed"
            )),
            "Invalid activation incident code"
        );
        let mut db = self
            .interactive
            .get()
            .await
            .context("Central policy capacity unavailable")?;
        let tx = db.transaction().await.map_err(database_error)?;
        management_lock(&tx).await?;
        let row=tx.query_opt("SELECT journal#>'{rollout,epoch}',membership FROM noisefence.policy_authority WHERE id=1 AND node=$1 AND epoch=$2 AND journal->>'owner'=node FOR UPDATE", &[&owner.node,&owner.epoch]).await.map_err(database_error)?.context("Policy authority identity mismatch")?;
        if row.get::<_, Option<Value>>(0).as_ref() != Some(&serde_json::to_value(epoch)?) {
            return Ok(false);
        }
        let recorded: BTreeMap<String, String> = serde_json::from_value(row.get(1))?;
        let code = if recorded != membership(&tx).await? {
            Some("membership_changed")
        } else {
            code
        };
        let incident =
            code.map(|code| serde_json::json!({"epoch":epoch,"at":crate::now(),"code":code}));
        tx.execute(
            "UPDATE noisefence.policy_authority SET incident=$1 WHERE id=1",
            &[&incident],
        )
        .await
        .map_err(database_error)?;
        tx.commit().await.map_err(database_error)?;
        Ok(true)
    }
    pub async fn policy_view(
        &self,
        owner: &Identity,
        actor: &str,
        administrator: bool,
        installed: i64,
        ready: bool,
    ) -> Result<Value> {
        let mut db = self
            .interactive
            .get()
            .await
            .context("Central policy capacity unavailable")?;
        let tx = db.transaction().await.map_err(database_error)?;
        management_lock(&tx).await?;
        // A status read must not deserialize model bundles merely to report
        // rollout progress. Mutation paths still validate the entire journal.
        let row=tx.query_opt("SELECT jsonb_build_object('current',jsonb_build_object('sequence',journal->'current_sequence','revision',journal#>'{current,revision}','digest',journal#>'{current,digest}'),'rollout',CASE WHEN journal->'rollout'='null'::jsonb OR journal->'rollout' IS NULL THEN NULL ELSE jsonb_build_object('epoch',journal#>'{rollout,epoch}','phase',journal#>'{rollout,phase}','participants',journal#>'{rollout,participants}','recovery_of',journal#>'{rollout,recovery_of}') END),membership,actor,scope,incident FROM noisefence.policy_authority WHERE id=1 AND node=$1 AND epoch=$2 AND journal->>'owner'=node FOR UPDATE", &[&owner.node,&owner.epoch]).await.map_err(database_error)?.context("Policy authority identity mismatch")?;
        let status: StatusProjection = serde_json::from_value(row.get(0))?;
        status.validate()?;
        let recorded: BTreeMap<String, String> = serde_json::from_value(row.get(1))?;
        let membership_matches = recorded == membership(&tx).await?;
        let initiator: Option<String> = row.get(2);
        let scope: Option<String> = row.get(3);
        let saved_incident: Option<Value> = row.get(4);
        let user=tx.query_opt("SELECT admin FROM noisefence.users WHERE username=$1 AND NOT disabled AND (NOT $2 OR admin)", &[&actor,&administrator]).await.map_err(database_error)?.context("Account privileges changed; reload the console")?;
        let grants: Vec<String> = tx
            .query(
                "SELECT address FROM noisefence.grants WHERE username=$1",
                &[&actor],
            )
            .await
            .map_err(database_error)?
            .into_iter()
            .map(|r| r.get(0))
            .collect();
        let own = initiator.as_deref() == Some(actor)
            && scope
                .as_deref()
                .is_some_and(|scope| crate::preferences::permitted(scope, user.get(0), &grants));
        let r = status.rollout.as_ref();
        let ready = ready && membership_matches;
        let incident = if !membership_matches {
            Some(
                serde_json::json!({"epoch":r.map(|r|&r.epoch).unwrap_or(&status.current),"at":crate::now(),"code":"membership_changed"}),
            )
        } else {
            saved_incident.filter(|i| {
                r.is_some_and(|r| serde_json::to_value(&r.epoch).ok().as_ref() == i.get("epoch"))
            })
        };
        Ok(serde_json::json!({
            "coordinator":true,"coordinated":true,"pending":r.is_some_and(|r|!matches!(r.phase,Phase::Released|Phase::Aborted)) || !ready,
            "installed_revision":installed,"smtp_ready":ready,"phase":r.map(|r|r.phase),
            "committed_revision":administrator.then_some(status.current.revision),
            "epoch":if administrator {r.map(|r|&r.epoch)} else {None},
            "participants":if administrator {r.map(|r|&r.participants)} else {None},
            "abortable":administrator && membership_matches && r.is_some_and(|r|r.phase==Phase::Preparing && r.recovery_of.is_none()),
            "recoverable":administrator && membership_matches && r.is_some_and(|r|r.phase==Phase::Committed && r.recovery_of.is_none()),
            "personal_change":if own {r.map(|r|serde_json::json!({"scope":scope,"revision":r.epoch.revision,"phase":r.phase}))} else {None},
            "incident":if administrator || own {incident} else {None},
        }))
    }
    pub async fn stage_policy(&self, owner: &Identity, proposal: Proposal<'_>) -> Result<Journal> {
        proposal.candidate.validate()?;
        ensure!(
            serde_json::to_vec(&proposal.candidate.settings)?.len() <= 128 * 1024,
            "Configuration exceeds its size limit"
        );
        ensure!(
            crate::cluster::POLICY_FRESHNESS_SECONDS.contains(&proposal.max_stale_seconds),
            "Invalid policy freshness bound"
        );
        let mut db = self
            .interactive
            .get()
            .await
            .context("Central policy capacity unavailable")?;
        let tx = db.transaction().await.map_err(database_error)?;
        management_lock(&tx).await?;
        let a = read(&tx, Some(owner)).await?;
        let version = approval(&tx, proposal.actor, proposal.session_hash, proposal.scope).await?;
        ensure!(
            a.journal.current().revision == proposal.revision
                && a.journal.current().digest == proposal.base_digest
                && proposal.revision.checked_add(1) == Some(proposal.candidate.revision),
            "Configuration changed; reload before staging"
        );
        if let Some(scope) = proposal.scope {
            scoped_delta(a.journal.current(), &proposal.candidate, scope)?;
        }
        if let Some(r) = a.journal.rollout()
            && r.phase() == Phase::Preparing
            && r.candidate().digest == proposal.candidate.digest
            && a.actor.as_deref() == Some(proposal.actor)
            && a.session.as_deref() == Some(proposal.session_hash)
            && a.actor_version == Some(version)
            && a.scope.as_deref() == proposal.scope
        {
            return Ok(a.journal);
        }
        let peers=tx.query("SELECT node,epoch,seen,protocol,build,revision,digest FROM noisefence.policy_peers", &[]).await.map_err(database_error)?;
        for (node, epoch) in &a.membership {
            if node == &owner.node {
                continue;
            }
            let p = peers
                .iter()
                .find(|p| p.get::<_, String>(0) == *node)
                .context("Every enabled MX must report activation support first")?;
            ensure!(
                p.get::<_, String>(1) == *epoch
                    && p.get::<_, i64>(2) >= crate::now() - proposal.max_stale_seconds
                    && p.get::<_, String>(3) == crate::cluster::activation::transport::PROTOCOL
                    && p.get::<_, String>(4) == env!("CARGO_PKG_VERSION")
                    && p.get::<_, i64>(5) == proposal.revision
                    && p.get::<_, String>(6) == a.journal.current().digest,
                "Every enabled MX must freshly report the exact base policy and activation protocol"
            );
        }
        let journal = a.journal.proposed(
            proposal.candidate,
            a.membership.into_keys().collect(),
            crate::now(),
        )?;
        save(&tx, &journal).await?;
        tx.execute("UPDATE noisefence.policy_authority SET actor=$1,actor_version=$2,session_hash=$3,scope=$4 WHERE id=1", &[&proposal.actor,&version,&proposal.session_hash,&proposal.scope]).await.map_err(database_error)?;
        audit(
            &tx,
            proposal.actor,
            "configuration_staged",
            journal.rollout().unwrap().epoch(),
        )
        .await?;
        tx.commit().await.map_err(database_error)?;
        Ok(journal)
    }
    pub async fn acknowledge_policy(
        &self,
        identity: &Identity,
        ack: &Acknowledgement,
    ) -> Result<Journal> {
        let mut db = self
            .interactive
            .get()
            .await
            .context("Central policy capacity unavailable")?;
        let tx = db.transaction().await.map_err(database_error)?;
        management_lock(&tx).await?;
        let a = read(&tx, None).await?;
        ensure!(
            a.membership.get(&identity.node) == Some(&identity.epoch),
            "Policy acknowledgement identity mismatch"
        );
        let journal = a.journal.acknowledged(&identity.node, ack, crate::now())?;
        save(&tx, &journal).await?;
        tx.commit().await.map_err(database_error)?;
        Ok(journal)
    }
    /// Atomic central revision/commit barrier; a retry after a lost response
    /// returns the already committed state without creating a second revision.
    pub async fn commit_policy(&self, owner: &Identity, epoch: &Epoch) -> Result<Journal> {
        let mut db = self
            .interactive
            .get()
            .await
            .context("Central policy capacity unavailable")?;
        let tx = db.transaction().await.map_err(database_error)?;
        management_lock(&tx).await?;
        let a = read(&tx, Some(owner)).await?;
        let r = a.journal.rollout().context("No activation rollout")?;
        ensure!(r.epoch() == epoch, "Proposal epoch mismatch");
        if matches!(r.phase(), Phase::Committed | Phase::Released) {
            return Ok(a.journal);
        }
        let actor = a.actor.as_deref().context("Missing activation approval")?;
        let version = approval(
            &tx,
            actor,
            a.session.as_deref().context("Missing activation session")?,
            a.scope.as_deref(),
        )
        .await?;
        ensure!(
            Some(version) == a.actor_version,
            "Activation approval changed"
        );
        if let Some(scope) = a.scope.as_deref() {
            scoped_delta(r.base(), r.candidate(), scope)?;
        }
        let head: i64 = tx
            .query_one(
                "SELECT revision FROM noisefence.policy_head WHERE id=1 FOR UPDATE",
                &[],
            )
            .await
            .map_err(database_error)?
            .get(0);
        ensure!(
            head == r.base().revision,
            "Policy head changed outside activation"
        );
        let journal = a.journal.committed(epoch, crate::now())?;
        revision(&tx, journal.current(), actor).await?;
        tx.execute("UPDATE noisefence.policy_head SET revision=$1,activated_at=NULL,activation_epoch=$2 WHERE id=1", &[&epoch.revision,&serde_json::to_value(epoch)?]).await.map_err(database_error)?;
        save(&tx, &journal).await?;
        audit(&tx, actor, "configuration", epoch).await?;
        tx.commit().await.map_err(database_error)?;
        Ok(journal)
    }
    pub async fn release_policy(&self, owner: &Identity, epoch: &Epoch) -> Result<Journal> {
        let mut db = self
            .interactive
            .get()
            .await
            .context("Central policy capacity unavailable")?;
        let tx = db.transaction().await.map_err(database_error)?;
        management_lock(&tx).await?;
        let a = read(&tx, Some(owner)).await?;
        let journal = a.journal.released_at(epoch, crate::now())?;
        save(&tx, &journal).await?;
        let changed=tx.execute("UPDATE noisefence.policy_head SET activated_at=COALESCE(activated_at,$1) WHERE id=1 AND revision=$2 AND activation_epoch=$3", &[&crate::now(),&epoch.revision,&serde_json::to_value(epoch)?]).await.map_err(database_error)?;
        ensure!(
            changed == 1,
            "Policy head does not match the release barrier"
        );
        tx.commit().await.map_err(database_error)?;
        Ok(journal)
    }
    pub async fn abort_policy(
        &self,
        owner: &Identity,
        epoch: &Epoch,
        actor: &str,
        session: &str,
    ) -> Result<Journal> {
        let mut db = self
            .interactive
            .get()
            .await
            .context("Central policy capacity unavailable")?;
        let tx = db.transaction().await.map_err(database_error)?;
        management_lock(&tx).await?;
        approval(&tx, actor, session, None).await?;
        let a = read(&tx, Some(owner)).await?;
        let duplicate = a
            .journal
            .rollout()
            .is_some_and(|r| r.epoch() == epoch && r.phase() == Phase::Aborted);
        let journal = a.journal.aborted(epoch, crate::now())?;
        save(&tx, &journal).await?;
        if !duplicate {
            audit(&tx, actor, "configuration_aborted", epoch).await?;
        }
        tx.commit().await.map_err(database_error)?;
        Ok(journal)
    }
    pub async fn recover_policy(
        &self,
        owner: &Identity,
        epoch: &Epoch,
        actor: &str,
        session: &str,
    ) -> Result<Journal> {
        let mut db = self
            .interactive
            .get()
            .await
            .context("Central policy capacity unavailable")?;
        let tx = db.transaction().await.map_err(database_error)?;
        management_lock(&tx).await?;
        let version = approval(&tx, actor, session, None).await?;
        let a = read(&tx, Some(owner)).await?;
        let r = a.journal.rollout().context("Missing rollout")?;
        if r.phase() == Phase::Preparing
            && r.recovery_of() == Some(epoch)
            && a.actor.as_deref() == Some(actor)
            && a.actor_version == Some(version)
            && a.session.as_deref() == Some(session)
        {
            return Ok(a.journal);
        }
        let mut rollback = r.base().clone();
        rollback.revision = a
            .journal
            .current()
            .revision
            .checked_add(1)
            .context("Revision exhausted")?;
        rollback.digest = rollback.hash()?;
        let journal = a.journal.recovered(epoch, rollback, crate::now())?;
        save(&tx, &journal).await?;
        tx.execute("UPDATE noisefence.policy_authority SET actor=$1,actor_version=$2,session_hash=$3,scope=NULL WHERE id=1", &[&actor,&version,&session]).await.map_err(database_error)?;
        audit(
            &tx,
            actor,
            "configuration_staged",
            journal.rollout().unwrap().epoch(),
        )
        .await?;
        tx.commit().await.map_err(database_error)?;
        Ok(journal)
    }
    /// A central read is not evidence that a local participant installed it.
    pub async fn activated_policy(&self) -> Result<Option<(i64, Value)>> {
        let db = self
            .interactive
            .get()
            .await
            .context("Central policy capacity unavailable")?;
        Ok(db.query_opt("SELECT r.id,r.settings FROM noisefence.policy_head h JOIN noisefence.policy_revisions r ON r.id=h.revision WHERE h.id=1 AND h.activated_at IS NOT NULL", &[]).await.map_err(database_error)?.map(|r|(r.get(0),r.get(1))))
    }
}
