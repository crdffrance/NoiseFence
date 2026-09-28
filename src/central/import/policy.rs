//! Preserve the existing coordinated policy journal rather than starting epoch zero.
use super::{Table, capture_tables, copy_tables};
use crate::{
    central::{Central, database_error},
    cluster::activation::Journal,
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub(super) const TABLES: &[Table] = &[
    Table {
        name: "audit",
        sqlite: "SELECT json_object('id',id,'created',created,'username',username,'action',action,'object_id',object_id) FROM audit ORDER BY id",
        columns: "id,created,username,action,object_id",
        types: "id bigint,created bigint,username text,action text,object_id text",
        insert: "id,created,username,action,object_id",
        select: "id,created,username,action,object_id",
        order: "id",
    },
    Table {
        name: "policy_revisions",
        sqlite: "SELECT json_object('id',id,'created',created,'username',username,'settings',json(settings),'sha256','') FROM console_revisions ORDER BY id",
        columns: "id,created,username,settings,sha256",
        types: "id bigint,created bigint,username text,settings jsonb,sha256 text",
        insert: "id,created,username,settings,sha256",
        select: "id,created,username,settings,sha256",
        order: "id",
    },
    Table {
        name: "cluster_nodes",
        sqlite: "SELECT json_object('node',id,'epoch','','name',name,'token_hash',token_hash,'enabled',json(CASE enabled WHEN 0 THEN 'false' ELSE 'true' END),'created',created,'version',version,'last_seen',last_seen,'applied_revision',applied_revision,'applied_digest',applied_digest,'status',json(status)) FROM cluster_nodes ORDER BY id",
        columns: "node,epoch,name,token_hash,enabled,created,version,last_seen,applied_revision,applied_digest,status",
        types: "node text,epoch text,name text,token_hash text,enabled boolean,created bigint,version bigint,last_seen bigint,applied_revision bigint,applied_digest text,status jsonb",
        insert: "node,epoch,name,token_hash,enabled,created,version,last_seen,applied_revision,applied_digest,status",
        select: "node,epoch,name,token_hash,enabled,created,version,last_seen,applied_revision,applied_digest,status",
        order: "node COLLATE \"C\"",
    },
];

/// Private offline snapshot. Spool epochs must come from the captured MXs,
/// never from a node name supplied by a network request.
pub struct PolicySnapshot {
    pub(super) tables: Vec<Vec<Value>>,
    pub(super) journal: Journal,
    pub(super) epochs: BTreeMap<String, String>,
    pub(super) membership: BTreeMap<String, String>,
}
impl PolicySnapshot {
    pub fn capture(
        tx: &rusqlite::Transaction<'_>,
        epochs: BTreeMap<String, String>,
    ) -> Result<Self> {
        ensure!(
            tx.prepare("PRAGMA foreign_key_check")?
                .query([])?
                .next()?
                .is_none(),
            "Migration source has inconsistent foreign keys"
        );
        let journal =
            Journal::read(tx)?.context("Initialize coordinated activation before migration")?;
        ensure!(
            journal.released(),
            "Finish or recover the current policy rollout before migration"
        );
        ensure!(
            (1..=64).contains(&epochs.len())
                && epochs
                    .iter()
                    .all(|(node, epoch)| crate::cluster::valid_id(node)
                        && uuid::Uuid::parse_str(epoch).is_ok_and(|v| v.to_string() == *epoch)),
            "Invalid captured spool identities"
        );
        ensure!(
            tx.query_row(
                "SELECT count(*) FROM cluster_nodes WHERE enabled NOT IN (0,1) OR version<0",
                [],
                |r| r.get::<_, i64>(0)
            )? == 0,
            "Invalid source node state"
        );
        let mut tables = capture_tables(tx, TABLES, 64 * 1024 * 1024, 4 * 1024 * 1024)?;
        ensure!(
            tables[1].len() <= 1000 && tables[2].len() < 64,
            "Policy migration snapshot exceeds limits"
        );
        let mut expected = BTreeMap::new();
        let owner_epoch = epochs
            .get(journal.owner())
            .context("Missing coordinator spool epoch")?;
        let local_identity = crate::central::outbox::identity(tx)?;
        ensure!(
            local_identity.node == journal.owner() && local_identity.epoch == *owner_epoch,
            "Captured coordinator epoch differs from its durable spool identity"
        );
        ensure!(
            tx.query_row(
                "SELECT count(*) FROM cluster_commands WHERE finished IS NULL",
                [],
                |r| r.get::<_, i64>(0)
            )? == 0,
            "Resolve outstanding legacy queue commands before migration"
        );
        expected.insert(journal.owner().to_string(), owner_epoch.clone());
        let mut membership = expected.clone();
        for node in &mut tables[2] {
            let name = node["node"]
                .as_str()
                .context("Invalid node ID")?
                .to_string();
            ensure!(
                name != journal.owner()
                    && crate::compatibility::valid_hash(
                        node["token_hash"].as_str().unwrap_or_default()
                    ),
                "Invalid legacy node identity"
            );
            let epoch = epochs.get(&name).context("Missing worker spool epoch")?;
            node["epoch"] = json!(epoch);
            expected.insert(name.clone(), epoch.clone());
            if node["enabled"] == true {
                membership.insert(name, epoch.clone());
            }
        }
        ensure!(
            expected == epochs,
            "Captured spool set differs from registered legacy nodes"
        );
        if let Some(rollout) = journal.rollout() {
            ensure!(
                rollout.participants().keys().eq(membership.keys()),
                "Resolve changed policy membership before migration"
            );
        }
        for revision in &mut tables[1] {
            ensure!(
                revision["id"].as_i64().is_some_and(|id| id >= 0),
                "Invalid historical policy revision"
            );
            let settings: crate::control::Settings =
                serde_json::from_value(revision["settings"].clone())?;
            revision["sha256"] = json!(crate::message::digest(&serde_json::to_vec(&settings)?));
        }
        let current = journal.current();
        if let Some(row) = tables[1].iter().find(|row| row["id"] == current.revision) {
            let saved: crate::control::Settings = serde_json::from_value(row["settings"].clone())?;
            ensure!(
                serde_json::to_value(saved)? == serde_json::to_value(&current.settings)?,
                "Installed policy differs from its historical revision"
            );
        } else {
            ensure!(
                current.revision == 0,
                "Installed policy revision is missing from source history"
            );
            tables[1].insert(0,json!({"id":0,"created":0,"username":"migration-bootstrap","settings":current.settings,"sha256":crate::message::digest(&serde_json::to_vec(&current.settings)?)}));
        }
        ensure!(
            tables[1]
                .iter()
                .all(|r| r["id"].as_i64().is_some_and(|id| id <= current.revision)),
            "Source history contains a policy newer than the installed journal"
        );
        Ok(Self {
            tables,
            journal,
            epochs,
            membership,
        })
    }
}
impl Central {
    /// Final import component, after accounts, metadata, diagnostics and learning.
    /// Preserves terminal rollouts and monotonic epochs. Does not select the
    /// backend on any MX or manufacture fresh policy acknowledgements.
    pub async fn import_policy(&self, snapshot: &PolicySnapshot) -> Result<()> {
        tokio::time::timeout(std::time::Duration::from_secs(60),async {
            let mut db=self.ingestion.get().await.map_err(|_|anyhow::anyhow!("Migration database unavailable"))?;
            let tx=db.transaction().await.map_err(database_error)?;
            crate::central::admin::management_lock(&tx).await?;
            tx.batch_execute("LOCK TABLE noisefence.sources,noisefence.audit,noisefence.policy_revisions,noisefence.cluster_nodes,noisefence.policy_head,noisefence.policy_authority,noisefence.policy_peers,noisefence.migration_state IN ACCESS EXCLUSIVE MODE").await.map_err(database_error)?;
            for table in ["audit","policy_revisions","cluster_nodes","policy_head","policy_authority","policy_peers"] {
                let count:i64=tx.query_one(&format!("SELECT count(*) FROM noisefence.{table}"),&[]).await.map_err(database_error)?.get(0);
                ensure!(count==0,"Policy import destination is not empty");
            }
            ensure!(!tx.query_one("SELECT EXISTS(SELECT 1 FROM noisefence.migration_state WHERE activated_at IS NOT NULL)",&[]).await.map_err(database_error)?.get::<_,bool>(0),"An activated migration cannot be overwritten");
            let sources:BTreeMap<String,String>=tx.query("SELECT node,epoch FROM noisefence.sources ORDER BY node LIMIT 65",&[]).await.map_err(database_error)?.into_iter().map(|r|(r.get(0),r.get(1))).collect();
            ensure!(sources==snapshot.epochs,"Imported source epochs differ from captured spools");
            for node in snapshot.membership.keys() {
                let enabled:bool=tx.query_one("SELECT enabled FROM noisefence.sources WHERE node=$1",&[node]).await.map_err(database_error)?.get(0);
                ensure!(enabled,"Policy import cannot re-enable a revoked source");
            }
            copy_tables(&tx,TABLES,&snapshot.tables).await?;
            for (node,epoch) in &snapshot.epochs {
                let enabled=snapshot.membership.contains_key(node);
                tx.execute("UPDATE noisefence.sources SET enabled=$3 WHERE node=$1 AND epoch=$2",&[node,epoch,&enabled]).await.map_err(database_error)?;
            }
            let current=snapshot.journal.current();
            let epoch=serde_json::to_value(snapshot.journal.current_epoch())?;
            let journal=serde_json::to_value(&snapshot.journal)?;
            let membership=serde_json::to_value(&snapshot.membership)?;
            // Zero denotes an imported installed policy with no independently
            // recorded activation timestamp. It is not a fresh peer heartbeat.
            tx.execute("INSERT INTO noisefence.policy_head VALUES(1,$1,0,$2)",&[&current.revision,&epoch]).await.map_err(database_error)?;
            let owner=snapshot.journal.owner();
            tx.execute("INSERT INTO noisefence.policy_authority(id,node,epoch,journal,membership) VALUES(1,$1,$2,$3,$4)",&[&owner,&snapshot.epochs[owner],&journal,&membership]).await.map_err(database_error)?;
            let copied=tx.query_one("SELECT journal,membership FROM noisefence.policy_authority WHERE id=1",&[]).await.map_err(database_error)?;
            ensure!(copied.get::<_,Value>(0)==journal && copied.get::<_,Value>(1)==membership,"Policy journal import parity mismatch");
            for table in ["audit","policy_revisions"] {
                let maximum:i64=tx.query_one(&format!("SELECT coalesce(max(id),0) FROM noisefence.{table}"),&[]).await.map_err(database_error)?.get(0);
                if maximum>0 {
                    tx.query_one(&format!("SELECT setval('noisefence.{table}_id_seq',GREATEST((SELECT last_value FROM noisefence.{table}_id_seq),$1),true)"),&[&maximum]).await.map_err(database_error)?;
                }
            }
            tx.commit().await.map_err(database_error)?;
            Ok(())
        }).await.context("Policy import deadline exceeded")?
    }
}
