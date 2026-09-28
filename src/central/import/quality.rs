//! Learning provenance moves only after all referenced messages and accounts.
use super::{Table, capture_tables, copy_tables};
use crate::central::{Central, database_error};
use anyhow::{Context, Result, ensure};
use serde_json::Value;

pub(super) const TABLES: &[Table] = &[
    Table {
        name: "feedback",
        sqlite: "SELECT json_object('username',f.username,'message_id',f.message_id,'spam',json(CASE f.spam WHEN 0 THEN 'false' ELSE 'true' END),'category',c.category,'created',f.created) FROM feedback f LEFT JOIN feedback_categories c ON c.username=f.username AND c.message_id=f.message_id ORDER BY f.username,f.message_id",
        columns: "username,message_id,spam,category,created",
        types: "username text,message_id text,spam boolean,category text,created bigint",
        insert: "username,message_id,spam,category,created",
        select: "username,message_id,spam,category,created",
        order: "username COLLATE \"C\",message_id COLLATE \"C\"",
    },
    Table {
        name: "quality_batches",
        sqlite: "SELECT json_object('id',b.id,'username',b.username,'created',b.created,'since',b.since,'until',b.until,'domain',b.domain,'seed',b.seed,'population',b.population,'selected',b.selected,'purpose',coalesce(p.purpose,'regression'),'cohort',coalesce(p.cohort,''),'provenance',NULL) FROM quality_batches b LEFT JOIN quality_purposes p ON p.batch_id=b.id ORDER BY b.id",
        columns: "id,username,created,since,until,domain,seed,population,selected,purpose,cohort,provenance",
        types: "id text,username text,created bigint,since bigint,until bigint,domain text,seed text,population bigint,selected bigint,purpose text,cohort text,provenance jsonb",
        insert: "id,username,created,since,until,domain,seed,population,selected,purpose,cohort,provenance",
        select: "id,username,created,since,until,domain,seed,population,selected,purpose,cohort,provenance",
        order: "id COLLATE \"C\"",
    },
    Table {
        name: "quality_members",
        sqlite: "SELECT json_object('batch_id',batch_id,'message_id',message_id,'rank',rank) FROM quality_members ORDER BY batch_id,message_id",
        columns: "batch_id,message_id,rank",
        types: "batch_id text,message_id text,rank bigint",
        insert: "batch_id,message_id,rank",
        select: "batch_id,message_id,rank",
        order: "batch_id COLLATE \"C\",message_id COLLATE \"C\"",
    },
    Table {
        name: "quality_reference_sets",
        sqlite: "SELECT json_object('batch_id',batch_id,'provenance',provenance) FROM quality_reference_sets ORDER BY batch_id",
        columns: "batch_id,provenance",
        types: "batch_id text,provenance text",
        insert: "batch_id,provenance",
        select: "batch_id,provenance",
        order: "batch_id COLLATE \"C\"",
    },
    Table {
        name: "quality_labels",
        sqlite: "SELECT json_object('username',username,'message_id',message_id,'risk',risk,'kind',kind,'created',created) FROM quality_labels ORDER BY username,message_id",
        columns: "username,message_id,risk,kind,created",
        types: "username text,message_id text,risk text,kind text,created bigint",
        insert: "username,message_id,risk,kind,created",
        select: "username,message_id,risk,kind,created",
        order: "username COLLATE \"C\",message_id COLLATE \"C\"",
    },
    Table {
        name: "quality_reserved",
        sqlite: "SELECT json_object('message_id',message_id,'created',created,'reason',reason) FROM quality_reserved ORDER BY message_id",
        columns: "message_id,created,reason",
        types: "message_id text,created bigint,reason text",
        insert: "message_id,created,reason",
        select: "message_id,created,reason",
        order: "message_id COLLATE \"C\"",
    },
    Table {
        name: "adaptive_labels",
        sqlite: "SELECT json_object('username',username,'message_id',message_id,'domain',domain,'class',class,'created',created) FROM adaptive_labels ORDER BY username,message_id,domain",
        columns: "username,message_id,domain,class,created",
        types: "username text,message_id text,domain text,class text,created bigint",
        insert: "username,message_id,domain,class,created",
        select: "username,message_id,domain,class,created",
        order: "username COLLATE \"C\",message_id COLLATE \"C\",domain COLLATE \"C\"",
    },
    Table {
        name: "quality_jobs",
        sqlite: "SELECT json_object('id',id,'username',username,'batch_id',batch_id,'operation',operation,'candidate_id',candidate_id,'status',status,'created',created,'started',started,'finished',finished,'report',json(report),'model_sha256',model_sha256) FROM quality_jobs ORDER BY id",
        columns: "id,username,batch_id,operation,candidate_id,status,created,started,finished,report,model_sha256",
        types: "id text,username text,batch_id text,operation text,candidate_id text,status text,created bigint,started bigint,finished bigint,report jsonb,model_sha256 text",
        insert: "id,username,batch_id,operation,candidate_id,status,created,started,finished,report,model_sha256",
        select: "id,username,batch_id,operation,candidate_id,status,created,started,finished,report,model_sha256",
        order: "id COLLATE \"C\"",
    },
    Table {
        name: "quality_export_batches",
        sqlite: "SELECT json_object('batch_id',batch_id,'exposed_at',exposed_at) FROM quality_export_batches ORDER BY batch_id",
        columns: "batch_id,exposed_at",
        types: "batch_id text,exposed_at bigint",
        insert: "batch_id,exposed_at",
        select: "batch_id,exposed_at",
        order: "batch_id COLLATE \"C\"",
    },
    Table {
        name: "quality_export_campaigns",
        sqlite: "SELECT json_object('fingerprint',fingerprint,'simhash',simhash,'exposed_at',exposed_at) FROM quality_export_campaigns ORDER BY fingerprint,simhash",
        columns: "fingerprint,simhash,exposed_at",
        types: "fingerprint text,simhash text,exposed_at bigint",
        insert: "fingerprint,simhash,exposed_at",
        select: "fingerprint,simhash,exposed_at",
        order: "fingerprint COLLATE \"C\",simhash COLLATE \"C\"",
    },
    Table {
        name: "quality_exposure_state",
        sqlite: "SELECT json_object('id',id,'tracking_since',tracking_since,'generation',0) FROM quality_exposure_state ORDER BY id",
        columns: "id,tracking_since,generation",
        types: "id integer,tracking_since bigint,generation bigint",
        insert: "id,tracking_since,generation",
        select: "id,tracking_since,generation",
        order: "id::text COLLATE \"C\"",
    },
];

/// Frozen learning provenance; contains no raw message bodies or attachments.
pub struct QualitySnapshot {
    pub(super) tables: Vec<Vec<Value>>,
}
impl QualitySnapshot {
    pub fn capture(tx: &rusqlite::Transaction<'_>) -> Result<Self> {
        ensure!(
            tx.prepare("PRAGMA foreign_key_check")?
                .query([])?
                .next()?
                .is_none(),
            "Migration source has inconsistent foreign keys"
        );
        ensure!(
            tx.query_row(
                "SELECT count(*) FROM feedback WHERE spam NOT IN (0,1)",
                [],
                |r| r.get::<_, i64>(0)
            )? == 0,
            "Invalid feedback boolean in migration source"
        );
        let tables = capture_tables(tx, TABLES, 64 * 1024 * 1024, 1024 * 1024)?;
        ensure!(
            tables
                .last()
                .is_some_and(|rows| rows.len() == 1 && rows[0]["id"] == 1),
            "Missing export exposure history"
        );
        Ok(Self { tables })
    }
}
impl Central {
    /// Offline-only primitive: requires imported message identities and users,
    /// no policy authority and no active migration. Does not activate anything.
    pub async fn import_quality(&self, snapshot: &QualitySnapshot) -> Result<()> {
        tokio::time::timeout(std::time::Duration::from_secs(60), async {
            let mut db=self.ingestion.get().await.map_err(|_|anyhow::anyhow!("Migration database unavailable"))?;
            let tx=db.transaction().await.map_err(database_error)?;
            crate::central::admin::management_lock(&tx).await?;
            let worker_free:bool=tx.query_one("SELECT pg_try_advisory_xact_lock(719021428125::bigint)",&[]).await.map_err(database_error)?.get(0);
            ensure!(worker_free,"Stop the central research worker before importing learning history");
            let names=TABLES.iter().map(|t|format!("noisefence.{}",t.name)).collect::<Vec<_>>().join(",");
            tx.batch_execute(&format!("LOCK TABLE {names},noisefence.policy_authority,noisefence.migration_state IN ACCESS EXCLUSIVE MODE")).await.map_err(database_error)?;
            let active:bool=tx.query_one("SELECT EXISTS(SELECT 1 FROM noisefence.policy_authority) OR EXISTS(SELECT 1 FROM noisefence.migration_state WHERE activated_at IS NOT NULL)",&[]).await.map_err(database_error)?.get(0);
            ensure!(!active,"Learning import cannot change an initialized authority");
            for table in &TABLES[..TABLES.len()-1] {
                let count:i64=tx.query_one(&format!("SELECT count(*) FROM noisefence.{}",table.name),&[]).await.map_err(database_error)?.get(0);
                ensure!(count==0,"Learning import destination is not empty");
            }
            let pristine:bool=tx.query_one("SELECT count(*)=1 AND coalesce(bool_and(id=1 AND generation=0),false) FROM noisefence.quality_exposure_state",&[]).await.map_err(database_error)?.get(0);
            ensure!(pristine,"Central learning export history already advanced");
            tx.execute("DELETE FROM noisefence.quality_exposure_state",&[]).await.map_err(database_error)?;
            copy_tables(&tx,TABLES,&snapshot.tables).await?;
            tx.commit().await.map_err(database_error)?;
            Ok(())
        }).await.context("Learning migration deadline exceeded")?
    }
}
