//! Human annotations and frozen evaluation cohorts; never inferred from scores.
use super::{Central, admin::management_lock, database_error};
use crate::quality::{
    self,
    evaluation::{Purpose, ReadinessCounts, Risk},
    qualification,
};
use anyhow::{Context, Result, ensure};
use deadpool_postgres::Transaction;
use serde_json::{Value, json};
use std::collections::BTreeMap;

const OBSERVATION: &str = "CASE WHEN octet_length((m.scan->'quality')::text)<=131072 THEN (m.scan->'quality')::text WHEN m.scan->'quality' IS NULL OR m.scan->'quality'='null'::jsonb THEN NULL ELSE '{}' END";
const COHORT: &str = "CASE WHEN length(m.scan#>>'{quality,artifacts_sha256}')=64 THEN m.scan#>>'{quality,artifacts_sha256}' ELSE '' END";
const ACCESS: &str = "EXISTS(SELECT 1 FROM noisefence.deliveries d JOIN noisefence.console_access a ON a.delivery_id=d.id WHERE d.message_id=m.id AND a.username=$1)";
pub struct Sample<'a> {
    pub since: i64,
    pub until: i64,
    pub count: usize,
    pub domain: &'a str,
    pub purpose: Purpose,
    pub cohort: &'a str,
}
async fn active(tx: &Transaction<'_>, user: &str) -> Result<()> {
    ensure!(
        tx.query_opt(
            "SELECT username FROM noisefence.users WHERE username=$1 AND NOT disabled FOR SHARE",
            &[&user]
        )
        .await
        .map_err(database_error)?
        .is_some(),
        "Account disabled or removed"
    );
    Ok(())
}
async fn audit(tx: &Transaction<'_>, user: &str, action: &str, id: &str) -> Result<()> {
    tx.execute(
        "INSERT INTO noisefence.audit(created,username,action,object_id) VALUES($1,$2,$3,$4)",
        &[&crate::now(), &user, &action, &id],
    )
    .await
    .map_err(database_error)?;
    Ok(())
}
async fn batch(tx: &Transaction<'_>, user: &str, id: &str) -> Result<tokio_postgres::Row> {
    active(tx, user).await?;
    tx.query_opt("SELECT since,until,population,selected,seed,purpose,cohort FROM noisefence.quality_batches WHERE id=$1 AND username=$2 AND created>=$3", &[&id,&user,&(crate::now()-30*86400)]).await.map_err(database_error)?.context("Sample not found")
}
impl Central {
    pub async fn quality_sample(&self, user: &str, s: Sample<'_>) -> Result<String> {
        ensure!(
            s.cohort.is_empty()
                || (s.purpose == Purpose::Development
                    && crate::compatibility::valid_hash(s.cohort)),
            "Cohort selection is for development only"
        );
        ensure!(
            (1..=50000).contains(&s.count)
                && s.since >= crate::now() - 30 * 86400
                && s.since < s.until
                && s.until <= crate::now()
                && (s.domain.is_empty() || crate::config::valid_domain(s.domain)),
            "Invalid sample window"
        );
        let mut db = self
            .interactive
            .get()
            .await
            .context("Central quality capacity unavailable")?;
        let tx = db.transaction().await.map_err(database_error)?;
        management_lock(&tx).await?;
        active(&tx, user).await?;
        let ids:Vec<String>=tx.query("SELECT m.id FROM noisefence.messages m WHERE NOT m.is_dsn AND m.created>=$2 AND m.created<$3 AND EXISTS(SELECT 1 FROM noisefence.deliveries d JOIN noisefence.console_access a ON a.delivery_id=d.id WHERE d.message_id=m.id AND a.username=$1 AND ($4='' OR lower(split_part(d.address,'@',2))=lower($4) OR lower(split_part(d.destination,'@',2))=lower($4))) AND ($5='' OR m.scan#>>'{quality,artifacts_sha256}'=$5) LIMIT 50001", &[&user,&s.since,&s.until,&s.domain,&s.cohort]).await.map_err(database_error)?.iter().map(|r|r.get(0)).collect();
        ensure!(
            !ids.is_empty() && ids.len() <= 50000,
            "Sample population empty or over capacity"
        );
        ensure!(
            tx.query_one(
                "SELECT count(*) FROM noisefence.quality_batches WHERE username=$1",
                &[&user]
            )
            .await
            .map_err(database_error)?
            .get::<_, i64>(0)
                < 100,
            "Too many retained samples"
        );
        let seed = crate::api::random_token();
        let population = ids.len() as i64;
        let mut draw: Vec<_> = ids
            .into_iter()
            .map(|id| {
                (
                    crate::message::digest(format!("{seed}:{id}").as_bytes()),
                    id,
                )
            })
            .collect();
        draw.sort_unstable();
        draw.truncate(s.count);
        let ids: Vec<_> = draw.into_iter().map(|(_, id)| id).collect();
        let id = uuid::Uuid::new_v4().to_string();
        tx.execute("INSERT INTO noisefence.quality_batches(id,username,created,since,until,domain,seed,population,selected,purpose,cohort) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)", &[&id,&user,&crate::now(),&s.since,&s.until,&s.domain,&seed,&population,&(ids.len() as i64),&s.purpose.as_str(),&s.cohort]).await.map_err(database_error)?;
        tx.execute("INSERT INTO noisefence.quality_members(batch_id,message_id,rank) SELECT $1,id,rank-1 FROM unnest($2::text[]) WITH ORDINALITY AS x(id,rank)", &[&id,&ids]).await.map_err(database_error)?;
        audit(&tx, user, "quality_sample", &id).await?;
        tx.commit().await.map_err(database_error)?;
        Ok(id)
    }
    pub async fn quality_label(
        &self,
        user: &str,
        id: &str,
        risk: Risk,
        kind: Option<quality::Kind>,
    ) -> Result<()> {
        let mut db = self
            .interactive
            .get()
            .await
            .context("Central quality capacity unavailable")?;
        let tx = db.transaction().await.map_err(database_error)?;
        management_lock(&tx).await?;
        active(&tx, user).await?;
        ensure!(tx.query_opt(&format!("SELECT m.id FROM noisefence.messages m WHERE m.id=$2 AND NOT m.is_dsn AND m.created>=$3 AND {ACCESS} FOR SHARE OF m"), &[&user,&id,&(crate::now()-30*86400)]).await.map_err(database_error)?.is_some(),"Message not found");
        tx.execute("INSERT INTO noisefence.quality_labels(username,message_id,risk,kind,created) VALUES($1,$2,$3,$4,$5) ON CONFLICT(username,message_id) DO UPDATE SET risk=excluded.risk,kind=excluded.kind,created=excluded.created", &[&user,&id,&risk.as_str(),&kind.map(quality::Kind::as_str),&crate::now()]).await.map_err(database_error)?;
        audit(&tx, user, "quality_label", id).await?;
        tx.commit().await.map_err(database_error)?;
        Ok(())
    }
    pub async fn quality_batches(&self, user: &str) -> Result<Vec<Value>> {
        let mut db = self
            .interactive
            .get()
            .await
            .context("Central quality capacity unavailable")?;
        let tx = db
            .build_transaction()
            .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
            .start()
            .await
            .map_err(database_error)?;
        active(&tx, user).await?;
        let rows=tx.query(&format!("SELECT b.id,b.created,b.since,b.until,b.domain,b.population,b.selected,(SELECT count(*) FROM noisefence.quality_members x JOIN noisefence.messages m ON m.id=x.message_id WHERE x.batch_id=b.id AND m.created>=$2 AND {ACCESS}), (SELECT count(*) FROM noisefence.quality_members x JOIN noisefence.messages m ON m.id=x.message_id JOIN noisefence.quality_labels l ON l.message_id=m.id AND l.username=$1 WHERE x.batch_id=b.id AND m.created>=$2 AND {ACCESS}), b.purpose,EXISTS(SELECT 1 FROM noisefence.quality_reference_sets r WHERE r.batch_id=b.id) FROM noisefence.quality_batches b WHERE b.username=$1 AND b.created>=$2 ORDER BY b.created DESC,b.id DESC LIMIT 100"), &[&user,&(crate::now()-30*86400)]).await.map_err(database_error)?;
        Ok(rows.iter().map(|r|json!({"id":r.get::<_,String>(0),"created":r.get::<_,i64>(1),"since":r.get::<_,i64>(2),"until":r.get::<_,i64>(3),"domain":r.get::<_,String>(4),"population":r.get::<_,i64>(5),"selected":r.get::<_,i64>(6),"available":r.get::<_,i64>(7),"labelled":r.get::<_,i64>(8),"purpose":r.get::<_,String>(9),"sampling":if r.get::<_,bool>(10) {"confirmed_regression"} else {"uniform_message"}})).collect())
    }
    pub async fn quality_members(&self, user: &str, id: &str, offset: usize) -> Result<Vec<Value>> {
        ensure!(offset <= 50000, "Invalid page");
        let mut db = self
            .interactive
            .get()
            .await
            .context("Central quality capacity unavailable")?;
        let tx = db
            .build_transaction()
            .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
            .start()
            .await
            .map_err(database_error)?;
        batch(&tx, user, id).await?;
        let rows=tx.query(&format!("SELECT m.id,m.created,m.sender,m.scan->>'subject',l.risk,l.kind,m.scan#>>'{{quality,schema}}' IS NOT NULL FROM noisefence.quality_members x JOIN noisefence.messages m ON m.id=x.message_id LEFT JOIN noisefence.quality_labels l ON l.message_id=m.id AND l.username=$1 WHERE x.batch_id=$2 AND m.created>=$3 AND {ACCESS} ORDER BY x.rank LIMIT 200 OFFSET $4"), &[&user,&id,&(crate::now()-30*86400),&(offset as i64)]).await.map_err(database_error)?;
        Ok(rows.iter().map(|r|json!({"id":r.get::<_,String>(0),"created":r.get::<_,i64>(1),"sender":r.get::<_,String>(2),"subject":r.get::<_,Option<String>>(3).unwrap_or_default(),"risk":r.get::<_,Option<String>>(4),"kind":r.get::<_,Option<String>>(5),"joint_observations":r.get::<_,bool>(6)})).collect())
    }
    pub async fn quality_observation_start(&self, user: &str) -> Result<Option<i64>> {
        let db = self
            .interactive
            .get()
            .await
            .context("Central quality capacity unavailable")?;
        Ok(db.query_one(&format!("SELECT MIN(m.created) FROM noisefence.messages m WHERE NOT m.is_dsn AND m.created>=$2 AND m.scan#>>'{{quality,protocol_sha256}}'=$3 AND right(m.scan#>>'{{evidence,artifacts,application}}',69)='-nf1.'||$4 AND {ACCESS}"), &[&user,&(crate::now()-30*86400),&quality::protocol_hash(),&crate::compatibility::DETECTOR_BUILD_SHA256]).await.map_err(database_error)?.get(0))
    }
    pub async fn quality_readiness(&self, user: &str, id: &str) -> Result<Value> {
        let mut db = self
            .interactive
            .get()
            .await
            .context("Central quality capacity unavailable")?;
        let tx = db
            .build_transaction()
            .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
            .start()
            .await
            .map_err(database_error)?;
        let selected: i64 = batch(&tx, user, id).await?.get(3);
        let query=tx.prepare(&format!("SELECT l.risk,l.kind,{OBSERVATION},{COHORT},m.scan->>'fingerprint',m.scan->>'campaign_simhash' FROM noisefence.quality_members x JOIN noisefence.messages m ON m.id=x.message_id LEFT JOIN noisefence.quality_labels l ON l.message_id=m.id AND l.username=$1 WHERE x.batch_id=$2 AND NOT m.is_dsn AND m.created>=$3 AND {ACCESS} LIMIT 50001")).await.map_err(database_error)?;
        let portal = tx
            .bind(&query, &[&user, &id, &(crate::now() - 30 * 86400)])
            .await
            .map_err(database_error)?;
        let mut counts = ReadinessCounts::default();
        loop {
            let rows = tx.query_portal(&portal, 16).await.map_err(database_error)?;
            if rows.is_empty() {
                break;
            }
            for r in rows {
                counts.add(
                    r.get::<_, Option<String>>(0).as_deref(),
                    r.get::<_, Option<String>>(1).as_deref(),
                    r.get::<_, Option<String>>(2).as_deref(),
                    &r.get::<_, String>(3),
                    r.get::<_, Option<String>>(4).as_deref(),
                    r.get::<_, Option<String>>(5).as_deref(),
                )?;
            }
        }
        Ok(counts.finish(selected.try_into()?))
    }
    pub async fn quality_qualification(
        &self,
        user: &str,
        current: String,
    ) -> Result<qualification::Readiness> {
        let mut db = self
            .interactive
            .get()
            .await
            .context("Central quality capacity unavailable")?;
        let tx = db
            .build_transaction()
            .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
            .start()
            .await
            .map_err(database_error)?;
        active(&tx, user).await?;
        let query=tx.prepare(&format!("SELECT {COHORT},{OBSERVATION},m.scan->>'fingerprint',m.scan->>'campaign_simhash',q.risk FROM noisefence.messages m LEFT JOIN noisefence.quality_labels q ON q.message_id=m.id AND q.username=$1 WHERE NOT m.is_dsn AND m.created>=$2 AND {ACCESS} LIMIT 50001")).await.map_err(database_error)?;
        let portal = tx
            .bind(&query, &[&user, &(crate::now() - 30 * 86400)])
            .await
            .map_err(database_error)?;
        let mut cohorts = BTreeMap::<String, qualification::Cohort>::new();
        let mut count = 0;
        loop {
            let rows = tx.query_portal(&portal, 16).await.map_err(database_error)?;
            if rows.is_empty() {
                break;
            }
            for r in rows {
                count += 1;
                ensure!(count <= 50000, "Readiness population exceeds capacity");
                let artifact: String = r.get(0);
                let eligible = quality::eligibility::inspect(
                    r.get::<_, Option<String>>(1).as_deref(),
                    &artifact,
                    r.get::<_, Option<String>>(2).as_deref(),
                    r.get::<_, Option<String>>(3).as_deref(),
                );
                cohorts
                    .entry(quality::eligibility::cohort(&artifact))
                    .or_default()
                    .record(r.get::<_, Option<String>>(4).as_deref(), eligible);
            }
        }
        Ok(qualification::summarize(current, cohorts))
    }
    pub async fn quality_cohorts(&self, user: &str) -> Result<Value> {
        let db = self
            .interactive
            .get()
            .await
            .context("Central quality capacity unavailable")?;
        let rows= db.query(&format!("SELECT m.scan#>>'{{quality,artifacts_sha256}}',count(*),min(m.created),max(m.created) FROM noisefence.messages m WHERE NOT m.is_dsn AND m.created>=$2 AND m.scan#>>'{{quality,protocol_sha256}}'=$3 AND {ACCESS} GROUP BY 1 ORDER BY max(m.created) DESC LIMIT 100"), &[&user,&(crate::now()-30*86400),&quality::protocol_hash()]).await.map_err(database_error)?;
        Ok(json!(rows.iter().map(|r|json!({"id":r.get::<_,Option<String>>(0).unwrap_or_default(),"messages":r.get::<_,i64>(1),"since":r.get::<_,i64>(2),"until":r.get::<_,i64>(3)})).collect::<Vec<_>>()))
    }
}

impl Central {
    /// Commit exposure accounting before any private export bytes leave the DB.
    /// Portal batches bound raw-scan memory; the projected export is capped too.
    pub async fn quality_export_rows(
        &self,
        user: &str,
        id: &str,
        candidate: Option<String>,
    ) -> Result<Vec<Value>> {
        ensure!(
            candidate
                .as_deref()
                .is_none_or(crate::compatibility::valid_hash),
            "Invalid candidate digest"
        );
        let mut db = self
            .interactive
            .get()
            .await
            .context("Central quality capacity unavailable")?;
        let tx = db
            .build_transaction()
            .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
            .start()
            .await
            .map_err(database_error)?;
        management_lock(&tx).await?;
        // Concurrent exporters that began before a preceding export committed
        // must fail serialization, never inspect an old exposure snapshot.
        let tracking:i64=tx.query_one("UPDATE noisefence.quality_exposure_state SET generation=generation+1 WHERE id=1 RETURNING tracking_since",&[]).await.map_err(database_error)?.get(0);
        let head = batch(&tx, user, id).await?;
        let purpose: String = head.get(5);
        let examined:bool=tx.query_one("SELECT EXISTS(SELECT 1 FROM noisefence.quality_jobs WHERE batch_id=$1 AND status IN ('complete','insufficient_labels','failed','interrupted'))", &[&id]).await.map_err(database_error)?.get(0);
        let references: bool = tx
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM noisefence.quality_reference_sets WHERE batch_id=$1)",
                &[&id],
            )
            .await
            .map_err(database_error)?
            .get(0);
        ensure!(
            !references || purpose == "regression",
            "References must stay regression-only"
        );
        let reservations=tx.query(&format!("SELECT DISTINCT m.scan->>'fingerprint',m.scan->>'campaign_simhash' FROM noisefence.quality_protected_messages p JOIN noisefence.messages m ON m.id=p.message_id WHERE m.created>=$2 AND {ACCESS} LIMIT 5001"), &[&user,&(crate::now()-30*86400)]).await.map_err(database_error)?;
        ensure!(reservations.len() <= 5000, "Too many protected campaigns");
        let reservations:Vec<_>=reservations.iter().map(|r|json!({"fingerprint":r.get::<_,Option<String>>(0),"simhash":r.get::<_,Option<String>>(1)})).collect();
        let mut out = vec![
            json!({"type":"header","schema":"noisefence-quality-dataset-1","batch":id,"since":head.get::<_,i64>(0),"until":head.get::<_,i64>(1),"population":head.get::<_,i64>(2),"selected":head.get::<_,i64>(3),"seed_sha256":crate::message::digest(head.get::<_,String>(4).as_bytes()),"sampling":if references {"confirmed_regression"} else {"uniform_message"},"protocol_sha256":quality::protocol_hash(),"captured_at":crate::now(),"decision_contract":quality::recorded::SCHEMA,"purpose":purpose,"cohort":head.get::<_,String>(6),"previously_examined":examined || references,"reserved_campaigns":reservations}),
        ];
        let query=tx.prepare(&format!("SELECT m.id,m.created,m.scan,l.risk,l.kind,l.created FROM noisefence.quality_members x JOIN noisefence.messages m ON m.id=x.message_id LEFT JOIN noisefence.quality_labels l ON l.message_id=m.id AND l.username=$1 WHERE x.batch_id=$2 AND m.created>=$3 AND {ACCESS} ORDER BY x.rank LIMIT 50001")).await.map_err(database_error)?;
        let portal = tx
            .bind(&query, &[&user, &id, &(crate::now() - 30 * 86400)])
            .await
            .map_err(database_error)?;
        let mut bytes = serde_json::to_vec(&out[0])?.len();
        loop {
            let rows = tx.query_portal(&portal, 8).await.map_err(database_error)?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                ensure!(out.len() <= 50000, "Quality export exceeds message limit");
                let scan: crate::engine::Scan = serde_json::from_value(row.get(2))?;
                let value = quality::evaluation::export_row(
                    &row.get::<_, String>(0),
                    row.get(1),
                    scan,
                    row.get(3),
                    row.get(4),
                    row.get(5),
                );
                bytes += serde_json::to_vec(&value)?.len();
                ensure!(
                    bytes <= 128 * 1024 * 1024,
                    "Quality export exceeds memory limit"
                );
                out.push(value);
            }
        }
        let mut exposure = record_exposure(&tx, id, &out[1..], tracking).await?;
        exposure.candidate_sha256 = candidate;
        if exposure.previously_exported || exposure.related_campaign_seen {
            out[0]["previously_examined"] = json!(true);
        }
        out[0]["exposure_tracking"] = serde_json::to_value(exposure)?;
        out.push(json!({"type":"footer","rows":out.len()-1}));
        tx.commit().await.map_err(database_error)?;
        Ok(out)
    }
}
async fn record_exposure(
    tx: &Transaction<'_>,
    batch: &str,
    rows: &[Value],
    tracking: i64,
) -> Result<quality::exposure::Exposure> {
    use quality::exposure::{Index, LIMIT, simhash};
    let time = crate::now();
    let cutoff = time - 30 * 86400;
    let previously: bool = tx
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM noisefence.quality_export_batches WHERE batch_id=$1)",
            &[&batch],
        )
        .await
        .map_err(database_error)?
        .get(0);
    tx.execute(
        "DELETE FROM noisefence.quality_export_campaigns WHERE exposed_at<$1",
        &[&cutoff],
    )
    .await
    .map_err(database_error)?;
    tx.execute(
        "DELETE FROM noisefence.quality_export_batches WHERE exposed_at<$1",
        &[&cutoff],
    )
    .await
    .map_err(database_error)?;
    let history = tx
        .query(
            "SELECT fingerprint,simhash FROM noisefence.quality_export_campaigns LIMIT 50001",
            &[],
        )
        .await
        .map_err(database_error)?;
    ensure!(
        history.len() <= LIMIT,
        "Research exposure history exceeds capacity"
    );
    let mut index = Index::new();
    for r in history {
        index.add(r.get(0), simhash(&r.get::<_, String>(1)));
    }
    let mut related = false;
    let mut incoming = std::collections::BTreeSet::new();
    for row in rows {
        if let Some(fingerprint) = row["fingerprint"]
            .as_str()
            .filter(|s| crate::compatibility::valid_hash(s))
        {
            let hash = row["simhash"]
                .as_str()
                .filter(|s| simhash(s).is_some())
                .unwrap_or("");
            if !related {
                related = index.contains(fingerprint, simhash(hash))?;
            }
            incoming.insert((fingerprint.to_owned(), hash.to_owned()));
        }
    }
    let (fingerprints, hashes): (Vec<_>, Vec<_>) = incoming.into_iter().unzip();
    tx.execute("INSERT INTO noisefence.quality_export_campaigns(fingerprint,simhash,exposed_at) SELECT fingerprint,simhash,$3 FROM unnest($1::text[],$2::text[]) AS x(fingerprint,simhash) ON CONFLICT(fingerprint,simhash) DO UPDATE SET exposed_at=excluded.exposed_at", &[&fingerprints,&hashes,&time]).await.map_err(database_error)?;
    ensure!(
        tx.query_one(
            "SELECT count(*) FROM noisefence.quality_export_campaigns",
            &[]
        )
        .await
        .map_err(database_error)?
        .get::<_, i64>(0)
            <= LIMIT as i64,
        "Research exposure history exceeds capacity"
    );
    tx.execute("INSERT INTO noisefence.quality_export_batches VALUES($1,$2) ON CONFLICT(batch_id) DO UPDATE SET exposed_at=excluded.exposed_at", &[&batch,&time]).await.map_err(database_error)?;
    Ok(quality::exposure::Exposure {
        schema: quality::exposure::SCHEMA,
        candidate_sha256: None,
        tracking_since: tracking,
        previously_exported: previously,
        related_campaign_seen: related,
    })
}
