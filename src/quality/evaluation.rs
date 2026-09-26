//! Frozen uniform sampling. No score-based selection, no inferred ground truth.
use crate::{now, quality::Kind, store::Store};
use anyhow::{Result, ensure};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{io::Write, os::unix::fs::OpenOptionsExt, path::Path};

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Risk {
    Legitimate,
    Spam,
    Uncertain,
}
impl Risk {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Legitimate => "legitimate",
            Self::Spam => "spam",
            Self::Uncertain => "uncertain",
        }
    }
}
pub async fn sample(
    store: &Store,
    username: String,
    since: i64,
    until: i64,
    count: usize,
    domain: String,
) -> Result<String> {
    sample_with_purpose(
        store,
        username,
        since,
        until,
        count,
        domain,
        Purpose::Regression,
        String::new(),
    )
    .await
}
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum Purpose {
    Development,
    #[default]
    Regression,
    Holdout,
}
impl Purpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Development => "development",
            Self::Regression => "regression",
            Self::Holdout => "holdout",
        }
    }
}
#[allow(clippy::too_many_arguments)]
pub async fn sample_with_purpose(
    store: &Store,
    username: String,
    since: i64,
    until: i64,
    count: usize,
    domain: String,
    purpose: Purpose,
    cohort: String,
) -> Result<String> {
    ensure!(
        cohort.is_empty() || (purpose == Purpose::Development && super::hash(&cohort)),
        "Cohort selection is for development only"
    );
    ensure!(
        (1..=50000).contains(&count)
            && since >= now() - 30 * 86400
            && since < until
            && until <= now()
            && (domain.is_empty() || crate::config::valid_domain(&domain)),
        "invalid sample window"
    );
    store.run(move |db| {
        let tx=db.transaction()?;
        let mut q=tx.prepare("SELECT m.id FROM messages m WHERE m.is_dsn=0 AND m.created>=?2 AND m.created<?3
          AND EXISTS(SELECT 1 FROM deliveries d JOIN console_access g ON g.delivery_id=d.id
          WHERE d.message_id=m.id AND g.username=?1 AND (?4='' OR lower(substr(d.address,-length(?4)-1))='@'||lower(?4) OR lower(substr(d.destination,-length(?4)-1))='@'||lower(?4))) AND (?5='' OR json_extract(m.scan,'$.quality.artifacts_sha256')=?5) LIMIT 50001")?;
        let ids: Vec<String>=q.query_map(params![username,since,until,domain,cohort],|r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
        drop(q); ensure!(ids.len()<=50000,"sample population exceeds capacity");
        ensure!(!ids.is_empty(),"no messages in this window");
        let batch_count:usize=tx.query_row("SELECT COUNT(*) FROM quality_batches WHERE username=?1",[&username],|r|r.get(0))?;
        ensure!(batch_count<100,"too many retained samples");
        let seed=crate::api::random_token();
        let mut draw:Vec<_>=ids.iter().map(|id|(crate::message::digest(format!("{seed}:{id}").as_bytes()),id)).collect();
        draw.sort_unstable(); draw.truncate(count);
        let id=uuid::Uuid::new_v4().to_string();
        tx.execute("INSERT INTO quality_batches VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",params![id,username,now(),since,until,domain,seed,ids.len(),draw.len()])?;
        tx.execute("INSERT INTO quality_purposes VALUES(?1,?2,?3)", params![id,purpose.as_str(),cohort])?;
        for (rank,(_,message_id)) in draw.iter().enumerate() {
            tx.execute("INSERT INTO quality_members VALUES(?1,?2,?3)",params![id,message_id,rank])?;
        }
        tx.execute("INSERT INTO audit(created,username,action,object_id) VALUES(?1,?2,'quality_sample',?3)",params![now(),username,id])?;
        tx.commit()?;Ok(id)
    }).await
}
pub async fn label(
    store: &Store,
    username: String,
    id: String,
    risk: Risk,
    kind: Option<Kind>,
) -> Result<()> {
    store.run(move |db| {
        let tx=db.transaction()?;
        let allowed:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM messages m JOIN deliveries d ON d.message_id=m.id JOIN console_access g ON g.delivery_id=d.id WHERE m.id=?1 AND g.username=?2 AND m.created>=?3 AND m.is_dsn=0)",params![id,username,now()-30*86400],|r|r.get(0))?;
        ensure!(allowed,"message not found");
        tx.execute("INSERT INTO quality_labels VALUES(?1,?2,?3,?4,?5) ON CONFLICT(username,message_id) DO UPDATE SET risk=excluded.risk,kind=excluded.kind,created=excluded.created",params![username,id,risk.as_str(),kind.map(Kind::as_str),now()])?;
        tx.execute("INSERT INTO audit(created,username,action,object_id) VALUES(?1,?2,'quality_label',?3)",params![now(),username,id])?;
        tx.commit()?;Ok(())
    }).await
}
pub async fn batches(store: &Store, username: String) -> Result<Vec<Value>> {
    store.read(move |db| {
        let mut q=db.prepare("SELECT b.id,b.created,b.since,b.until,b.domain,b.population,b.selected,
          (SELECT COUNT(*) FROM quality_members x JOIN messages m ON m.id=x.message_id WHERE x.batch_id=b.id AND m.created>=?2 AND EXISTS(SELECT 1 FROM deliveries d JOIN console_access a ON a.delivery_id=d.id WHERE d.message_id=m.id AND a.username=?1)),
          (SELECT COUNT(*) FROM quality_members x JOIN messages m ON m.id=x.message_id JOIN quality_labels l ON l.message_id=m.id AND l.username=?1 WHERE x.batch_id=b.id AND m.created>=?2 AND EXISTS(SELECT 1 FROM deliveries d JOIN console_access a ON a.delivery_id=d.id WHERE d.message_id=m.id AND a.username=?1))
          ,COALESCE((SELECT purpose FROM quality_purposes p WHERE p.batch_id=b.id),'regression'),EXISTS(SELECT 1 FROM quality_reference_sets r WHERE r.batch_id=b.id) FROM quality_batches b WHERE b.username=?1 AND b.created>=?2 ORDER BY b.created DESC,b.id DESC LIMIT 100")?;
        let rows=q.query_map(params![username,now()-30*86400],|r|Ok(json!({"id":r.get::<_,String>(0)?,"created":r.get::<_,i64>(1)?,"since":r.get::<_,i64>(2)?,"until":r.get::<_,i64>(3)?,"domain":r.get::<_,String>(4)?,"population":r.get::<_,usize>(5)?,"selected":r.get::<_,usize>(6)?,"available":r.get::<_,usize>(7)?,"labelled":r.get::<_,usize>(8)?,"sampling":if r.get::<_,bool>(10)? {"confirmed_regression"} else {"uniform_message"},"purpose":r.get::<_,String>(9)?})))?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }).await
}
/// Start of the recent collection period, independent of scores and completeness.
pub async fn observation_start(store: &Store, username: String) -> Result<Option<i64>> {
    store.read(move |db| {
        Ok(db.query_row("SELECT MIN(m.created) FROM messages m WHERE m.is_dsn=0 AND m.created>=?2
          AND CASE WHEN json_valid(m.scan) THEN json_extract(m.scan,'$.quality.protocol_sha256')=?3 AND substr(json_extract(m.scan,'$.evidence.artifacts.application'),-69)='-nf1.'||?4 ELSE 0 END
          AND EXISTS(SELECT 1 FROM deliveries d JOIN console_access a ON a.delivery_id=d.id WHERE d.message_id=m.id AND a.username=?1)",
          params![username,now()-30*86400,super::protocol_hash(),crate::compatibility::DETECTOR_BUILD_SHA256],|r|r.get(0))?)
    }).await
}
pub async fn members(store: &Store, username: String, batch: String) -> Result<Vec<Value>> {
    members_page(store, username, batch, 0).await
}

/// Counts only, with the same current access checks as annotation. This does
/// not claim that chronological folds, campaigns or both classes are sufficient.
pub async fn readiness(store: &Store, username: String, batch: String) -> Result<Value> {
    store.read(move |db| {
        let selected: Option<usize> = db.query_row("SELECT selected FROM quality_batches WHERE id=?1 AND username=?2 AND created>=?3",
            params![batch,username,now()-30*86400], |r|r.get(0)).optional()?;
        let selected = selected.ok_or_else(||anyhow::anyhow!("sample not found"))?;
        let sql = format!("SELECT l.risk,l.kind, {}, {},
          json_extract(m.scan,'$.fingerprint'), json_extract(m.scan,'$.campaign_simhash')
          FROM quality_members x JOIN messages m ON m.id=x.message_id
          LEFT JOIN quality_labels l ON l.message_id=m.id AND l.username=?1
          WHERE x.batch_id=?2 AND m.is_dsn=0 AND m.created>=?3 AND EXISTS(SELECT 1 FROM deliveries d JOIN console_access a ON a.delivery_id=d.id WHERE d.message_id=m.id AND a.username=?1) LIMIT 50001",
          super::eligibility::OBSERVATION_SQL, super::eligibility::COHORT_SQL);
        let mut query = db.prepare(&sql)?;
        let mut rows = query.query(params![username,batch,now()-30*86400])?;
        let (mut available, mut labelled, mut risk_labels, mut kind_labels, mut risk_observed, mut kind_observed, mut missing) = (0usize,0usize,0usize,0usize,0usize,0usize,0usize);
        let mut cohorts = std::collections::BTreeSet::new();
        let mut exclusions = std::collections::BTreeMap::new();
        while let Some(row) = rows.next()? {
            available += 1;
            ensure!(available <= 50000, "Readiness population exceeds capacity");
            let risk: Option<String> = row.get(0)?;
            let kind: Option<String> = row.get(1)?;
            let observation: Option<String> = row.get(2)?;
            let artifact: String = row.get(3)?;
            let fingerprint: Option<String> = row.get(4)?;
            let simhash: Option<String> = row.get(5)?;
            let eligibility = super::eligibility::inspect(observation.as_deref(), &artifact, fingerprint.as_deref(), simhash.as_deref());
            let observed = eligibility.is_ok();
            if let Err(reason) = eligibility { *exclusions.entry(reason).or_insert(0usize) += 1; }
            labelled += usize::from(risk.is_some());
            let certain = matches!(risk.as_deref(),Some("legitimate"|"spam"));
            risk_labels += usize::from(certain);
            kind_labels += usize::from(kind.is_some());
            risk_observed += usize::from(certain && observed);
            kind_observed += usize::from(kind.is_some() && observed);
            missing += usize::from(!observed);
            if observed { cohorts.insert(artifact); }
        }
        Ok(json!({"selected":selected,"available":available,"labelled":labelled,"risk_labels":risk_labels,
            "kind_labels":kind_labels,"risk_with_observations":risk_observed,"kind_with_observations":kind_observed,
            "missing_or_incompatible_observations":missing,"detector_cohorts":cohorts.len(),"exclusions":exclusions,
            "training_validated":false,"observation_only":true}))
    }).await
}
pub async fn members_page(
    store: &Store,
    username: String,
    batch: String,
    offset: usize,
) -> Result<Vec<Value>> {
    ensure!(offset <= 50000, "invalid page");
    store.read(move |db| {
        let allowed:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM quality_batches WHERE id=?1 AND username=?2 AND created>=?3)",params![batch,username,now()-30*86400],|r|r.get(0))?;
        ensure!(allowed,"sample not found");
        let mut q=db.prepare("SELECT m.id,m.created,m.sender,json_extract(m.scan,'$.subject'),l.risk,l.kind,json_extract(m.scan,'$.quality.schema') IS NOT NULL FROM quality_members x JOIN messages m ON m.id=x.message_id LEFT JOIN quality_labels l ON l.message_id=m.id AND l.username=?1
          WHERE x.batch_id=?2 AND m.created>=?3 AND EXISTS(SELECT 1 FROM deliveries d JOIN console_access a ON a.delivery_id=d.id WHERE d.message_id=m.id AND a.username=?1) ORDER BY x.rank LIMIT 200 OFFSET ?4")?;
        Ok(q.query_map(params![username,batch,now()-30*86400,offset],|r|Ok(json!({"id":r.get::<_,String>(0)?,"created":r.get::<_,i64>(1)?,"sender":r.get::<_,String>(2)?,"subject":r.get::<_,String>(3)?,"risk":r.get::<_,Option<String>>(4)?,"kind":r.get::<_,Option<String>>(5)?,"joint_observations":r.get::<_,bool>(6)?})))?.collect::<rusqlite::Result<Vec<_>>>()?)
    }).await
}

/// Server-side private export; snapshots contain no body, subject or mailbox identity.
pub async fn export(
    store: &Store,
    username: String,
    batch: String,
    output: &Path,
) -> Result<Value> {
    export_for_candidate(store, username, batch, output, None).await
}

pub async fn export_for_candidate(
    store: &Store,
    username: String,
    batch: String,
    output: &Path,
    candidate_sha256: Option<String>,
) -> Result<Value> {
    ensure!(
        candidate_sha256.as_deref().is_none_or(super::hash),
        "Invalid candidate digest"
    );
    let rows=store.run(move |db| {
        let tx=db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let db=&tx;
        let worker:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM cluster_state WHERE key='role' AND value='worker')",[],|r|r.get(0))?;
        ensure!(!worker,"Quality exports run on the coordinator only");
        let header:Option<Value>=db.query_row("SELECT since,until,population,selected,seed FROM quality_batches WHERE id=?1 AND username=?2 AND created>=?3",params![batch,username,now()-30*86400],|r| Ok(json!({"type":"header","schema":"noisefence-quality-dataset-1","batch":batch,"since":r.get::<_,i64>(0)?,"until":r.get::<_,i64>(1)?,"population":r.get::<_,usize>(2)?,"selected":r.get::<_,usize>(3)?,"seed_sha256":crate::message::digest(r.get::<_,String>(4)?.as_bytes()),"sampling":"uniform_message","protocol_sha256":super::protocol_hash(),"captured_at":now()}))).optional()?;
        let mut header=header.ok_or_else(||anyhow::anyhow!("sample not found"))?;
        header["decision_contract"]=json!(super::recorded::SCHEMA);
        let purpose: Option<(String,String)>=db.query_row("SELECT purpose,cohort FROM quality_purposes WHERE batch_id=?1",[&batch],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        let (purpose,cohort)=purpose.unwrap_or(("regression".into(),String::new()));
        header["purpose"]=json!(purpose);header["cohort"]=json!(cohort);
        let examined:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM quality_jobs WHERE batch_id=?1 AND status IN ('complete','insufficient_labels','failed','interrupted'))",[&batch],|r|r.get(0))?;
        header["previously_examined"]=json!(examined);
        let references:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM quality_reference_sets WHERE batch_id=?1)",[&batch],|r|r.get(0))?;
        if references {ensure!(purpose=="regression","References must stay regression-only");header["sampling"]=json!("confirmed_regression");header["previously_examined"]=json!(true);}
        // Only campaign fingerprints are exported, and only for currently accessible references.
        let mut reserved=db.prepare("SELECT DISTINCT json_extract(m.scan,'$.fingerprint'),json_extract(m.scan,'$.campaign_simhash') FROM quality_protected_messages p JOIN messages m ON m.id=p.message_id WHERE m.created>=?2 AND EXISTS(SELECT 1 FROM deliveries d JOIN console_access a ON a.delivery_id=d.id WHERE d.message_id=m.id AND a.username=?1) LIMIT 5001")?;
        let reservations=reserved.query_map(params![username,now()-30*86400],|r|Ok(json!({"fingerprint":r.get::<_,Option<String>>(0)?,"simhash":r.get::<_,Option<String>>(1)?})))?.collect::<rusqlite::Result<Vec<_>>>()?;
        ensure!(reservations.len()<=5000,"too many protected campaigns");
        header["reserved_campaigns"]=json!(reservations);
        let mut out=vec![header];
        let mut q=db.prepare("SELECT m.id,m.created,m.scan,l.risk,l.kind,l.created FROM quality_members x JOIN messages m ON m.id=x.message_id LEFT JOIN quality_labels l ON l.message_id=m.id AND l.username=?1 WHERE x.batch_id=?2 AND m.created>=?3 AND EXISTS(SELECT 1 FROM deliveries d JOIN console_access a ON a.delivery_id=d.id WHERE d.message_id=m.id AND a.username=?1) ORDER BY x.rank")?;
        let mut rows=q.query(params![username,batch,now()-30*86400])?;
        while let Some(row)=rows.next()? {
            let scan:crate::engine::Scan=serde_json::from_str(&row.get::<_,String>(2)?)?;
            let decisions=super::recorded::snapshot(&scan);
            let engine=decisions["engine"].clone();
            let quality=scan.quality.map(|mut q| {q.sender.key=None;if let Some(b)=&mut q.sender.behavior { b.sample=None; }q});
            out.push(json!({"type":"row","id":crate::message::digest(row.get::<_,String>(0)?.as_bytes()),"observed_at":row.get::<_,i64>(1)?,"fingerprint":scan.fingerprint,"simhash":scan.campaign_simhash,"risk":row.get::<_,Option<String>>(3)?,"kind":row.get::<_,Option<String>>(4)?,"labelled_at":row.get::<_,Option<i64>>(5)?,"legacy_decision":engine,"baseline_complete":decisions["engine"]["complete"],"delivery_classification":decisions["final"]["category"],"decision_snapshot":decisions,"quality":quality,"rspamd":scan.rspamd.map(|r|json!({"status":r.status,"action":r.action,"score":r.score,"profile":r.profile,"settings_sha256":r.settings_sha256})),"legacy_score":engine["raw_score"],"pipeline_elapsed_ms":scan.elapsed_ms}));
        }
        drop(rows);drop(q);drop(reserved);
        let mut exposure=super::exposure::record(&tx,&batch,&out[1..],now())?;
        exposure.candidate_sha256=candidate_sha256;
        if exposure.previously_exported || exposure.related_campaign_seen {out[0]["previously_examined"]=json!(true);}
        out[0]["exposure_tracking"]=serde_json::to_value(exposure)?;
        out.push(json!({"type":"footer","rows":out.len()-1}));
        tx.commit()?;Ok(out)
    }).await?;
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let temporary = parent.join(format!(".quality-export-{}", uuid::Uuid::new_v4()));
    let write = (|| -> Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        for row in &rows {
            serde_json::to_writer(&mut file, row)?;
            file.write_all(b"\n")?;
        }
        file.sync_all()?;
        // Refuse overwriting a previous frozen sample or a symlink.
        std::fs::hard_link(&temporary, output)?;
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    let _ = std::fs::remove_file(&temporary);
    write?;
    Ok(json!({"rows":rows.len()-2,"schema":"noisefence-quality-dataset-1","contains_bodies":false}))
}
