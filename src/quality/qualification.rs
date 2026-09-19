//! Dataset readiness is not an activation certificate or an accuracy estimate.
use crate::store::Store;
use anyhow::{Result, ensure};
use rusqlite::params;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Default, Serialize)]
pub struct Cohort {
    pub messages: usize,
    pub usable: usize,
    pub wanted: usize,
    pub unwanted: usize,
    pub uncertain: usize,
    pub unlabelled: usize,
}
#[derive(Serialize)]
pub struct Readiness {
    pub schema: &'static str,
    pub current_cohort: String,
    pub cohorts: BTreeMap<String, Cohort>,
    pub minimum_wanted_test_messages: usize,
    pub minimum_unwanted_test_messages: usize,
    pub qualification_required: bool,
    pub blockers: Vec<&'static str>,
}
pub async fn inspect(store: &Store, username: String, current: String) -> Result<Readiness> {
    store.read(move |db| {
        let mut q = db.prepare("SELECT COALESCE(json_extract(m.scan,'$.quality.artifacts_sha256'),'unrecorded'), COALESCE(json_extract(m.scan,'$.quality.complete_features'),0), json_extract(m.scan,'$.quality.source'), q.risk FROM messages m LEFT JOIN quality_labels q ON q.message_id=m.id AND q.username=?1 WHERE m.is_dsn=0 AND m.created>=?2 AND EXISTS(SELECT 1 FROM deliveries d JOIN console_access a ON a.delivery_id=d.id WHERE d.message_id=m.id AND a.username=?1) LIMIT 50001")?;
        let mut cohorts = BTreeMap::<String,Cohort>::new();
        let mut count = 0;
        for row in q.query_map(params![username,crate::now()-30*86400], |r| Ok((r.get::<_,String>(0)?,r.get::<_,bool>(1)?,r.get::<_,Option<String>>(2)?,r.get::<_,Option<String>>(3)?)))? {
            let (key, complete, source, label) = row?;
            count += 1; ensure!(count<=50000, "Readiness population exceeds capacity");
            let c=cohorts.entry(key).or_default(); c.messages+=1;
            if complete && source.as_deref()==Some("smtp_session") {c.usable+=1;}
            match label.as_deref() { Some("legitimate")=>c.wanted+=1, Some("spam")=>c.unwanted+=1, Some("uncertain")=>c.uncertain+=1, _=>c.unlabelled+=1 }
        }
        let c=cohorts.get(&current);
        let mut blockers=Vec::new();
        if c.is_none_or(|c| c.messages==0) {blockers.push("no_current_cohort");}
        if c.is_none_or(|c| c.wanted<10000) {blockers.push("insufficient_wanted_labels");}
        if c.is_none_or(|c| c.unwanted<2000) {blockers.push("insufficient_unwanted_labels");}
        if c.is_some_and(|c| c.usable<c.messages) {blockers.push("incomplete_observations");}
        // Even sufficient message counts do not prove campaign independence,
        // held-out chronology, calibration, confidence bounds or latency.
        blockers.push("independent_evaluation_required");
        Ok(Readiness { schema:"noisefence-release-readiness-1",current_cohort:current,cohorts,minimum_wanted_test_messages:10000,minimum_unwanted_test_messages:2000,qualification_required:true,blockers })
    }).await
}
