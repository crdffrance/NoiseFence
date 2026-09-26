//! Dataset readiness is not an activation certificate or an accuracy estimate.
use super::eligibility::{self, Exclusion};
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
    pub usable_wanted: usize,
    pub usable_unwanted: usize,
    pub usable_uncertain: usize,
    pub usable_unlabelled: usize,
    pub exclusions: BTreeMap<Exclusion, usize>,
}
impl Cohort {
    fn record(&mut self, label: Option<&str>, eligibility: Result<(), Exclusion>) {
        self.messages += 1;
        let usable = eligibility.is_ok();
        if let Err(reason) = eligibility {
            *self.exclusions.entry(reason).or_default() += 1;
        }
        self.usable += usize::from(usable);
        match label {
            Some("legitimate") => {
                self.wanted += 1;
                self.usable_wanted += usize::from(usable);
            }
            Some("spam") => {
                self.unwanted += 1;
                self.usable_unwanted += usize::from(usable);
            }
            Some("uncertain") => {
                self.uncertain += 1;
                self.usable_uncertain += usize::from(usable);
            }
            _ => {
                self.unlabelled += 1;
                self.usable_unlabelled += usize::from(usable);
            }
        }
    }
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
fn blockers(cohort: Option<&Cohort>) -> Vec<&'static str> {
    let mut result = Vec::new();
    if cohort.is_none_or(|c| c.messages == 0) {
        result.push("no_current_cohort");
    }
    if cohort.is_none_or(|c| c.usable_wanted < 10000) {
        result.push("insufficient_wanted_labels");
    }
    if cohort.is_none_or(|c| c.usable_unwanted < 2000) {
        result.push("insufficient_unwanted_labels");
    }
    if cohort.is_some_and(|c| c.usable < c.messages) {
        result.push("incomplete_observations");
    }
    // Usable labels still do not establish reserved test membership, campaign
    // independence, chronological folds, calibrated quality or latency.
    result.push("independent_evaluation_required");
    result
}

pub async fn inspect(store: &Store, username: String, current: String) -> Result<Readiness> {
    store.read(move |db| {
        let sql = format!("SELECT {}, {}, json_extract(m.scan,'$.fingerprint'), json_extract(m.scan,'$.campaign_simhash'), q.risk
            FROM messages m LEFT JOIN quality_labels q ON q.message_id=m.id AND q.username=?1
            WHERE m.is_dsn=0 AND m.created>=?2 AND EXISTS(SELECT 1 FROM deliveries d
            JOIN console_access a ON a.delivery_id=d.id WHERE d.message_id=m.id AND a.username=?1) LIMIT 50001",
            eligibility::COHORT_SQL, eligibility::OBSERVATION_SQL);
        let mut query = db.prepare(&sql)?;
        let mut rows = query.query(params![username,crate::now()-30*86400])?;
        let mut cohorts = BTreeMap::<String, Cohort>::new();
        let mut count = 0;
        while let Some(row) = rows.next()? {
            count += 1;
            ensure!(count <= 50000, "Readiness population exceeds capacity");
            let artifact: String = row.get(0)?;
            let observation: Option<String> = row.get(1)?;
            let fingerprint: Option<String> = row.get(2)?;
            let simhash: Option<String> = row.get(3)?;
            let label: Option<String> = row.get(4)?;
            let eligible = eligibility::inspect(observation.as_deref(), &artifact, fingerprint.as_deref(), simhash.as_deref());
            cohorts.entry(eligibility::cohort(&artifact)).or_default().record(label.as_deref(), eligible);
        }
        let blockers = blockers(cohorts.get(&current));
        Ok(Readiness {
            schema:"noisefence-release-readiness-2", current_cohort:current, cohorts,
            minimum_wanted_test_messages:10000, minimum_unwanted_test_messages:2000,
            qualification_required:true, blockers,
        })
    }).await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn label_minima_require_usable_intersections_and_never_certify_activation() {
        let mut cohort = Cohort {
            messages: 12000,
            wanted: 10000,
            unwanted: 2000,
            ..Default::default()
        };
        let missing = blockers(Some(&cohort));
        assert!(missing.contains(&"insufficient_wanted_labels"));
        assert!(missing.contains(&"insufficient_unwanted_labels"));
        cohort.usable = 12000;
        cohort.usable_wanted = 10000;
        cohort.usable_unwanted = 2000;
        assert_eq!(
            blockers(Some(&cohort)),
            vec!["independent_evaluation_required"]
        );
        cohort.usable_wanted -= 1;
        cohort.usable -= 1;
        assert!(blockers(Some(&cohort)).contains(&"insufficient_wanted_labels"));
    }
}
