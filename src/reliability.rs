//! Recipient-scoped quality and health accounting, never a delivery policy.
mod coverage;
pub mod health;
pub mod proton;
use crate::{
    engine::Scan,
    fusion::runtime::{Decision, DecisionSource, Outcome},
    store::Store,
};
use anyhow::{Result, ensure};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, Instant},
};

const MAX_ROWS: usize = 5000;
const MAX_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Options {
    pub days: u32,
    pub domain: String,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            days: 7,
            domain: String::new(),
        }
    }
}
impl Options {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (1..=29).contains(&self.days)
                && (self.domain.is_empty()
                    || (crate::config::valid_domain(&self.domain)
                        && self.domain == self.domain.to_ascii_lowercase())),
            "invalid reliability scope"
        );
        Ok(())
    }
}

#[derive(Default, Clone, Serialize)]
pub struct Counts {
    pub tp: usize,
    pub fp: usize,
    pub tn: usize,
    pub missed: usize,
    pub spam_review: usize,
    pub legitimate_review: usize,
}
impl Counts {
    pub fn add(&mut self, outcome: Outcome, spam: bool) {
        match (outcome, spam) {
            (Outcome::Unwanted, true) => self.tp += 1,
            (Outcome::Unwanted, false) => self.fp += 1,
            (Outcome::Legitimate, true) => self.missed += 1,
            (Outcome::Legitimate, false) => self.tn += 1,
            (Outcome::Undetermined, true) => self.spam_review += 1,
            (Outcome::Undetermined, false) => self.legitimate_review += 1,
        }
    }
    pub fn report(&self) -> Value {
        let spam = self.tp + self.missed + self.spam_review;
        let ham = self.tn + self.fp + self.legitimate_review;
        json!({"counts":self,"labelled":spam+ham,"recall":interval(self.tp,spam),
            "false_positive_rate":interval(self.fp,ham),"precision":interval(self.tp,self.tp+self.fp),
            "abstention":interval(self.spam_review+self.legitimate_review,spam+ham)})
    }
}
/// Two-sided Wilson 95% interval; an empty denominator is unavailable, never zero error.
pub fn interval(events: usize, total: usize) -> Option<Value> {
    if total == 0 || events > total {
        return None;
    }
    let n = total as f64;
    let p = events as f64 / n;
    let z = 1.959963984540054_f64;
    let denom = 1.0 + z * z / n;
    let center = (p + z * z / (2.0 * n)) / denom;
    let radius = z * (p * (1.0 - p) / n + z * z / (4.0 * n * n)).sqrt() / denom;
    Some(
        json!({"events":events,"total":total,"value":p,"lower":(center-radius).max(0.0),"upper":(center+radius).min(1.0),"confidence":0.95,"method":"wilson_two_sided"}),
    )
}
fn outcome(scan: &Scan) -> Outcome {
    scan.decision
        .as_ref()
        .map_or(Outcome::Undetermined, |d| d.outcome)
}
fn fixed_token<T: Serialize>(value: T) -> String {
    serde_json::to_value(value)
        .unwrap()
        .as_str()
        .unwrap_or("unknown")
        .into()
}
fn safe_symbol(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 96
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

#[derive(Default, Serialize)]
struct Window {
    messages: usize,
    incomplete: usize,
    spam: usize,
    review: usize,
    legitimate: usize,
    disagreements: usize,
    detector_status: BTreeMap<String, BTreeMap<String, usize>>,
    coverage: coverage::Coverage,
    #[serde(skip)]
    latencies: Vec<u64>,
    p95_ms: Option<u64>,
}
impl Window {
    fn add(&mut self, scan: &Scan) {
        self.messages += 1;
        self.coverage.add(scan);
        self.incomplete += usize::from(!scan.complete);
        match outcome(scan) {
            Outcome::Unwanted => self.spam += 1,
            Outcome::Undetermined => self.review += 1,
            Outcome::Legitimate => self.legitimate += 1,
        }
        self.disagreements +=
            usize::from(scan.arbitration.as_ref().is_some_and(|a| {
                matches!(a.resolution, crate::decision::Resolution::Disagreement)
            }));
        self.latencies.push(scan.elapsed_ms);
        let mut states = vec![
            ("semantic", fixed_token(&scan.semantic.status)),
            ("llm", fixed_token(&scan.llm.status)),
            ("antivirus", fixed_token(&scan.antivirus.status)),
            ("signatures", fixed_token(&scan.signatures.status)),
            ("vision", fixed_token(scan.vision.status)),
        ];
        if let Some(p) = &scan.protection {
            states.extend([
                ("crdf", fixed_token(&p.crdf.status)),
                ("virustotal", fixed_token(&p.virustotal.status)),
                ("url_feed", fixed_token(&p.feed_status)),
                (
                    "redirects",
                    p.url_resolution.as_ref().map_or("disabled".into(), |r| {
                        if r.omitted > 0 || r.chains.iter().any(|c| !c.complete) {
                            "limited".into()
                        } else {
                            "complete".into()
                        }
                    }),
                ),
            ]);
        }
        if let Some(n) = &scan.native_filter {
            states.push(("native", fixed_token(n.report.status)));
        }
        for (name, state) in states {
            *self
                .detector_status
                .entry(name.into())
                .or_default()
                .entry(state)
                .or_default() += 1;
        }
    }
    fn finish(&mut self) {
        self.latencies.sort_unstable();
        self.p95_ms = self
            .latencies
            .get((self.latencies.len() * 95).div_ceil(100).saturating_sub(1))
            .copied();
    }
}

#[derive(Default, Serialize)]
struct Symbol {
    source: String,
    hits: usize,
    labelled_spam: usize,
    labelled_legitimate: usize,
    spam_decision_on_legitimate: usize,
    absorbed: usize,
    raw_weight_sum: f64,
    replayed: usize,
    frozen_decision_changes: usize,
    false_positives_avoided: usize,
    detected_spam_lost: usize,
}
#[derive(Default, Serialize)]
struct Cohort {
    messages: usize,
    complete: usize,
    native: usize,
    risk_labels: usize,
    targeted_labels: usize,
    first_seen: i64,
    last_seen: i64,
    current_build: bool,
    versions: BTreeSet<String>,
}
#[derive(Default)]
struct Accumulator {
    all: Window,
    recent: Window,
    current_recent: Window,
    quality_misses: coverage::Misses,
    targeted_misses: coverage::Misses,
    reference: Window,
    days: BTreeMap<i64, Window>,
    cohorts: BTreeMap<String, Cohort>,
    symbols: BTreeMap<String, Symbol>,
    pairs: BTreeMap<(String, String), usize>,
    comparisons: BTreeMap<String, (Counts, Counts)>,
    quality: Counts,
    targeted: Counts,
    unlabelled: usize,
    invalid_labels: usize,
    invalid_scans: usize,
    missing_cohorts: usize,
    historical_replays_unavailable: usize,
    saturation: usize,
    compatible_observations: usize,
    current_protocol: usize,
}

/// Replays only proven legacy observations. The LLM calls and antivirus results stay frozen.
/// This removes a score weight, not its underlying evidence or a recipient's delivery action.
pub fn without_weight(scan: &Scan, id: &str) -> Option<Outcome> {
    let policy = scan.analysis_policy.as_ref()?;
    if !scan.complete
        || policy.version != crate::decision::VERSION
        || !(0.0..100.0).contains(&policy.threshold)
    {
        return None;
    }
    let original = scan
        .arbitration
        .as_ref()
        .map_or(scan.decision.as_ref()?, |a| &a.baseline);
    if original.source != DecisionSource::Legacy {
        return None;
    }
    let breakdown = crate::detection_diagnostics::breakdown(scan);
    if !breakdown.matches_recorded_score {
        return None;
    }
    let total = breakdown
        .families
        .values()
        .try_fold(0.0, |sum, v| Some(sum + (*v)?))?;
    let replay = |score: f64| {
        let mut copy = scan.clone();
        copy.arbitration = None;
        copy.score = score;
        copy.decision = Some(Decision::legacy(&copy, policy.threshold));
        crate::decision::apply(&mut copy, policy.require_corroboration);
        outcome(&copy)
    };
    if replay(scan.score) != outcome(scan) {
        return None;
    }
    let weight: f64 = scan
        .reasons
        .iter()
        .filter(|r| r.id == id)
        .map(|r| r.weight)
        .sum();
    if !weight.is_finite() || !total.is_finite() {
        return None;
    }
    Some(replay(crate::engine::sigmoid(total - weight) * 100.0))
}

impl Accumulator {
    fn add(
        &mut self,
        scan: &Scan,
        created: i64,
        risk: Option<&str>,
        feedback: Option<i64>,
        now: i64,
    ) {
        self.all.add(scan);
        self.days
            .entry(created / 86400 * 86400)
            .or_default()
            .add(scan);
        if created >= now - 86400 {
            self.recent.add(scan);
        } else {
            self.reference.add(scan);
        }
        self.saturation += usize::from(crate::detection_diagnostics::breakdown(scan).saturated);
        let label = match risk {
            Some("spam") => Some((true, true)),
            Some("legitimate") => Some((false, true)),
            Some("uncertain") => None,
            Some(_) => {
                self.invalid_labels += 1;
                None
            }
            None => match feedback {
                Some(0) => Some((false, false)),
                Some(1) => Some((true, false)),
                None => None,
                _ => {
                    self.invalid_labels += 1;
                    None
                }
            },
        };
        if let Some((spam, quality)) = label {
            if spam {
                if quality {
                    self.quality_misses.add(scan);
                } else {
                    self.targeted_misses.add(scan);
                }
            }
            if quality {
                self.quality.add(outcome(scan), spam);
            } else {
                self.targeted.add(outcome(scan), spam);
            }
        } else {
            self.unlabelled += 1;
        }
        let current = scan
            .evidence
            .as_ref()
            .and_then(|e| e.artifacts.compatibility_hash())
            == Some(crate::compatibility::DETECTOR_BUILD_SHA256);
        self.compatible_observations += usize::from(current);
        if current && created >= now - 86400 {
            self.current_recent.add(scan);
        }
        if let Some(q) = &scan.quality {
            self.current_protocol +=
                usize::from(q.protocol_sha256 == crate::quality::protocol_hash());
            if crate::compatibility::valid_hash(&q.artifacts_sha256)
                && (self.cohorts.contains_key(&q.artifacts_sha256) || self.cohorts.len() < 128)
            {
                let cohort = self.cohorts.entry(q.artifacts_sha256.clone()).or_default();
                cohort.messages += 1;
                cohort.complete += usize::from(q.complete_features);
                cohort.native += usize::from(scan.native_filter.is_some());
                cohort.risk_labels += usize::from(label.is_some_and(|(_, quality)| quality));
                cohort.targeted_labels += usize::from(label.is_some_and(|(_, quality)| !quality));
                cohort.current_build = current;
                cohort.first_seen = if cohort.first_seen == 0 {
                    created
                } else {
                    cohort.first_seen.min(created)
                };
                cohort.last_seen = cohort.last_seen.max(created);
                if let Some(e) = &scan.evidence {
                    cohort
                        .versions
                        .insert(e.artifacts.application.chars().take(100).collect());
                }
                if let (Some((spam, _)), Some(p)) = (
                    label,
                    q.prediction
                        .as_ref()
                        .filter(|p| p.observation_only && q.candidate_status == "complete"),
                ) {
                    let key = format!(
                        "{}:{}",
                        q.artifacts_sha256,
                        p.model.chars().take(100).collect::<String>()
                    );
                    if self.comparisons.contains_key(&key) || self.comparisons.len() < 128 {
                        let pair = self.comparisons.entry(key).or_default();
                        pair.0.add(outcome(scan), spam);
                        pair.1.add(
                            match p.risk.as_str() {
                                "spam" => Outcome::Unwanted,
                                "legitimate" => Outcome::Legitimate,
                                _ => Outcome::Undetermined,
                            },
                            spam,
                        );
                    }
                }
            } else {
                self.missing_cohorts += 1;
            }
        } else {
            self.missing_cohorts += 1;
        }
        let mut ids = BTreeSet::new();
        let mut weights = BTreeMap::<String, f64>::new();
        for r in scan
            .reasons
            .iter()
            .take(256)
            .filter(|r| safe_symbol(&r.id) && r.weight.is_finite() && r.weight != 0.0)
        {
            *weights.entry(r.id.clone()).or_default() += r.weight;
        }
        for (id, weight) in weights.into_iter().take(64) {
            let key = format!("legacy:{id}");
            if !self.symbols.contains_key(&key) && self.symbols.len() >= 512 {
                continue;
            }
            let row = self.symbols.entry(key.clone()).or_default();
            row.source = "legacy".into();
            add_symbol(row, label, outcome(scan), weight);
            ids.insert(key);
            if let Some(without) = without_weight(scan, &id) {
                row.replayed += 1;
                row.frozen_decision_changes += usize::from(without != outcome(scan));
                if let Some((spam, _)) = label {
                    row.false_positives_avoided += usize::from(
                        !spam && outcome(scan) == Outcome::Unwanted && without != Outcome::Unwanted,
                    );
                    row.detected_spam_lost += usize::from(
                        spam && outcome(scan) == Outcome::Unwanted && without != Outcome::Unwanted,
                    );
                }
            } else {
                self.historical_replays_unavailable += 1;
            }
        }
        if let Some(n) = scan
            .native_filter
            .as_ref()
            .filter(|n| n.report.status == crate::native_filter::Status::Complete)
            && let Some(score) = &n.report.score
        {
            for symbol in score
                .symbols
                .iter()
                .take(64)
                .filter(|s| safe_symbol(&s.id) && s.weight.is_finite())
            {
                let key = format!("native:{}", symbol.id);
                if !self.symbols.contains_key(&key) && self.symbols.len() >= 512 {
                    continue;
                }
                let row = self.symbols.entry(key.clone()).or_default();
                row.source = "native_observation".into();
                add_symbol(row, label, outcome(scan), symbol.weight);
                row.absorbed += usize::from(!symbol.absorbed_by.is_empty());
                ids.insert(key);
            }
        }
        let ids: Vec<_> = ids.into_iter().take(64).collect();
        for (i, a) in ids.iter().enumerate() {
            for b in ids.iter().skip(i + 1) {
                let key = (a.clone(), b.clone());
                if self.pairs.contains_key(&key) || self.pairs.len() < 2048 {
                    *self.pairs.entry(key).or_default() += 1;
                }
            }
        }
    }
    fn report(mut self, options: &Options, now: i64, truncated: bool) -> Value {
        self.all.finish();
        self.recent.finish();
        self.current_recent.finish();
        self.reference.finish();
        for day in self.days.values_mut() {
            day.finish();
        }
        let mut alerts = vec![];
        if truncated {
            alerts.push(json!({"code":"limited_history","level":"notice","detail":"Le bilan est partiel ; les tests de changement de distribution sont désactivés."}));
        }
        if self.quality.tp
            + self.quality.fp
            + self.quality.tn
            + self.quality.missed
            + self.quality.spam_review
            + self.quality.legitimate_review
            < 100
        {
            alerts.push(json!({"code":"insufficient_labels","level":"notice","detail":"Les annotations restent insuffisantes pour valider la qualité du filtre."}));
        }
        if self.invalid_scans > 0 {
            alerts.push(json!({"code":"invalid_observations","level":"warning","detail":"Certaines observations conservées ne peuvent pas être interprétées."}));
        }
        if !truncated
            && self.invalid_scans == 0
            && self.recent.messages >= 30
            && self.reference.messages >= 30
        {
            for (name, new, old) in [
                ("spam_rate_shift", self.recent.spam, self.reference.spam),
                (
                    "incomplete_rate_shift",
                    self.recent.incomplete,
                    self.reference.incomplete,
                ),
            ] {
                let p = new as f64 / self.recent.messages as f64;
                let q = old as f64 / self.reference.messages as f64;
                let low = interval(new, self.recent.messages).unwrap()["lower"]
                    .as_f64()
                    .unwrap();
                let high = interval(old, self.reference.messages).unwrap()["upper"]
                    .as_f64()
                    .unwrap();
                if p - q >= 0.15 && low > high {
                    alerts.push(json!({"code":name,"level":"warning","detail":"Hausse à examiner : campagne réelle, évolution du trafic ou dégradation possible. Aucune désactivation automatique."}));
                }
            }
        }
        for (name, states) in &self.recent.detector_status {
            let unavailable: usize = [
                "unavailable",
                "busy",
                "quota",
                "stale",
                "limited",
                "unscannable",
            ]
            .iter()
            .map(|s| states.get(*s).copied().unwrap_or(0))
            .sum();
            let total: usize = states
                .iter()
                .filter(|(k, _)| k.as_str() != "disabled")
                .map(|(_, n)| n)
                .sum();
            if unavailable >= 3 && unavailable * 10 >= total {
                alerts.push(json!({"code":"detector_degraded","detector":name,"level":"warning","detail":"Contrôles incomplets ou indisponibles récurrents ; examiner le service et ses quotas."}));
            }
        }
        let mut pairs: Vec<_> = self
            .pairs
            .into_iter()
            .map(|((a, b), hits)| json!({"a":a,"b":b,"hits":hits}))
            .collect();
        pairs.sort_by_key(|v| std::cmp::Reverse(v["hits"].as_u64().unwrap_or(0)));
        pairs.truncate(30);
        let comparisons:Vec<_>=self.comparisons.into_iter().map(|(id,(baseline,candidate))|json!({"cohort_model":id,"baseline":baseline.report(),"candidate":candidate.report()})).collect();
        json!({"schema":"noisefence-reliability-1","version":env!("CARGO_PKG_VERSION"),"checked_at":now,"since":now-i64::from(options.days)*86400,
            "scope":{"domain":options.domain,"days":options.days},"status":if truncated {"limited"} else {"complete"},
            "observations":self.all,"last_24h":self.recent,"reference":self.reference,"days":self.days,
            "current_build_last_24h":self.current_recent,"missed_diagnostics":{"quality":self.quality_misses,"targeted":self.targeted_misses},
            "cohorts":self.cohorts,"current_build_observations":self.compatible_observations,"current_protocol_observations":self.current_protocol,
            "missing_cohorts":self.missing_cohorts,"quality_labels":self.quality.report(),"targeted_feedback":self.targeted.report(),
            "unlabelled":self.unlabelled,"invalid_labels":self.invalid_labels,"invalid_scans":self.invalid_scans,"saturated_scores":self.saturation,
            "symbols":self.symbols,"cooccurrences":pairs,"historical_replays_unavailable":self.historical_replays_unavailable,
            "candidate_comparisons":comparisons,"alerts":alerts,"may_activate":false,"affects_delivery":false,
            "limitations":["Les annotations et corrections peuvent être sélectionnées ; aucune estimation du trafic sans échantillon indépendant représentatif.",
                "Les retraits de poids rejouent des observations historiques figées : ils ne simulent pas de nouveaux appels LLM, les actions par destinataire ou le dossier Proton.",
                "Les symboles natifs sont consultatifs. Leurs correspondances et cooccurrences ne prouvent ni causalité ni indépendance.",
                "Les comparaisons portent uniquement sur les prédictions candidates enregistrées et annotées ; leur couverture et leur sélection restent à évaluer."]})
    }
}
fn add_symbol(row: &mut Symbol, label: Option<(bool, bool)>, actual: Outcome, weight: f64) {
    row.hits += 1;
    row.raw_weight_sum += weight;
    if let Some((spam, _)) = label {
        row.labelled_spam += usize::from(spam);
        row.labelled_legitimate += usize::from(!spam);
        row.spam_decision_on_legitimate += usize::from(!spam && actual == Outcome::Unwanted);
    }
}

pub async fn audit(store: &Store, username: String, options: Options) -> Result<Value> {
    options.validate()?;
    store.read(move |db| {
        let now=crate::now();let since=now-i64::from(options.days)*86400;
        let active:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM users WHERE username=?1 AND disabled=0)",[&username],|r|r.get(0))?;
        ensure!(active,"active account required");
        let mut q=db.prepare("SELECT m.created,m.scan,l.risk,f.spam FROM messages m
            LEFT JOIN quality_labels l ON l.message_id=m.id AND l.username=?1 AND l.created>=m.created AND l.created<=?3
            LEFT JOIN feedback f ON f.message_id=m.id AND f.username=?1 AND f.created>=m.created AND f.created<=?3
            WHERE m.is_dsn=0 AND m.created>=?2 AND m.created<=?3 AND EXISTS(
              SELECT 1 FROM deliveries d JOIN console_access a ON a.delivery_id=d.id
              WHERE d.message_id=m.id AND a.username=?1 AND (?4='' OR lower(substr(d.destination,instr(d.destination,'@')+1))=?4 OR lower(substr(d.address,instr(d.address,'@')+1))=?4))
            ORDER BY m.created DESC,m.id LIMIT 5001")?;
        let mut rows=q.query(params![username,since,now,options.domain])?;
        let started=Instant::now();let mut bytes=0;let mut count=0;let mut truncated=false;let mut result=Accumulator::default();
        while let Some(row)=rows.next()? {
            if count==MAX_ROWS || started.elapsed()>Duration::from_secs(2) {truncated=true;break;}
            let raw:String=row.get(1)?;bytes+=raw.len();count+=1;
            if bytes>MAX_BYTES {truncated=true;break;}
            if raw.len()>512*1024 {result.invalid_scans+=1;continue;}
            let scan:Scan=match serde_json::from_str(&raw){Ok(s)=>s,Err(_)=>{result.invalid_scans+=1;continue;}};
            let risk:Option<String>=row.get(2)?;
            result.add(&scan,row.get(0)?,risk.as_deref(),row.get(3)?,now);
        }
        Ok(result.report(&options,now,truncated))
    }).await
}
