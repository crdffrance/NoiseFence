//! Private export and chronological, campaign-separated evaluation, all in Rust.
use super::{
    bayes::{Example, Model},
    input::{Features, similarity},
};
use anyhow::{Result, ensure};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs::{File, OpenOptions},
    io::Write,
    path::Path,
};

fn private_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}
fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    let mut file = private_file(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}
#[derive(Default, Serialize)]
pub struct ExportReport {
    pub exported: usize,
    pub missing_features: usize,
    pub incompatible_features: usize,
    pub conflicting_labels: usize,
    pub incomplete: usize,
}
pub async fn export(
    store: &crate::store::Store,
    username: String,
    scope: String,
    output: &Path,
) -> Result<ExportReport> {
    ensure!(
        crate::config::valid_domain(&scope) && scope == scope.to_ascii_lowercase(),
        "invalid native export domain"
    );
    let (rows,report)=store.read(move |db| {
        let admin:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM users WHERE username=?1 AND admin=1 AND disabled=0)",[&username],|r|r.get(0))?;
        ensure!(admin,"native domain model export requires an enabled administrator");
        let now=crate::now();
        let mut query=db.prepare("SELECT m.id,m.created,m.scan,MIN(f.spam),MAX(f.spam),MAX(f.created)
          FROM messages m JOIN feedback f ON f.message_id=m.id JOIN users u ON u.username=f.username
          WHERE m.created>=?1 AND m.created<?2 AND m.is_dsn=0 AND f.created>=?1 AND f.created<?2 AND u.disabled=0
          AND EXISTS(SELECT 1 FROM deliveries d JOIN console_access a ON a.delivery_id=d.id
            WHERE d.message_id=m.id AND a.username=f.username AND lower(substr(d.destination,instr(d.destination,'@')+1))=?3)
          AND EXISTS(SELECT 1 FROM deliveries d JOIN console_access a ON a.delivery_id=d.id
            WHERE d.message_id=m.id AND a.username=?4 AND lower(substr(d.destination,instr(d.destination,'@')+1))=?3)
          GROUP BY m.id ORDER BY m.created,m.id LIMIT 50001")?;
        let mut rows=Vec::new();let mut report=ExportReport::default();
        for (index,row) in query.query_map(params![now-30*86400,now,scope,username],|r|Ok((r.get::<_,String>(0)?,r.get::<_,i64>(1)?,r.get::<_,String>(2)?,r.get::<_,i64>(3)?,r.get::<_,i64>(4)?,r.get::<_,i64>(5)?)))?.enumerate() {
            ensure!(index<50_000,"native export exceeds 50000 messages");
            let (id,observed_at,scan,min,max,labelled_at)=row?;
            ensure!((0..=1).contains(&min) && (0..=1).contains(&max),"invalid native human label");
            if min!=max {report.conflicting_labels+=1;continue;}
            let scan:crate::engine::Scan=serde_json::from_str(&scan)?;
            let Some(observation)=scan.native_filter else {report.missing_features+=1;continue;};
            if observation.report.status!=super::Status::Complete {report.incomplete+=1;continue;}
            let Some(features)=observation.features else {report.missing_features+=1;continue;};
            if features.protocol!=super::input::PROTOCOL {report.incompatible_features+=1;continue;}
            let row=Example {scope:scope.clone(),id:crate::message::digest(id.as_bytes()),observed_at,labelled_at,spam:min==1,features};row.validate()?;
            rows.push(row);report.exported+=1;
        }
        Ok((rows,report))
    }).await?;
    let mut file = private_file(output)?;
    for row in rows {
        serde_json::to_writer(&mut file, &row)?;
        file.write_all(b"\n")?;
    }
    file.sync_all()?;
    Ok(report)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Metrics {
    pub ham: usize,
    pub spam: usize,
    pub true_positive: usize,
    pub false_positive: usize,
    pub unavailable: usize,
    pub recall: f64,
    pub false_positive_rate: f64,
    pub precision: Option<f64>,
    pub recall_ci95: [f64; 2],
    pub false_positive_rate_ci95: [f64; 2],
}
fn wilson(success: usize, total: usize) -> [f64; 2] {
    if total == 0 {
        return [0.0, 1.0];
    }
    let n = total as f64;
    let p = success as f64 / n;
    let z = 1.959963984540054;
    let den = 1.0 + z * z / n;
    let center = (p + z * z / (2.0 * n)) / den;
    let margin = z * ((p * (1.0 - p) + z * z / (4.0 * n)) / n).sqrt() / den;
    [(center - margin).max(0.0), (center + margin).min(1.0)]
}
fn metrics(model: &Model, rows: &[Example], threshold: f64) -> Metrics {
    let mut m = Metrics {
        ham: 0,
        spam: 0,
        true_positive: 0,
        false_positive: 0,
        unavailable: 0,
        recall: 0.0,
        false_positive_rate: 0.0,
        precision: None,
        recall_ci95: [0.0, 1.0],
        false_positive_rate_ci95: [0.0, 1.0],
    };
    for row in rows {
        let prediction = model.predict(
            &row.features,
            std::slice::from_ref(&row.scope),
            model.created,
        );
        let positive = prediction.raw_log_odds.is_some_and(|s| s >= threshold);
        m.unavailable += usize::from(prediction.raw_log_odds.is_none());
        if row.spam {
            m.spam += 1;
            m.true_positive += usize::from(positive);
        } else {
            m.ham += 1;
            m.false_positive += usize::from(positive);
        }
    }
    m.recall = m.true_positive as f64 / m.spam.max(1) as f64;
    m.false_positive_rate = m.false_positive as f64 / m.ham.max(1) as f64;
    if m.true_positive + m.false_positive > 0 {
        m.precision = Some(m.true_positive as f64 / (m.true_positive + m.false_positive) as f64);
    }
    m.recall_ci95 = wilson(m.true_positive, m.spam);
    m.false_positive_rate_ci95 = wilson(m.false_positive, m.ham);
    m
}

#[derive(Serialize, Deserialize)]
pub struct Manifest {
    pub protocol: String,
    pub dataset_sha256: String,
    pub seen_campaigns: Vec<Features>,
}
#[derive(Serialize)]
pub struct TrainingReport {
    pub schema: &'static str,
    pub dataset_sha256: String,
    pub model_sha256: String,
    pub manifest_sha256: String,
    pub train_until: i64,
    pub validation_until: i64,
    pub train: usize,
    pub excluded_boundary: usize,
    pub excluded_conflict: usize,
    pub duplicates: usize,
    pub threshold: f64,
    pub validation: Metrics,
    pub test: Metrics,
    pub may_activate: bool,
    pub limitation: &'static str,
}

// MinHash LSH buckets only propose candidates; actual similarity is checked.
// Exact duplicate campaigns are collapsed first to bound large repeated sends.
pub(crate) fn groups(rows: &[Example]) -> Result<Vec<Vec<usize>>> {
    let mut exact: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    for (index, row) in rows.iter().enumerate() {
        exact
            .entry(&row.features.fingerprint)
            .or_default()
            .push(index);
    }
    let unique: Vec<_> = exact.into_values().collect();
    let mut parent: Vec<_> = (0..unique.len()).collect();
    fn root(parent: &[usize], mut i: usize) -> usize {
        while parent[i] != i {
            i = parent[i];
        }
        i
    }
    let mut buckets: HashMap<(usize, Vec<u64>), Vec<usize>> = HashMap::new();
    let mut comparisons = 0usize;
    for (index, group) in unique.iter().enumerate() {
        let features = &rows[group[0]].features;
        let mut candidates = BTreeSet::new();
        if features.text_shingles >= 24 {
            for (band, hashes) in features.text.chunks(4).enumerate() {
                let bucket = buckets.entry((band, hashes.to_vec())).or_default();
                candidates.extend(bucket.iter().copied());
                bucket.push(index);
            }
        }
        for candidate in candidates {
            comparisons += 1;
            ensure!(
                comparisons <= 1_000_000,
                "native campaign comparison budget exceeded"
            );
            if similarity(&features.text, &rows[unique[candidate][0]].features.text)
                .is_some_and(|s| s >= 0.875)
            {
                let a = root(&parent, index);
                let b = root(&parent, candidate);
                parent[a.max(b)] = a.min(b);
            }
        }
    }
    let mut result: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (index, group) in unique.into_iter().enumerate() {
        result
            .entry(root(&parent, index))
            .or_default()
            .extend(group);
    }
    Ok(result.into_values().collect())
}

pub fn train(
    input: &Path,
    output: &Path,
    version: &str,
    train_until: i64,
    validation_until: i64,
) -> Result<TrainingReport> {
    ensure!(
        !output.exists() && train_until > 0 && validation_until > train_until,
        "invalid native output or chronological boundaries"
    );
    let (rows, dataset_sha256) = super::bayes::read_examples(input)?;
    ensure!(
        !rows.is_empty() && rows.iter().all(|r| r.scope == rows[0].scope),
        "native training needs one domain"
    );
    let mut unique_ids = BTreeSet::new();
    ensure!(
        rows.iter().all(|r| unique_ids.insert(&r.id)),
        "duplicate native example id"
    );
    let mut splits: [Vec<Example>; 3] = Default::default();
    let mut boundary = 0;
    let mut conflict = 0;
    let mut duplicates = 0;
    let period = |t| {
        if t < train_until {
            0
        } else if t < validation_until {
            1
        } else {
            2
        }
    };
    for group in groups(&rows)? {
        let first = &rows[group[0]];
        if group.iter().any(|&i| rows[i].spam != first.spam) {
            conflict += group.len();
            continue;
        }
        if group
            .iter()
            .any(|&i| period(rows[i].observed_at) != period(first.observed_at))
        {
            boundary += group.len();
            continue;
        }
        let index = *group
            .iter()
            .min_by_key(|&&i| (rows[i].observed_at, &rows[i].id))
            .unwrap();
        // Simulated historical fitting may only use labels available then.
        let cutoff = match period(first.observed_at) {
            0 => train_until,
            1 => validation_until,
            _ => i64::MAX,
        };
        if rows[index].labelled_at >= cutoff {
            boundary += group.len();
            continue;
        }
        duplicates += group.len() - 1;
        splits[period(first.observed_at)].push(rows[index].clone());
    }
    for split in &splits {
        ensure!(
            split.len() >= 12
                && split.iter().filter(|r| r.spam).count() >= 2
                && split.iter().filter(|r| !r.spam).count() >= 2,
            "each native period needs 12 independent campaigns and at least two examples per class"
        );
    }
    let model = Model::fit(&splits[0], version, dataset_sha256.clone())?;
    let mut scores: Vec<(f64, bool)> = splits[1]
        .iter()
        .filter_map(|r| {
            model
                .predict(&r.features, std::slice::from_ref(&r.scope), model.created)
                .raw_log_odds
                .map(|s| (s, r.spam))
        })
        .collect();
    scores.sort_by(|a, b| b.0.total_cmp(&a.0));
    // Select using validation alone, allowing zero validation positives. Report
    // the independent test and uncertainty without an automatic activation gate.
    let mut threshold = 601.0;
    let mut positives = 0usize;
    let mut false_positives = 0usize;
    let mut best = 0usize;
    let mut index = 0;
    let ham = splits[1].iter().filter(|r| !r.spam).count();
    while index < scores.len() {
        let value = scores[index].0;
        while index < scores.len() && scores[index].0 == value {
            positives += usize::from(scores[index].1);
            false_positives += usize::from(!scores[index].1);
            index += 1;
        }
        if false_positives as f64 / ham as f64 <= 0.001 && positives > best {
            best = positives;
            threshold = value;
        }
    }
    let model_bytes = serde_json::to_vec_pretty(&model)?;
    let manifest = Manifest {
        protocol: super::input::PROTOCOL.into(),
        dataset_sha256: dataset_sha256.clone(),
        seen_campaigns: rows
            .iter()
            .map(|r| {
                let mut f = r.features.clone();
                f.osb.clear();
                f
            })
            .collect(),
    };
    let report = TrainingReport {
        schema: "noisefence-osb-evaluation-1",
        dataset_sha256,
        model_sha256: crate::message::digest(&model_bytes),
        manifest_sha256: crate::message::digest(&serde_json::to_vec_pretty(&manifest)?),
        train_until,
        validation_until,
        train: splits[0].len(),
        excluded_boundary: boundary,
        excluded_conflict: conflict,
        duplicates,
        threshold,
        validation: metrics(&model, &splits[1], threshold),
        test: metrics(&model, &splits[2], threshold),
        may_activate: false,
        limitation: "Observation only. Small or historical samples do not demonstrate production recall or false-positive rate. OSB scores are not calibrated probabilities.",
    };
    std::fs::create_dir(output)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(output, std::fs::Permissions::from_mode(0o700))?;
    }
    write_json(&output.join("model.json"), &model)?;
    write_json(&output.join("manifest.json"), &manifest)?;
    write_json(&output.join("report.json"), &report)?;
    Ok(report)
}

#[derive(Serialize)]
pub struct EvaluationReport {
    pub schema: &'static str,
    pub independent: bool,
    pub known_campaigns: usize,
    pub excluded: usize,
    pub metrics: Metrics,
    pub may_activate: bool,
}
pub fn evaluate(
    input: &Path,
    model_path: &Path,
    manifest_path: &Path,
    training_report: &Path,
    output: &Path,
) -> Result<EvaluationReport> {
    let (model, model_hash) = Model::load(model_path)?;
    let report: serde_json::Value =
        serde_json::from_slice(&super::read_bounded(training_report, 1024 * 1024)?)?;
    let manifest_bytes = super::read_bounded(manifest_path, 64 * 1024 * 1024)?;
    ensure!(
        report["schema"] == "noisefence-osb-evaluation-1"
            && report["model_sha256"] == model_hash
            && report["manifest_sha256"] == crate::message::digest(&manifest_bytes),
        "native evaluation artifact mismatch"
    );
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)?;
    ensure!(
        manifest.protocol == super::input::PROTOCOL
            && manifest.dataset_sha256 == model.training_sha256,
        "native history protocol mismatch"
    );
    let threshold = report["threshold"]
        .as_f64()
        .filter(|n| n.is_finite())
        .ok_or_else(|| anyhow::anyhow!("invalid native threshold"))?;
    let (rows, _) = super::bayes::read_examples(input)?;
    ensure!(
        rows.iter().all(|r| r.scope == model.scope),
        "native evaluation scope mismatch"
    );
    let mut accepted = Vec::new();
    let mut known = 0;
    let mut excluded = 0;
    let mut comparisons = 0usize;
    ensure!(
        manifest.seen_campaigns.len() <= 50_000,
        "native history size limit"
    );
    let mut exact = BTreeSet::new();
    let mut buckets: HashMap<(usize, Vec<u64>), Vec<usize>> = HashMap::new();
    for (index, old) in manifest.seen_campaigns.iter().enumerate() {
        old.validate()?;
        exact.insert(&old.fingerprint);
        if old.text_shingles >= 24 {
            for (band, hashes) in old.text.chunks(4).enumerate() {
                buckets
                    .entry((band, hashes.to_vec()))
                    .or_default()
                    .push(index);
            }
        }
    }
    for group in groups(&rows)? {
        let first = &rows[group[0]];
        if group.len() > 1
            || group.iter().any(|&i| {
                rows[i].observed_at <= model.created || rows[i].observed_at >= model.expires
            })
        {
            excluded += group.len();
            continue;
        }
        let mut overlap = exact.contains(&first.features.fingerprint);
        let mut candidates = BTreeSet::new();
        if !overlap && first.features.text_shingles >= 24 {
            for (band, hashes) in first.features.text.chunks(4).enumerate() {
                if let Some(indices) = buckets.get(&(band, hashes.to_vec())) {
                    candidates.extend(indices);
                }
            }
        }
        for &index in candidates {
            let old = &manifest.seen_campaigns[index];
            comparisons += 1;
            ensure!(
                comparisons <= 1_000_000,
                "native independent comparison budget exceeded"
            );
            if similarity(&old.text, &first.features.text).is_some_and(|s| s >= 0.875) {
                overlap = true;
                break;
            }
        }
        if overlap {
            known += 1;
        } else {
            accepted.push(first.clone());
        }
    }
    let metrics = metrics(&model, &accepted, threshold);
    let result = EvaluationReport {
        schema: "noisefence-osb-independent-1",
        independent: known == 0
            && excluded == 0
            && metrics.unavailable == 0
            && metrics.ham > 0
            && metrics.spam > 0,
        known_campaigns: known,
        excluded,
        metrics,
        may_activate: false,
    };
    write_json(output, &result)?;
    Ok(result)
}
