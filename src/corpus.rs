use crate::{
    engine::{FEATURE_COUNT, Model, Scan, extract, sigmoid},
    message, now,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    fs::{self, File},
    io::{BufRead, BufReader, Write},
    path::Path,
};
#[derive(Clone, Serialize, Deserialize)]
pub struct Example {
    pub spam: bool,
    pub fingerprint: String,
    pub features: Vec<(usize, f64)>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metrics {
    pub ham: usize,
    pub spam: usize,
    pub true_positive: usize,
    pub false_positive: usize,
    pub recall: f64,
    pub precision: f64,
    pub false_positive_rate: f64,
    pub recall_ci95: [f64; 2],
    pub fpr_ci95: [f64; 2],
}
#[derive(Serialize, Deserialize)]
pub struct Report {
    pub model_sha256: String,
    pub corpus_sha256: String,
    pub created: i64,
    pub threshold: f64,
    pub split: String,
    pub train: usize,
    pub validation: Metrics,
    pub test: Metrics,
    pub eligible: bool,
    pub limitation: String,
}
fn wilson(k: usize, n: usize) -> [f64; 2] {
    if n == 0 {
        return [0.0, 1.0];
    }
    let n = n as f64;
    let p = k as f64 / n;
    let z = 1.959963984540054;
    let denom = 1.0 + z * z / n;
    let center = (p + z * z / (2.0 * n)) / denom;
    let half = z * ((p * (1.0 - p) + z * z / (4.0 * n)) / n).sqrt() / denom;
    [(center - half).max(0.0), (center + half).min(1.0)]
}
pub fn evaluate(model: &Model, examples: &[Example], threshold: f64) -> Metrics {
    let mut m = Metrics {
        ham: 0,
        spam: 0,
        true_positive: 0,
        false_positive: 0,
        recall: 0.0,
        precision: 0.0,
        false_positive_rate: 0.0,
        recall_ci95: [0.0, 1.0],
        fpr_ci95: [0.0, 1.0],
    };
    for e in examples {
        let predicted = sigmoid(model.logit(&e.features)) * 100.0 >= threshold;
        if e.spam {
            m.spam += 1;
            if predicted {
                m.true_positive += 1;
            }
        } else {
            m.ham += 1;
            if predicted {
                m.false_positive += 1;
            }
        }
    }
    m.recall = m.true_positive as f64 / m.spam.max(1) as f64;
    m.precision = m.true_positive as f64 / (m.true_positive + m.false_positive).max(1) as f64;
    m.false_positive_rate = m.false_positive as f64 / m.ham.max(1) as f64;
    m.recall_ci95 = wilson(m.true_positive, m.spam);
    m.fpr_ci95 = wilson(m.false_positive, m.ham);
    m
}
pub fn load_examples(path: &Path) -> Result<Vec<Example>> {
    let mut examples = Vec::new();
    let mut labels = BTreeMap::new();
    for line in BufReader::new(File::open(path)?).lines() {
        let e: Example = serde_json::from_str(&line?)?;
        ensure!(
            e.fingerprint.len() == 64
                && e.fingerprint.bytes().all(|b| b.is_ascii_hexdigit())
                && e.features.len() <= FEATURE_COUNT
                && e.features
                    .iter()
                    .all(|(i, x)| *i < FEATURE_COUNT && x.is_finite() && x.abs() <= 1.0),
            "invalid corpus features"
        );
        if let Some(label) = labels.insert(e.fingerprint.clone(), e.spam) {
            ensure!(
                label == e.spam,
                "conflicting labels for campaign {}",
                e.fingerprint
            );
            continue;
        }
        examples.push(e);
    }
    Ok(examples)
}
pub fn import(ham: &Path, spam: &Path, output: &Path) -> Result<usize> {
    let mut file = File::create(output)?;
    let mut count = 0;
    let mut seen = HashSet::new();
    for (dir, label) in [(ham, false), (spam, true)] {
        for entry in fs::read_dir(dir)? {
            let path = entry?.path();
            if !path.is_file() || fs::metadata(&path)?.len() > 2 * 1024 * 1024 {
                continue;
            }
            let bytes = fs::read(path)?;
            let normalized = String::from_utf8_lossy(&bytes)
                .replace("\r\n", "\n")
                .replace('\n', "\r\n");
            let scan = extract(normalized.as_bytes(), 2 * 1024 * 1024);
            if !scan.complete || scan.features.is_empty() || !seen.insert(scan.fingerprint.clone())
            {
                continue;
            }
            writeln!(
                file,
                "{}",
                serde_json::to_string(&Example {
                    spam: label,
                    fingerprint: scan.fingerprint,
                    features: scan.features
                })?
            )?;
            count += 1;
        }
    }
    file.sync_all()?;
    Ok(count)
}
pub fn train(input: &Path, output: &Path, threshold: f64) -> Result<Report> {
    ensure!(
        threshold.is_finite() && (0.0..=100.0).contains(&threshold),
        "invalid threshold"
    );
    let mut examples = load_examples(input)?;
    examples.sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));
    let mut train = Vec::new();
    let mut validation = Vec::new();
    let mut test = Vec::new();
    for e in examples {
        let group = u64::from_str_radix(&e.fingerprint[..8], 16)? % 10;
        match group {
            0 => test.push(e),
            1 => validation.push(e),
            _ => train.push(e),
        }
    }
    for (name, split) in [
        ("training", &train),
        ("validation", &validation),
        ("test", &test),
    ] {
        ensure!(
            split.iter().any(|e| e.spam) && split.iter().any(|e| !e.spam),
            "{name} split needs both classes"
        );
    }
    let mut model = Model {
        version: format!("lr-{}", now()),
        feature_version: 1,
        bias: 0.0,
        weights: vec![0.0; FEATURE_COUNT],
        idf: vec![1.0; FEATURE_COUNT],
        trained_at: now(),
        examples: train.len(),
    };
    let mut frequencies = vec![0usize; FEATURE_COUNT];
    for e in &train {
        for (i, _) in &e.features {
            frequencies[*i] += 1;
        }
    }
    for (idf, df) in model.idf.iter_mut().zip(frequencies) {
        *idf = ((train.len() + 1) as f64 / (df + 1) as f64).ln() + 1.0;
    }
    let matrix: Vec<Vec<(usize, f64)>> = train
        .iter()
        .map(|e| {
            let norm = e
                .features
                .iter()
                .map(|(i, x)| (x * model.idf[*i]).powi(2))
                .sum::<f64>()
                .sqrt()
                .max(1e-12);
            e.features
                .iter()
                .map(|(i, x)| (*i, x * model.idf[*i] / norm))
                .collect()
        })
        .collect();
    // IDF is fitted only on training data. Full-batch L2 logistic regression.
    for _ in 0..1000 {
        let mut gradient = vec![0.0; FEATURE_COUNT];
        let mut bias = 0.0;
        for (e, features) in train.iter().zip(&matrix) {
            let logit = model.bias
                + features
                    .iter()
                    .map(|(i, x)| model.weights[*i] * x)
                    .sum::<f64>();
            let error = sigmoid(logit) - if e.spam { 1.0 } else { 0.0 };
            bias += error;
            for (i, x) in features {
                gradient[*i] += error * x;
            }
        }
        let n = train.len() as f64;
        model.bias -= 4.0 * bias / n;
        for (w, g) in model.weights.iter_mut().zip(gradient) {
            *w -= 4.0 * (g / n + 0.00001 * *w);
        }
    }
    // Operating-point calibration uses validation ham only, never the test set.
    // Map its most permissive <=0.1% FPR cutoff to the configured suspicion index.
    let mut ham_logits: Vec<f64> = validation
        .iter()
        .filter(|e| !e.spam)
        .map(|e| model.logit(&e.features))
        .collect();
    ham_logits.sort_by(|a, b| b.total_cmp(a));
    let allowed = (ham_logits.len() as f64 * 0.001).floor() as usize;
    let cutoff = ham_logits[allowed.min(ham_logits.len() - 1)] + 0.02;
    let p = (threshold / 100.0).clamp(0.000001, 0.999999);
    model.bias += (p / (1.0 - p)).ln() - cutoff;
    let bytes = serde_json::to_vec(&model)?;
    fs::write(output, &bytes)?;
    let validation = evaluate(&model, &validation, threshold);
    let test = evaluate(&model, &test, threshold);
    let eligible = validation.recall >= 0.95
        && validation.false_positive_rate <= 0.001
        && test.recall >= 0.95
        && test.fpr_ci95[1] <= 0.001;
    let report=Report{model_sha256:message::digest(&bytes),corpus_sha256:message::digest(&fs::read(input)?),created:now(),threshold,split:"deterministic campaign-grouped 80/10/10; no temporal representativeness claim".into(),train:train.len(),validation,test,eligible,limitation:"Public historical data does not demonstrate current production capture. This evaluates text classification only; the full live pipeline needs separate recent validation.".into()};
    fs::write(
        format!("{}.report.json", output.display()),
        serde_json::to_vec_pretty(&report)?,
    )?;
    Ok(report)
}
pub fn activate(candidate: &Path, report: &Path, destination: &Path) -> Result<()> {
    Model::load(candidate)?;
    let bytes = fs::read(candidate)?;
    let report: Report = serde_json::from_slice(&fs::read(report)?)?;
    ensure!(
        message::digest(&bytes) == report.model_sha256
            && report.eligible
            && report.test.recall >= 0.95
            && report.test.fpr_ci95[1] <= 0.001,
        "model quality gate not met"
    );
    let temporary = destination.with_extension("tmp");
    let mut f = File::create(&temporary)?;
    f.write_all(&bytes)?;
    f.sync_all()?;
    fs::rename(&temporary, destination)?;
    File::open(destination.parent().unwrap_or(Path::new(".")))?.sync_all()?;
    Ok(())
}
pub async fn export_feedback(store: &crate::store::Store, output: &Path) -> Result<usize> {
    let rows=store.run(|db|{let mut q=db.prepare("SELECT m.scan,MIN(f.spam),MAX(f.spam) FROM messages m JOIN feedback f ON f.message_id=m.id GROUP BY m.id HAVING MIN(f.spam)=MAX(f.spam)")?;Ok(q.query_map([],|r|Ok((r.get::<_,String>(0)?,r.get::<_,bool>(1)?)))?.collect::<rusqlite::Result<Vec<_>>>()?)}).await?;
    let mut f = File::create(output)?;
    let mut count = 0;
    for (scan, spam) in rows {
        let scan: Scan = serde_json::from_str(&scan)?;
        if scan.complete && !scan.features.is_empty() {
            writeln!(
                f,
                "{}",
                serde_json::to_string(&Example {
                    spam,
                    fingerprint: scan.fingerprint,
                    features: scan.features
                })?
            )?;
            count += 1;
        }
    }
    f.sync_all()?;
    Ok(count)
}
pub fn benchmark(input: &Path, iterations: usize) -> Result<serde_json::Value> {
    ensure!(
        iterations > 0 && iterations <= 100_000,
        "invalid iterations"
    );
    let raw = fs::read(input)?;
    ensure!(
        raw.len() <= 1024 * 1024,
        "benchmark fixture must be <=1 MiB"
    );
    let mut timings = Vec::new();
    for _ in 0..iterations {
        let t = std::time::Instant::now();
        std::hint::black_box(extract(&raw, 2 * 1024 * 1024));
        timings.push(t.elapsed().as_micros() as u64);
    }
    timings.sort();
    Ok(
        serde_json::json!({"iterations":iterations,"bytes":raw.len(),"extraction_p50_us":timings[iterations/2],"extraction_p95_us":timings[(iterations*95/100).min(iterations-1)],"scope":"local feature extraction; excludes DNS, TLS, queue I/O and live delivery"}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn uncertainty_for_small_corpus() {
        assert!(wilson(0, 100)[1] > 0.001);
        assert!(wilson(0, 4000)[1] < 0.001);
    }
    #[test]
    fn metrics_defined_for_empty_corpus() {
        let m = Model {
            version: "test".into(),
            feature_version: 1,
            bias: 0.0,
            weights: vec![0.0; FEATURE_COUNT],
            idf: vec![],
            trained_at: 0,
            examples: 0,
        };
        let report = evaluate(&m, &[], 95.0);
        assert_eq!(report.fpr_ci95, [0.0, 1.0]);
    }
}
