//! Offline training only. Explicit labels, chronological folds and campaign exclusion.
use super::{
    Class, SCHEMA, WIDTH,
    data::{Example, write_json},
    model::{Model, Neural},
};
use anyhow::{Result, ensure};
use rand::{Rng, SeedableRng, seq::SliceRandom};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

pub(crate) fn counts(rows: &[Example]) -> [u32; 5] {
    let mut n = [0; 5];
    for r in rows {
        n[r.class.index()] += 1;
    }
    n
}
fn binary(rows: &[Example]) -> Vec<crate::native_filter::bayes::Example> {
    rows.iter()
        .map(|r| crate::native_filter::bayes::Example {
            scope: r.scope.clone(),
            id: r.id.clone(),
            observed_at: r.observed_at,
            labelled_at: r.labelled_at,
            spam: matches!(r.class, Class::Spam | Class::Phishing | Class::Scam),
            features: r.features.clone(),
        })
        .collect()
}
pub(crate) fn split(
    rows: &[Example],
    train_until: i64,
    validation_until: i64,
) -> Result<([Vec<Example>; 3], usize)> {
    ensure!(
        train_until > 0 && validation_until > train_until && validation_until < crate::now(),
        "invalid adaptive temporal boundaries"
    );
    ensure!(
        !rows.is_empty() && rows.len() <= 5000,
        "invalid adaptive training size"
    );
    let mut ids = BTreeSet::new();
    for row in rows {
        row.validate()?;
        ensure!(
            row.scope == rows[0].scope
                && row.protocol_sha256 == rows[0].protocol_sha256
                && ids.insert(&row.id),
            "mixed adaptive scopes/protocols or duplicate ids"
        );
    }
    let fold = |t| {
        if t < train_until {
            0
        } else if t < validation_until {
            1
        } else {
            2
        }
    };
    let mut splits: [Vec<Example>; 3] = Default::default();
    let mut excluded = 0;
    for group in crate::native_filter::learning::groups(&binary(rows))? {
        let first = &rows[*group
            .iter()
            .min_by_key(|&&i| (rows[i].observed_at, &rows[i].id))
            .unwrap()];
        let f = fold(first.observed_at);
        let cutoff = [train_until, validation_until, i64::MAX][f];
        if group.iter().any(|&i| {
            rows[i].class != first.class
                || fold(rows[i].observed_at) != f
                || rows[i].labelled_at >= cutoff
        }) {
            excluded += group.len();
            continue;
        }
        splits[f].push(first.clone());
        excluded += group.len() - 1;
    }
    for (i, rows) in splits.iter().enumerate() {
        let minimum = if i == 0 { 20 } else { 5 };
        ensure!(
            counts(rows).iter().all(|&n| n >= minimum),
            "adaptive training requires 20 independent campaigns per class in training and 5 per class in validation and test, with labels known before each cutoff"
        );
    }
    Ok((splits, excluded))
}
fn loss(model: &Neural, rows: &[Example]) -> f64 {
    let n = counts(rows);
    rows.iter()
        .map(|r| {
            -model.forward(&r.vector).1[r.class.index()].max(1e-12).ln() / n[r.class.index()] as f64
        })
        .sum::<f64>()
        / 5.0
}
pub(crate) fn fit_neural(train: &[Example], validation: &[Example]) -> (Neural, usize) {
    let mut rng = rand::rngs::StdRng::seed_from_u64(0x4e_46_01);
    let mut model = Neural {
        input_weights: (0..WIDTH)
            .map(|_| (0..WIDTH).map(|_| rng.gen_range(-0.2..0.2)).collect())
            .collect(),
        hidden_bias: vec![0.0; WIDTH],
        output_weights: (0..5)
            .map(|_| (0..WIDTH).map(|_| rng.gen_range(-0.2..0.2)).collect())
            .collect(),
        output_bias: vec![0.0; 5],
    };
    let n = counts(train);
    let mut best = model.clone();
    let mut best_loss = loss(&model, validation);
    let mut best_epoch = 0;
    let mut indices: Vec<_> = (0..train.len()).collect();
    // Bounded, deterministic SGD; balanced classes, L2 decay, validation early stopping.
    for epoch in 1..=120 {
        indices.shuffle(&mut rng);
        let rate = 0.025 / (1.0 + epoch as f64 / 60.0);
        for &i in &indices {
            let row = &train[i];
            let c = row.class.index();
            let (hidden, mut delta) = model.forward(&row.vector);
            delta[c] -= 1.0;
            let balance = (train.len() as f64 / (5.0 * n[c] as f64)).min(10.0);
            let dh: [f64; WIDTH] = std::array::from_fn(|h| {
                (0..5)
                    .map(|c| delta[c] * model.output_weights[c][h])
                    .sum::<f64>()
                    * (1.0 - hidden[h] * hidden[h])
            });
            for (c, d) in delta.iter().enumerate() {
                for (h, x) in hidden.iter().enumerate() {
                    let w = &mut model.output_weights[c][h];
                    *w = (*w - rate * (balance * d * x + 0.001 * (*w))).clamp(-8.0, 8.0);
                }
                model.output_bias[c] = (model.output_bias[c] - rate * balance * d).clamp(-8.0, 8.0);
            }
            for (h, d) in dh.iter().enumerate() {
                for (j, x) in row.vector.iter().enumerate() {
                    let w = &mut model.input_weights[h][j];
                    *w = (*w - rate * (balance * d * x + 0.001 * (*w))).clamp(-8.0, 8.0);
                }
                model.hidden_bias[h] = (model.hidden_bias[h] - rate * balance * d).clamp(-8.0, 8.0);
            }
        }
        let current = loss(&model, validation);
        if current < best_loss - 1e-5 {
            best = model.clone();
            best_loss = current;
            best_epoch = epoch;
        }
        if epoch - best_epoch >= 15 {
            break;
        }
    }
    (best, best_epoch)
}
pub(crate) fn fit(
    train: &[Example],
    validation: &[Example],
    version: &str,
    dataset: String,
) -> Result<(Model, usize)> {
    let mut tokens: BTreeMap<u32, [u32; 5]> = BTreeMap::new();
    for r in train {
        for id in &r.features.osb {
            tokens.entry(*id).or_default()[r.class.index()] += 1;
        }
    }
    let (neural, epoch) = fit_neural(train, validation);
    let mut model = Model {
        schema: SCHEMA.into(),
        protocol_sha256: train[0].protocol_sha256.clone(),
        version: version.into(),
        scope: train[0].scope.clone(),
        created: crate::now(),
        expires: crate::now() + 30 * 86400,
        dataset_sha256: dataset,
        classes: counts(train),
        counts: tokens
            .into_iter()
            .filter(|(_, n)| n.iter().sum::<u32>() >= 2)
            .collect(),
        neural,
        thresholds: [1.0; 5],
    };
    // Fixed grid chosen on validation only. A class with no convincing support
    // stays disabled. Normalized strengths are not calibrated probabilities.
    for class in 0..5 {
        for threshold in [0.9, 0.95, 0.975, 0.99, 0.995] {
            let mut tp = 0usize;
            let mut fp = 0usize;
            model.thresholds[class] = threshold;
            for r in validation {
                if let Some((b, n)) = model.predict(&r.features, &r.vector)
                    && model
                        .select(&b, &n, &BTreeMap::new())
                        .is_some_and(|c| c.index() == class)
                {
                    if r.class.index() == class {
                        tp += 1;
                    } else {
                        fp += 1;
                    }
                }
            }
            if tp >= 5 && fp == 0 {
                break;
            }
            model.thresholds[class] = 1.0;
        }
    }
    model.validate()?;
    Ok((model, epoch))
}
fn wilson(k: usize, n: usize) -> [f64; 2] {
    if n == 0 {
        return [0.0, 1.0];
    }
    let p = k as f64 / n as f64;
    let n = n as f64;
    let z = 1.959963984540054;
    let den = 1.0 + z * z / n;
    let center = (p + z * z / (2.0 * n)) / den;
    let margin = z * (p * (1.0 - p) / n + z * z / (4.0 * n * n)).sqrt() / den;
    [(center - margin).max(0.0), (center + margin).min(1.0)]
}
pub(crate) fn metrics(model: &Model, rows: &[Example]) -> Value {
    let mut matrix = [[0usize; 6]; 5];
    for r in rows {
        let p = model
            .predict(&r.features, &r.vector)
            .and_then(|(b, n)| model.select(&b, &n, &BTreeMap::new()))
            .map_or(5, Class::index);
        matrix[r.class.index()][p] += 1;
    }
    let good: usize = matrix[..2].iter().flatten().sum();
    let fp: usize = matrix[..2]
        .iter()
        .map(|r| r[2..5].iter().sum::<usize>())
        .sum();
    let bad: usize = matrix[2..].iter().flatten().sum();
    let tp: usize = matrix[2..]
        .iter()
        .map(|r| r[2..5].iter().sum::<usize>())
        .sum();
    let per_class:Vec<_>=(0..5).map(|c| {
        let support=matrix[c].iter().sum::<usize>();let selected=matrix.iter().map(|r|r[c]).sum::<usize>();
        json!({"class":super::CLASSES[c],"support":support,"recall":matrix[c][c] as f64/support.max(1) as f64,
            "recall_ci95":wilson(matrix[c][c],support),"precision":(selected>0).then(||matrix[c][c] as f64/selected as f64)})
    }).collect();
    json!({"classes":super::CLASSES,"columns":["legitimate","publicity","spam","phishing","scam","abstained"],"confusion":matrix,"per_class":per_class,
        "benign":good,"threats":bad,"false_positives":fp,"true_positives":tp,
        "recall":tp as f64/bad.max(1) as f64,"recall_ci95":wilson(tp,bad),
        "false_positive_rate":fp as f64/good.max(1) as f64,"false_positive_rate_ci95":wilson(fp,good),
        "precision":(tp+fp>0).then(||tp as f64/(tp+fp) as f64)})
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    scope: String,
    protocol_sha256: String,
    dataset_sha256: String,
    model_sha256: String,
    evaluated_until: i64,
    seen: Vec<crate::native_filter::input::Features>,
}
pub fn train(
    input: &Path,
    output: &Path,
    version: &str,
    train_until: i64,
    validation_until: i64,
) -> Result<Value> {
    ensure!(!output.exists(), "adaptive output already exists");
    let (rows, sha) = super::data::read(input)?;
    let (folds, excluded) = split(&rows, train_until, validation_until)?;
    let (model, epoch) = fit(&folds[0], &folds[1], version, sha.clone())?;
    let model_bytes = serde_json::to_vec_pretty(&model)?;
    ensure!(
        model_bytes.len() <= super::model::MAX_BYTES,
        "adaptive model exceeds capacity"
    );
    let model_sha = crate::message::digest(&model_bytes);
    let manifest = Manifest {
        schema: SCHEMA.into(),
        scope: model.scope.clone(),
        protocol_sha256: model.protocol_sha256.clone(),
        dataset_sha256: sha.clone(),
        model_sha256: model_sha.clone(),
        evaluated_until: rows
            .iter()
            .map(|r| r.observed_at.max(r.labelled_at))
            .max()
            .unwrap(),
        seen: rows
            .iter()
            .map(|r| {
                let mut f = r.features.clone();
                f.osb.clear();
                f
            })
            .collect(),
    };
    let report = json!({"schema":SCHEMA,"dataset_sha256":sha,"model_sha256":model_sha,
        "manifest_sha256":crate::message::digest(&serde_json::to_vec_pretty(&manifest)?),"train_until":train_until,"validation_until":validation_until,
        "fold_classes":folds.each_ref().map(|f|counts(f)),"excluded":excluded,"neural_selected_epoch":epoch,
        "validation":metrics(&model,&folds[1]),"test":metrics(&model,&folds[2]),"calibrated":false,"may_activate":false,"observation_only":true});
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(output)?;
    write_json(&output.join("model.json"), &model)?;
    write_json(&output.join("manifest.json"), &manifest)?;
    write_json(&output.join("report.json"), &report)?;
    std::fs::File::open(output)?.sync_all()?;
    Ok(report)
}
pub fn evaluate(
    input: &Path,
    model_path: &Path,
    manifest_path: &Path,
    report_path: &Path,
    output: &Path,
) -> Result<Value> {
    let (model, model_sha) = Model::load(model_path)?;
    let bytes = crate::native_filter::read_bounded(manifest_path, 8 * 1024 * 1024)?;
    let manifest: Manifest = serde_json::from_slice(&bytes)?;
    let report: Value = serde_json::from_slice(&crate::native_filter::read_bounded(
        report_path,
        128 * 1024,
    )?)?;
    ensure!(
        manifest.schema == SCHEMA
            && manifest.scope == model.scope
            && manifest.protocol_sha256 == model.protocol_sha256
            && manifest.model_sha256 == model_sha
            && report["model_sha256"] == model_sha
            && report["dataset_sha256"] == manifest.dataset_sha256
            && manifest.dataset_sha256 == model.dataset_sha256
            && report["manifest_sha256"] == crate::message::digest(&bytes)
            && (1..=5000).contains(&manifest.seen.len()),
        "invalid adaptive frozen evaluation provenance"
    );
    for f in &manifest.seen {
        f.validate()?;
    }
    let (rows, dataset_sha) = super::data::read(input)?;
    let mut ids = BTreeSet::new();
    ensure!(
        rows.iter().all(|r| r.scope == model.scope
            && r.protocol_sha256 == model.protocol_sha256
            && r.observed_at > manifest.evaluated_until
            && ids.insert(&r.id)),
        "evaluation requires later independent messages in the same domain/protocol"
    );
    let mut joined = binary(&rows);
    for (i, f) in manifest.seen.iter().enumerate() {
        joined.push(crate::native_filter::bayes::Example {
            scope: model.scope.clone(),
            id: format!("seen-{i}"),
            observed_at: 1,
            labelled_at: 1,
            spam: false,
            features: f.clone(),
        });
    }
    let mut independent = Vec::new();
    let mut excluded = 0;
    for group in crate::native_filter::learning::groups(&joined)? {
        let current: Vec<_> = group.iter().filter(|&&i| i < rows.len()).copied().collect();
        if current.is_empty() {
            continue;
        }
        if group.len() != current.len()
            || current
                .iter()
                .any(|&i| rows[i].class != rows[current[0]].class)
        {
            excluded += current.len();
            continue;
        }
        let i = *current
            .iter()
            .min_by_key(|&&i| (rows[i].observed_at, &rows[i].id))
            .unwrap();
        independent.push(rows[i].clone());
        excluded += current.len() - 1;
    }
    ensure!(
        !independent.is_empty(),
        "no independent adaptive evaluation campaigns"
    );
    let result = json!({"schema":SCHEMA,"model_sha256":model_sha,"dataset_sha256":dataset_sha,"evaluated":independent.len(),"excluded":excluded,
        "metrics":metrics(&model,&independent),"may_activate":false,"observation_only":true});
    write_json(output, &result)?;
    Ok(result)
}
