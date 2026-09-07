//! Offline manifest-based feature export, without network or production state.
use anyhow::{Result, ensure};
use serde::Deserialize;
use std::{
    fs::File,
    io::{BufRead, BufReader, BufWriter, Write},
    path::{Path, PathBuf},
};

#[derive(Deserialize)]
struct Record {
    path: PathBuf,
    spam: bool,
    source: String,
    #[serde(default)]
    external_test: bool,
    year: Option<u32>,
}

pub fn benchmark(
    model: &Path,
    message: &Path,
    iterations: usize,
    semantic: Option<&crate::config::SemanticFilter>,
) -> Result<serde_json::Value> {
    ensure!(
        (1..=10_000).contains(&iterations),
        "invalid benchmark iterations"
    );
    let loaded_model = crate::engine::Model::load(model)?;
    ensure!(
        semantic.is_none() || loaded_model.feature_version == crate::features::VERSION,
        "semantic benchmark requires lexical feature schema 3"
    );
    #[cfg(feature = "semantic")]
    let semantic_model = semantic
        .map(|config| crate::semantic::Hybrid::load(config, model, 95.0))
        .transpose()?;
    #[cfg(not(feature = "semantic"))]
    ensure!(
        semantic.is_none(),
        "semantic support is not compiled in this binary"
    );
    let model = loaded_model;
    let version = model.version.as_str();
    #[cfg(feature = "semantic")]
    let version = semantic_model
        .as_ref()
        .map_or(version, |semantic| semantic.version());
    let bytes = std::fs::read(message)?;
    ensure!(
        bytes.len() <= 1024 * 1024,
        "benchmark message must be <=1 MiB"
    );
    let mut timings = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let started = std::time::Instant::now();
        let scan = if model.feature_version == crate::features::VERSION {
            crate::features::extract(&bytes, 2 * 1024 * 1024)
        } else {
            crate::engine::extract(&bytes, 2 * 1024 * 1024)
        };
        ensure!(scan.complete, "incomplete benchmark extraction");
        let logit = model.logit(&scan.features);
        #[cfg(feature = "semantic")]
        let logit = if let Some(semantic) = &semantic_model {
            let result = semantic.offline(&bytes);
            ensure!(
                result.status == crate::engine::SemanticStatus::Complete,
                "semantic benchmark incomplete"
            );
            logit + result.contribution.unwrap()
        } else {
            logit
        };
        std::hint::black_box(logit);
        timings.push(started.elapsed().as_micros() as u64);
    }
    timings.sort_unstable();
    Ok(
        serde_json::json!({"model":version,"feature_version":model.feature_version,"semantic_enabled":semantic.is_some(),
        "iterations":iterations,"bytes":bytes.len(),"os":std::env::consts::OS,"arch":std::env::consts::ARCH,
        "p50_us":timings[iterations/2],"p95_us":timings[(iterations*95/100).min(iterations-1)],
        "p99_us":timings[(iterations*99/100).min(iterations-1)],
        "scope":"native MIME/text features plus fitted model; excludes DNS, scanners, LLM, queue and model loading"}),
    )
}

pub fn export(
    manifest: &Path,
    root: &Path,
    output: &Path,
    version: u32,
) -> Result<serde_json::Value> {
    ensure!(
        version == 1 || version == crate::features::VERSION,
        "unsupported feature schema"
    );
    let root = root.canonicalize()?;
    let mut writer = BufWriter::new(File::create(output)?);
    let mut exported = 0usize;
    let mut skipped = 0usize;
    for line in BufReader::new(File::open(manifest)?).lines() {
        let record: Record = serde_json::from_str(&line?)?;
        let path = root.join(&record.path).canonicalize()?;
        ensure!(path.starts_with(&root), "manifest path escapes corpus root");
        if std::fs::metadata(&path)?.len() > 2 * 1024 * 1024 {
            skipped += 1;
            continue;
        }
        let raw = std::fs::read(&path)?;
        let scan = if version == crate::features::VERSION {
            crate::features::extract(&raw, 2 * 1024 * 1024)
        } else {
            crate::engine::extract(&raw, 2 * 1024 * 1024)
        };
        let campaign = crate::features::campaign_text(&raw).unwrap_or_default();
        if !scan.complete || scan.features.is_empty() || campaign.len() < 20 {
            skipped += 1;
            continue;
        }
        writeln!(
            writer,
            "{}",
            serde_json::json!({
                "feature_version":version, "spam":record.spam, "source":record.source,
                "external_test":record.external_test, "year":record.year,
                "fingerprint":scan.fingerprint, "campaign":crate::message::digest(campaign.as_bytes()),
                "simhash":crate::features::simhash(&campaign), "features":scan.features,
                "raw_sha256":crate::message::digest(&raw), "rule_logit":scan.reasons.iter().map(|r| r.weight).sum::<f64>()
            })
        )?;
        exported += 1;
        if exported.is_multiple_of(1000) {
            eprintln!("exported {exported} messages");
        }
    }
    writer.flush()?;
    writer.get_ref().sync_all()?;
    Ok(serde_json::json!({"exported":exported,"skipped":skipped,"feature_version":version}))
}
