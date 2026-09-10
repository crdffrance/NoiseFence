//! Offline manifest-based feature export, without network or production state.
use anyhow::{Result, ensure};
use serde::Deserialize;
use std::{
    fs::File,
    io::{BufRead, BufReader, BufWriter, Write},
    path::{Path, PathBuf},
};

/// Export optional detector observations on an explicitly authorized development
/// manifest. Reserved external-test records are excluded BEFORE opening their
/// paths. No Engine, DNS resolver, model, cloud client, or production store opens.
pub fn export_detectors(
    config: &crate::config::Config,
    manifest: &Path,
    root: &Path,
    output: &Path,
    limit: usize,
) -> Result<serde_json::Value> {
    use std::{
        collections::HashSet, fs::OpenOptions, io::Read, os::unix::fs::OpenOptionsExt,
        time::Instant,
    };
    ensure!(
        (1..=100_000).contains(&limit),
        "invalid detector export limit"
    );
    ensure!(
        config.heuristics.is_some() || config.content_inspection.is_some(),
        "configure at least one local research detector"
    );
    let runtime = crate::research_engines::Runtime::new(config)?;
    let root = root.canonicalize()?;
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    struct Partial(PathBuf);
    impl Drop for Partial {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let partial = Partial(parent.join(format!(".detectors-{}.partial", uuid::Uuid::new_v4())));
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&partial.0)?;
    let mut out = BufWriter::new(file);
    writeln!(
        out,
        "{}",
        serde_json::json!({"type":"header","schema":"noisefence-detectors-1",
        "application":env!("CARGO_PKG_VERSION"),"purpose":"development_observations",
        "external_test_opened":false,"contains_bodies":false,
        "heuristics_sha256":config.heuristics.as_ref().map(|s| crate::message::digest(serde_json::to_string(s).unwrap().as_bytes())),
        "content_settings":config.content_inspection})
    )?;
    let mut reader = BufReader::new(File::open(manifest)?);
    let mut line = Vec::new();
    let mut seen = HashSet::new();
    let (mut considered, mut exported, mut reserved, mut large, mut duplicates) = (0, 0, 0, 0, 0);
    let mut timings = Vec::new();
    loop {
        line.clear();
        if reader.by_ref().take(16_385).read_until(b'\n', &mut line)? == 0 {
            break;
        }
        ensure!(line.len() <= 16_384, "detector manifest line too large");
        considered += 1;
        ensure!(
            considered <= limit,
            "detector manifest exceeds explicit row limit"
        );
        let record: Record = serde_json::from_slice(&line)?;
        if record.external_test {
            reserved += 1;
            continue;
        }
        ensure!(
            !record.source.is_empty()
                && record.source.len() <= 100
                && record
                    .source
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
            "invalid corpus source identifier"
        );
        let path = root.join(&record.path).canonicalize()?;
        ensure!(path.starts_with(&root), "manifest path escapes corpus root");
        ensure!(
            std::fs::metadata(&path)?.is_file(),
            "corpus entry must be a regular file"
        );
        let mut raw = Vec::new();
        File::open(&path)?
            .take(config.filter.max_analysis_bytes as u64 + 1)
            .read_to_end(&mut raw)?;
        if raw.len() > config.filter.max_analysis_bytes {
            large += 1;
            continue;
        }
        let hash = crate::message::digest(&raw);
        if !seen.insert(hash.clone()) {
            duplicates += 1;
            continue;
        }
        let started = Instant::now();
        let report = runtime.offline(&raw);
        let elapsed_us = started.elapsed().as_micros() as u64;
        timings.push(elapsed_us);
        let campaign = crate::features::campaign_text(&raw);
        writeln!(
            out,
            "{}",
            serde_json::json!({"type":"row","source":record.source,
            "spam":record.spam,"year":record.year,"raw_sha256":hash,
            "campaign":campaign.as_ref().map(|c| crate::message::digest(c.as_bytes())),
            "simhash":campaign.as_deref().map(crate::features::simhash),
            "elapsed_us":elapsed_us,"execution":report.execution,
            "heuristics":report.heuristics,"content_inspection":report.content})
        )?;
        exported += 1;
    }
    timings.sort_unstable();
    let result = serde_json::json!({"considered":considered,"exported":exported,
        "reserved_test_excluded":reserved,"oversize":large,"exact_duplicates":duplicates,
        "p95_us":(!timings.is_empty()).then(||timings[((timings.len()-1)*95)/100]),
        "scope":"local optional detectors; excludes base extraction, DNS, history, sandbox, queue and model loading",
        "independent_quality_evaluation":false});
    writeln!(
        out,
        "{}",
        serde_json::json!({"type":"footer","report":result})
    )?;
    out.flush()?;
    out.get_ref().sync_all()?;
    std::fs::hard_link(&partial.0, output)?;
    std::fs::remove_file(&partial.0)?;
    File::open(parent)?.sync_all()?;
    Ok(result)
}

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
