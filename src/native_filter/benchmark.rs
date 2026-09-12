//! Local performance probe. No database, DNS, API, SMTP delivery or learning.
use super::{Runtime, Settings, Status, input, rules};
use anyhow::{Result, ensure};
use serde::Serialize;
use std::{path::Path, sync::Arc, time::Instant};

#[derive(Serialize)]
pub struct Report {
    pub version: &'static str,
    pub schema: &'static str,
    pub arch: &'static str,
    pub available_cpus: usize,
    pub bytes: usize,
    pub messages: usize,
    pub concurrency: usize,
    pub unavailable: usize,
    pub elapsed_ms: f64,
    pub messages_per_second: f64,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub patterns: usize,
    pub regex_set_ms: f64,
    pub individual_regex_ms: f64,
    pub identical_matches: bool,
    pub includes: &'static str,
    pub excludes: &'static str,
}
pub async fn run(path: &Path, iterations: usize, concurrency: usize) -> Result<Report> {
    ensure!(
        (1..=10_000).contains(&iterations) && (1..=8).contains(&concurrency),
        "invalid native benchmark limits"
    );
    let raw = Arc::new(super::read_bounded(path, 2 * 1024 * 1024)?);
    let settings = Settings {
        max_parallel: concurrency,
        max_bytes: 2 * 1024 * 1024,
        timeout_ms: 1000,
        fuzzy_memory: false,
        ..Default::default()
    };
    let runtime = Runtime::new(settings)?;
    // Warm up compilation, regex caches and MIME extraction before measurement.
    ensure!(
        runtime.inspect(&raw, &[]).await.report.status == Status::Complete,
        "native benchmark fixture cannot be analyzed"
    );
    let started = Instant::now();
    let mut tasks = tokio::task::JoinSet::new();
    for worker in 0..concurrency {
        let runtime = runtime.clone();
        let raw = raw.clone();
        tasks.spawn(async move {
            let mut times = Vec::new();
            let mut unavailable = 0;
            for _ in (worker..iterations).step_by(concurrency) {
                let started = Instant::now();
                let mut observation = runtime.inspect(&raw, &[]).await;
                runtime.finish(&mut observation, &crate::engine::Scan::default());
                unavailable += usize::from(observation.report.status != Status::Complete);
                times.push(started.elapsed().as_secs_f64() * 1000.);
            }
            (times, unavailable)
        });
    }
    let mut times = Vec::new();
    let mut unavailable = 0;
    while let Some(result) = tasks.join_next().await {
        let (part, failures) = result?;
        times.extend(part);
        unavailable += failures;
    }
    let elapsed_ms = started.elapsed().as_secs_f64() * 1000.;
    times.sort_by(f64::total_cmp);
    let percentile = |p: f64| times[((times.len() - 1) as f64 * p).ceil() as usize];
    let input = input::extract(&raw, 2 * 1024 * 1024)?;
    // A 128-pattern bank exercises the workload the batched matcher targets.
    let mut patterns = rules::default_patterns();
    for i in patterns.len()..128 {
        patterns.push(rules::Pattern {
            exclude_negated: false,
            id: format!("BENCH_{i}"),
            label: "Benchmark literal".into(),
            family: rules::Family::Content,
            weight: 0.,
            target: rules::Target::Body,
            pattern: format!(r"\bbenchmarkword{i}\b"),
        });
    }
    let matcher = rules::Matcher::compile(&patterns)?;
    let individual: Vec<_> = patterns
        .iter()
        .map(|p| regex::Regex::new(&p.pattern))
        .collect::<std::result::Result<_, _>>()?;
    let matched: std::collections::BTreeSet<_> =
        matcher.inspect(&input).into_iter().map(|r| r.id).collect();
    let baseline: std::collections::BTreeSet<_> = patterns
        .iter()
        .zip(&individual)
        .filter(|(p, r)| {
            r.is_match(match p.target {
                rules::Target::Subject => &input.subject,
                rules::Target::Body => &input.body,
                rules::Target::Html => &input.html,
            })
        })
        .map(|(p, _)| p.id.clone())
        .collect();
    ensure!(matched == baseline, "native regex benchmark parity failure");
    let loops = iterations.min(1000);
    let start = Instant::now();
    for _ in 0..loops {
        std::hint::black_box(matcher.inspect(&input));
    }
    let regex_set_ms = start.elapsed().as_secs_f64() * 1000.;
    let start = Instant::now();
    for _ in 0..loops {
        for (p, r) in patterns.iter().zip(&individual) {
            std::hint::black_box(r.is_match(match p.target {
                rules::Target::Subject => &input.subject,
                rules::Target::Body => &input.body,
                rules::Target::Html => &input.html,
            }));
        }
    }
    let individual_regex_ms = start.elapsed().as_secs_f64() * 1000.;
    Ok(Report {
        version: env!("CARGO_PKG_VERSION"),
        schema: "noisefence-native-benchmark-1",
        arch: std::env::consts::ARCH,
        available_cpus: std::thread::available_parallelism()?.get(),
        bytes: raw.len(),
        messages: times.len(),
        concurrency,
        unavailable,
        elapsed_ms,
        messages_per_second: times.len() as f64 * 1000. / elapsed_ms,
        p50_ms: percentile(0.5),
        p95_ms: percentile(0.95),
        p99_ms: percentile(0.99),
        patterns: patterns.len(),
        regex_set_ms,
        individual_regex_ms,
        identical_matches: true,
        includes: "MIME normalization, OSB features, text/HTML sketches, patterns, structured HTML/MIME rules, composites and caps",
        excludes: "Trained Bayes inference, fuzzy database, historical engine, SMTP, disk persistence, OCR, DNS and external services",
    })
}
