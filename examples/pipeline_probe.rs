//! Repeat the configured analysis in one process with warm caches, without SMTP delivery.
//! This measures controlled cases, not production traffic quality or SMTP throughput.
use anyhow::{Context, Result, ensure};
use clap::Parser;
use noisefence::{config::Config, engine::Engine, message};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashSet},
    fs::{File, OpenOptions},
    io::{Read, Write},
    net::IpAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

#[derive(Parser)]
struct Args {
    #[arg(long)]
    config: PathBuf,
    /// JSON array of explicit local cases and their SMTP authentication context.
    #[arg(long)]
    cases: PathBuf,
    #[arg(long)]
    output: PathBuf,
    #[arg(long, default_value_t = 30)]
    iterations: usize,
    #[arg(long, default_value_t = 3)]
    warmup: usize,
    #[arg(long, default_value_t = 100)]
    interval_ms: u64,
    /// Permit configured paid text analysis, charged to the configured shared ledger.
    #[arg(long)]
    allow_paid_llm: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    path: PathBuf,
    source_ip: IpAddr,
    helo: String,
    mail_from: String,
}

fn bounded_read(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let file = File::open(path)?;
    ensure!(file.metadata()?.is_file(), "expected a regular input file");
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "input exceeds benchmark size limit");
    Ok(bytes)
}

fn quantiles(mut timings: Vec<u64>) -> Value {
    if timings.is_empty() {
        return Value::Null;
    }
    timings.sort_unstable();
    let at = |percent: usize| timings[(timings.len() * percent).div_ceil(100) - 1];
    json!({"samples":timings.len(), "p50_us":at(50), "p95_us":at(95),
        "max_us":timings.last(), "method":"nearest rank"})
}

#[tokio::main(worker_threads = 4)]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    let args = Args::parse();
    ensure!(
        (1..=100).contains(&args.iterations),
        "iterations must be 1..100"
    );
    ensure!((1..=5).contains(&args.warmup), "warmup must be 1..5");
    ensure!(args.interval_ms <= 5000, "interval must be at most 5000 ms");
    let config = Arc::new(Config::load(&args.config)?);
    let paid = config
        .llm
        .as_ref()
        .is_some_and(|c| c.monthly_budget_micro_eur > 0);
    ensure!(
        !paid || args.allow_paid_llm,
        "configured paid text analysis requires --allow-paid-llm; it uses the configured shared budget"
    );
    let cases: Vec<Case> = serde_json::from_slice(&bounded_read(&args.cases, 65_536)?)?;
    ensure!(
        (1..=8).contains(&cases.len()),
        "expected 1..8 explicit cases"
    );
    let mut names = HashSet::new();
    let mut inputs = Vec::new();
    for case in &cases {
        ensure!(
            !case.id.is_empty()
                && case.id.len() <= 64
                && case
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
                && names.insert(&case.id),
            "invalid or duplicate case identifier"
        );
        ensure!(
            noisefence::config::valid_domain(&case.helo)
                && noisefence::config::valid_address(&case.mail_from),
            "invalid explicit SMTP context"
        );
        let path = args
            .cases
            .parent()
            .unwrap_or(Path::new("."))
            .join(&case.path);
        let raw = bounded_read(&path, 1_048_576)?;
        message::validate(&raw).context("invalid benchmark email")?;
        inputs.push(raw);
    }
    // Refuse an existing/unwritable destination before loading models or making paid calls.
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut output = options.open(&args.output)?;
    let load_started = Instant::now();
    let engine = Engine::new(config.clone())?;
    let load_us = load_started.elapsed().as_micros() as u64;
    writeln!(
        output,
        "{}",
        json!({"record":"configuration", "version":env!("CARGO_PKG_VERSION"),
        "engine_load_us":load_us, "iterations":args.iterations, "warmup":args.warmup,
        "concurrency":1, "tokio_workers":4, "interval_ms":args.interval_ms, "authentication":config.filter.authentication,
        "antivirus":config.antivirus.is_some(), "signatures":config.signatures.is_some(),
        "smtp_policy":config.smtp_policy.is_some(), "semantic":config.filter.semantic.is_some(), "reputation":config.filter.spamhaus_key_env.is_some(),
        "paid_llm":paid, "arc_sealing":config.filter.arc_key.is_some(), "sent":false,
        "scope":"controlled full Engine::process calls; excludes model loading, file reading, SMTP, durable queue, relay and inter-call intervals",
        "not_a_production_quality_or_latency_claim":true})
    )?;
    output.sync_all()?;
    let mut summaries = Vec::new();
    for (case, raw) in cases.iter().zip(&inputs) {
        let mut elapsed = Vec::new();
        let mut completed_elapsed = Vec::new();
        let mut complete = 0;
        let mut errors = 0;
        let mut statuses: BTreeMap<String, usize> = BTreeMap::new();
        for iteration in 0..args.warmup + args.iterations {
            let warmup = iteration < args.warmup;
            let started = Instant::now();
            let result = engine
                .process(
                    raw,
                    case.source_ip,
                    &case.helo,
                    &case.mail_from,
                    &uuid::Uuid::new_v4().to_string(),
                )
                .await;
            let elapsed_us = started.elapsed().as_micros() as u64;
            let details = match result {
                Ok((scan, rewritten)) => {
                    drop(rewritten);
                    if !warmup && scan.complete {
                        complete += 1;
                        completed_elapsed.push(elapsed_us);
                    }
                    if !warmup {
                        for (name, value) in [
                            ("smtp_policy", json!(scan.smtp_policy.status)),
                            ("semantic", json!(scan.semantic.status)),
                            ("antivirus", json!(scan.antivirus.status)),
                            ("signatures", json!(scan.signatures.status)),
                            ("llm", json!(scan.llm.status)),
                        ] {
                            *statuses
                                .entry(format!("{name}:{}", value.as_str().unwrap_or("unknown")))
                                .or_default() += 1;
                        }
                    }
                    json!({"complete":scan.complete, "score":scan.score, "model":scan.model,
                        "feature_version":scan.feature_version, "features_complete":scan.features_complete,
                        "engine_elapsed_ms":scan.elapsed_ms, "semantic_ms":scan.semantic.elapsed_ms,
                        "antivirus_ms":scan.antivirus.elapsed_ms, "signatures_ms":scan.signatures.elapsed_ms,
                        "smtp_policy_ms":scan.smtp_policy.elapsed_ms, "smtp_policy_status":scan.smtp_policy.status,
                        "llm_ms":scan.llm.elapsed_ms, "semantic_status":scan.semantic.status,
                        "antivirus_status":scan.antivirus.status, "signatures_status":scan.signatures.status,
                        "llm_status":scan.llm.status,
                        "reason_ids":scan.reasons.iter().map(|r| &r.id).collect::<Vec<_>>()})
                }
                Err(_) => {
                    if !warmup {
                        errors += 1;
                    }
                    json!({"complete":false,"error":"processing_failed"})
                }
            };
            writeln!(
                output,
                "{}",
                json!({"record":"trial","case":case.id,"warmup":warmup,"iteration":iteration,"elapsed_us":elapsed_us,"analysis":details})
            )?;
            if !warmup {
                elapsed.push(elapsed_us);
            }
            tokio::time::sleep(Duration::from_millis(args.interval_ms)).await;
        }
        summaries.push(
            json!({"case":case.id,"message_bytes":raw.len(),"message_sha256":message::digest(raw),
            "all_trials":quantiles(elapsed),"complete_trials_only":quantiles(completed_elapsed),
            "complete":complete,"incomplete":args.iterations-complete-errors,"errors":errors,
            "statuses":statuses}),
        );
    }
    let summary = json!({"record":"summary","run_finished":true,"cases":summaries,"sent":false,
        "all_trials_include_failures":true, "feature_vectors_and_content_saved":false});
    writeln!(output, "{summary}")?;
    output.sync_all()?;
    println!("{summary}");
    Ok(())
}
