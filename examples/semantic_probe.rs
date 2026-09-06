//! Native parity/latency probe. Local JSONL texts only; no delivery or network.
use anyhow::{Result, ensure};
use clap::Parser;
use std::{
    io::{BufRead, Write},
    path::PathBuf,
    time::Instant,
};

#[derive(Parser)]
struct Args {
    #[arg(long)]
    encoder: PathBuf,
    #[arg(long)]
    input: PathBuf,
    #[arg(long)]
    output: PathBuf,
    #[arg(long, default_value_t = 1)]
    iterations: usize,
}
fn main() -> Result<()> {
    let args = Args::parse();
    ensure!((1..=1000).contains(&args.iterations), "invalid iterations");
    let start = Instant::now();
    let encoder = noisefence::semantic::Encoder::load(&args.encoder)?;
    eprintln!("model loaded in {} ms", start.elapsed().as_millis());
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut out = std::io::BufWriter::new(options.open(&args.output)?);
    for line in std::io::BufReader::new(std::fs::File::open(&args.input)?).lines() {
        let row: serde_json::Value = serde_json::from_str(&line?)?;
        let subject = row["subject"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("missing subject"))?;
        let body = row["body"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("missing body"))?;
        let mut timings = Vec::new();
        let mut tokens = Vec::new();
        let mut vector = Vec::new();
        for _ in 0..args.iterations {
            let start = Instant::now();
            (tokens, vector) = encoder.embed(subject, body)?;
            timings.push(start.elapsed().as_micros() as u64);
        }
        timings.sort_unstable();
        writeln!(
            out,
            "{}",
            serde_json::json!({"raw_sha256":row["raw_sha256"],
            "tokens":tokens,"vector":vector,"iterations":args.iterations,
            "p50_us":timings[args.iterations/2],
            "p95_us":timings[(args.iterations*95/100).min(args.iterations-1)]})
        )?;
    }
    out.flush()?;
    out.get_ref().sync_all()?;
    Ok(())
}
