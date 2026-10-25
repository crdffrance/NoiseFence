//! Local-only diagnostic. Never delivers mail, fetches URLs, contacts an IdP or
//! trusts authentication headers from an imported original.
use anyhow::{Result, ensure};
use clap::Parser;
use noisefence::identity::{
    detection,
    directory::{Catalog, MAX_BYTES, Snapshot},
    relationships::Request,
};
use std::{
    collections::BTreeSet,
    io::Read,
    path::{Path, PathBuf},
};

#[derive(Parser)]
struct Args {
    #[arg(long)]
    directory: PathBuf,
    #[arg(long)]
    message: PathBuf,
    #[arg(long)]
    recipient: String,
    /// Fixed evaluation time for a synthetic fixture; never changes stored dates.
    #[arg(long)]
    at: Option<i64>,
}
fn read(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= maximum, "Diagnostic input exceeds limit");
    Ok(bytes)
}
fn main() -> Result<()> {
    let args = Args::parse();
    let at = args.at.unwrap_or_else(noisefence::now);
    let snapshot = Snapshot::decode(&read(&args.directory, MAX_BYTES)?, at)?;
    let directory = Catalog::new(vec![snapshot], at)?;
    let raw = read(&args.message, 2 * 1024 * 1024)?;
    // No invented authentication, labels, relationship history or demand signal.
    // Live native detectors will supply those when pipeline wiring is completed.
    let report = detection::inspect(
        &directory,
        &raw,
        &[args.recipient],
        None,
        &BTreeSet::<Request>::new(),
        None,
        at,
    );
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
