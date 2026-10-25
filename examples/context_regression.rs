//! Offline, digest-bound replay of private recorded scans. No provider calls.
//! Input: JSONL {id, scan}; originals: <id>.eml. Output contains no mail text.
use anyhow::{Context, Result, ensure};
use std::{
    fs::File,
    io::{BufRead, BufReader, Read},
    path::PathBuf,
};
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().collect();
    ensure!(
        args.len() == 3,
        "usage: context_regression observations.jsonl originals-directory"
    );
    let mut input = BufReader::new(File::open(&args[1])?);
    let originals = PathBuf::from(&args[2]);
    loop {
        let mut line = String::new();
        if input
            .by_ref()
            .take(8 * 1024 * 1024 + 1)
            .read_line(&mut line)?
            == 0
        {
            break;
        }
        ensure!(
            line.len() <= 8 * 1024 * 1024,
            "Recorded row exceeds size limit"
        );
        let row: serde_json::Value = serde_json::from_str(&line)?;
        let id = row["id"].as_str().context("Missing message ID")?;
        ensure!(
            uuid::Uuid::parse_str(id)?.to_string() == id,
            "Noncanonical message ID"
        );
        let result = (|| -> Result<_> {
            let scan: noisefence::engine::Scan = serde_json::from_value(row["scan"].clone())?;
            let path = originals.join(format!("{id}.eml"));
            let file = File::open(path).context("Original unavailable")?;
            ensure!(
                file.metadata()?.is_file(),
                "Original must be a regular file"
            );
            let mut raw = Vec::new();
            file.take(2 * 1024 * 1024 + 1).read_to_end(&mut raw)?;
            noisefence::decision::replay::compare(&raw, &scan)
        })();
        println!(
            "{}",
            match result {
                Ok(report) => serde_json::json!({"id":id,"status":"complete","report":report}),
                Err(error) =>
                    serde_json::json!({"id":id,"status":"unavailable","error":error.to_string()}),
            }
        );
    }
    Ok(())
}
