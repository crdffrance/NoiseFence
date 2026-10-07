//! Read-only replay of recorded analysis JSONL. No network, model loading or delivery.
//! Inputs remain private; stdout contains aggregate counters only.
use anyhow::{Context, ensure};
use noisefence::{decision, engine::Scan, mailing};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{BufRead, BufReader},
};
fn main() -> anyhow::Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        args.len() == 2,
        "usage: decision_replay private-labelled-scans.jsonl"
    );
    let mut counts = BTreeMap::<String, usize>::new();
    for line in BufReader::new(File::open(&args[1])?).lines() {
        let line = line?;
        // psql transaction status lines are not data.
        if !line.starts_with('{') {
            continue;
        }
        ensure!(line.len() <= 8 * 1024 * 1024, "oversized snapshot");
        let row: serde_json::Value = serde_json::from_str(&line)?;
        let label = row["label"].as_str().context("missing human label")?;
        ensure!(
            ["spam", "legitimate"].contains(&label),
            "ambiguous or unsupported label"
        );
        let original: Scan = serde_json::from_value(row["scan"].clone())?;
        let threshold = noisefence::assessment::recorded_threshold(&original)
            .context("snapshot lacks receipt-time threshold")?;
        *counts
            .entry(format!(
                "recorded/{label}/{}",
                row["category"].as_str().context("missing category")?
            ))
            .or_default() += 1;
        for corroboration in [false, true] {
            let mut scan = original.clone();
            scan.recipient_decision = None;
            decision::apply(&mut scan, corroboration);
            decision::finalize(&mut scan, threshold);
            let category = serde_json::to_value(mailing::category(&scan, threshold))?;
            *counts
                .entry(format!(
                    "corroboration={corroboration}/{label}/{}",
                    category.as_str().unwrap()
                ))
                .or_default() += 1;
        }
    }
    println!("{}", serde_json::to_string_pretty(&counts)?);
    Ok(())
}
