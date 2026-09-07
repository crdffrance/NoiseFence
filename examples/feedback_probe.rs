//! Verify retained-vector predictions against the native model contract.
//! This is an offline parity probe, not a quality or encoder benchmark.
#[cfg(feature = "semantic")]
fn main() -> anyhow::Result<()> {
    use anyhow::{Context, ensure};
    use std::{
        fs,
        io::{BufRead, BufReader},
        path::Path,
    };
    let args: Vec<_> = std::env::args().collect();
    ensure!(
        args.len() == 4,
        "usage: feedback_probe model.json combination.json feedback.jsonl"
    );
    let model = noisefence::engine::Model::load(Path::new(&args[1]))?;
    let combination: noisefence::semantic::Combination =
        serde_json::from_slice(&fs::read(&args[2])?)?;
    combination.validate(&noisefence::message::digest(&fs::read(&args[1])?), 95.0)?;
    for line in BufReader::new(fs::File::open(&args[3])?).lines() {
        let row: serde_json::Value = serde_json::from_str(&line?)?;
        let features: Vec<(usize, f64)> = serde_json::from_value(row["features"].clone())?;
        let vector: Vec<f32> = serde_json::from_value(row["semantic"]["features"].clone())?;
        let protocol: noisefence::learning::SemanticProtocol =
            serde_json::from_value(row["semantic"]["protocol"].clone())?;
        ensure!(
            protocol == noisefence::learning::SemanticProtocol::pinned() && vector.len() == 384,
            "invalid protocol/vector"
        );
        let lexical = model.logit(&features);
        let semantic = vector
            .iter()
            .zip(&combination.head_weights)
            .map(|(x, w)| f64::from(*x) * w)
            .sum::<f64>()
            + combination.head_bias;
        println!(
            "{}",
            serde_json::json!({"id":row["id"].as_str().context("missing identity")?,"lexical_logit":lexical,
            "combined_logit":lexical+combination.semantic_weight*semantic+combination.score_bias_delta})
        );
    }
    Ok(())
}
#[cfg(not(feature = "semantic"))]
fn main() {
    eprintln!("feedback_probe requires --features semantic");
    std::process::exit(2);
}
