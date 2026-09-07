//! Synthetic offline observations for software parity tests, never SMTP traffic.
use anyhow::{Result, ensure};
use noisefence::{
    config::Config,
    evidence::{Artifacts, AuthResult, Evidence, Source, State},
    message::digest,
};
use std::{fs::OpenOptions, io::Write, os::unix::fs::OpenOptionsExt};

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    ensure!(args.len() == 2, "usage: fusion_fixture output.jsonl");
    let config: Config = toml::from_str(include_str!("../config/development.toml"))?;
    let artifacts = Artifacts::new(
        &config,
        Some(digest(b"synthetic lexical fixture")),
        Some(digest(b"synthetic semantic fixture")),
        false,
    );
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&args[1])?;
    for i in 0..400 {
        let id = digest(format!("fusion software fixture {i}").as_bytes());
        let h = hex::decode(&id)?;
        let spam = i % 2 == 1;
        let mut e = Evidence::new(&config, artifacts.clone(), false);
        e.source = Source::SmtpSession; // Fixture only: assert the trusted path's contract.
        e.analysis_complete = true;
        e.lexical_state = State::Complete;
        e.lexical_logit =
            Some((if spam { 2.0 } else { -2.0 }) + (f64::from(h[0]) / 255.0 - 0.5) * 5.0);
        e.semantic_state = State::Complete;
        e.semantic_logit =
            Some((if spam { 1.0 } else { -1.0 }) + (f64::from(h[1]) / 255.0 - 0.5) * 3.0);
        e.legacy_score = Some(100.0 / (1.0 + (-e.lexical_logit.unwrap()).exp()));
        e.authentication.arc_state = State::Complete;
        e.authentication.arc = Some(AuthResult::None);
        e.authentication.arc_can_seal = Some(true);
        if i % 17 == 0 {
            e.lexical_state = State::Unavailable;
            e.lexical_logit = None;
            e.analysis_complete = false;
        }
        let row = serde_json::json!({"schema":"noisefence-learning-1","source":"local_human_feedback",
            "id":id,"fingerprint":digest(format!("canonical fixture {i}").as_bytes()),"simhash":&id[..16],
            "observed_at":1788739200+i,"labelled_at":1788740200+i,"feature_version":3,"spam":spam,"evidence":e});
        writeln!(output, "{row}")?;
    }
    output.sync_all()?;
    Ok(())
}
