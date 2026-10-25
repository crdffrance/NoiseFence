//! Offline walk-forward identity evaluation. No provider, model, queue or console
//! writes. Authentication is recorded input, never inferred from mail headers.
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use noisefence::{
    engine::Scan,
    identity::{correlation, learning, memory_key::Key, runtime},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    path::Path,
};
#[path = "contact_memory_replay/fixtures.rs"]
mod fixtures;

const MAX_INPUT: usize = 64 * 1024 * 1024;
#[derive(Deserialize, Serialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum Provenance {
    Synthetic,
    GatewayRecorded,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Input {
    protocol: String,
    provenance: Provenance,
    evaluation_after: i64,
    #[serde(default)]
    settings: learning::Settings,
    events: Vec<Event>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Event {
    id: String,
    received_at: i64,
    accepted: bool,
    envelope_sender: String,
    recipient: String,
    original_base64: String,
    scan: Scan,
    #[serde(default)]
    directory: Option<runtime::Document>,
}
#[derive(Serialize)]
struct ResultRow {
    id: String,
    received_at: i64,
    phase: &'static str,
    campaign_group: usize,
    campaign_seen_in_history: bool,
    retained: bool,
    memory: learning::Report,
    directory: Option<runtime::Report>,
    observation: correlation::Report,
    contribution: correlation::Report,
}
fn replay(mut input: Input, root: &Path) -> Result<Vec<ResultRow>> {
    ensure!(
        input.protocol == "identity-replay-input-1",
        "Unknown replay protocol"
    );
    ensure!(
        !input.events.is_empty() && input.events.len() <= 4096,
        "Replay requires 1..4096 events"
    );
    ensure!(
        input.evaluation_after > 0,
        "An explicit evaluation boundary is required"
    );
    input.settings.validate()?;
    ensure!(
        input.settings.key_id.is_none(),
        "Replay creates a disposable private key; do not supply an installation ID"
    );
    let key = Key::install(root, None)?;
    input.settings.key_id = Some(key.id().into());
    let mut config: noisefence::config::Config =
        toml::from_str(include_str!("../config/development.toml"))?;
    config.data_dir = root.into();
    let policy = noisefence::protection::Policy::default();
    let feed = noisefence::protection::Feed::default();
    let mut rows = Vec::<learning::Row>::new();
    let mut results = Vec::new();
    let mut ids = BTreeSet::new();
    let mut groups = BTreeMap::<String, usize>::new();
    let mut history_groups = BTreeSet::new();
    let mut previous = 0;
    for event in input.events {
        ensure!(
            !event.id.is_empty()
                && event.id.len() <= 100
                && event
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
                && ids.insert(event.id.clone()),
            "Invalid or duplicate event ID"
        );
        ensure!(
            event.received_at > 0 && event.received_at >= previous,
            "Events must be chronologically ordered by receipt time"
        );
        previous = event.received_at;
        noisefence::identity::mailbox(&event.recipient)?;
        if !event.envelope_sender.is_empty() {
            noisefence::identity::mailbox(&event.envelope_sender)?;
        }
        ensure!(
            event.original_base64.len() <= 2 * 1024 * 1024 * 4 / 3 + 4,
            "Replay original exceeds 2 MiB"
        );
        let raw = STANDARD
            .decode(&event.original_base64)
            .context("Invalid base64 original")?;
        ensure!(
            raw.len() <= 2 * 1024 * 1024,
            "Replay original exceeds 2 MiB"
        );
        let mut scan = event.scan;
        ensure!(
            scan.raw_sha256.as_deref() == Some(noisefence::message::digest(&raw).as_str()),
            "Recorded original digest differs"
        );
        ensure!(
            scan.fingerprint == noisefence::engine::extract(&raw, 2 * 1024 * 1024).fingerprint,
            "Recorded campaign fingerprint differs from this build"
        );
        // Recalculate only the new component; model/LLM/Rspamd verdicts cannot
        // establish a contact or provide an evaluation label.
        scan.contact_learning = None;
        scan.identity = None;
        scan.identity_correlation = None;
        let (_, targets) = noisefence::protection::local_checks(&raw, "", &config, &policy, &feed);
        let context = learning::ReplayContext {
            secret: Some(&key),
            settings: &input.settings,
            raw: &raw,
            scan: &scan,
            recipient: &event.recipient,
            targets: &targets,
            envelope_sender: &event.envelope_sender,
        };
        let observation = context.assess(&rows, false, event.received_at);
        let retained = event.accepted && observation.sample.is_some();
        scan.contact_learning = Some(observation.clone());
        if let Some(document) = event.directory {
            let catalog = document.validate(event.received_at)?;
            let loaded = runtime::Loaded {
                sha256: noisefence::message::digest(&serde_json::to_vec(&document)?),
                catalog,
            };
            scan.identity =
                Some(loaded.inspect_message(&raw, &event.recipient, &scan, event.received_at));
        }
        let group = groups.len();
        let group = *groups.entry(scan.fingerprint.clone()).or_insert(group);
        let phase = if event.received_at < input.evaluation_after {
            "history"
        } else {
            "evaluation"
        };
        let seen = history_groups.contains(&group);
        results.push(ResultRow {
            id: event.id,
            received_at: event.received_at,
            phase,
            campaign_group: group,
            campaign_seen_in_history: seen,
            retained,
            memory: observation.report,
            directory: scan.identity.clone(),
            observation: correlation::inspect(&correlation::Settings::default(), &scan),
            contribution: correlation::inspect(
                &correlation::Settings {
                    mode: correlation::Mode::Contribute,
                    ..Default::default()
                },
                &scan,
            ),
        });
        if phase == "history" {
            history_groups.insert(group);
        }
        // Evaluate first. Current mail and labels never train their own result.
        if retained {
            rows.push(learning::Row {
                created: event.received_at,
                sample: observation.sample.unwrap(),
                unwanted_at: None,
            });
        }
        rows.retain(|r| {
            r.created >= event.received_at - i64::from(input.settings.retention_days) * 86400
        });
    }
    ensure!(
        results.iter().any(|r| r.phase == "evaluation"),
        "No events after evaluation boundary"
    );
    Ok(results)
}
fn main() -> Result<()> {
    let arguments: Vec<_> = std::env::args().collect();
    if arguments.len() == 3 && arguments[1] == "--synthetic-fixture" {
        return fixtures::write(Path::new(&arguments[2]));
    }
    ensure!(
        arguments.len() == 2,
        "usage: contact_memory_replay private-recorded-events.json | --synthetic-fixture new-directory"
    );
    let mut bytes = Vec::new();
    std::fs::File::open(&arguments[1])?
        .take(MAX_INPUT as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= MAX_INPUT, "Replay input exceeds 64 MiB");
    let input: Input = serde_json::from_slice(&bytes)?;
    let provenance = input.provenance;
    let evaluation_after = input.evaluation_after;
    let settings = input.settings.clone();
    let temporary = tempfile::tempdir()?;
    let rows = replay(input, temporary.path())?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "protocol": "identity-replay-result-1", "provenance": provenance,
            "input_sha256": noisefence::message::digest(&bytes),
        "evaluation_after": evaluation_after, "settings": settings,
        "version": env!("CARGO_PKG_VERSION"),
            "scope": "identity_corroboration_not_message_verdict", "mode": "walk_forward",
            "network_used": false, "production_changed": false, "evaluation_labels_used": false,
            "rows": rows,
        }))?
    );
    Ok(())
}
