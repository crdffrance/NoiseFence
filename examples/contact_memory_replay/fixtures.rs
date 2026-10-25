//! Public synthetic contract cases. Labels are written to a separate file and
//! never supplied to replay(). They do not establish independent real efficacy.
use super::*;
#[derive(Deserialize)]
struct Case {
    id: String,
    family: String,
    label: String,
    from: String,
    body: String,
    auth: String,
    #[serde(default)]
    recipient: Option<String>,
    #[serde(default)]
    reply: Option<String>,
    #[serde(default)]
    directory: Option<String>,
    regular: bool,
    alert: bool,
}
fn cases() -> Result<Vec<Case>> {
    Ok(serde_json::from_str(include_str!(
        "../../tests/fixtures/identity/replay-cases.json"
    ))?)
}
fn event(
    id: &str,
    addresses: (&str, Option<&str>),
    body: &str,
    at: i64,
    auth: &str,
    recipient: &str,
    root: &Path,
) -> Result<Event> {
    let (from, reply) = addresses;
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut config: noisefence::config::Config =
        toml::from_str(include_str!("../../config/development.toml"))?;
    config.data_dir = root.into();
    config.native_filter = Some(Default::default());
    config.protection = Some(Default::default());
    let engine = noisefence::engine::Engine::new(std::sync::Arc::new(config))?;
    let reply = reply
        .map(|r| format!("Reply-To: {r}\r\n"))
        .unwrap_or_default();
    let authentication_header = if auth == "imported" {
        "Authentication-Results: forged.test; dkim=pass; dmarc=pass\r\n"
    } else {
        ""
    };
    let raw = format!("{authentication_header}From: {from}\r\nTo: {recipient}\r\n{reply}Subject: {id}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{body}\r\n").into_bytes();
    let mut scan = engine.offline(&raw);
    use noisefence::evidence::{AuthResult, Source, State};
    let evidence = scan
        .evidence
        .as_mut()
        .context("Fixture evidence unavailable")?;
    evidence.source = if auth == "imported" {
        Source::ContentOnly
    } else {
        Source::SmtpSession
    };
    evidence.authentication.dmarc_state = if auth == "unavailable" {
        State::Unavailable
    } else {
        State::Complete
    };
    let result = match auth {
        "pass" => AuthResult::Pass,
        "fail" => AuthResult::Fail,
        _ => AuthResult::TempError,
    };
    evidence.authentication.dmarc_dkim = Some(result);
    evidence.authentication.dmarc_spf = Some(result);
    Ok(Event {
        id: id.into(),
        received_at: at,
        accepted: true,
        envelope_sender: "bounce@external.test".into(),
        recipient: recipient.into(),
        original_base64: STANDARD.encode(raw),
        scan,
        directory: None,
    })
}
fn fixture(root: &Path) -> Result<Input> {
    const AT: i64 = 1_780_000_000;
    let mut events = Vec::new();
    let words = [
        "architecture",
        "budget",
        "garden",
        "schedule",
        "summary",
        "shipping",
    ];
    for (index, word) in words.iter().enumerate() {
        let at = AT - (6 - index as i64) * 86400;
        events.push(event(
            &format!("history-{word}"),
            ("Known Supplier <supplier@external.test>", None),
            &format!("The {word} update is ready."),
            at,
            "pass",
            "alice@example.test",
            root,
        )?);
        // Same original/fingerprint on different dates cannot create six campaigns.
        let mut repeat = event(
            "same-campaign",
            ("Repeated Sender <repeat@external.test>", None),
            "Our standing newsletter invitation.",
            at,
            "pass",
            "alice@example.test",
            root,
        )?;
        repeat.id = format!("repeated-{word}");
        events.push(repeat);
    }
    for (index, case) in cases()?.into_iter().enumerate() {
        let mut current = event(
            &case.id,
            (&case.from, case.reply.as_deref()),
            &case.body,
            AT + index as i64,
            &case.auth,
            case.recipient.as_deref().unwrap_or("alice@example.test"),
            root,
        )?;
        if let Some(variant) = &case.directory {
            let mut source: serde_json::Value =
                serde_json::from_str(include_str!("../../tests/fixtures/identity/directory.json"))?;
            source["completed_at"] = (AT - 3600).into();
            if variant == "homonym" || variant == "delegate" {
                source["people"].as_array_mut().unwrap().push(serde_json::json!({
                    "id":"person-assistant","display_name":if variant == "homonym" { "Alice Finance" } else { "Assistant" },
                    "kind":"person","activity":"active","addresses":["assistant@example.test"],"protected_roles":["finance"]
                }));
            }
            if variant == "delegate" {
                source["delegations"] = serde_json::json!([{"owner":"person-alice","delegate":"person-assistant","address":"alice@example.test"}]);
            }
            current.directory = Some(serde_json::from_value(
                serde_json::json!({"schema":runtime::SCHEMA,"sources":[source]}),
            )?);
        }
        events.push(current);
    }
    Ok(Input {
        protocol: "identity-replay-input-1".into(),
        provenance: Provenance::Synthetic,
        evaluation_after: AT,
        settings: Default::default(),
        events,
    })
}
pub(super) fn write(output: &Path) -> Result<()> {
    let temporary = tempfile::tempdir()?;
    let input = fixture(temporary.path())?;
    let labels: Vec<_> = cases()?.iter().map(|c| serde_json::json!({"id":c.id,"family":c.family,"label":c.label,"expected_regular":c.regular,"expected_identity_candidate":c.alert})).collect();
    std::fs::create_dir(output).context("Fixture output must be a new directory")?;
    std::fs::write(
        output.join("events.json"),
        serde_json::to_vec_pretty(&input)?,
    )?;
    std::fs::write(
        output.join("labels.json"),
        serde_json::to_vec_pretty(
            &serde_json::json!({"protocol":"identity-evaluation-labels-1","provenance":"synthetic_fixture","cases":labels}),
        )?,
    )?;
    println!("Synthetic events and separate labels written; no provider or production access.");
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn chronological_cases_preserve_limits_and_expose_known_false_candidates() {
        let root = tempfile::tempdir().unwrap();
        let input = fixture(root.path()).unwrap();
        let result = replay(input, root.path()).unwrap();
        for case in cases().unwrap() {
            let row = result.iter().find(|r| r.id == case.id).unwrap();
            assert_eq!(
                row.memory.regular, case.regular,
                "{} memory: {:?}",
                case.id, row.memory
            );
            assert_eq!(
                row.contribution.corroborated, case.alert,
                "{} correlation: {:?}",
                case.id, row.contribution
            );
            assert_eq!(row.observation.applied_weight, 0.);
            assert!(!row.campaign_seen_in_history);
            if case.auth != "pass" {
                assert!(!row.retained, "{} must not teach", case.id);
            }
        }
    }
    #[test]
    fn rejected_history_never_establishes_a_regular_sender() {
        let root = tempfile::tempdir().unwrap();
        let mut input = fixture(root.path()).unwrap();
        for event in &mut input.events {
            if event.received_at < input.evaluation_after {
                event.accepted = false;
            }
        }
        let result = replay(input, root.path()).unwrap();
        assert!(
            result
                .iter()
                .filter(|r| r.phase == "history")
                .all(|r| !r.retained)
        );
        let usual = result.iter().find(|r| r.id == "usual-supplier").unwrap();
        assert!(!usual.memory.regular);
        assert!(usual.retained); // Accepted now, after its own comparison.
    }
    #[test]
    fn rejects_receipt_reordering_duplicate_ids_and_mismatched_originals() {
        for mode in 0..3 {
            let root = tempfile::tempdir().unwrap();
            let mut input = fixture(root.path()).unwrap();
            match mode {
                0 => input.events.swap(0, 5),
                1 => input.events[1].id = input.events[0].id.clone(),
                _ => {
                    input.events[0].original_base64 =
                        STANDARD.encode(b"From: wrong@example.test\r\n\r\nwrong")
                }
            }
            assert!(replay(input, root.path()).is_err());
        }
    }
}
