mod common;
use noisefence::{
    engine::{Engine, Scan},
    evidence::{AuthResult, Source, State},
    identity::learning::{self, Observation, Row, Settings, Snapshot},
    store::Store,
};
use std::sync::Arc;
fn scan(config: Arc<noisefence::config::Config>, raw: &[u8]) -> Scan {
    let mut scan = Engine::new(config).unwrap().offline(raw);
    let e = scan.evidence.as_mut().unwrap();
    e.source = Source::SmtpSession;
    e.authentication.dmarc_state = State::Complete;
    e.authentication.dmarc_dkim = Some(AuthResult::Pass);
    scan
}
#[test]
fn eligibility_uses_original_single_from_and_trusted_smtp_not_imported_headers() {
    let root = tempfile::tempdir().unwrap();
    let key = noisefence::identity::memory_key::Key::install(root.path(), None).unwrap();
    let cfg = common::config(root.path());
    let mut s = scan(cfg, common::MESSAGE);
    let targets = Default::default();
    let sample =
        learning::capture(&key, common::MESSAGE, &s, "alice@example.test", &targets).unwrap();
    let other = learning::capture(&key, common::MESSAGE, &s, "bob@example.test", &targets).unwrap();
    assert_ne!(sample.key, other.key);
    let serialized = serde_json::to_string(&sample).unwrap();
    assert!(!serialized.contains("sender@example.org"));
    assert!(!serialized.contains("alice"));
    s.evidence.as_mut().unwrap().source = Source::ContentOnly;
    assert!(learning::capture(&key, common::MESSAGE, &s, "alice@example.test", &targets).is_none());
    s.evidence.as_mut().unwrap().source = Source::SmtpSession;
    s.evidence.as_mut().unwrap().authentication.dmarc_dkim = Some(AuthResult::Fail);
    assert!(learning::capture(&key, common::MESSAGE, &s, "alice@example.test", &targets).is_none());
    s.evidence.as_mut().unwrap().authentication.dmarc_dkim = Some(AuthResult::Pass);
    let duplicate = [b"From: forged@evil.test\r\n".as_slice(), common::MESSAGE].concat();
    assert!(learning::capture(&key, &duplicate, &s, "alice@example.test", &targets).is_none());
    s.antivirus.status = noisefence::antivirus::AntivirusStatus::Malware;
    assert!(learning::capture(&key, common::MESSAGE, &s, "alice@example.test", &targets).is_none());
}
#[tokio::test]
async fn accepted_history_survives_restart_is_scoped_and_refuses_stale_central_fallback() {
    let root = tempfile::tempdir().unwrap();
    let key = noisefence::identity::memory_key::Key::install(root.path(), None).unwrap();
    let cfg = common::config(root.path());
    let store = Store::open(root.path()).unwrap();
    let s = scan(cfg.clone(), common::MESSAGE);
    let targets = Default::default();
    let settings = Settings {
        key_id: Some(key.id().into()),
        ..Default::default()
    };
    let recipient = cfg.recipient("alice@example.test").unwrap();
    let now = noisefence::now();
    let current =
        learning::capture(&key, common::MESSAGE, &s, &recipient.address, &targets).unwrap();
    let mut rows = Vec::new();
    for day in 1..=6 {
        let mut sample = current.clone();
        sample.campaign = noisefence::message::digest(format!("distinct {day}").as_bytes());
        let mut accepted = s.clone();
        accepted.contact_learning = Some(Observation {
            sample: Some(sample.clone()),
            report: Default::default(),
        });
        let id = uuid::Uuid::new_v4().to_string();
        store
            .enqueue(
                id.clone(),
                "sender@example.org".into(),
                vec![recipient.clone()],
                accepted,
                common::MESSAGE.to_vec(),
            )
            .await
            .unwrap();
        store
            .run(move |db| {
                db.execute(
                    "UPDATE messages SET created=?1 WHERE id=?2",
                    rusqlite::params![now - day * 86400, id],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        rows.push(Row {
            created: now - day * 86400,
            sample,
            unwanted_at: None,
        });
    }
    drop(store);
    let store = Store::open(root.path()).unwrap();
    let result = learning::prepare(
        Some(&key),
        root.path(),
        &settings,
        common::MESSAGE,
        &s,
        std::slice::from_ref(&recipient),
        &targets,
        "sender@example.org",
    )
    .await;
    assert!(
        result[&recipient.address].report.regular,
        "{:?}",
        result[&recipient.address].report
    );
    let bob = noisefence::config::Recipient {
        address: "bob@example.test".into(),
        destination: "bob@example.test".into(),
        hosts: vec![],
    };
    let result = learning::prepare(
        Some(&key),
        root.path(),
        &settings,
        common::MESSAGE,
        &s,
        &[recipient.clone(), bob.clone()],
        &targets,
        "sender@example.org",
    )
    .await;
    assert!(result[&recipient.address].report.regular);
    assert_eq!(result[&bob.address].report.campaigns, 0);
    let bounce = learning::prepare(
        Some(&key),
        root.path(),
        &settings,
        common::MESSAGE,
        &s,
        std::slice::from_ref(&recipient),
        &targets,
        "",
    )
    .await;
    assert!(bounce[&recipient.address].sample.is_none());
    noisefence::runtime_history::require(&store).await.unwrap();
    let missing = learning::prepare(
        Some(&key),
        root.path(),
        &settings,
        common::MESSAGE,
        &s,
        std::slice::from_ref(&recipient),
        &targets,
        "sender@example.org",
    )
    .await;
    assert_eq!(missing[&recipient.address].report.status, "unavailable");
    let mut snapshot = noisefence::runtime_history::Snapshot {
        protocol: noisefence::runtime_history::PROTOCOL.into(),
        generation: 1,
        created: noisefence::now(),
        rows: vec![],
        contacts: Some(Snapshot {
            rows,
            limited: false,
        }),
    };
    noisefence::runtime_history::install(root.path(), snapshot.clone())
        .await
        .unwrap();
    let shared = learning::prepare(
        Some(&key),
        root.path(),
        &settings,
        common::MESSAGE,
        &s,
        std::slice::from_ref(&recipient),
        &targets,
        "sender@example.org",
    )
    .await;
    assert!(shared[&recipient.address].report.regular);
    snapshot.generation = 2;
    snapshot.contacts.as_mut().unwrap().limited = true;
    noisefence::runtime_history::install(root.path(), snapshot.clone())
        .await
        .unwrap();
    let limited = learning::prepare(
        Some(&key),
        root.path(),
        &settings,
        common::MESSAGE,
        &s,
        std::slice::from_ref(&recipient),
        &targets,
        "sender@example.org",
    )
    .await;
    assert_eq!(limited[&recipient.address].report.status, "limited");
    snapshot.generation = 3;
    snapshot.contacts = None;
    noisefence::runtime_history::install(root.path(), snapshot)
        .await
        .unwrap();
    let old = learning::prepare(
        Some(&key),
        root.path(),
        &settings,
        common::MESSAGE,
        &s,
        &[recipient],
        &targets,
        "sender@example.org",
    )
    .await;
    assert_eq!(old["alice@example.test"].report.status, "unavailable");
}
#[test]
fn policy_replication_preserves_models_and_refuses_unsupported_workers() {
    let root = tempfile::tempdir().unwrap();
    let key = noisefence::identity::memory_key::Key::install(root.path(), None).unwrap();
    let mut cfg = (*common::config(root.path())).clone();
    let before = noisefence::cluster::artifacts::capture(
        &cfg,
        noisefence::control::Settings::from_config(&cfg),
        0,
    )
    .unwrap();
    cfg.contact_learning = Some(Settings {
        key_id: Some(key.id().into()),
        ..Default::default()
    });
    cfg.validate().unwrap();
    let policy = noisefence::control::Settings::from_config(&cfg);
    let after = noisefence::cluster::artifacts::capture(&cfg, policy.clone(), 1).unwrap();
    assert_eq!(
        noisefence::cluster::artifacts::model_digest(&before.bundle).unwrap(),
        noisefence::cluster::artifacts::model_digest(&after.bundle).unwrap()
    );
    assert!(after.bundle.for_build("0.32.0-rc.2").is_err());
    assert!(after.bundle.for_build("0.32.0-rc.3").is_err());
    let worker = tempfile::tempdir().unwrap();
    let mut wc = (*common::config(worker.path())).clone();
    noisefence::cluster::artifacts::freeze(worker.path(), &after, 0).unwrap();
    let without_key =
        noisefence::cluster::artifacts::materialize(&wc, &after.bundle, true).unwrap();
    let without_key = Engine::new(Arc::new(without_key)).unwrap();
    assert_eq!(
        without_key.software_identity()["contact_memory"]["key_available"],
        false
    );
    noisefence::identity::memory_key::Key::install(
        worker.path(),
        Some(&root.path().join("contact-memory/key")),
    )
    .unwrap();
    assert_eq!(
        noisefence::cluster::artifacts::materialize(&wc, &after.bundle, true)
            .unwrap()
            .contact_learning,
        cfg.contact_learning
    );
    wc.contact_learning = cfg.contact_learning.clone();
    assert!(
        noisefence::cluster::artifacts::materialize(&wc, &before.bundle, false)
            .unwrap()
            .contact_learning
            .is_none()
    );
    let mut altered = after.bundle.clone();
    altered.shared["contact_learning"]["key_id"] = serde_json::json!("a".repeat(64));
    altered.digest = altered.hash().unwrap();
    assert!(altered.validate().is_err());
    let private = hex::encode(std::fs::read(root.path().join("contact-memory/key")).unwrap());
    assert!(
        !serde_json::to_string(&after.bundle)
            .unwrap()
            .contains(&private)
    );
    let mut bad = policy;
    bad.contact_learning.as_mut().unwrap().minimum_campaigns = 1;
    assert!(bad.effective(&cfg).is_err());
}

#[tokio::test]
async fn authentication_failure_is_compared_but_never_added_to_learned_history() {
    let root = tempfile::tempdir().unwrap();
    let key = noisefence::identity::memory_key::Key::install(root.path(), None).unwrap();
    let cfg = common::config(root.path());
    let store = Store::open(root.path()).unwrap();
    let targets = Default::default();
    let recipient = cfg.recipient("alice@example.test").unwrap();
    let known = scan(cfg.clone(), common::MESSAGE);
    let original =
        learning::capture(&key, common::MESSAGE, &known, &recipient.address, &targets).unwrap();
    let now = noisefence::now();
    let rows: Vec<Row> = (1..=6)
        .map(|day| {
            let mut sample = original.clone();
            sample.campaign =
                noisefence::message::digest(format!("prior campaign {day}").as_bytes());
            Row {
                created: now - day * 86400,
                sample,
                unwanted_at: None,
            }
        })
        .collect();
    let replay_rows = rows.clone();
    noisefence::runtime_history::require(&store).await.unwrap();
    noisefence::runtime_history::install(
        root.path(),
        noisefence::runtime_history::Snapshot {
            protocol: noisefence::runtime_history::PROTOCOL.into(),
            generation: 1,
            created: now,
            rows: vec![],
            contacts: Some(Snapshot {
                rows,
                limited: false,
            }),
        },
    )
    .await
    .unwrap();
    let raw = [
        b"Reply-To: attacker@elsewhere.test\r\n".as_slice(),
        common::MESSAGE,
    ]
    .concat();
    let current = scan(cfg, &raw);
    for (state, result, expected_alignment) in [
        (
            State::Complete,
            AuthResult::Fail,
            learning::Alignment::NotVerified,
        ),
        (
            State::Complete,
            AuthResult::None,
            learning::Alignment::NotVerified,
        ),
        (
            State::Unavailable,
            AuthResult::Pass,
            learning::Alignment::Unavailable,
        ),
        (
            State::Complete,
            AuthResult::TempError,
            learning::Alignment::Unavailable,
        ),
    ] {
        let mut current = current.clone();
        let authentication = &mut current.evidence.as_mut().unwrap().authentication;
        authentication.dmarc_state = state;
        authentication.dmarc_dkim = Some(result);
        assert!(learning::capture(&key, &raw, &current, &recipient.address, &targets).is_none());
        let reports = learning::prepare(
            Some(&key),
            root.path(),
            &Settings {
                key_id: Some(key.id().into()),
                ..Default::default()
            },
            &raw,
            &current,
            std::slice::from_ref(&recipient),
            &targets,
            "sender@example.org",
        )
        .await;
        let observation = &reports[&recipient.address];
        let replay_settings = Settings {
            key_id: Some(key.id().into()),
            ..Default::default()
        };
        let replayed = learning::ReplayContext {
            secret: Some(&key),
            settings: &replay_settings,
            raw: &raw,
            scan: &current,
            recipient: &recipient.address,
            targets: &targets,
            envelope_sender: "sender@example.org",
        }
        .assess(&replay_rows, false, now);
        assert_eq!(
            serde_json::to_value(&replayed).unwrap(),
            serde_json::to_value(observation).unwrap(),
            "Offline replay and SMTP preparation must agree on the same recorded evidence"
        );
        assert!(observation.report.regular && observation.report.observation_only);
        assert_eq!(observation.report.learning_eligible, Some(false));
        assert_eq!(observation.report.dkim_alignment, Some(expected_alignment));
        assert!(
            observation.sample.is_none(),
            "A compared claim must never become retained learning metadata"
        );
        assert!(
            observation
                .report
                .changes
                .contains(&"reply_destination".into())
        );
        assert_eq!(
            observation
                .report
                .changes
                .contains(&"dkim_alignment".into()),
            expected_alignment == learning::Alignment::NotVerified
        );
    }
    let mut imported = current;
    imported.evidence.as_mut().unwrap().source = Source::ContentOnly;
    let reports = learning::prepare(
        Some(&key),
        root.path(),
        &Settings {
            key_id: Some(key.id().into()),
            ..Default::default()
        },
        &raw,
        &imported,
        std::slice::from_ref(&recipient),
        &targets,
        "sender@example.org",
    )
    .await;
    assert_eq!(reports[&recipient.address].report.status, "ineligible");
    assert!(reports[&recipient.address].sample.is_none());
}

#[tokio::test]
async fn unavailable_or_mismatched_key_never_learns_or_disables_the_mail_engine() {
    let root = tempfile::tempdir().unwrap();
    let cfg = common::config(root.path());
    let key = noisefence::identity::memory_key::Key::install(root.path(), None).unwrap();
    let recipient = cfg.recipient("alice@example.test").unwrap();
    let scan = scan(cfg.clone(), common::MESSAGE);
    let settings = Settings {
        key_id: Some(key.id().into()),
        ..Default::default()
    };
    let targets = Default::default();
    for secret in [None, Some(&key)] {
        let mut selected = settings.clone();
        if secret.is_some() {
            selected.key_id = Some("0".repeat(64));
        }
        let reports = learning::prepare(
            secret,
            root.path(),
            &selected,
            common::MESSAGE,
            &scan,
            std::slice::from_ref(&recipient),
            &targets,
            "sender@example.org",
        )
        .await;
        assert_eq!(
            reports[&recipient.address].report.status,
            "privacy_key_unavailable"
        );
        assert!(reports[&recipient.address].sample.is_none());
        assert!(!reports[&recipient.address].report.regular);
    }
    let mut config = (*cfg).clone();
    config.contact_learning = Some(settings);
    std::fs::remove_file(root.path().join("contact-memory/key")).unwrap();
    assert!(Engine::new(Arc::new(config)).is_ok());
}

#[test]
fn key_epochs_and_recipient_hmacs_never_mix_with_unkeyed_history() {
    let root = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    let cfg = common::config(root.path());
    let s = scan(cfg, common::MESSAGE);
    let key = noisefence::identity::memory_key::Key::install(root.path(), None).unwrap();
    let foreign = noisefence::identity::memory_key::Key::install(other.path(), None).unwrap();
    let targets = Default::default();
    let current =
        learning::capture(&key, common::MESSAGE, &s, "alice@example.test", &targets).unwrap();
    let swapped = learning::capture(
        &foreign,
        common::MESSAGE,
        &s,
        "alice@example.test",
        &targets,
    )
    .unwrap();
    let alias = learning::capture(
        &key,
        common::MESSAGE,
        &s,
        "alice+tag@example.test",
        &targets,
    )
    .unwrap();
    assert_ne!(current.key, swapped.key);
    assert_ne!(current.reply, swapped.reply);
    assert_ne!(current.campaign, swapped.campaign);
    assert_ne!(current.key, alias.key);
    assert_ne!(current.campaign, alias.campaign);
    let now = noisefence::now();
    let settings = Settings {
        key_id: Some(key.id().into()),
        ..Default::default()
    };
    let rows: Vec<_> = (1..=6)
        .map(|day| {
            let mut sample = current.clone();
            sample.protocol = learning::LEGACY_PROTOCOL.into();
            sample.key_id = None;
            sample.campaign = noisefence::message::digest(format!("legacy{day}").as_bytes());
            assert!(sample.valid());
            Row {
                created: now - day * 86400,
                sample,
                unwanted_at: None,
            }
        })
        .collect();
    let history = learning::assess(&settings, &current, &rows, false, now);
    assert_eq!(history.campaigns, 0);
    assert!(!history.regular);
    assert_eq!(
        learning::assess(&settings, &rows[0].sample, &[], false, now).status,
        "ineligible"
    );
    assert_eq!(
        learning::assess(&settings, &swapped, &[], false, now).status,
        "ineligible"
    );
}

#[test]
fn operator_cli_reports_only_key_id_and_cannot_silently_replace_lost_material() {
    let root = tempfile::tempdir().unwrap();
    let config = common::config(root.path());
    let file = root.path().join("fixture.toml");
    std::fs::write(&file, toml::to_string(&*config).unwrap()).unwrap();
    let invoke = |args: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_noisefence"))
            .arg("--config")
            .arg(&file)
            .arg("contact-memory-key")
            .args(args)
            .output()
            .unwrap()
    };
    assert!(!invoke(&["--check"]).status.success());
    assert!(!root.path().join("contact-memory").exists());
    let created = invoke(&[]);
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&created.stdout).unwrap();
    assert_eq!(result["activated"], false);
    assert_eq!(result.as_object().unwrap().len(), 2);
    let key = noisefence::identity::memory_key::Key::load(root.path()).unwrap();
    assert_eq!(result["key_id"], key.id());
    let check = invoke(&["--check"]);
    assert!(check.status.success());
    assert_eq!(created.stdout, check.stdout);
    std::fs::remove_file(root.path().join("contact-memory/key")).unwrap();
    assert!(!invoke(&[]).status.success());
    assert!(!root.path().join("contact-memory/key").exists());
}
