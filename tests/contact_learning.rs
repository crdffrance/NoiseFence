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
    let cfg = common::config(root.path());
    let mut s = scan(cfg, common::MESSAGE);
    let targets = Default::default();
    let sample = learning::capture(common::MESSAGE, &s, "alice@example.test", &targets).unwrap();
    let other = learning::capture(common::MESSAGE, &s, "bob@example.test", &targets).unwrap();
    assert_ne!(sample.key, other.key);
    let serialized = serde_json::to_string(&sample).unwrap();
    assert!(!serialized.contains("sender@example.org"));
    assert!(!serialized.contains("alice"));
    s.evidence.as_mut().unwrap().source = Source::ContentOnly;
    assert!(learning::capture(common::MESSAGE, &s, "alice@example.test", &targets).is_none());
    s.evidence.as_mut().unwrap().source = Source::SmtpSession;
    s.evidence.as_mut().unwrap().authentication.dmarc_dkim = Some(AuthResult::Fail);
    assert!(learning::capture(common::MESSAGE, &s, "alice@example.test", &targets).is_none());
    s.evidence.as_mut().unwrap().authentication.dmarc_dkim = Some(AuthResult::Pass);
    let duplicate = [b"From: forged@evil.test\r\n".as_slice(), common::MESSAGE].concat();
    assert!(learning::capture(&duplicate, &s, "alice@example.test", &targets).is_none());
    s.antivirus.status = noisefence::antivirus::AntivirusStatus::Malware;
    assert!(learning::capture(common::MESSAGE, &s, "alice@example.test", &targets).is_none());
}
#[tokio::test]
async fn accepted_history_survives_restart_is_scoped_and_refuses_stale_central_fallback() {
    let root = tempfile::tempdir().unwrap();
    let cfg = common::config(root.path());
    let store = Store::open(root.path()).unwrap();
    let s = scan(cfg.clone(), common::MESSAGE);
    let targets = Default::default();
    let settings = Settings::default();
    let recipient = cfg.recipient("alice@example.test").unwrap();
    let now = noisefence::now();
    let current = learning::capture(common::MESSAGE, &s, &recipient.address, &targets).unwrap();
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
    let mut cfg = (*common::config(root.path())).clone();
    let before = noisefence::cluster::artifacts::capture(
        &cfg,
        noisefence::control::Settings::from_config(&cfg),
        0,
    )
    .unwrap();
    cfg.contact_learning = Some(Settings::default());
    cfg.validate().unwrap();
    let policy = noisefence::control::Settings::from_config(&cfg);
    let after = noisefence::cluster::artifacts::capture(&cfg, policy.clone(), 1).unwrap();
    assert_eq!(
        noisefence::cluster::artifacts::model_digest(&before.bundle).unwrap(),
        noisefence::cluster::artifacts::model_digest(&after.bundle).unwrap()
    );
    assert!(after.bundle.for_build("0.32.0-rc.2").is_err());
    let worker = tempfile::tempdir().unwrap();
    let mut wc = (*common::config(worker.path())).clone();
    noisefence::cluster::artifacts::freeze(worker.path(), &after, 0).unwrap();
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
    let mut bad = policy;
    bad.contact_learning.as_mut().unwrap().minimum_campaigns = 1;
    assert!(bad.effective(&cfg).is_err());
}

#[tokio::test]
async fn authentication_failure_is_compared_but_never_added_to_learned_history() {
    let root = tempfile::tempdir().unwrap();
    let cfg = common::config(root.path());
    let store = Store::open(root.path()).unwrap();
    let targets = Default::default();
    let recipient = cfg.recipient("alice@example.test").unwrap();
    let known = scan(cfg.clone(), common::MESSAGE);
    let original =
        learning::capture(common::MESSAGE, &known, &recipient.address, &targets).unwrap();
    let now = noisefence::now();
    let rows = (1..=6)
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
        assert!(learning::capture(&raw, &current, &recipient.address, &targets).is_none());
        let reports = learning::prepare(
            root.path(),
            &Settings::default(),
            &raw,
            &current,
            std::slice::from_ref(&recipient),
            &targets,
            "sender@example.org",
        )
        .await;
        let observation = &reports[&recipient.address];
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
        root.path(),
        &Settings::default(),
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
