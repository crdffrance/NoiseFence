mod common;
#[path = "common/fusion.rs"]
mod fixture;
use noisefence::{
    engine::Scan,
    message::digest,
    quality::{
        self, Kind,
        evaluation::{self, Risk},
    },
    store::Store,
};
use rusqlite::params;
use serde_json::json;

fn observed(config: &noisefence::config::Config) -> Scan {
    let (_, e) = fixture::fixture(config);
    Scan {
        complete: true,
        features_complete: Some(true),
        evidence: Some(e),
        fingerprint: digest(b"campaign"),
        campaign_simhash: Some("abcdef0123456789".into()),
        ..Default::default()
    }
}
fn model(report: &quality::Report) -> quality::Model {
    let linear = json!({"bias":0.0,"weights":vec![0.;quality::specs().len()]});
    serde_json::from_value(json!({"schema":"noisefence-quality-model-1","version":"SOFTWARE-TEST-ONLY",
        "protocol_sha256":quality::protocol_hash(),"artifacts_sha256":report.artifacts_sha256,"dataset_sha256":digest(b"synthetic"),
        "trained_at":noisefence::now(),"profiles":[report.availability_profile],"risk":linear,"calibration":[1.,0.],"thresholds":[0.2,0.8],
        "kinds":quality::KINDS,"kind_models":vec![linear;6],"kind_temperature":1.0})).unwrap()
}
#[test]
fn joint_model_is_bound_to_provenance_and_never_relabels_the_original() {
    let root = tempfile::tempdir().unwrap();
    let cfg = common::config(root.path());
    let mut scan = observed(&cfg);
    scan.score = 99.;
    scan.decision = Some(noisefence::fusion::runtime::Decision::legacy(&scan, 95.));
    let before = serde_json::to_value(&scan).unwrap();
    let report = quality::snapshot(&scan, None);
    assert!(report.complete_features);
    assert_eq!(report.values.len(), quality::specs().len());
    let mut candidate = model(&report);
    candidate.validate().unwrap();
    candidate.risk.bias = -5.;
    let prediction = candidate.predict(&report).unwrap();
    assert_eq!(prediction.risk, "legitimate");
    assert!(prediction.observation_only);
    assert_eq!(serde_json::to_value(&scan).unwrap(), before);
    let mut changed = report.clone();
    changed.artifacts_sha256 = digest(b"other");
    assert!(candidate.predict(&changed).is_err());
    changed = report.clone();
    changed.availability_profile.push_str("/unavailable");
    assert!(candidate.predict(&changed).is_err());
    changed = report.clone();
    changed.complete_features = false;
    assert!(candidate.predict(&changed).is_err());
    changed = report.clone();
    changed.source = "supplied_envelope".into();
    assert!(candidate.predict(&changed).is_err());
    changed = report.clone();
    changed.values[0] = f64::NAN;
    assert!(candidate.predict(&changed).is_err());
    candidate.risk.weights.pop();
    assert!(candidate.validate().is_err());
    assert!(!report.public().to_string().contains("values"));
    assert!(!report.public().to_string().contains("artifacts_sha256"));
}
#[test]
fn provider_scopes_and_overlap_remain_separate_features() {
    use noisefence::protection::{ProviderObservation, ProviderReport, Report, Status};
    let root = tempfile::tempdir().unwrap();
    let mut scan = observed(&common::config(root.path()));
    let observation = ProviderObservation {
        indicator_sha256: digest(b"host"),
        scope: "host_lookup".into(),
        verdict: "malicious".into(),
        queried_at: noisefence::now(),
        cached: false,
        cache_max_age_seconds: 0,
        analysis_max_age_seconds: None,
    };
    scan.protection = Some(Report {
        crdf: ProviderReport {
            status: Status::Complete,
            captured_at: Some(noisefence::now()),
            observations: vec![observation.clone()],
            ..Default::default()
        },
        virustotal: ProviderReport {
            status: Status::Complete,
            captured_at: Some(noisefence::now()),
            observations: vec![ProviderObservation {
                scope: "domain".into(),
                ..observation
            }],
            ..Default::default()
        },
        ..Default::default()
    });
    let report = quality::snapshot(&scan, None);
    let value = |name: &str| {
        report.values[quality::specs()
            .iter()
            .position(|f| f.name == name)
            .unwrap()]
    };
    assert_eq!(value("provider.shared_indicator_hits"), 1.);
    assert_eq!(value("provider.crdf.host_lookup.malicious"), 1.);
    assert_eq!(value("provider.crdf.file.malicious"), 0.);
    assert!(
        !noisefence::confirmation::corroborated(&scan),
        "Unvalidated providers do not force legacy classification"
    );
}
async fn account(store: &Store, name: &str, admin: bool, address: &str) {
    let (name, address) = (name.to_owned(), address.to_owned());
    store
        .run(move |db| {
            db.execute(
                "INSERT INTO users(username,password,admin) VALUES(?1,'unused',?2)",
                params![name, admin],
            )?;
            if !address.is_empty() {
                db.execute("INSERT INTO grants VALUES(?1,?2)", params![name, address])?;
            }
            Ok(())
        })
        .await
        .unwrap();
}
async fn insert(store: &Store, scan: &Scan, recipient: &str, created: i64) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    let key = id.clone();
    let scan = serde_json::to_string(scan).unwrap();
    let recipient = recipient.to_owned();
    store.run(move|db|{db.execute("INSERT INTO messages(id,created,sender,scan,raw_present) VALUES(?1,?2,'private-correspondent@example.org',?3,0)",params![key,created,scan])?;
        db.execute("INSERT INTO deliveries(message_id,address,destination,hosts,next_attempt) VALUES(?1,?2,?2,'[]',0)",params![key,recipient])?;Ok(())}).await.unwrap();
    id
}
#[tokio::test]
async fn samples_are_frozen_scoped_and_include_missing_observations_without_invented_labels() {
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path()).unwrap();
    let cfg = common::config(root.path());
    account(&store, "alice", false, "alice@example.test").await;
    account(&store, "bob", false, "bob@example.test").await;
    let now = noisefence::now();
    let mut scan = observed(&cfg);
    scan.subject = "PRIVATE SUBJECT".into();
    scan.quality = Some(quality::snapshot(&scan, None));
    scan.quality.as_mut().unwrap().sender.behavior = Some(quality::behavior::Report {
        status: "insufficient_history".into(),
        sample: Some(quality::behavior::Sample {
            protocol: "sender-behavior-1".into(),
            policy: digest(b"policy"),
            recipient: digest(b"PRIVATE RECIPIENT"),
            links: [digest(b"PRIVATE LINK")].into(),
            requests: Default::default(),
        }),
        ..Default::default()
    });
    let first = insert(&store, &scan, "alice@example.test", now - 100).await;
    scan.quality = None;
    scan.complete = false;
    insert(&store, &scan, "alice@example.test", now - 90).await;
    let bob = insert(&store, &scan, "bob@example.test", now - 90).await;
    let batch = evaluation::sample(
        &store,
        "alice".into(),
        now - 1000,
        now,
        50,
        "example.test".into(),
    )
    .await
    .unwrap();
    let members = evaluation::members(&store, "alice".into(), batch.clone())
        .await
        .unwrap();
    assert_eq!(members.len(), 2);
    assert_eq!(
        evaluation::observation_start(&store, "alice".into())
            .await
            .unwrap(),
        Some(now - 100)
    );
    assert_eq!(
        evaluation::observation_start(&store, "bob".into())
            .await
            .unwrap(),
        None
    );
    assert!(
        evaluation::members_page(&store, "alice".into(), batch.clone(), 200)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        evaluation::members_page(&store, "alice".into(), batch.clone(), 50001)
            .await
            .is_err()
    );
    assert!(members.iter().all(|m| m["risk"].is_null()));
    assert!(members.iter().all(|m| m.get("score").is_none()));
    assert!(members.iter().any(|m| m["joint_observations"] == false));
    let readiness = evaluation::readiness(&store, "alice".into(), batch.clone())
        .await
        .unwrap();
    assert_eq!(readiness["selected"], 2);
    assert_eq!(readiness["available"], 2);
    assert_eq!(readiness["risk_with_observations"], 0);
    assert_eq!(readiness["missing_or_incompatible_observations"], 1);
    assert!(!readiness.to_string().contains("PRIVATE"));
    assert!(
        evaluation::readiness(&store, "bob".into(), batch.clone())
            .await
            .is_err()
    );
    insert(&store, &scan, "alice@example.test", now - 80).await;
    assert_eq!(
        evaluation::members(&store, "alice".into(), batch.clone())
            .await
            .unwrap()
            .len(),
        2
    );
    assert!(
        evaluation::members(&store, "bob".into(), batch.clone())
            .await
            .is_err()
    );
    assert!(
        evaluation::label(
            &store,
            "alice".into(),
            bob,
            Risk::Legitimate,
            Some(Kind::Conversation)
        )
        .await
        .is_err()
    );
    evaluation::label(
        &store,
        "alice".into(),
        first.clone(),
        Risk::Legitimate,
        Some(Kind::Newsletter),
    )
    .await
    .unwrap();
    let readiness = evaluation::readiness(&store, "alice".into(), batch.clone())
        .await
        .unwrap();
    assert_eq!(readiness["risk_with_observations"], 1);
    assert_eq!(readiness["kind_with_observations"], 1);
    assert_eq!(readiness["training_validated"], false);
    let output = root.path().join("dataset.jsonl");
    evaluation::export(&store, "alice".into(), batch.clone(), &output)
        .await
        .unwrap();
    let raw = std::fs::read_to_string(&output).unwrap();
    assert!(!raw.contains("PRIVATE SUBJECT"));
    assert!(!raw.contains(&digest(b"PRIVATE RECIPIENT")));
    assert!(!raw.contains(&digest(b"PRIVATE LINK")));
    assert!(!raw.contains("private-correspondent"));
    assert!(!raw.contains(&first));
    assert!(raw.contains("newsletter"));
    let exported: Vec<serde_json::Value> = raw
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(exported[0]["decision_contract"], quality::recorded::SCHEMA);
    for row in &exported[1..exported.len() - 1] {
        assert_eq!(
            row["decision_snapshot"]["schema"],
            quality::recorded::SCHEMA
        );
        assert_eq!(row["legacy_decision"], row["decision_snapshot"]["engine"]);
    }

    assert!(
        evaluation::export(&store, "alice".into(), batch.clone(), &output)
            .await
            .is_err()
    );
    evaluation::label(&store, "alice".into(), first.clone(), Risk::Uncertain, None)
        .await
        .unwrap();
    let id = first.clone();
    store
        .run(move |db| {
            assert_eq!(
                db.query_row(
                    "SELECT COUNT(*) FROM feedback WHERE message_id=?1",
                    [id],
                    |r| r.get::<_, usize>(0)
                )?,
                0
            );
            Ok(())
        })
        .await
        .unwrap();
    store
        .run(|db| {
            db.execute("DELETE FROM grants WHERE username='alice'", [])?;
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(
        evaluation::readiness(&store, "alice".into(), batch.clone())
            .await
            .unwrap()["available"],
        0
    );
    assert!(
        evaluation::members(&store, "alice".into(), batch)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        evaluation::label(&store, "alice".into(), first, Risk::Spam, None)
            .await
            .is_err()
    );
}
#[tokio::test]
async fn sender_memory_needs_authentication_diversity_earlier_labels_and_matching_scope() {
    use noisefence::evidence::{AuthResult, Source, State};
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path()).unwrap();
    let cfg = common::config(root.path());
    account(&store, "reviewer", true, "").await;
    let mut scan = observed(&cfg);
    let auth = &mut scan.evidence.as_mut().unwrap().authentication;
    auth.dmarc_state = State::Complete;
    auth.dmarc_dkim = Some(AuthResult::Pass);
    let scope = vec!["example.test".into()];
    let now = noisefence::now();
    let empty = quality::history::inspect(root.path(), common::MESSAGE, &scan, &scope).await;
    assert!(!empty.established);
    assert!(empty.key.is_some());
    for i in 0..5 {
        let mut previous = scan.clone();
        previous.fingerprint = digest(format!("campaign-{i}").as_bytes());
        previous.sender_history = Some(empty.clone());
        let id = insert(
            &store,
            &previous,
            "alice@example.test",
            now - (i + 1) * 86400,
        )
        .await;
        store
            .run(move |db| {
                db.execute(
                    "INSERT INTO feedback VALUES('reviewer',?1,0,?2)",
                    params![id, now - 10],
                )?;
                Ok(())
            })
            .await
            .unwrap();
    }
    let established = quality::history::inspect(root.path(), common::MESSAGE, &scan, &scope).await;
    assert!(established.established);
    assert_eq!(established.legitimate_campaigns, 5);
    assert!(
        !quality::history::inspect(
            root.path(),
            common::MESSAGE,
            &scan,
            &["another.test".into()]
        )
        .await
        .established
    );
    scan.evidence.as_mut().unwrap().source = Source::SuppliedEnvelope;
    assert!(
        quality::history::inspect(root.path(), common::MESSAGE, &scan, &scope)
            .await
            .key
            .is_none()
    );
    scan.evidence.as_mut().unwrap().source = Source::SmtpSession;
    scan.evidence.as_mut().unwrap().authentication.dmarc_dkim = Some(AuthResult::Fail);
    assert!(
        quality::history::inspect(root.path(), common::MESSAGE, &scan, &scope)
            .await
            .key
            .is_none()
    );
}

#[test]
fn independent_kind_availability_never_discards_a_valid_risk_prediction() {
    let root = tempfile::tempdir().unwrap();
    let cfg = common::config(root.path());
    let report = quality::snapshot(&observed(&cfg), None);
    let mut candidate = model(&report);
    candidate.schema = "noisefence-quality-model-2".into();
    candidate.training_manifest_sha256 = Some(digest(b"private manifest"));
    candidate.kind_profiles = vec!["different_profile".into()];
    candidate.validate().unwrap();
    let prediction = candidate.predict(&report).unwrap();
    assert_eq!(prediction.risk_probability, 0.5);
    assert_eq!(prediction.kind, "unavailable");
    assert_eq!(prediction.kind_status, "unsupported_profile");
    assert!(prediction.kind_probabilities.is_empty());
    candidate.kind_models.clear();
    candidate.kinds.clear();
    candidate.kind_profiles.clear();
    candidate.validate().unwrap();
    assert_eq!(
        candidate.predict(&report).unwrap().kind_status,
        "not_trained"
    );
    candidate.training_manifest_sha256 = None;
    assert!(candidate.validate().is_err());
    candidate.schema = "noisefence-quality-model-1".into();
    assert!(candidate.validate().is_err());
}

#[test]
fn native_observations_are_calibration_inputs_without_recounting_the_legacy_model() {
    use noisefence::native_filter::{
        Runtime, Settings, Status,
        rules::{Family, Symbol},
    };
    let root = tempfile::tempdir().unwrap();
    let cfg = common::config(root.path());
    let mut scan = observed(&cfg);
    let native = Runtime::new(Settings::default()).unwrap();
    let before = quality::snapshot(&scan, None);
    let mut observation = native.offline(common::MESSAGE, &["example.test".into()]);
    observation.local_symbols = vec![Symbol {
        id: "NF_CREDENTIALS".into(),
        label: "request".into(),
        family: Family::Content,
        weight: 0.6,
        absorbed_by: vec![],
    }];
    observation.report.bayes.status = "complete".into();
    observation.report.bayes.raw_log_odds = Some(1000.);
    observation.report.bayes_sha256 = Some(digest(b"model"));
    native.finish(&mut observation, &scan);
    scan.native_filter = Some(observation);
    let active = serde_json::to_value(&scan.decision).unwrap();
    let after = quality::snapshot(&scan, None);
    let value = |r: &quality::Report, name: &str| {
        r.values[quality::specs()
            .iter()
            .position(|f| f.name == name)
            .unwrap()]
    };
    assert_eq!(value(&before, "native.state.disabled"), 1.);
    assert_eq!(value(&after, "native.state.complete"), 1.);
    assert!((value(&after, "native.content_points") - 0.12).abs() < 1e-10);
    assert_eq!(value(&after, "native.bayes.log_odds_clipped_32"), 1.);
    assert_ne!(before.artifacts_sha256, after.artifacts_sha256);
    assert_ne!(before.availability_profile, after.availability_profile);
    assert_eq!(serde_json::to_value(&scan.decision).unwrap(), active);
    for (a, b) in before
        .values
        .iter()
        .zip(&after.values)
        .zip(quality::specs())
        .filter(|(_, spec)| !spec.name.starts_with("native."))
    {
        assert_eq!(
            a.0, a.1,
            "native observations changed existing feature {}",
            b.name
        );
    }
    scan.native_filter.as_mut().unwrap().report.status = Status::Limited;
    let limited = quality::snapshot(&scan, None);
    assert_eq!(value(&limited, "native.state.limited"), 1.);
    assert_eq!(value(&limited, "native.content_points"), 0.);
    assert_eq!(value(&limited, "native.bayes.log_odds_clipped_32"), 0.);
    assert!(
        model(&after).predict(&limited).is_err(),
        "a missing control is a different availability profile"
    );
}

#[tokio::test]
async fn behavior_uses_operational_feedback_and_stays_out_of_delivery() {
    use noisefence::{
        config::Recipient,
        evidence::{AuthResult, State},
        native_filter, protection,
    };
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path()).unwrap();
    let cfg = common::config(root.path());
    account(&store, "reviewer", true, "").await;
    let mut scan = observed(&cfg);
    scan.evidence.as_mut().unwrap().authentication.dmarc_state = State::Complete;
    scan.evidence.as_mut().unwrap().authentication.dmarc_dkim = Some(AuthResult::Pass);
    {
        let a = &mut scan.evidence.as_mut().unwrap().authentication;
        a.state = State::Complete;
        a.spf_state = State::Complete;
        a.spf = Some(AuthResult::Pass);
        a.dkim_state = State::Complete;
        a.dkim = Some(vec![AuthResult::Pass]);
        a.dmarc_spf = Some(AuthResult::Pass);
    }
    scan.native_filter = Some(
        native_filter::Runtime::new(Default::default())
            .unwrap()
            .inspect(common::MESSAGE, &["example.test".into()])
            .await,
    );
    scan.protection = Some(protection::Report {
        local_status: protection::Status::Complete,
        ..Default::default()
    });
    let scope = vec!["example.test".into()];
    let recipient = Recipient {
        address: "alice@example.test".into(),
        destination: "alice@example.test".into(),
        hosts: vec![],
    };
    let mut targets = protection::Targets {
        urls: vec!["https://known.example.org/PRIVATE-PATH".into()],
        ..Default::default()
    };
    let initial = quality::history::inspect_with_context(
        root.path(),
        common::MESSAGE,
        &scan,
        &scope,
        std::slice::from_ref(&recipient),
        &targets,
    )
    .await;
    assert_eq!(
        initial.behavior.as_ref().unwrap().status,
        "insufficient_history"
    );
    let now = noisefence::now();
    for i in 0..5 {
        let mut previous = scan.clone();
        previous.fingerprint = digest(format!("behavior campaign {i}").as_bytes());
        previous.sender_history = Some(initial.clone());
        let id = insert(&store, &previous, &recipient.address, now - (i + 1) * 86400).await;
        store
            .run(move |db| {
                db.execute(
                    "INSERT INTO feedback VALUES('reviewer',?1,0,?2)",
                    params![id, now - 1],
                )?;
                Ok(())
            })
            .await
            .unwrap();
    }
    targets.urls = vec!["https://new.example.org/PRIVATE-PATH".into()];
    let mut bob = recipient.clone();
    bob.address = "bob@example.test".into();
    let history = quality::history::inspect_with_context(
        root.path(),
        common::MESSAGE,
        &scan,
        &scope,
        std::slice::from_ref(&bob),
        &targets,
    )
    .await;
    let b = history.behavior.as_ref().unwrap();
    assert_eq!(b.status, "complete");
    assert!(b.new_link_domain && b.new_recipient);
    scan.sender_history = Some(history);
    let before = serde_json::to_value(&scan).unwrap();
    let q = quality::snapshot(&scan, None);
    let at = |name: &str| {
        q.values[quality::specs()
            .iter()
            .position(|s| s.name == name)
            .unwrap()]
    };
    assert_eq!(at("behavior.new_link_domain"), 1.0);
    assert_eq!(at("behavior.new_recipient"), 1.0);
    assert_eq!(serde_json::to_value(&scan).unwrap(), before);
    let public = q.public().to_string();
    for private in [
        "PRIVATE-PATH",
        "example.org",
        "bob@example.test",
        "recipient\":\"",
        "sample",
    ] {
        assert!(!public.contains(private));
    }
    let shared = quality::history::inspect_with_context(
        root.path(),
        common::MESSAGE,
        &scan,
        &scope,
        &[recipient, bob],
        &targets,
    )
    .await;
    assert!(shared.behavior.unwrap().sample.is_none());
    let scoped = quality::history::inspect_with_context(
        root.path(),
        common::MESSAGE,
        &scan,
        &["elsewhere.test".into()],
        &[],
        &targets,
    )
    .await;
    assert_eq!(scoped.legitimate_campaigns, 0);
    store
        .run(|db| {
            db.execute("UPDATE users SET disabled=1 WHERE username='reviewer'", [])?;
            Ok(())
        })
        .await
        .unwrap();
    let revoked = quality::history::inspect(root.path(), common::MESSAGE, &scan, &scope).await;
    assert_eq!(revoked.legitimate_campaigns, 0);
}

#[tokio::test]
async fn evaluation_truth_never_changes_operational_feedback_and_protects_near_campaigns() {
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path()).unwrap();
    account(&store, "admin", true, "").await;
    let mut scan = observed(&common::config(root.path()));
    scan.quality = Some(quality::snapshot(&scan, None));
    let id = insert(&store, &scan, "alice@example.test", noisefence::now() - 100).await;
    store
        .feedback("admin".into(), id.clone(), true)
        .await
        .unwrap();
    evaluation::label(
        &store,
        "admin".into(),
        id.clone(),
        Risk::Legitimate,
        Some(Kind::Notification),
    )
    .await
    .unwrap();
    let batch = evaluation::sample(
        &store,
        "admin".into(),
        noisefence::now() - 200,
        noisefence::now(),
        50,
        String::new(),
    )
    .await
    .unwrap();
    let key = id.clone();
    store
        .run(move |db| {
            assert!(db.query_row(
                "SELECT spam FROM feedback WHERE message_id=?1",
                [&key],
                |r| r.get::<_, bool>(0)
            )?);
            assert_eq!(
                db.query_row(
                    "SELECT COUNT(*) FROM training_feedback WHERE message_id=?1",
                    [&key],
                    |r| r.get::<_, usize>(0)
                )?,
                0
            );
            let reserved = quality::reservations::Reserved::load(db)?;
            let mut similar = scan.clone();
            similar.fingerprint = digest(b"different exact campaign");
            similar.campaign_simhash = Some("abcdef0123456788".into());
            assert!(reserved.contains(&similar));
            similar.campaign_simhash = Some("0000000000000000".into());
            assert!(!reserved.contains(&similar));
            Ok(())
        })
        .await
        .unwrap();
    store
        .feedback("admin".into(), id.clone(), false)
        .await
        .unwrap();
    let reference = batch.clone();
    store
        .run(move |db| {
            db.execute(
                "INSERT INTO quality_reference_sets VALUES(?1,'confirmed by the user')",
                [&reference],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(
        evaluation::batches(&store, "admin".into()).await.unwrap()[0]["sampling"],
        "confirmed_regression"
    );
    let output = root.path().join("reference.jsonl");
    evaluation::export(&store, "admin".into(), batch.clone(), &output)
        .await
        .unwrap();
    let text = std::fs::read_to_string(output).unwrap();
    let header: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
    assert_eq!(header["sampling"], "confirmed_regression");
    assert_eq!(header["previously_examined"], true);
    let rows = evaluation::members(&store, "admin".into(), batch)
        .await
        .unwrap();
    assert_eq!(rows[0]["risk"], "legitimate");
    evaluation::label(&store, "admin".into(), id, Risk::Uncertain, None)
        .await
        .unwrap();
}

#[tokio::test]
async fn calibration_jobs_enforce_purpose_ownership_capacity_and_immutable_candidates() {
    use quality::{
        evaluation::Purpose,
        workflow::{self, Request},
    };
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path()).unwrap();
    account(&store, "admin", true, "").await;
    account(&store, "alice", false, "alice@example.test").await;
    let scan = observed(&common::config(root.path()));
    insert(&store, &scan, "alice@example.test", noisefence::now() - 50).await;
    let regression = evaluation::sample(
        &store,
        "admin".into(),
        noisefence::now() - 100,
        noisefence::now(),
        50,
        String::new(),
    )
    .await
    .unwrap();
    assert!(
        workflow::enqueue(
            &store,
            "admin".into(),
            Request {
                batch: regression.clone(),
                operation: "train".into(),
                candidate: None
            }
        )
        .await
        .is_err()
    );
    assert!(
        workflow::enqueue(
            &store,
            "alice".into(),
            Request {
                batch: regression.clone(),
                operation: "compare".into(),
                candidate: None
            }
        )
        .await
        .is_err()
    );
    let comparison = workflow::enqueue(
        &store,
        "admin".into(),
        Request {
            batch: regression.clone(),
            operation: "compare".into(),
            candidate: None,
        },
    )
    .await
    .unwrap();
    assert!(
        workflow::cancel(&store, "alice".into(), comparison.clone())
            .await
            .is_err()
    );
    workflow::cancel(&store, "admin".into(), comparison)
        .await
        .unwrap();
    let development = evaluation::sample_with_purpose(
        &store,
        "admin".into(),
        noisefence::now() - 100,
        noisefence::now(),
        50,
        String::new(),
        Purpose::Development,
        String::new(),
    )
    .await
    .unwrap();
    let job = workflow::enqueue(
        &store,
        "admin".into(),
        Request {
            batch: development.clone(),
            operation: "train".into(),
            candidate: None,
        },
    )
    .await
    .unwrap();
    assert!(
        workflow::enqueue(
            &store,
            "admin".into(),
            Request {
                batch: development,
                operation: "train".into(),
                candidate: None
            }
        )
        .await
        .is_err()
    );
    assert!(
        workflow::candidate(&store, root.path(), "admin".into(), job.clone())
            .await
            .is_err()
    );
    assert!(
        workflow::Selection {
            job: Some("../../config".into()),
            sha256: Some(digest(b"x"))
        }
        .path(root.path())
        .is_err()
    );
    let mut m = model(&quality::snapshot(&scan, None));
    m.schema = "noisefence-quality-model-2".into();
    m.training_manifest_sha256 = Some(digest(b"manifest"));
    m.kind_profiles = m.profiles.clone();
    let path = root
        .path()
        .join("calibration")
        .join(&job)
        .join("candidate/model.json");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let bytes = serde_json::to_vec(&m).unwrap();
    std::fs::write(&path, &bytes).unwrap();
    let hash = digest(&bytes);
    let key = job.clone();
    store
        .run(move |db| {
            db.execute(
                "UPDATE quality_jobs SET status='complete',model_sha256=?2 WHERE id=?1",
                params![key, hash],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    workflow::candidate(&store, root.path(), "admin".into(), job.clone())
        .await
        .unwrap();
    assert!(
        workflow::candidate(&store, root.path(), "alice".into(), job.clone())
            .await
            .is_err()
    );
    std::fs::write(&path, [bytes, b" ".to_vec()].concat()).unwrap();
    assert!(
        workflow::candidate(&store, root.path(), "admin".into(), job)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn release_readiness_is_scoped_cohort_specific_and_never_an_activation_certificate() {
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path()).unwrap();
    let cfg = common::config(root.path());
    account(&store, "alice", false, "alice@example.test").await;
    account(&store, "bob", false, "bob@example.test").await;
    let mut scan = observed(&cfg);
    scan.quality = Some(quality::snapshot(&scan, None));
    let cohort = scan.quality.as_ref().unwrap().artifacts_sha256.clone();
    let id = insert(&store, &scan, "alice@example.test", noisefence::now()).await;
    evaluation::label(&store, "alice".into(), id, Risk::Legitimate, None)
        .await
        .unwrap();
    insert(&store, &scan, "bob@example.test", noisefence::now()).await;
    insert(
        &store,
        &scan,
        "alice@example.test",
        noisefence::now() - 31 * 86400,
    )
    .await;
    let dsn = insert(&store, &scan, "alice@example.test", noisefence::now()).await;
    store
        .run(move |db| {
            db.execute("UPDATE messages SET is_dsn=1 WHERE id=?1", [dsn])?;
            Ok(())
        })
        .await
        .unwrap();
    scan.quality.as_mut().unwrap().artifacts_sha256 = digest(b"old");
    insert(&store, &scan, "alice@example.test", noisefence::now()).await;
    let r = quality::qualification::inspect(&store, "alice".into(), cohort.clone())
        .await
        .unwrap();
    assert_eq!(r.cohorts.len(), 2);
    assert_eq!(r.cohorts[&cohort].messages, 1);
    assert_eq!(r.cohorts[&cohort].wanted, 1);
    assert_eq!(r.cohorts[&cohort].usable, 1);
    assert_eq!(r.cohorts[&cohort].usable_wanted, 1);
    assert_eq!(r.schema, "noisefence-release-readiness-2");
    assert!(r.qualification_required && r.blockers.contains(&"independent_evaluation_required"));
    let bob = quality::qualification::inspect(&store, "bob".into(), cohort.clone())
        .await
        .unwrap();
    assert_eq!(bob.cohorts.len(), 1);
    assert_eq!(bob.cohorts[&cohort].wanted, 0);
    assert_eq!(bob.cohorts[&cohort].unlabelled, 1);
    assert!(
        !serde_json::to_string(&r)
            .unwrap()
            .contains("private-correspondent")
    );
}

#[test]
fn unsupported_llm_claims_are_diagnostic_only_and_do_not_enter_joint_features() {
    use noisefence::{evidence::State, llm};
    let root = tempfile::tempdir().unwrap();
    let mut scan = observed(&common::config(root.path()));
    scan.llm = llm::LlmResult {
        status: llm::LlmStatus::Complete,
        verdict: Some(llm::Verdict {
            category: llm::Category::Phishing,
            spam_probability: 0.99,
            confidence: 0.99,
            explanation: "Invented domain ownership".into(),
        }),
        grounding: Some(llm::grounding::Report {
            version: "llm-grounding-1".into(),
            supported: false,
            mail_kind: Kind::Notification,
            accepted_citations: 0,
            issues: vec![llm::grounding::Issue::OwnershipNotObserved],
        }),
        ..Default::default()
    };
    assert_eq!(scan.llm.advisory_weight(), 0.);
    assert_eq!(
        scan.llm.opinion(),
        Some(noisefence::fusion::runtime::Outcome::Undetermined)
    );
    let mut evidence = scan.evidence.take().unwrap();
    evidence.refresh(&scan);
    assert_eq!(evidence.llm.state, State::Unavailable);
    assert!(evidence.llm.category.is_none());
    assert!(evidence.llm.reported_probability.is_none());
    assert!(evidence.llm.reported_confidence.is_none());
    assert_eq!(scan.llm.status, llm::LlmStatus::Complete);
}

#[tokio::test]
async fn release_and_sample_readiness_share_eligibility_and_preserve_every_label() {
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path()).unwrap();
    let cfg = common::config(root.path());
    account(&store, "alice", false, "alice@example.test").await;
    account(&store, "bob", false, "bob@example.test").await;
    let now = noisefence::now();
    let mut original = observed(&cfg);
    original.quality = Some(quality::snapshot(&original, None));
    let cohort = original.quality.as_ref().unwrap().artifacts_sha256.clone();
    for risk in [
        Some(Risk::Legitimate),
        Some(Risk::Spam),
        Some(Risk::Uncertain),
        None,
    ] {
        let id = insert(&store, &original, "alice@example.test", now - 100).await;
        if let Some(risk) = risk {
            evaluation::label(&store, "alice".into(), id, risk, Some(Kind::Notification))
                .await
                .unwrap();
        }
    }
    // Known labels survive every exclusion. The same campaign intentionally
    // repeats: readiness counts do not claim independent campaigns or tests.
    type EligibilityCase = (&'static str, fn(&mut Scan));
    let cases: &[EligibilityCase] = &[
        ("incomplete_extraction", |s| {
            s.quality.as_mut().unwrap().complete_features = false
        }),
        ("unsupported_protocol", |s| {
            s.quality.as_mut().unwrap().protocol_sha256 = digest(b"old protocol")
        }),
        ("non_smtp_observation", |s| {
            s.quality.as_mut().unwrap().source = "supplied_envelope".into()
        }),
        ("invalid_observation", |s| {
            s.quality.as_mut().unwrap().schema = "unknown".into()
        }),
        ("invalid_features", |s| {
            s.quality.as_mut().unwrap().values.clear()
        }),
        ("invalid_features", |s| {
            s.quality.as_mut().unwrap().values[0] = 1e10
        }),
        ("missing_campaign_identity", |s| s.campaign_simhash = None),
        ("missing_campaign_identity", |s| s.fingerprint.clear()),
        ("invalid_provenance", |s| {
            s.quality.as_mut().unwrap().availability_profile = "PRIVATE INVALID PROFILE".into()
        }),
        ("invalid_provenance", |s| {
            s.quality.as_mut().unwrap().artifacts_sha256 = "PRIVATE INVALID COHORT".into()
        }),
        ("missing_observation", |s| s.quality = None),
        ("invalid_observation", |s| {
            s.quality.as_mut().unwrap().candidate_status = "PRIVATE".repeat(20000)
        }),
    ];
    let mut expected = std::collections::BTreeMap::new();
    for (reason, mutate) in cases {
        let mut scan = original.clone();
        mutate(&mut scan);
        let id = insert(&store, &scan, "alice@example.test", now - 100).await;
        evaluation::label(
            &store,
            "alice".into(),
            id,
            Risk::Legitimate,
            Some(Kind::Other),
        )
        .await
        .unwrap();
        *expected.entry(*reason).or_insert(0) += 1;
    }
    // A different recipient's labels cannot change Alice's numerators.
    let id = insert(&store, &original, "bob@example.test", now - 100).await;
    evaluation::label(&store, "bob".into(), id, Risk::Spam, None)
        .await
        .unwrap();
    let batch = evaluation::sample(
        &store,
        "alice".into(),
        now - 1000,
        now,
        50,
        "example.test".into(),
    )
    .await
    .unwrap();
    let release = quality::qualification::inspect(&store, "alice".into(), cohort.clone())
        .await
        .unwrap();
    let sample = evaluation::readiness(&store, "alice".into(), batch.clone())
        .await
        .unwrap();
    let counts = &release.cohorts[&cohort];
    assert_eq!(counts.usable, 4);
    assert_eq!(
        (
            counts.usable_wanted,
            counts.usable_unwanted,
            counts.usable_uncertain,
            counts.usable_unlabelled
        ),
        (1, 1, 1, 1)
    );
    assert_eq!(
        release.cohorts.values().map(|c| c.wanted).sum::<usize>(),
        cases.len() + 1
    );
    assert_eq!(
        release.cohorts.values().map(|c| c.messages).sum::<usize>(),
        cases.len() + 4
    );
    for c in release.cohorts.values() {
        assert_eq!(
            c.messages,
            c.wanted + c.unwanted + c.uncertain + c.unlabelled
        );
        assert_eq!(
            c.usable,
            c.usable_wanted + c.usable_unwanted + c.usable_uncertain + c.usable_unlabelled
        );
        assert_eq!(c.messages - c.usable, c.exclusions.values().sum::<usize>());
    }
    assert_eq!(sample["available"], cases.len() + 4);
    assert_eq!(sample["risk_labels"], cases.len() + 2);
    assert_eq!(sample["risk_with_observations"], 2);
    assert_eq!(sample["kind_with_observations"], 3);
    assert_eq!(sample["missing_or_incompatible_observations"], cases.len());
    assert_eq!(sample["exclusions"], json!(expected));
    let mut combined = std::collections::BTreeMap::<String, usize>::new();
    for c in release.cohorts.values() {
        for (reason, count) in serde_json::to_value(&c.exclusions)
            .unwrap()
            .as_object()
            .unwrap()
        {
            *combined.entry(reason.clone()).or_default() += count.as_u64().unwrap() as usize;
        }
    }
    assert_eq!(json!(combined), sample["exclusions"]);
    assert!(release.blockers.contains(&"insufficient_wanted_labels"));
    assert!(
        release
            .blockers
            .contains(&"independent_evaluation_required")
    );
    assert!(!serde_json::to_string(&release).unwrap().contains("PRIVATE"));
    assert!(!sample.to_string().contains("PRIVATE"));
    store
        .run(|db| {
            db.execute("DELETE FROM grants WHERE username='alice'", [])?;
            Ok(())
        })
        .await
        .unwrap();
    let revoked = quality::qualification::inspect(&store, "alice".into(), cohort)
        .await
        .unwrap();
    assert!(revoked.cohorts.is_empty());
    let revoked_sample = evaluation::readiness(&store, "alice".into(), batch)
        .await
        .unwrap();
    assert_eq!(revoked_sample["available"], 0);
    assert_eq!(revoked_sample["risk_with_observations"], 0);
}

#[test]
fn provider_features_and_native_context_share_frozen_eligibility_without_false_votes() {
    use noisefence::{
        native_filter::rules,
        observations,
        protection::{ProviderObservation, ProviderReport, Report, Status},
    };
    let root = tempfile::tempdir().unwrap();
    let mut scan = observed(&common::config(root.path()));
    let target = ProviderObservation {
        indicator_sha256: digest(b"host"),
        scope: "host_lookup".into(),
        verdict: "malicious".into(),
        queried_at: 1234,
        cached: false,
        cache_max_age_seconds: 0,
        analysis_max_age_seconds: None,
    };
    let mut protection = Report {
        crdf: ProviderReport {
            status: Status::Complete,
            captured_at: Some(1234),
            observations: vec![target.clone(), target],
            ..Default::default()
        },
        ..Default::default()
    };
    protection.add(
        "known_malicious_indicator",
        "link_reputation",
        "host",
        "crdf",
        "private response",
    );
    scan.protection = Some(protection);
    let value = |scan: &Scan, name: &str| {
        quality::snapshot(scan, None).values[quality::specs()
            .iter()
            .position(|f| f.name == name)
            .unwrap()]
    };
    let before = serde_json::to_value(&scan).unwrap();
    assert_eq!(value(&scan, "provider.crdf.host_lookup.malicious"), 1.);
    assert_eq!(value(&scan, "provider.shared_indicator_hits"), 0.);
    assert_eq!(
        rules::context(&scan)
            .iter()
            .filter(|s| s.id == "NF_MALICIOUS_INDICATOR")
            .count(),
        1
    );
    assert_eq!(serde_json::to_value(&scan).unwrap(), before);
    for invalid in [false, true] {
        let p = &mut scan.protection.as_mut().unwrap().crdf;
        if invalid {
            p.captured_at = None;
        } else {
            p.observations[1].verdict = "no_hit".into();
        }
        assert_eq!(value(&scan, "provider.crdf.host_lookup.malicious"), 0.);
        assert_eq!(value(&scan, "provider.shared_indicator_hits"), 0.);
        assert!(rules::context(&scan).is_empty());
        assert!(
            observations::capture(&scan)
                .observations
                .iter()
                .filter(|o| o.id.starts_with("crdf."))
                .all(|o| o.exclusion.is_some())
        );
    }
}
