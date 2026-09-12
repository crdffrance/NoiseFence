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
            observations: vec![observation.clone()],
            ..Default::default()
        },
        virustotal: ProviderReport {
            status: Status::Complete,
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
    assert!(!raw.contains("private-correspondent"));
    assert!(!raw.contains(&first));
    assert!(raw.contains("newsletter"));
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
