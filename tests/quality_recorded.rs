#[allow(dead_code)]
mod common;
use noisefence::{
    actions::{self, Action},
    config::Mode,
    decision_record,
    diagnostics::AnalysisPolicy,
    engine::Scan,
    fusion::runtime::Decision,
    mailing::Category,
    quality::recorded,
};
use serde_json::json;

fn receipt(config: &noisefence::config::Config, complete: bool) -> Scan {
    let mut scan = Scan {
        score: 99.,
        complete,
        features_complete: Some(true),
        analysis_policy: Some(AnalysisPolicy::capture(config)),
        ..Default::default()
    };
    scan.decision = Some(Decision::legacy(&scan, config.filter.threshold));
    noisefence::decision::resolve_by_score(&mut scan, true, config.filter.threshold);
    scan.action = Some(actions::evaluate(&scan, config));
    decision_record::record_recipient(&mut scan, config, None, 1234);
    scan
}

#[test]
fn exports_frozen_verdicts_despite_later_mutable_fields_and_partial_coverage() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = (*common::config(dir.path())).clone();
    cfg.filter.mode = Mode::Observe;
    for complete in [true, false] {
        let mut scan = receipt(&cfg, complete);
        let expected = recorded::snapshot(&scan);
        assert_eq!(expected["engine"]["outcome"], "unwanted");
        assert_eq!(expected["engine"]["complete"], complete);
        assert_eq!(expected["final"]["category"], "spam");
        assert_eq!(expected["action"]["effective"], "deliver");
        scan.score = 0.;
        scan.complete = !complete;
        scan.decision = Some(Decision::legacy(&scan, 100.));
        scan.delivery_classification = Some(Category::Legitimate);
        scan.action = None;
        let restored: Scan = serde_json::from_value(serde_json::to_value(scan).unwrap()).unwrap();
        assert_eq!(recorded::snapshot(&restored), expected);
    }
}

#[test]
fn recipient_override_and_actions_are_distinct_from_engine_and_privacy_safe() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = common::config(dir.path());
    let mut scan = receipt(&cfg, false);
    scan.recipient_decision = None;
    let policy = noisefence::custom_filtering::Assessment {
        trace: None,
        policy: "PRIVATE POLICY".into(),
        profile: Some("PRIVATE PROFILE".into()),
        threshold: 100.,
        original_category: Category::Spam,
        category: Category::Legitimate,
        matched: vec![],
        unavailable_conditions: 0,
        action: actions::Applied {
            coverage: None,
            requested: Action::Tag,
            effective: Action::Deliver,
            reason: "PRIVATE REASON".into(),
            quarantine_days: 7,
        },
    };
    decision_record::record_recipient(&mut scan, &cfg, Some(&policy), 1234);
    let result = recorded::snapshot(&scan);
    assert_eq!(result["engine"]["outcome"], "unwanted");
    assert_eq!(result["final"]["classification"], "legitimate");
    assert_eq!(result["final"]["classification_source"], "recipient_policy");
    assert_eq!(
        result["action"],
        json!({"requested":"tag", "effective":"deliver"})
    );
    assert!(!result.to_string().contains("PRIVATE"));
    let shared: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/recorded-decisions.json")).unwrap();
    assert_eq!(result, shared);
}

#[test]
fn invalid_receipt_is_explicitly_missing_not_replaced_by_legacy_result() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = common::config(dir.path());
    let mut scan = receipt(&cfg, true);
    scan.analysis_result.as_mut().unwrap().version = u32::MAX;
    assert_eq!(
        recorded::snapshot(&scan),
        json!({"schema":recorded::SCHEMA,
        "provenance":"invalid", "engine":null, "final":null, "action":null})
    );
}

#[test]
fn missing_scores_and_legacy_decisions_are_not_invented() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = common::config(dir.path());
    let mut scan = Scan {
        features_complete: Some(false),
        ..Default::default()
    };
    scan.action = Some(actions::evaluate(&scan, &cfg));
    decision_record::record_recipient(&mut scan, &cfg, None, 1234);
    let result = recorded::snapshot(&scan);
    assert!(result["final"]["score"].is_null());
    assert!(result["engine"]["raw_score"].is_null());
    assert_eq!(result["final"]["classification"], "unassessed");
    assert_eq!(result["action"]["effective"], "deliver");
    let legacy = recorded::snapshot(&Scan {
        score: 99.,
        complete: true,
        ..Default::default()
    });
    assert_eq!(legacy["provenance"], "legacy");
    assert!(legacy["engine"].is_null());
    assert!(legacy["action"].is_null());
    assert_eq!(legacy["final"]["category"], "undetermined");
}

#[tokio::test]
async fn population_export_preserves_receipts_and_quarantining_is_not_delivery_completion() {
    use noisefence::{api, population, search::Search, store::Store};
    let dir = tempfile::tempdir().unwrap();
    let cfg = common::config(dir.path());
    let store = Store::open(dir.path()).unwrap();
    api::create_user(
        &store,
        "alice".into(),
        uuid::Uuid::new_v4().to_string(),
        vec!["alice@example.test".into()],
        false,
    )
    .await
    .unwrap();
    for (id, category) in [
        ("override", Category::Legitimate),
        ("spam", Category::Spam),
        ("pub", Category::Publicity),
    ] {
        let mut scan = receipt(&cfg, false);
        scan.recipient_decision = None;
        let policy = noisefence::custom_filtering::Assessment {
            trace: None,
            policy: "PRIVATE POLICY".into(),
            profile: None,
            threshold: 95.,
            original_category: Category::Spam,
            category,
            matched: vec![],
            unavailable_conditions: 0,
            action: actions::Applied {
                coverage: None,
                requested: Action::Quarantine,
                effective: Action::Deliver,
                reason: "observation".into(),
                quarantine_days: 14,
            },
        };
        decision_record::record_recipient(&mut scan, &cfg, Some(&policy), 1234);
        // Old fields can evolve on retry/history updates. Receipt remains authoritative.
        scan.score = 0.;
        scan.complete = true;
        scan.decision = Some(Decision::legacy(&scan, 100.));
        scan.delivery_classification = Some(Category::Spam);
        let expected = recorded::snapshot(&scan);
        store
            .enqueue(
                id.into(),
                "PRIVATE SENDER".into(),
                vec![cfg.recipient("alice@example.test").unwrap()],
                scan,
                common::MESSAGE.to_vec(),
            )
            .await
            .unwrap();
        let detail = store
            .diagnostics("alice".into(), id.into())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            serde_json::to_value(detail.analysis.assessment.category).unwrap(),
            expected["final"]["category"]
        );
        let list = store
            .search_messages_with_policy(
                "alice".into(),
                Search {
                    filter: category.as_str().into(),
                    ..Default::default()
                },
                0.,
                false,
            )
            .await
            .unwrap();
        assert!(list.messages.iter().any(|m| m.id == id));
    }
    let output = dir.path().join("population.jsonl");
    population::export(
        &store,
        &output,
        noisefence::now() - 60,
        noisefence::now() + 1,
    )
    .await
    .unwrap();
    let text = std::fs::read_to_string(&output).unwrap();
    assert!(!text.contains("PRIVATE"));
    let rows: Vec<serde_json::Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(rows[0]["schema"], population::SCHEMA);
    for (id, category) in [
        ("override", "legitimate"),
        ("spam", "spam"),
        ("pub", "publicity"),
    ] {
        let row = rows
            .iter()
            .find(|r| r["id"] == noisefence::message::digest(id.as_bytes()))
            .unwrap();
        assert_eq!(row["decision"]["outcome"], "legitimate"); // legacy diagnostic field only
        let snapshot = &row["decision_snapshot"];
        assert_eq!(snapshot["engine"]["outcome"], "unwanted");
        assert_eq!(snapshot["final"]["category"], category);
        assert_eq!(snapshot["final"]["score"], 99.);
        assert_eq!(snapshot["final"]["complete"], false);
        assert_eq!(
            snapshot["action"],
            json!({"requested":"quarantine","effective":"deliver"})
        );
        let parsed: recorded::contract::Snapshot =
            serde_json::from_value(snapshot.clone()).unwrap();
        parsed.validate().unwrap();
    }
}
