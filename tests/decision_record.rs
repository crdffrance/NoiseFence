mod common;
use noisefence::{
    actions::{self, Action},
    assessment,
    config::Mode,
    decision_record::{self, Classification, Coverage},
    diagnostics::AnalysisPolicy,
    engine::Scan,
    fusion::runtime::Decision,
    mailing::Category,
};

fn recorded(config: &noisefence::config::Config, complete: bool) -> Scan {
    let mut scan = Scan {
        score: 99.,
        complete,
        features_complete: Some(true),
        model: "fixture".into(),
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
fn receipt_survives_serialization_live_configuration_and_observer_changes() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = (*common::config(dir.path())).clone();
    cfg.filter.threshold = 95.;
    cfg.filter.mode = Mode::Observe;
    for complete in [true, false] {
        let scan = recorded(&cfg, complete);
        let before = serde_json::to_value(assessment::historical(&scan)).unwrap();
        let mut restored: Scan =
            serde_json::from_slice(&serde_json::to_vec(&scan).unwrap()).unwrap();
        let mut changed = cfg.clone();
        changed.filter.threshold = 100.;
        changed.filter.mode = Mode::Enforce;
        restored.score = 0.;
        restored.decision = Some(Decision::legacy(&restored, 100.));
        restored.delivery_classification = Some(Category::Legitimate);
        restored.complete = !complete;
        decision_record::record_recipient(&mut restored, &changed, None, 5678);
        noisefence::decision::project_history(&mut restored, true, 100.);
        assert_eq!(
            serde_json::to_value(assessment::assess(&restored, 100.)).unwrap(),
            before
        );
        assert_eq!(
            actions::evaluate(&restored, &changed).effective,
            Action::Deliver
        );
        assert_eq!(
            noisefence::mailing::category(&restored, 100.),
            Category::Spam
        );
        assert_eq!(
            restored.recipient_decision.as_ref().unwrap().recorded_at,
            1234
        );
    }
}

#[test]
fn failed_content_is_unassessed_without_suppressing_malware_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = common::config(dir.path());
    for malware in [false, true] {
        let mut scan = Scan {
            features_complete: Some(false),
            ..Default::default()
        };
        if malware {
            scan.antivirus.status = noisefence::antivirus::AntivirusStatus::Malware;
        }
        scan.decision = Some(Decision::legacy(&scan, cfg.filter.threshold));
        noisefence::decision::apply(&mut scan, false);
        noisefence::decision::resolve_by_score(&mut scan, true, cfg.filter.threshold);
        scan.action = Some(actions::evaluate(&scan, &cfg));
        decision_record::record_recipient(&mut scan, &cfg, None, 1234);
        let record = scan.recipient_decision.unwrap();
        assert_eq!(record.assessment.score.value, None);
        assert_eq!(
            record.classification,
            if malware {
                Classification::Malware
            } else {
                Classification::Unassessed
            }
        );
        assert_eq!(record.coverage, Coverage::Unavailable);
        assert_eq!(record.assessment.action.unwrap().effective, Action::Deliver);
    }
}

#[test]
fn legacy_without_a_policy_never_borrows_the_live_threshold() {
    let scan = Scan {
        score: 99.,
        complete: true,
        ..Default::default()
    };
    let view = assessment::historical(&scan);
    assert_eq!(view.category, Category::Undetermined);
    assert_eq!(view.content_threshold, None);
    assert!(!view.decision_recorded);
    assert_eq!(view.score.value, Some(99.));
}

#[tokio::test]
async fn persisted_views_filters_and_numeric_search_use_the_same_receipt() {
    use noisefence::{api, search::Search, store::Store};
    let dir = tempfile::tempdir().unwrap();
    let cfg = common::config(dir.path());
    let store = Store::open(dir.path()).unwrap();
    api::create_user(
        &store,
        "alice".into(),
        "test-password-123456".into(),
        vec!["alice@example.test".into()],
        false,
    )
    .await
    .unwrap();
    for (id, address) in [
        ("visible", "alice@example.test"),
        ("private", "bob@example.test"),
    ] {
        store
            .enqueue(
                id.into(),
                "sender@example.org".into(),
                vec![cfg.recipient(address).unwrap()],
                recorded(&cfg, false),
                common::MESSAGE.to_vec(),
            )
            .await
            .unwrap();
    }
    for threshold in [0., 100.] {
        for resolve in [false, true] {
            let page = store
                .search_messages_with_policy(
                    "alice".into(),
                    Search {
                        filter: "spam".into(),
                        min_score: Some(99.),
                        max_score: Some(99.),
                        ..Default::default()
                    },
                    threshold,
                    resolve,
                )
                .await
                .unwrap();
            assert_eq!(page.total, 1);
            assert_eq!(page.messages[0].id, "visible");
            let view = &page.messages[0].assessment;
            assert_eq!(view.category, Category::Spam);
            assert_eq!(view.score.value, Some(99.));
            assert!(!view.complete);
            assert_eq!(view.action.as_ref().unwrap().effective, Action::Deliver);
            let detail = store
                .diagnostics_for_with_policy(
                    "alice".into(),
                    "visible".into(),
                    None,
                    resolve,
                    threshold,
                )
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                serde_json::to_value(&detail.analysis.assessment).unwrap(),
                serde_json::to_value(view).unwrap()
            );
            assert!(
                store
                    .diagnostics("alice".into(), "private".into())
                    .await
                    .unwrap()
                    .is_none()
            );
        }
    }
}
