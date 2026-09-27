mod common;
use noisefence::{
    assessment, decision,
    engine::Scan,
    fusion::runtime::{Decision, DecisionSource, Outcome},
    mailing::Category,
};

fn review(score: f64, complete: bool) -> Scan {
    Scan {
        score,
        complete,
        features_complete: Some(true),
        model: "fixture".into(),
        decision: Some(Decision {
            source: DecisionSource::Legacy,
            outcome: Outcome::Undetermined,
            score: None,
            model: "fixture".into(),
        }),
        ..Default::default()
    }
}

#[test]
fn threshold_resolves_uncertainty_without_changing_evidence_or_coverage() {
    let root = tempfile::tempdir().unwrap();
    let mut cfg = (*common::config(root.path())).clone();
    cfg.filter.mode = noisefence::config::Mode::Enforce;
    for complete in [false, true] {
        for score in [0., 94.999, 95., 99.8, 100.] {
            let mut s = review(score, complete);
            let previous = s.decision.clone().unwrap();
            decision::resolve_by_score(&mut s, true, 95.);
            assert_eq!(
                s.decision.as_ref().unwrap().outcome,
                if score >= 95. {
                    Outcome::Unwanted
                } else {
                    Outcome::Legitimate
                }
            );
            assert_eq!(s.score, score);
            assert_eq!(s.complete, complete);
            let resolution = s.score_resolution.as_ref().unwrap();
            assert_eq!(resolution.previous, previous);
            assert_eq!(resolution.partial, !complete);
            assert_ne!(assessment::assess(&s, 95.).category, Category::Undetermined);
            if !complete {
                assert_eq!(
                    noisefence::actions::evaluate(&s, &cfg).effective,
                    noisefence::actions::Action::Deliver
                );
            }
            let once = serde_json::to_value(&s).unwrap();
            decision::resolve_by_score(&mut s, true, 95.);
            assert_eq!(serde_json::to_value(&s).unwrap(), once);
            decision::resolve_by_score(&mut s, false, 95.);
            assert_eq!(s.decision, Some(previous));
            assert!(s.score_resolution.is_none());
        }
    }
}

#[test]
fn no_score_fails_open_and_never_invents_a_zero_or_overrides_malware() {
    for score in [f64::NAN, f64::INFINITY, -1., 101.] {
        let mut s = review(score, false);
        decision::resolve_by_score(&mut s, true, 95.);
        assert_eq!(s.decision.unwrap().outcome, Outcome::Legitimate);
        assert_eq!(s.score_resolution.unwrap().score, None);
    }
    let mut s = review(0., false);
    s.features_complete = Some(false);
    decision::resolve_by_score(&mut s, true, 0.);
    let a = assessment::assess(&s, 0.);
    assert_eq!(a.score.value, None);
    assert_eq!(a.category, Category::Legitimate);
    let mut s = review(0., false);
    s.decision.as_mut().unwrap().source = DecisionSource::Antivirus;
    s.decision.as_mut().unwrap().outcome = Outcome::Unwanted;
    decision::resolve_by_score(&mut s, true, 95.);
    assert!(s.score_resolution.is_none());
    assert_eq!(s.decision.unwrap().outcome, Outcome::Unwanted);
}

#[test]
fn disagreement_resolves_once_and_keeps_the_original_opinions() {
    use noisefence::llm::{Category as LlmCategory, LlmResult, LlmStatus, Verdict};
    let mut s = review(99.8, true);
    s.decision = Some(Decision::legacy(&s, 95.));
    s.llm = LlmResult {
        status: LlmStatus::Complete,
        verdict: Some(Verdict {
            category: LlmCategory::Legitimate,
            spam_probability: 0.1,
            confidence: 0.95,
            explanation: "Fixture".into(),
        }),
        ..Default::default()
    };
    decision::apply(&mut s, false);
    assert_eq!(s.decision.as_ref().unwrap().outcome, Outcome::Undetermined);
    decision::resolve_by_score(&mut s, true, 95.);
    assert_eq!(s.decision.as_ref().unwrap().outcome, Outcome::Unwanted);
    assert_eq!(s.arbitration.as_ref().unwrap().opinion, Outcome::Legitimate);
    let once = serde_json::to_value(&s).unwrap();
    decision::apply(&mut s, false);
    decision::resolve_by_score(&mut s, true, 95.);
    assert_eq!(serde_json::to_value(&s).unwrap(), once);
}

#[tokio::test]
async fn historical_search_projection_matches_totals_and_preserves_private_rows_and_deliveries() {
    use noisefence::{api, search::Search, store::Store};
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path()).unwrap();
    let cfg = common::config(root.path());
    api::create_user(
        &store,
        "alice".into(),
        "test-password-123456".into(),
        vec!["alice@example.test".into()],
        false,
    )
    .await
    .unwrap();
    for (id, score, complete, recipient, pub_mail) in [
        ("high", 99.8, true, "alice@example.test", false),
        ("low", 80., true, "alice@example.test", false),
        ("partial", 99., false, "alice@example.test", false),
        ("marketing", 60., true, "alice@example.test", true),
        ("hidden", 99.9, true, "bob@example.test", false),
    ] {
        let mut scan = review(score, complete);
        let mut policy = noisefence::diagnostics::AnalysisPolicy::capture(&cfg);
        policy.threshold = 95.;
        scan.analysis_policy = Some(policy);
        if pub_mail {
            scan.delivery_classification = Some(Category::Undetermined);
            scan.mailing=Some(noisefence::mailing::inspect(b"Subject: Offre exclusive\r\nList-Unsubscribe: <https://example.org/unsubscribe>\r\n\r\nProfitez de nos offres exclusives. Achetez maintenant avec 50% de reduction.",&Default::default(),10000));
        }
        store
            .enqueue(
                id.into(),
                "sender@example.org".into(),
                vec![cfg.recipient(recipient).unwrap()],
                scan,
                common::MESSAGE.to_vec(),
            )
            .await
            .unwrap();
    }
    let before = store
        .read(|db| {
            Ok(db
                .prepare("SELECT scan FROM messages ORDER BY id")?
                .query_map([], |r| r.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?)
        })
        .await
        .unwrap();
    for (filter, expected) in [
        ("all", 4),
        ("spam", 2),
        ("legitimate", 1),
        ("publicity", 1),
        ("review", 0),
        ("incomplete", 1),
    ] {
        let page = store
            .search_messages_with_policy(
                "alice".into(),
                Search {
                    filter: filter.into(),
                    ..Default::default()
                },
                50.,
                true,
            )
            .await
            .unwrap();
        assert_eq!(page.total, expected, "{filter}");
        assert_eq!(page.messages.len() as u64, expected);
        for m in page.messages {
            assert_ne!(m.id, "hidden");
            assert_ne!(m.category, Category::Undetermined);
            assert!(m.assessment.score_resolution.as_ref().unwrap().projected);
            assert!(!m.assessment.decision_recorded);
            assert_eq!(
                m.assessment.score_resolution.as_ref().unwrap().threshold,
                95.
            );
        }
    }
    let diagnostics = store
        .diagnostics_for_with_policy("alice".into(), "high".into(), None, true, 50.)
        .await
        .unwrap()
        .unwrap();
    assert!(diagnostics.analysis.score_resolution.unwrap().projected);
    assert!(
        store
            .diagnostics_for_with_policy("alice".into(), "hidden".into(), None, true, 50.)
            .await
            .unwrap()
            .is_none()
    );
    let after = store
        .read(|db| {
            Ok(db
                .prepare("SELECT scan FROM messages ORDER BY id")?
                .query_map([], |r| r.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?)
        })
        .await
        .unwrap();
    assert_eq!(before, after);
    let pending = store
        .read(|db| {
            Ok(db.query_row(
                "SELECT COUNT(*) FROM deliveries WHERE status='pending'",
                [],
                |r| r.get::<_, u64>(0),
            )?)
        })
        .await
        .unwrap();
    assert_eq!(pending, 5);
}

#[test]
fn offline_pipeline_records_operator_policy_and_resolves_missing_confirmation() {
    let root = tempfile::tempdir().unwrap();
    let mut cfg = (*common::config(root.path())).clone();
    cfg.filter.threshold = 0.;
    cfg.filter.require_corroboration = true;
    cfg.filter.resolve_uncertain_by_score = true;
    let engine = noisefence::engine::Engine::new(std::sync::Arc::new(cfg)).unwrap();
    let scan = engine.offline(common::MESSAGE);
    assert_eq!(scan.decision.as_ref().unwrap().outcome, Outcome::Unwanted);
    assert!(scan.score_resolution.is_some());
    assert!(scan.analysis_policy.unwrap().resolve_uncertain_by_score);
}
