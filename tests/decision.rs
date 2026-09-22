mod common;
use noisefence::{
    antivirus::{AntivirusResult, AntivirusStatus as Av},
    config::Mode,
    decision,
    engine::Scan,
    fusion::runtime::{Decision, DecisionSource, Outcome},
    llm::{Category as LlmCategory, LlmResult, LlmStatus, Verdict as LlmVerdict},
    mailing::{self, Category},
    message::SubjectTag,
};

const PROMOTION: &[u8] = b"Subject: Offres exclusives\r\nList-Unsubscribe: <https://example.org/unsubscribe>\r\n\r\nProfitez de nos offres exclusives. Achetez maintenant avec 50% de reduction.\r\n";

#[test]
fn malware_priority_is_stable_across_scores_fusion_advice_and_mailing() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = (*common::config(dir.path())).clone();
    cfg.mailing = Some(mailing::Settings::default());
    let publicity = mailing::inspect(PROMOTION, &mailing::Policy::default(), 10000);
    assert!(publicity.is_publicity());
    for complete in [false, true] {
        for source in [DecisionSource::Legacy, DecisionSource::Fusion] {
            for outcome in [
                Outcome::Legitimate,
                Outcome::Unwanted,
                Outcome::Undetermined,
            ] {
                for score in [0., 94.9, 95., 100.] {
                    for confirmation in [false, true] {
                        let mut scan = Scan {
                            complete,
                            score,
                            antivirus: AntivirusResult {
                                status: Av::Malware,
                                signature: Some("Test.Malware".into()),
                                ..Default::default()
                            },
                            mailing: Some(publicity.clone()),
                            llm: LlmResult {
                                status: LlmStatus::Complete,
                                verdict: Some(LlmVerdict {
                                    category: LlmCategory::Legitimate,
                                    confidence: 1.,
                                    spam_probability: 0.,
                                    explanation: "Contradictory advice fixture".into(),
                                }),
                                ..Default::default()
                            },
                            decision: Some(Decision {
                                source,
                                outcome,
                                score: complete.then_some(score),
                                model: "fixture".into(),
                            }),
                            ..Default::default()
                        };
                        let features = scan.features.clone();
                        decision::apply(&mut scan, confirmation);
                        assert_eq!(scan.complete, complete);
                        assert_eq!(scan.score, score);
                        assert_eq!(scan.features, features);
                        assert_eq!(mailing::category(&scan, 95.), Category::Spam);
                        let d = scan.decision.as_ref().unwrap();
                        assert_eq!(d.source, DecisionSource::Antivirus);
                        assert_eq!(d.outcome, Outcome::Unwanted);
                        assert!(d.score.is_none());
                        assert!(!scan.pub_tagged);
                        for mode in [Mode::Observe, Mode::Tag] {
                            cfg.filter.mode = mode;
                            assert_eq!(
                                decision::subject_tag(&scan, &cfg),
                                (complete && mode == Mode::Tag).then_some(SubjectTag::Spam)
                            );
                        }
                        let once = serde_json::to_value(&scan).unwrap();
                        decision::apply(&mut scan, confirmation);
                        assert_eq!(serde_json::to_value(scan).unwrap(), once);
                    }
                }
            }
        }
    }
}

#[test]
fn advisory_signatures_and_publicity_never_override_security_decisions() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = (*common::config(dir.path())).clone();
    cfg.mailing = Some(mailing::Settings::default());
    cfg.filter.mode = Mode::Tag;
    for av in [
        Av::Clean,
        Av::Disabled,
        Av::Suspicious,
        Av::Unscannable,
        Av::Unavailable,
    ] {
        for (score, complete, expected) in [
            (1., true, Category::Publicity),
            (99., true, Category::Undetermined),
            (99., false, Category::Undetermined),
        ] {
            let complete = complete && !matches!(av, Av::Unscannable | Av::Unavailable);
            let expected = if complete {
                expected
            } else {
                Category::Undetermined
            };
            let mut scan = Scan {
                score,
                complete,
                antivirus: AntivirusResult {
                    status: av.clone(),
                    ..Default::default()
                },
                signatures: AntivirusResult {
                    status: Av::Malware,
                    ..Default::default()
                },
                mailing: Some(mailing::inspect(
                    PROMOTION,
                    &mailing::Policy::default(),
                    10000,
                )),
                ..Default::default()
            };
            scan.decision = Some(Decision::legacy(&scan, 95.));
            decision::apply(&mut scan, true);
            assert_eq!(mailing::category(&scan, 95.), expected);
            assert_eq!(
                decision::subject_tag(&scan, &cfg),
                (expected == Category::Publicity).then_some(SubjectTag::Publicity)
            );
            assert!(
                !scan
                    .reasons
                    .iter()
                    .any(|r| r.id == decision::MALWARE_REASON)
            );
        }
    }
}

#[test]
fn llm_scoring_validates_advice_but_cannot_supply_its_own_confirmation() {
    for (category, confidence, probability, expected) in [
        (LlmCategory::Spam, 0.9, 0.9, 1.5),
        (LlmCategory::Phishing, 1., 1., 1.5),
        (LlmCategory::Spam, 0.899, 0.99, 0.),
        (LlmCategory::Spam, 0.99, 0.899, 0.),
        (LlmCategory::Legitimate, 0.95, 0.1, -0.5),
        (LlmCategory::Legitimate, 1., 1., 0.),
        (LlmCategory::Ambiguous, 1., 1., 0.),
        (LlmCategory::Spam, 1.01, 1., 0.),
        (LlmCategory::Spam, f64::NAN, 1., 0.),
        (LlmCategory::Legitimate, 1., -0.1, 0.),
    ] {
        for status in [
            LlmStatus::Complete,
            LlmStatus::Unavailable,
            LlmStatus::NotNeeded,
            LlmStatus::Disabled,
            LlmStatus::Busy,
            LlmStatus::BudgetLimited,
            LlmStatus::PricingExpired,
        ] {
            let weight = if status == LlmStatus::Complete {
                expected
            } else {
                0.
            };
            let scan = Scan {
                llm: LlmResult {
                    status,
                    verdict: Some(LlmVerdict {
                        category: category.clone(),
                        confidence,
                        spam_probability: probability,
                        explanation: "Fixture".into(),
                    }),
                    ..Default::default()
                },
                ..Default::default()
            };
            assert_eq!(scan.llm.advisory_weight(), weight);
            assert!(!noisefence::confirmation::corroborated(&scan));
        }
    }
}

#[test]
fn ip_policy_lists_and_errors_never_receive_malicious_reputation_weight() {
    use noisefence::evidence::{self, Query, Source, State};
    let dir = tempfile::tempdir().unwrap();
    let cfg = common::config(dir.path());
    for (codes, malicious) in [
        (vec!["127.0.0.2"], true),
        (vec!["127.0.0.3", "127.0.0.4", "127.0.0.9"], true),
        (vec!["127.0.0.10", "127.0.0.11", "127.0.0.30"], false),
        (vec!["127.0.0.2", "127.0.0.11"], true),
        (vec!["127.0.0.2", "127.255.255.250"], false),
        (vec!["127.0.1.4"], false),
        (vec![], false),
    ] {
        let codes: Vec<_> = codes.iter().map(|c| c.parse().unwrap()).collect();
        assert_eq!(evidence::malicious_ip(&codes), malicious);
        let mut e = evidence::Evidence::new(
            &cfg,
            evidence::Artifacts::new(&cfg, None, None, false),
            false,
        );
        e.source = Source::SmtpSession;
        e.reputation.ip = Query {
            state: State::Complete,
            codes,
        };
        let scan = Scan {
            evidence: Some(e),
            ..noisefence::engine::extract(common::MESSAGE, 10000)
        };
        assert_eq!(noisefence::confirmation::corroborated(&scan), malicious);
    }
}

fn advice_scan(score: f64, category: LlmCategory) -> Scan {
    let probability = match category {
        LlmCategory::Legitimate => 0.05,
        LlmCategory::Spam | LlmCategory::Phishing => 0.95,
        LlmCategory::Ambiguous => 0.5,
    };
    let mut scan = Scan {
        score,
        complete: true,
        tagged: true,
        pub_tagged: true,
        features: vec![(3, 2.)],
        model: "uncalibrated-fixture".into(),
        llm: LlmResult {
            status: LlmStatus::Complete,
            verdict: Some(LlmVerdict {
                category,
                confidence: 0.95,
                spam_probability: probability,
                explanation: "Fixture".into(),
            }),
            ..Default::default()
        },
        ..Default::default()
    };
    scan.decision = Some(Decision::legacy(&scan, 95.));
    scan
}

#[test]
fn conflicting_advice_abstains_in_both_directions_without_relabelling_or_rescoring() {
    for (score, advice) in [
        (99.999, LlmCategory::Legitimate),
        (10., LlmCategory::Phishing),
        (10., LlmCategory::Spam),
        (99., LlmCategory::Ambiguous),
        (10., LlmCategory::Ambiguous),
    ] {
        for confirmation in [false, true] {
            let mut scan = advice_scan(score, advice.clone());
            let baseline = scan.decision.clone();
            decision::apply(&mut scan, confirmation);
            assert_eq!(
                scan.decision.as_ref().unwrap().outcome,
                Outcome::Undetermined
            );
            assert_eq!(scan.decision.as_ref().unwrap().score, None);
            assert_eq!(scan.score, score);
            assert_eq!(scan.features, vec![(3, 2.)]);
            assert!(scan.complete);
            assert!(!scan.tagged && !scan.pub_tagged);
            assert_eq!(
                Some(scan.arbitration.as_ref().unwrap().baseline.clone()),
                baseline
            );
            let once = serde_json::to_value(&scan).unwrap();
            decision::apply(&mut scan, confirmation);
            assert_eq!(serde_json::to_value(&scan).unwrap(), once);
            let restored: Scan = serde_json::from_value(once.clone()).unwrap();
            assert_eq!(serde_json::to_value(restored).unwrap(), once);
        }
    }
}

#[test]
fn agreement_never_counts_as_independent_confirmation_and_can_be_reapplied() {
    let mut scan = advice_scan(99., LlmCategory::Spam);
    decision::apply(&mut scan, false);
    assert_eq!(scan.decision.as_ref().unwrap().outcome, Outcome::Unwanted);
    decision::apply(&mut scan, true);
    assert_eq!(
        scan.decision.as_ref().unwrap().outcome,
        Outcome::Undetermined
    );
    let once = serde_json::to_value(&scan).unwrap();
    decision::apply(&mut scan, true);
    assert_eq!(serde_json::to_value(&scan).unwrap(), once);
    decision::apply(&mut scan, false);
    assert_eq!(scan.decision.as_ref().unwrap().outcome, Outcome::Unwanted);
    assert!(
        !scan
            .reasons
            .iter()
            .any(|r| r.id == noisefence::confirmation::REVIEW_REASON)
    );
    scan.llm.verdict.as_mut().unwrap().category = LlmCategory::Legitimate;
    scan.llm.verdict.as_mut().unwrap().spam_probability = 0.;
    decision::apply(&mut scan, false);
    assert_eq!(
        scan.decision.as_ref().unwrap().outcome,
        Outcome::Undetermined
    );
}

#[test]
fn unavailable_invalid_and_unselected_advice_cannot_change_a_decision() {
    for status in [
        LlmStatus::Disabled,
        LlmStatus::NotNeeded,
        LlmStatus::Busy,
        LlmStatus::BudgetLimited,
        LlmStatus::PricingExpired,
        LlmStatus::Unavailable,
    ] {
        let mut scan = advice_scan(99., LlmCategory::Legitimate);
        scan.llm.status = status;
        let before = scan.decision.clone();
        decision::apply(&mut scan, false);
        assert_eq!(scan.decision, before);
        assert!(scan.arbitration.is_none());
    }
    let mut scan = advice_scan(99., LlmCategory::Legitimate);
    scan.llm.verdict.as_mut().unwrap().confidence = f64::NAN;
    decision::apply(&mut scan, false);
    assert_eq!(scan.decision.as_ref().unwrap().outcome, Outcome::Unwanted);
    assert!(scan.arbitration.is_none());
    for (confidence, probability) in [(0.49, 0.), (1., 1.), (1., 0.5)] {
        let mut scan = advice_scan(99., LlmCategory::Legitimate);
        scan.llm.verdict.as_mut().unwrap().confidence = confidence;
        scan.llm.verdict.as_mut().unwrap().spam_probability = probability;
        decision::apply(&mut scan, false);
        assert_eq!(scan.arbitration.unwrap().opinion, Outcome::Undetermined);
    }
}

#[test]
fn corroboration_resolves_ambiguity_but_never_erases_a_definite_contradiction() {
    use noisefence::evidence::{Artifacts, Evidence, Query, Source, State};
    let dir = tempfile::tempdir().unwrap();
    let cfg = common::config(dir.path());
    for (advice, expected) in [
        (LlmCategory::Ambiguous, Outcome::Unwanted),
        (LlmCategory::Legitimate, Outcome::Undetermined),
    ] {
        let mut scan = advice_scan(99., advice);
        let mut e = Evidence::new(&cfg, Artifacts::new(&cfg, None, None, false), false);
        e.source = Source::SmtpSession;
        e.reputation.ip = Query {
            state: State::Complete,
            codes: vec!["127.0.0.2".parse().unwrap()],
        };
        scan.evidence = Some(e);
        decision::apply(&mut scan, true);
        assert_eq!(scan.decision.as_ref().unwrap().outcome, expected);
    }
    for complete in [false, true] {
        let mut scan = advice_scan(99., LlmCategory::Legitimate);
        scan.complete = complete;
        scan.decision.as_mut().unwrap().source = DecisionSource::Fusion;
        let before = scan.decision.clone();
        decision::apply(&mut scan, true);
        assert_eq!(scan.decision, before);
        assert!(scan.arbitration.is_none());
    }
}

fn partial_phishing() -> Scan {
    use noisefence::{
        engine::Signal,
        evidence::{Artifacts, AuthResult, Evidence, Source, State},
    };
    let root = tempfile::tempdir().unwrap();
    let cfg = common::config(root.path());
    let mut e = Evidence::new(&cfg, Artifacts::new(&cfg, None, None, false), false);
    e.source = Source::SmtpSession;
    let a = &mut e.authentication;
    a.state = State::Complete;
    a.spf_state = State::Complete;
    a.spf = Some(AuthResult::SoftFail);
    a.dkim_state = State::Complete;
    a.dkim = Some(vec![]);
    a.dmarc_state = State::Complete;
    a.dmarc_spf = Some(AuthResult::None);
    a.dmarc_dkim = Some(AuthResult::None);
    a.arc_state = State::Complete;
    a.arc = Some(AuthResult::None);
    let mut scan = advice_scan(99.9, LlmCategory::Phishing);
    scan.complete = false;
    scan.features_complete = Some(true);
    scan.evidence = Some(e);
    scan.message_context = Some(Default::default());
    scan.antivirus.status = Av::Clean;
    scan.signatures = AntivirusResult {
        status: Av::Suspicious,
        signature: Some("Sanesecurity.Phishing.Test.UNOFFICIAL".into()),
        ..Default::default()
    };
    scan.reasons.push(Signal {
        id: "smtp_policy_unavailable".into(),
        detail: "Synthetic timeout".into(),
        weight: 0.,
    });
    scan.decision = Some(Decision::legacy(&scan, 95.));
    scan
}

#[test]
fn qualified_partial_threat_actions_use_observed_requirements_not_raw_score() {
    use noisefence::{
        action_coverage::Basis,
        actions::{self, Action},
    };
    let root = tempfile::tempdir().unwrap();
    let mut cfg = (*common::config(root.path())).clone();
    cfg.filter.mode = Mode::Enforce;
    cfg.filter.partial_actions = true;
    cfg.filter.resolve_uncertain_by_score = false;
    cfg.actions = Some(actions::Policy {
        spam: Action::Quarantine,
        publicity: Action::Deliver,
        malware: Action::Quarantine,
        quarantine_days: 7,
    });
    let mut scan = partial_phishing();
    scan.score = 5.; // A deterministic evidence finding is not a fabricated high score.
    decision::apply(&mut scan, true);
    let a = actions::evaluate(&scan, &cfg);
    assert_eq!(a.effective, Action::Quarantine);
    assert_eq!(a.coverage.unwrap().basis, Basis::EstablishedThreat);
    assert_eq!(scan.score, 5.);
    assert!(!scan.complete);
    scan.evidence.as_mut().unwrap().authentication.spf =
        Some(noisefence::evidence::AuthResult::Pass);
    // Keep the old verdict to exercise the runtime coverage guard defensively.
    let a = actions::evaluate(&scan, &cfg);
    assert_eq!(a.effective, Action::Deliver);
    assert!(!a.coverage.unwrap().eligible());
}

#[test]
fn independent_positive_evidence_survives_an_unrelated_dns_failure_without_enforcement() {
    let mut scan = partial_phishing();
    decision::apply(&mut scan, true);
    assert_eq!(scan.decision.as_ref().unwrap().outcome, Outcome::Unwanted);
    assert!(scan.decision.as_ref().unwrap().score.is_none());
    assert!(!scan.complete);
    assert_eq!(scan.score, 99.9);
    let once = serde_json::to_value(&scan).unwrap();
    decision::apply(&mut scan, true);
    assert_eq!(serde_json::to_value(&scan).unwrap(), once);
    let root = tempfile::tempdir().unwrap();
    let mut cfg = (*common::config(root.path())).clone();
    cfg.filter.mode = Mode::Tag;
    for action in [
        noisefence::actions::Action::Tag,
        noisefence::actions::Action::Quarantine,
    ] {
        cfg.actions = Some(noisefence::actions::Policy {
            spam: action,
            publicity: action,
            malware: action,
            quarantine_days: 14,
        });
        assert_eq!(
            noisefence::actions::evaluate(&scan, &cfg).effective,
            noisefence::actions::Action::Deliver
        );
        assert!(decision::subject_tag(&scan, &cfg).is_none());
    }
}

#[test]
fn partial_risk_needs_every_independent_signal_and_cannot_override_other_models() {
    use noisefence::{
        engine::Signal,
        evidence::{AuthResult, Source, State},
    };
    for missing in 0..15 {
        let mut scan = partial_phishing();
        match missing {
            0 => scan.signatures.status = Av::Clean,
            1 => scan.llm.status = LlmStatus::Unavailable,
            2 => scan.llm.verdict.as_mut().unwrap().spam_probability = 0.1,
            3 => scan.llm.verdict.as_mut().unwrap().category = LlmCategory::Legitimate,
            4 => scan.evidence.as_mut().unwrap().authentication.dkim = Some(vec![AuthResult::Pass]),
            5 => scan.evidence.as_mut().unwrap().authentication.dmarc_state = State::Unavailable,
            6 => scan.evidence.as_mut().unwrap().source = Source::ContentOnly,
            7 => scan.evidence.as_mut().unwrap().authentication.arc = Some(AuthResult::Pass),
            8 => scan.features_complete = Some(false),
            9 => scan.reasons.push(Signal {
                id: "vision_incomplete".into(),
                detail: "fixture".into(),
                weight: 0.,
            }),
            10 => scan.message_context.as_mut().unwrap().threat_report = true,
            11 => scan.message_context.as_mut().unwrap().transaction_notice = true,
            12 => scan.antivirus.status = Av::Unavailable,
            13 => scan.decision.as_mut().unwrap().source = DecisionSource::Fusion,
            _ => scan.reasons.clear(),
        }
        decision::apply(&mut scan, true);
        assert_eq!(
            scan.decision.unwrap().outcome,
            Outcome::Undetermined,
            "case {missing}"
        );
    }
}

#[test]
fn corroborated_direct_extortion_survives_one_missing_content_check_but_never_enforces() {
    for absent in ["llm", "signature"] {
        let mut scan = partial_phishing();
        scan.message_context.as_mut().unwrap().direct_extortion = true;
        if absent == "llm" {
            scan.llm.status = LlmStatus::Unavailable;
            scan.reasons.push(noisefence::engine::Signal {
                id: "llm_unavailable".into(),
                detail: "fixture".into(),
                weight: 0.,
            });
        } else {
            scan.signatures.status = Av::Clean;
        }
        decision::apply(&mut scan, true);
        assert_eq!(scan.decision.as_ref().unwrap().outcome, Outcome::Unwanted);
        assert!(!scan.tagged && !scan.pub_tagged && !scan.complete);
        let once = serde_json::to_value(&scan).unwrap();
        decision::apply(&mut scan, true);
        assert_eq!(serde_json::to_value(&scan).unwrap(), once);
        scan.llm.status = LlmStatus::Unavailable;
        scan.signatures.status = Av::Clean;
        scan.decision = Some(Decision::legacy(&scan, 95.));
        decision::apply(&mut scan, true);
        assert_eq!(scan.decision.unwrap().outcome, Outcome::Undetermined);
    }
}

#[test]
fn extortion_hint_cannot_override_authenticated_mail_or_a_legitimate_opinion() {
    for case in 0..5 {
        let mut scan = partial_phishing();
        scan.message_context.as_mut().unwrap().direct_extortion = true;
        match case {
            0 => {
                scan.evidence.as_mut().unwrap().source =
                    noisefence::evidence::Source::SuppliedEnvelope
            }
            1 => {
                scan.evidence.as_mut().unwrap().authentication.spf =
                    Some(noisefence::evidence::AuthResult::Pass)
            }
            2 => scan.message_context.as_mut().unwrap().threat_report = true,
            3 => scan.message_context.as_mut().unwrap().encrypted = true,
            _ => {
                let v = scan.llm.verdict.as_mut().unwrap();
                v.category = LlmCategory::Legitimate;
                v.spam_probability = 0.1;
            }
        }
        decision::apply(&mut scan, true);
        assert_eq!(scan.decision.unwrap().outcome, Outcome::Undetermined);
    }
}

#[test]
fn injected_lure_corroborates_only_an_enabled_rule_and_respects_contradiction() {
    use noisefence::{
        engine::Signal,
        evidence::{Evidence, Source},
    };
    for (weight, opinion, complete, expected) in [
        (1.5, LlmCategory::Ambiguous, true, Outcome::Unwanted),
        (0.0, LlmCategory::Ambiguous, true, Outcome::Undetermined),
        (1.5, LlmCategory::Legitimate, true, Outcome::Undetermined),
        (1.5, LlmCategory::Ambiguous, false, Outcome::Undetermined),
    ] {
        let root = tempfile::tempdir().unwrap();
        let cfg = common::config(root.path());
        let mut evidence = Evidence::new(
            &cfg,
            noisefence::evidence::Artifacts::new(&cfg, None, None, false),
            false,
        );
        evidence.source = Source::SmtpSession;
        let mut scan = Scan {
            complete,
            score: 98.5,
            evidence: Some(evidence),
            message_context: Some(noisefence::message_context::Context {
                injected_reward_lure: true,
                ..Default::default()
            }),
            reasons: vec![Signal {
                id: "injected_reward_lure".into(),
                detail: "Synthetic fixture".into(),
                weight,
            }],
            llm: LlmResult {
                status: LlmStatus::Complete,
                coherent: Some(true),
                verdict: Some(LlmVerdict {
                    category: opinion.clone(),
                    confidence: 0.9,
                    spam_probability: if matches!(opinion, LlmCategory::Legitimate) {
                        0.1
                    } else {
                        0.5
                    },
                    explanation: "Fixture".into(),
                }),
                ..Default::default()
            },
            ..Default::default()
        };
        scan.decision = Some(Decision::legacy(&scan, 95.));
        decision::apply(&mut scan, true);
        assert_eq!(scan.decision.as_ref().unwrap().outcome, expected);
        let once = serde_json::to_value(&scan).unwrap();
        decision::apply(&mut scan, true);
        assert_eq!(serde_json::to_value(&scan).unwrap(), once);
    }
}
