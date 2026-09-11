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
