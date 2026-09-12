mod common;
use noisefence::{
    actions::Action,
    config::Mode,
    custom_filtering::*,
    engine::Scan,
    mailing::Category,
    store::{QueueVariant, Store},
};
fn rule(id: &str, scope: &str, category: Category) -> Rule {
    Rule {
        id: id.into(),
        name: id.into(),
        enabled: true,
        priority: 10,
        scope: scope.into(),
        expires: None,
        any: false,
        conditions: vec![Condition {
            field: Field::Subject,
            op: Operator::Contains,
            value: "Offre".into(),
        }],
        category: Some(category),
        action: Some(Action::Quarantine),
        stop: true,
    }
}
fn scan() -> Scan {
    Scan {
        score: 99.0,
        complete: true,
        ..Default::default()
    }
}

fn level_policy(threshold: f64) -> Policy {
    Policy {
        profiles: vec![Profile {
            id: "level".into(),
            name: "Level".into(),
            threshold: Some(threshold),
            // Deliberately false: the server must enforce confirmation for operating levels.
            require_corroboration: false,
            spam: Action::Quarantine,
            publicity: Action::Deliver,
            review: Action::Deliver,
            quarantine_days: 7,
        }],
        bindings: vec![Binding {
            scope: "*".into(),
            profile: "level".into(),
        }],
        ..Default::default()
    }
}

#[test]
fn sensitivity_levels_are_monotonic_and_never_confirm_an_isolated_score() {
    use noisefence::evidence::{Artifacts, AuthResult, Evidence, Source, State};
    let tmp = tempfile::tempdir().unwrap();
    let mut cfg = (*common::config(tmp.path())).clone();
    cfg.filter.mode = Mode::Enforce;
    let recipient = cfg.recipient("alice@example.test").unwrap();
    let mut evidence = Evidence::new(&cfg, Artifacts::new(&cfg, None, None, false), false);
    evidence.source = Source::SmtpSession;
    evidence.authentication.dmarc_state = State::Complete;
    evidence.authentication.dmarc_spf = Some(AuthResult::Fail);
    evidence.authentication.dmarc_dkim = Some(AuthResult::Fail);
    assert!(LEVELS.windows(2).all(|w| w[0].threshold > w[1].threshold));
    for score in [
        0., 84.9, 85., 89.9, 90., 94.9, 95., 97.9, 98., 99.49, 99.5, 100.,
    ] {
        let mut detections = 0;
        for (i, level) in LEVELS.iter().enumerate() {
            let policy = level_policy(level.threshold);
            policy.validate(&cfg).unwrap();
            for confirmed in [false, true] {
                let mut scan = Scan {
                    score,
                    evidence: confirmed.then(|| evidence.clone()),
                    ..scan()
                };
                scan.decision = Some(noisefence::fusion::runtime::Decision::legacy(
                    &scan,
                    cfg.filter.threshold,
                ));
                noisefence::decision::apply(&mut scan, true);
                let before = serde_json::to_value(&scan).unwrap();
                let result = assess(&policy, &cfg, &scan, &Facts::default(), &recipient, 100);
                let expected = if score < level.threshold {
                    Category::Legitimate
                } else if confirmed {
                    Category::Spam
                } else {
                    Category::Undetermined
                };
                assert_eq!(
                    result.category, expected,
                    "score={score}, level={i}, confirmed={confirmed}"
                );
                assert_eq!(
                    result.action.effective,
                    if expected == Category::Spam {
                        Action::Quarantine
                    } else {
                        Action::Deliver
                    }
                );
                assert_eq!(
                    serde_json::to_value(&scan).unwrap(),
                    before,
                    "never mutate model evidence or LLM selection"
                );
                if confirmed && expected == Category::Spam {
                    detections += 1;
                }
                if confirmed && detections > 0 {
                    assert_eq!(expected, Category::Spam);
                }
            }
        }
    }
}

#[test]
fn levels_preserve_calibration_inherit_domains_and_keep_existing_revision_shape() {
    let tmp = tempfile::tempdir().unwrap();
    let mut cfg = (*common::config(tmp.path())).clone();
    cfg.filter.semantic = Some(noisefence::config::SemanticFilter {
        encoder_dir: "fixture".into(),
        combination: "fixture".into(),
        max_parallel: 1,
        timeout_ms: 500,
    });
    let mut policy = level_policy(90.);
    policy.validate(&cfg).unwrap();
    assert_eq!(cfg.filter.threshold, 95.);
    let mut domain = policy.profiles[0].clone();
    domain.id = "domain".into();
    domain.threshold = None;
    policy.profiles.push(domain);
    policy.bindings.push(Binding {
        scope: "*@example.test".into(),
        profile: "domain".into(),
    });
    let recipient = cfg.recipient("alice@example.test").unwrap();
    let evaluate = |p: &Policy| assess(p, &cfg, &scan(), &Facts::default(), &recipient, 100);
    assert_eq!(evaluate(&policy).threshold, 90.);
    policy.profiles[1].threshold = Some(98.);
    assert_eq!(evaluate(&policy).threshold, 98.);
    let mut address = policy.profiles[0].clone();
    address.id = "address".into();
    address.threshold = Some(99.5);
    policy.profiles.push(address);
    policy.bindings.push(Binding {
        scope: "alice@example.test".into(),
        profile: "address".into(),
    });
    assert_eq!(evaluate(&policy).threshold, 99.5);
    policy.profiles[2].threshold = None;
    assert_eq!(evaluate(&policy).threshold, 98.);
    policy.validate(&cfg).unwrap();
    let serialized = serde_json::to_value(&policy).unwrap();
    assert_eq!(serialized.as_object().unwrap().len(), 3);
    assert_eq!(serialized["profiles"][0].as_object().unwrap().len(), 8);
    assert_eq!(
        serde_json::from_value::<Policy>(serialized).unwrap(),
        policy
    );
    for bad in [49.9, 100.1, f64::NAN, f64::INFINITY] {
        assert!(level_policy(bad).validate(&cfg).is_err());
    }
}

#[test]
fn levels_cannot_bypass_fusion_malware_or_incomplete_analysis() {
    use noisefence::{
        antivirus::AntivirusStatus,
        fusion::runtime::{Decision, DecisionSource, Outcome},
    };
    let tmp = tempfile::tempdir().unwrap();
    let mut cfg = (*common::config(tmp.path())).clone();
    cfg.filter.mode = Mode::Enforce;
    let recipient = cfg.recipient("alice@example.test").unwrap();
    let policy = level_policy(85.);
    let mut s = scan();
    s.decision = Some(Decision {
        source: DecisionSource::Fusion,
        outcome: Outcome::Undetermined,
        score: None,
        model: "fixture".into(),
    });
    let result = assess(&policy, &cfg, &s, &Facts::default(), &recipient, 100);
    assert_eq!(result.category, Category::Undetermined);
    assert_eq!(result.threshold, cfg.filter.threshold);
    cfg.fusion = Some(noisefence::fusion::runtime::Settings {
        model: "fixture".into(),
        mode: noisefence::fusion::runtime::Mode::Decision,
        validation_report: None,
    });
    assert!(policy.validate(&cfg).is_err());
    s.decision = None;
    assert_eq!(
        assess(&policy, &cfg, &s, &Facts::default(), &recipient, 100).threshold,
        cfg.filter.threshold
    );
    cfg.fusion = None;
    s.complete = false;
    assert_eq!(
        assess(&policy, &cfg, &s, &Facts::default(), &recipient, 100)
            .action
            .effective,
        Action::Deliver
    );
    s.antivirus.status = AntivirusStatus::Malware;
    cfg.actions = Some(noisefence::actions::Policy {
        spam: Action::Deliver,
        publicity: Action::Deliver,
        malware: Action::Quarantine,
        quarantine_days: 7,
    });
    for level in LEVELS {
        let p = level_policy(level.threshold);
        assert_eq!(
            assess(&p, &cfg, &s, &Facts::default(), &recipient, 100)
                .action
                .effective,
            Action::Quarantine
        );
        cfg.filter.mode = Mode::Observe;
        assert_eq!(
            assess(&p, &cfg, &s, &Facts::default(), &recipient, 100)
                .action
                .effective,
            Action::Deliver
        );
        cfg.filter.mode = Mode::Enforce;
    }
}
#[test]
fn scoped_order_expiry_missing_facts_and_malware_priority() {
    let tmp = tempfile::tempdir().unwrap();
    let mut cfg = (*common::config(tmp.path())).clone();
    cfg.filter.mode = Mode::Enforce;
    let mut policy = Policy {
        rules: vec![
            rule("a", "alice@example.test", Category::Publicity),
            rule("b", "*", Category::Spam),
        ],
        ..Default::default()
    };
    policy.validate(&cfg).unwrap();
    let recipient = cfg.recipient("alice@example.test").unwrap();
    let mut facts = Facts::default();
    facts.put(Field::Subject, "OFFRE du jour");
    let result = assess(&policy, &cfg, &scan(), &facts, &recipient, 100);
    assert_eq!(result.category, Category::Publicity);
    assert_eq!(result.matched.len(), 1);
    assert_eq!(result.action.effective, Action::Quarantine);
    policy.rules[0].expires = Some(100);
    assert_eq!(
        assess(&policy, &cfg, &scan(), &facts, &recipient, 100).matched[0].id,
        "b"
    );
    policy.rules[0].expires = None;
    policy.rules[0].conditions[0] = Condition {
        field: Field::Dmarc,
        op: Operator::Absent,
        value: String::new(),
    };
    assert_eq!(facts.matches(&policy.rules[0].conditions[0]), None);
    let result = assess(&policy, &cfg, &scan(), &facts, &recipient, 100);
    assert_eq!(result.matched[0].id, "b");
    assert_eq!(result.unavailable_conditions, 1);
    let mut malicious = scan();
    malicious.antivirus.status = noisefence::antivirus::AntivirusStatus::Malware;
    policy.rules[1].category = Some(Category::Legitimate);
    policy.rules[1].action = Some(Action::Deliver);
    cfg.actions = Some(noisefence::actions::Policy {
        spam: Action::Quarantine,
        publicity: Action::Deliver,
        malware: Action::Quarantine,
        quarantine_days: 14,
    });
    let result = assess(&policy, &cfg, &malicious, &facts, &recipient, 100);
    assert_eq!(result.category, Category::Spam);
    assert_eq!(result.action.effective, Action::Quarantine);
    cfg.filter.mode = Mode::Observe;
    assert_eq!(
        assess(&policy, &cfg, &malicious, &facts, &recipient, 100)
            .action
            .effective,
        Action::Deliver
    );
}
#[test]
fn profile_specificity_and_incomplete_fail_open() {
    let tmp = tempfile::tempdir().unwrap();
    let mut cfg = (*common::config(tmp.path())).clone();
    cfg.filter.mode = Mode::Enforce;
    let mk = |id: &str, action| Profile {
        id: id.into(),
        name: id.into(),
        threshold: None,
        require_corroboration: false,
        spam: action,
        publicity: action,
        review: Action::Deliver,
        quarantine_days: 7,
    };
    let policy = Policy {
        profiles: vec![
            mk("global", Action::Quarantine),
            mk("address", Action::Deliver),
        ],
        bindings: vec![
            Binding {
                scope: "*".into(),
                profile: "global".into(),
            },
            Binding {
                scope: "alice@example.test".into(),
                profile: "address".into(),
            },
        ],
        ..Default::default()
    };
    policy.validate(&cfg).unwrap();
    let recipient = cfg.recipient("alice@example.test").unwrap();
    let facts = Facts::default();
    let result = assess(&policy, &cfg, &scan(), &facts, &recipient, 100);
    assert_eq!(result.profile.as_deref(), Some("address"));
    assert_eq!(result.action.effective, Action::Deliver);
    let mut p = policy.clone();
    p.bindings.pop();
    let mut incomplete = scan();
    incomplete.complete = false;
    assert_eq!(
        assess(&p, &cfg, &incomplete, &facts, &recipient, 100)
            .action
            .effective,
        Action::Deliver
    );
    let mut invalid = policy;
    invalid.bindings.push(invalid.bindings[0].clone());
    assert!(invalid.validate(&cfg).is_err());
}
#[test]
fn tag_gate_cannot_be_bypassed_by_custom_rule() {
    let tmp = tempfile::tempdir().unwrap();
    let mut cfg = (*common::config(tmp.path())).clone();
    cfg.filter.mode = Mode::Enforce;
    cfg.actions = Some(noisefence::actions::Policy {
        spam: Action::Deliver,
        publicity: Action::Deliver,
        malware: Action::Deliver,
        quarantine_days: 14,
    });
    cfg.custom_filtering = Some(Policy {
        rules: vec![Rule {
            action: Some(Action::Tag),
            ..rule("r", "*", Category::Spam)
        }],
        ..Default::default()
    });
    assert!(cfg.validate().is_err());
    cfg.filter.mode = Mode::Observe;
    cfg.validate().unwrap();
}
#[tokio::test]
async fn durable_batch_rolls_back_every_variant_and_preserves_existing_spool() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = common::config(tmp.path());
    let store = Store::open(tmp.path()).unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    let other = uuid::Uuid::new_v4().to_string();
    let mk = |id: String| QueueVariant {
        id,
        scan: scan(),
        raw: common::MESSAGE.to_vec(),
        recipients: vec![(cfg.recipient("alice@example.test").unwrap(), None)],
    };
    store
        .enqueue_variants("s@example.org".into(), vec![mk(id.clone())])
        .await
        .unwrap();
    assert!(
        store
            .enqueue_variants(
                "s@example.org".into(),
                vec![mk(other.clone()), mk(id.clone())]
            )
            .await
            .is_err()
    );
    assert!(!store.raw_path(&other).exists());
    assert_eq!(std::fs::read(store.raw_path(&id)).unwrap(), common::MESSAGE);
    let count = store
        .run(|db| Ok(db.query_row("SELECT COUNT(*) FROM messages", [], |r| r.get::<_, i64>(0))?))
        .await
        .unwrap();
    assert_eq!(count, 1);
    let third = uuid::Uuid::new_v4().to_string();
    let fourth = uuid::Uuid::new_v4().to_string();
    let mut v = mk(fourth.clone());
    v.recipients.push(v.recipients[0].clone());
    assert!(
        store
            .enqueue_variants("s@example.org".into(), vec![mk(third.clone()), v])
            .await
            .is_err()
    );
    assert!(!store.raw_path(&third).exists());
    assert!(!store.raw_path(&fourth).exists());
    store.recover().await.unwrap();
    assert!(store.claim().await.unwrap().is_some());
}

#[test]
fn recipient_profiles_reapply_arbitration_with_their_own_threshold() {
    use noisefence::{
        decision,
        fusion::runtime::{Decision, Outcome},
        llm::{Category as LlmCategory, LlmResult, LlmStatus, Verdict},
    };
    let tmp = tempfile::tempdir().unwrap();
    let mut cfg = (*common::config(tmp.path())).clone();
    cfg.filter.threshold = 95.;
    cfg.filter.require_corroboration = false;
    cfg.filter.mode = Mode::Observe;
    let mut scan = scan();
    scan.llm = LlmResult {
        status: LlmStatus::Complete,
        verdict: Some(Verdict {
            category: LlmCategory::Legitimate,
            confidence: 0.95,
            spam_probability: 0.05,
            explanation: "Fixture".into(),
        }),
        ..Default::default()
    };
    scan.decision = Some(Decision::legacy(&scan, 95.));
    decision::apply(&mut scan, false);
    assert_eq!(
        scan.decision.as_ref().unwrap().outcome,
        Outcome::Undetermined
    );
    for (threshold, expected) in [
        (None, Category::Undetermined),
        (Some(90.), Category::Undetermined),
        (Some(100.), Category::Legitimate),
    ] {
        let policy = Policy {
            profiles: vec![Profile {
                id: "p".into(),
                name: "Fixture".into(),
                threshold,
                require_corroboration: false,
                spam: Action::Quarantine,
                publicity: Action::Deliver,
                review: Action::Deliver,
                quarantine_days: 7,
            }],
            bindings: vec![Binding {
                scope: "*".into(),
                profile: "p".into(),
            }],
            ..Default::default()
        };
        let result = assess(
            &policy,
            &cfg,
            &scan,
            &Facts::default(),
            &cfg.recipient("alice@example.test").unwrap(),
            100,
        );
        assert_eq!(result.category, expected);
        assert_eq!(result.action.effective, Action::Deliver);
    }
}
