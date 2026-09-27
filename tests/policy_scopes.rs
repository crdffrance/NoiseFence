#[allow(dead_code)]
mod common;
use noisefence::{
    actions::Action,
    config::Mode,
    custom_filtering::*,
    engine::Scan,
    mailing::Category,
    policy_trace::{Origin, Outcome},
    preferences::Preference,
};

fn profile(id: &str, threshold: Option<f64>) -> Profile {
    Profile {
        id: id.into(),
        name: id.into(),
        threshold,
        require_corroboration: true,
        spam: Action::Quarantine,
        publicity: Action::Deliver,
        review: Action::Deliver,
        quarantine_days: 7,
    }
}
fn rule(id: &str, scope: &str, priority: u16, category: Category) -> Rule {
    Rule {
        id: id.into(),
        name: id.into(),
        scope: scope.into(),
        priority,
        enabled: true,
        expires: None,
        any: false,
        conditions: vec![Condition {
            field: Field::Subject,
            op: Operator::Contains,
            value: "fixture".into(),
        }],
        category: Some(category),
        action: None,
        stop: false,
    }
}
fn scan() -> Scan {
    Scan {
        score: 96.,
        complete: true,
        features_complete: Some(true),
        subject: "fixture".into(),
        ..Default::default()
    }
}

#[test]
fn scope_profiles_inherit_through_personal_and_admin_without_losing_domain_rules() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = (*common::config(dir.path())).clone();
    cfg.filter.resolve_uncertain_by_score = true;
    let recipient = cfg.recipient("alice@example.test").unwrap();
    let base = Policy {
        ordering: Ordering::Scoped,
        profiles: vec![
            profile("global", Some(95.)),
            profile("admin-domain", Some(98.)),
        ],
        bindings: vec![
            Binding {
                scope: "*".into(),
                profile: "global".into(),
            },
            Binding {
                scope: "*@example.test".into(),
                profile: "admin-domain".into(),
            },
        ],
        ..Default::default()
    };
    cfg.preferences.mailboxes.insert(
        "*@example.test".into(),
        Preference {
            profile: Some(profile("personal-domain", None)),
            rules: vec![rule(
                "domain-rule",
                "*@example.test",
                0,
                Category::Publicity,
            )],
        },
    );
    cfg.preferences.mailboxes.insert(
        recipient.address.clone(),
        Preference {
            profile: Some(profile("personal-mailbox", None)),
            rules: vec![],
        },
    );
    cfg.validate().unwrap();
    base.validate(&cfg).unwrap();
    let combined = cfg.preferences.policy(&base, &recipient);
    let scan = scan();
    let facts = Facts::metadata("sender@example.org", &scan);
    let a = assess(&combined, &cfg, &scan, &facts, &recipient, 100);
    assert_eq!(a.threshold, 98.);
    assert_eq!(a.profile.as_deref(), Some("personal-mailbox"));
    assert_eq!(a.category, Category::Publicity);
    let trace = a.trace.unwrap();
    assert_eq!(
        trace
            .profiles
            .iter()
            .map(|p| p.name.as_str())
            .collect::<Vec<_>>(),
        vec![
            "personal-mailbox",
            "personal-domain",
            "admin-domain",
            "global"
        ]
    );
    assert_eq!(trace.threshold_profile.as_deref(), Some("admin-domain"));
    assert_eq!(trace.rules.len(), 1);
    assert_eq!(trace.rules[0].origin, Origin::Personal);
    // An address preference containing only rules still inherits the domain profile.
    cfg.preferences
        .mailboxes
        .get_mut(&recipient.address)
        .unwrap()
        .profile = None;
    let a = assess(
        &cfg.preferences.policy(&base, &recipient),
        &cfg,
        &scan,
        &facts,
        &recipient,
        100,
    );
    assert_eq!(a.profile.as_deref(), Some("personal-domain"));
    assert_eq!(a.threshold, 98.);
    let bob = cfg.recipient("bob@example.test").unwrap();
    let trace = assess(
        &cfg.preferences.policy(&base, &bob),
        &cfg,
        &scan,
        &facts,
        &bob,
        100,
    )
    .trace
    .unwrap();
    assert!(
        trace
            .profiles
            .iter()
            .all(|p| p.scope != "alice@example.test")
    );
}

#[test]
fn scoped_rules_have_stable_authority_specificity_stop_and_missing_fact_traces() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = (*common::config(dir.path())).clone();
    cfg.filter.mode = Mode::Enforce;
    let recipient = cfg.recipient("alice@example.test").unwrap();
    cfg.preferences.mailboxes.insert(
        recipient.address.clone(),
        Preference {
            profile: None,
            rules: vec![rule(
                "user",
                &recipient.address,
                65535,
                Category::Legitimate,
            )],
        },
    );
    let mut base = Policy {
        ordering: Ordering::Scoped,
        rules: vec![
            rule("address", &recipient.address, 0, Category::Spam),
            rule("global", "*", 65535, Category::Legitimate),
            rule("domain", "*@example.test", 0, Category::Publicity),
        ],
        ..Default::default()
    };
    let scan = scan();
    let facts = Facts::metadata("s@example.org", &scan);
    let result = assess(
        &cfg.preferences.policy(&base, &recipient),
        &cfg,
        &scan,
        &facts,
        &recipient,
        100,
    );
    assert_eq!(result.category, Category::Spam);
    let trace = result.trace.unwrap();
    assert_eq!(
        trace
            .rules
            .iter()
            .map(|r| r.name.as_str())
            .collect::<Vec<_>>(),
        vec!["user", "global", "domain", "address"]
    );
    assert_eq!(trace.category_rule.as_deref(), Some("address"));
    base.rules.reverse();
    let shuffled = assess(
        &cfg.preferences.policy(&base, &recipient),
        &cfg,
        &scan,
        &facts,
        &recipient,
        100,
    );
    assert_eq!(
        serde_json::to_value(shuffled.trace).unwrap(),
        serde_json::to_value(&trace).unwrap()
    );
    base.rules
        .iter_mut()
        .find(|r| r.id == "global")
        .unwrap()
        .stop = true;
    let stopped = assess(
        &cfg.preferences.policy(&base, &recipient),
        &cfg,
        &scan,
        &facts,
        &recipient,
        100,
    );
    assert_eq!(stopped.category, Category::Legitimate);
    let trace = stopped.trace.unwrap();
    assert_eq!(trace.stopped_by.as_deref(), Some("global"));
    assert_eq!(trace.rules[2].outcome, Outcome::Stopped);
    // An unknown body is not an empty body and cannot match an Absent condition.
    let mut missing = rule("body", "*", 0, Category::Spam);
    missing.conditions = vec![Condition {
        field: Field::Body,
        op: Operator::Absent,
        value: String::new(),
    }];
    base.rules = vec![missing];
    let result = assess(&base, &cfg, &scan, &facts, &recipient, 100);
    assert_eq!(result.unavailable_conditions, 1);
    assert!(result.matched.is_empty());
    assert_eq!(
        result.trace.unwrap().rules[0].outcome,
        Outcome::MissingFacts
    );
    // Malware still takes precedence over an explicit administrator allow rule.
    base.rules = vec![rule("allow", "*", 0, Category::Legitimate)];
    let mut malware = scan.clone();
    malware.antivirus.status = noisefence::antivirus::AntivirusStatus::Malware;
    let result = assess(&base, &cfg, &malware, &facts, &recipient, 100);
    assert_eq!(result.category, Category::Spam);
    assert!(result.trace.unwrap().malware_override);
}

#[test]
fn origins_cannot_be_supplied_by_clients_and_legacy_rule_ids_cannot_collide() {
    assert!(
        serde_json::from_value::<Policy>(serde_json::json!({"origins":{"rules":{"admin":"user"}}}))
            .is_err()
    );
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = (*common::config(dir.path())).clone();
    let recipient = cfg.recipient("alice@example.test").unwrap();
    cfg.preferences.mailboxes.insert(
        recipient.address.clone(),
        Preference {
            profile: None,
            rules: vec![rule(
                "mailbox-0",
                &recipient.address,
                0,
                Category::Legitimate,
            )],
        },
    );
    for ordering in [Ordering::LegacyPriority, Ordering::Scoped] {
        let base = Policy {
            ordering,
            rules: vec![
                rule("mailbox-0", "*", 0, Category::Spam),
                rule("__personal_rule_0", "*", 1, Category::Spam),
            ],
            ..Default::default()
        };
        let combined = cfg.preferences.policy(&base, &recipient);
        assert_eq!(
            combined
                .rules
                .iter()
                .map(|r| &r.id)
                .collect::<std::collections::HashSet<_>>()
                .len(),
            3
        );
        let restored: Policy =
            serde_json::from_value(serde_json::to_value(&combined).unwrap()).unwrap();
        assert!(restored.origins.rules.is_empty());
        let trace = assess(
            &combined,
            &cfg,
            &scan(),
            &Facts::metadata("s@example.org", &scan()),
            &recipient,
            100,
        )
        .trace
        .unwrap();
        assert_eq!(
            trace
                .rules
                .iter()
                .filter(|r| r.origin == Origin::Personal)
                .count(),
            1
        );
        assert_eq!(trace.rules.last().unwrap().origin, Origin::Administrator);
    }
}

#[test]
fn personal_ties_use_original_ids_and_canonical_score_rules_match_the_display() {
    use noisefence::fusion::runtime::{Decision, DecisionSource, Outcome as Verdict};
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = (*common::config(dir.path())).clone();
    let recipient = cfg.recipient("alice@example.test").unwrap();
    let base = Policy {
        ordering: Ordering::Scoped,
        ..Default::default()
    };
    let mut rules = vec![
        rule("z-last", &recipient.address, 1, Category::Spam),
        rule("a-first", &recipient.address, 1, Category::Legitimate),
    ];
    for _ in 0..2 {
        cfg.preferences.mailboxes.insert(
            recipient.address.clone(),
            Preference {
                profile: None,
                rules: rules.clone(),
            },
        );
        let result = assess(
            &cfg.preferences.policy(&base, &recipient),
            &cfg,
            &scan(),
            &Facts::metadata("s@example.org", &scan()),
            &recipient,
            100,
        );
        assert_eq!(result.category, Category::Spam);
        assert_eq!(
            result
                .trace
                .unwrap()
                .rules
                .iter()
                .map(|r| r.name.as_str())
                .collect::<Vec<_>>(),
            vec!["a-first", "z-last"]
        );
        rules.reverse();
    }
    let mut scan = scan();
    scan.score = 10.;
    scan.decision = Some(Decision {
        source: DecisionSource::Fusion,
        outcome: Verdict::Unwanted,
        score: Some(98.),
        model: "fusion-fixture".into(),
    });
    let mut r = rule("high-risk", "*", 0, Category::Spam);
    r.conditions = vec![Condition {
        field: Field::Score,
        op: Operator::AtLeast,
        value: "95".into(),
    }];
    let mut p = Policy {
        ordering: Ordering::Scoped,
        rules: vec![r],
        ..Default::default()
    };
    let facts = Facts::metadata("s@example.org", &scan);
    assert_eq!(
        noisefence::assessment::assess(&scan, 95.).score.value,
        Some(98.)
    );
    assert_eq!(
        assess(&p, &cfg, &scan, &facts, &recipient, 100)
            .matched
            .len(),
        1
    );
    p.ordering = Ordering::LegacyPriority;
    assert!(
        assess(&p, &cfg, &scan, &facts, &recipient, 100)
            .matched
            .is_empty()
    );
}

#[test]
fn alias_policy_trace_uses_only_applicable_scopes_and_specificity_is_explicit() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = common::config(dir.path());
    let recipient = noisefence::config::Recipient {
        address: "alias@original.test".into(),
        destination: "alice@example.test".into(),
        hosts: vec![],
    };
    let scopes = [
        "*",
        "*@example.test",
        "*@original.test",
        "alice@example.test",
        "alias@original.test",
    ];
    let mut base = Policy {
        ordering: Ordering::Scoped,
        ..Default::default()
    };
    for (i, scope) in scopes.iter().enumerate() {
        let id = format!("p{i}");
        base.profiles.push(profile(&id, Some(90. + i as f64)));
        base.bindings.push(Binding {
            scope: (*scope).into(),
            profile: id,
        });
    }
    base.bindings.push(Binding {
        scope: "other@example.test".into(),
        profile: "p0".into(),
    });
    let result = assess(&base, &cfg, &scan(), &Facts::default(), &recipient, 100);
    assert_eq!(result.threshold, 94.);
    let trace = result.trace.unwrap();
    assert_eq!(
        trace
            .profiles
            .iter()
            .map(|p| p.scope.as_str())
            .collect::<Vec<_>>(),
        scopes.into_iter().rev().collect::<Vec<_>>()
    );
}

#[test]
fn frozen_sample_changes_policy_not_receipts_and_never_invents_a_zero() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = (*common::config(dir.path())).clone();
    cfg.filter.resolve_uncertain_by_score = true;
    let recipient = cfg.recipient("alice@example.test").unwrap();
    let mut scan = scan();
    scan.decision = Some(noisefence::fusion::runtime::Decision::legacy(&scan, 95.));
    noisefence::decision::apply(&mut scan, true);
    noisefence::decision::resolve_by_score(&mut scan, true, 95.);
    noisefence::decision_record::record_recipient(&mut scan, &cfg, None, 100);
    let before = serde_json::to_value(&scan).unwrap();
    let policy = Policy {
        ordering: Ordering::Scoped,
        profiles: vec![profile("tolerant", Some(99.))],
        bindings: vec![Binding {
            scope: "*".into(),
            profile: "tolerant".into(),
        }],
        ..Default::default()
    };
    let result = simulate(&policy, &cfg, &scan, "s@example.org", &recipient, 100);
    assert_eq!(result.category, Category::Legitimate);
    assert_eq!(result.threshold, 99.);
    assert_eq!(
        noisefence::assessment::historical(&scan).category,
        Category::Spam
    );
    assert_eq!(serde_json::to_value(&scan).unwrap(), before);
    assert_eq!(
        serde_json::to_value(&result).unwrap(),
        serde_json::to_value(simulate(
            &policy,
            &cfg,
            &scan,
            "s@example.org",
            &recipient,
            100
        ))
        .unwrap()
    );
    let mut unknown = scan.clone();
    unknown.analysis_result.as_mut().unwrap().score.raw = None;
    unknown.score = 0.;
    unknown.features_complete = Some(false);
    let mut rule = rule("low-score", "*", 0, Category::Publicity);
    rule.conditions = vec![Condition {
        field: Field::Score,
        op: Operator::AtMost,
        value: "1".into(),
    }];
    let result = simulate(
        &Policy {
            rules: vec![rule],
            ..Default::default()
        },
        &cfg,
        &unknown,
        "s@example.org",
        &recipient,
        100,
    );
    assert!(result.matched.is_empty());
    assert_eq!(result.unavailable_conditions, 1);
    let mut truncated = scan.clone();
    truncated.subject = "x".repeat(500);
    assert!(
        !Facts::metadata("s@example.org", &truncated)
            .values
            .contains_key(&Field::Subject)
    );
    let raw = format!(
        "From: s@example.org\r\nSubject: {}suffix\r\n\r\nbody\r\n",
        truncated.subject
    );
    assert_eq!(
        Facts::message(raw.as_bytes(), "s@example.org", &truncated, 4096).values[&Field::Subject]
            [0]
        .len(),
        506
    );
}
