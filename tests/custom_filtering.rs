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
