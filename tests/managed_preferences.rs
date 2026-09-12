mod common;
use noisefence::{
    actions::{Action, Policy as Actions},
    config::Mode,
    custom_filtering::{Condition, Facts, Field, Operator, Policy, Rule, assess},
    engine::Scan,
    mailing::Category,
    preferences::Preference,
};
fn rule(scope: &str, category: Category, action: Action) -> Rule {
    Rule {
        id: "rule".into(),
        name: "Règle synthétique".into(),
        enabled: true,
        priority: 0,
        scope: scope.into(),
        expires: None,
        any: false,
        conditions: vec![Condition {
            field: Field::Subject,
            op: Operator::Contains,
            value: "Rendez-vous".into(),
        }],
        category: Some(category),
        action: Some(action),
        stop: false,
    }
}
#[test]
fn personal_rules_are_recipient_bound_with_admin_malware_and_observation_guards() {
    let root = tempfile::tempdir().unwrap();
    let mut cfg = (*common::config(root.path())).clone();
    cfg.filter.mode = Mode::Enforce;
    cfg.actions = Some(Actions {
        spam: Action::Quarantine,
        publicity: Action::Deliver,
        malware: Action::Quarantine,
        quarantine_days: 14,
    });
    cfg.preferences.mailboxes.insert(
        "alice@example.test".into(),
        Preference {
            profile: None,
            rules: vec![rule(
                "alice@example.test",
                Category::Spam,
                Action::Quarantine,
            )],
        },
    );
    cfg.validate().unwrap();
    let base = Policy::default();
    let alice = cfg.recipient("alice@example.test").unwrap();
    let bob = cfg.recipient("bob@example.test").unwrap();
    let mut scan = Scan {
        score: 1.,
        complete: true,
        ..Default::default()
    };
    let facts = Facts::message(common::MESSAGE, "sender@example.org", &scan, 1024 * 1024);
    let personal = cfg.preferences.policy(&base, &alice);
    let a = assess(&personal, &cfg, &scan, &facts, &alice, noisefence::now());
    assert_eq!(a.category, Category::Spam);
    assert_eq!(a.action.effective, Action::Quarantine);
    assert!(
        assess(
            &cfg.preferences.policy(&base, &bob),
            &cfg,
            &scan,
            &facts,
            &bob,
            noisefence::now()
        )
        .matched
        .is_empty()
    );
    let admin = Policy {
        rules: vec![rule("*", Category::Legitimate, Action::Deliver)],
        ..Default::default()
    };
    let combined = cfg.preferences.policy(&admin, &alice);
    let decision = assess(&combined, &cfg, &scan, &facts, &alice, noisefence::now());
    assert_eq!(decision.category, Category::Legitimate);
    assert_eq!(decision.action.effective, Action::Deliver);
    assert_eq!(decision.matched.len(), 2);
    scan.antivirus.status = noisefence::antivirus::AntivirusStatus::Malware;
    assert_eq!(
        assess(&combined, &cfg, &scan, &facts, &alice, noisefence::now())
            .action
            .effective,
        Action::Quarantine
    );
    cfg.filter.mode = Mode::Observe;
    assert_eq!(
        assess(&combined, &cfg, &scan, &facts, &alice, noisefence::now())
            .action
            .effective,
        Action::Deliver
    );
    scan.antivirus.status = Default::default();
    scan.complete = false;
    cfg.filter.mode = Mode::Enforce;
    assert_eq!(
        assess(&personal, &cfg, &scan, &facts, &alice, noisefence::now())
            .action
            .effective,
        Action::Deliver
    );
}
#[test]
fn personal_scope_actions_and_proton_requirements_cannot_be_bypassed() {
    let root = tempfile::tempdir().unwrap();
    let mut cfg = (*common::config(root.path())).clone();
    let mut preference = Preference {
        profile: None,
        rules: vec![rule("*", Category::Spam, Action::Tag)],
    };
    cfg.preferences
        .mailboxes
        .insert("alice@example.test".into(), preference.clone());
    assert!(cfg.validate().is_err());
    preference.rules[0].scope = "alice@example.test".into();
    preference.rules[0].stop = true;
    cfg.preferences
        .mailboxes
        .insert("alice@example.test".into(), preference.clone());
    assert!(cfg.validate().is_err());
    preference.rules[0].stop = false;
    cfg.preferences
        .mailboxes
        .insert("alice@example.test".into(), preference);
    cfg.validate().unwrap();
    cfg.actions = Some(Actions {
        spam: Action::Deliver,
        publicity: Action::Deliver,
        malware: Action::Quarantine,
        quarantine_days: 14,
    });
    cfg.filter.mode = Mode::Enforce;
    assert!(
        cfg.validate().is_err(),
        "personal tag still needs Proton validation"
    );
    cfg.filter.mode = Mode::Observe;
    cfg.preferences.allowed_actions = vec![Action::Deliver];
    assert!(cfg.validate().is_err());
}
#[test]
fn exact_mailbox_overrides_domain_and_disabled_self_service_inherits() {
    let root = tempfile::tempdir().unwrap();
    let mut cfg = (*common::config(root.path())).clone();
    let empty = Policy::default();
    let recipient = cfg.recipient("alice@example.test").unwrap();
    cfg.preferences.mailboxes.insert(
        "*@example.test".into(),
        Preference {
            profile: None,
            rules: vec![rule("*@example.test", Category::Spam, Action::Quarantine)],
        },
    );
    cfg.preferences.mailboxes.insert(
        "alice@example.test".into(),
        Preference {
            profile: None,
            rules: vec![],
        },
    );
    cfg.validate().unwrap();
    assert!(cfg.preferences.policy(&empty, &recipient).rules.is_empty());
    cfg.preferences.mailboxes.remove("alice@example.test");
    assert_eq!(cfg.preferences.policy(&empty, &recipient).rules.len(), 1);
    cfg.preferences.enabled = false;
    assert!(cfg.preferences.policy(&empty, &recipient).rules.is_empty());
}
#[test]
fn rbl_credentials_are_bound_to_original_zone_and_provider() {
    let root = tempfile::tempdir().unwrap();
    let mut cfg = (*common::config(root.path())).clone();
    let mut settings:noisefence::rbl::Settings=serde_json::from_value(serde_json::json!({"lists":[{"id":"licensed","provider":"licensed","zone":"rbl.example.test","key_env":"LICENSED_KEY","listed_codes":["127.0.0.2"]}]})).unwrap();
    assert!(noisefence::management::validate_rbl(&settings, &cfg).is_err());
    cfg.rbl = Some(settings.clone());
    noisefence::management::validate_rbl(&settings, &cfg).unwrap();
    settings.lists[0].zone = "exfil.example.test".into();
    assert!(noisefence::management::validate_rbl(&settings, &cfg).is_err());
    settings.lists[0].zone = "rbl.example.test".into();
    settings.lists[0].key_env = Some("SCALEWAY_SECRET_KEY".into());
    assert!(noisefence::management::validate_rbl(&settings, &cfg).is_err());
}

#[test]
fn case_distinct_mailboxes_do_not_share_personal_preferences() {
    let root = tempfile::tempdir().unwrap();
    let mut cfg = (*common::config(root.path())).clone();
    cfg.domains[0].recipients.push("Alice@example.test".into());
    cfg.preferences.mailboxes.insert(
        "Alice@example.test".into(),
        Preference {
            profile: None,
            rules: vec![rule(
                "Alice@example.test",
                Category::Spam,
                Action::Quarantine,
            )],
        },
    );
    cfg.validate().unwrap();
    let base = Policy::default();
    assert_eq!(
        cfg.preferences
            .policy(&base, &cfg.recipient("Alice@example.test").unwrap())
            .rules
            .len(),
        1
    );
    assert!(
        cfg.preferences
            .policy(&base, &cfg.recipient("alice@example.test").unwrap())
            .rules
            .is_empty()
    );
}

#[test]
fn inherit_keeps_the_administrator_exact_mailbox_threshold_and_follows_later_updates() {
    use noisefence::custom_filtering::{Binding, Profile};
    let root = tempfile::tempdir().unwrap();
    let mut cfg = (*common::config(root.path())).clone();
    let recipient = cfg.recipient("alice@example.test").unwrap();
    let mut profile = Profile {
        id: "admin".into(),
        name: "Global".into(),
        threshold: Some(98.),
        require_corroboration: true,
        spam: Action::Quarantine,
        publicity: Action::Deliver,
        review: Action::Deliver,
        quarantine_days: 14,
    };
    let mut base = Policy {
        profiles: vec![profile.clone()],
        bindings: vec![Binding {
            scope: recipient.address.clone(),
            profile: "admin".into(),
        }],
        rules: vec![],
    };
    profile.id = "personal".into();
    profile.threshold = None;
    cfg.preferences.mailboxes.insert(
        recipient.address.clone(),
        Preference {
            profile: Some(profile),
            rules: vec![],
        },
    );
    cfg.validate().unwrap();
    assert_eq!(
        cfg.preferences
            .policy(&base, &recipient)
            .profiles
            .last()
            .unwrap()
            .threshold,
        Some(98.)
    );
    base.profiles[0].threshold = Some(90.);
    assert_eq!(
        cfg.preferences
            .policy(&base, &recipient)
            .profiles
            .last()
            .unwrap()
            .threshold,
        Some(90.)
    );
    assert_eq!(
        cfg.preferences.mailboxes[&recipient.address]
            .profile
            .as_ref()
            .unwrap()
            .threshold,
        None
    );
}
