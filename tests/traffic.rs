mod common;
use noisefence::{
    config::Mode,
    traffic::{
        self, Action, Policy, Report, Settings,
        runtime::{Request, check, policy_hash},
        verification,
    },
};
use rusqlite::{Connection, params};
fn setup() -> (tempfile::TempDir, noisefence::config::Config, Connection) {
    let root = tempfile::tempdir().unwrap();
    let mut cfg = (*common::config(root.path())).clone();
    cfg.filter.mode = Mode::Enforce;
    cfg.smtp_admission = Some(noisefence::smtp_admission::Settings {
        traffic: Some(Box::new(Settings {
            enabled: true,
            policy: Policy {
                action: Action::Defer,
                sender_limit: 2,
                domain_limit: 0,
                recipient_limit: 0,
                duplicate_limit: 0,
                ..Default::default()
            },
            ..Default::default()
        })),
        ..Default::default()
    });
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch(traffic::runtime::SCHEMA).unwrap();
    db.execute_batch(verification::SCHEMA).unwrap();
    (root, cfg, db)
}
fn request(cfg: &noisefence::config::Config) -> Request {
    Request {
        id: uuid::Uuid::new_v4().to_string(),
        policy_hash: policy_hash(cfg),
        peer: "192.0.2.1".parse().unwrap(),
        sender: "sender@example.org".into(),
        recipients: vec!["alice@example.test".into()],
        fingerprint: noisefence::message::digest(common::MESSAGE),
        authenticated: false,
        verification_eligible: false,
    }
}
fn report(
    db: &mut Connection,
    cfg: &noisefence::config::Config,
    req: &Request,
    time: i64,
) -> Report {
    check(db, cfg, req, time)
        .unwrap()
        .remove("alice@example.test")
        .unwrap()
}
#[test]
fn defaults_are_inert_and_do_not_send_challenges() {
    let s = Settings::default();
    assert!(!s.enabled && !s.verification.enabled && !s.policy.verify_new_senders);
    assert_eq!(s.policy.action, Action::Observe);
    s.validate().unwrap();
}
#[test]
fn shared_authority_deduplicates_rpc_retries_and_limits_attempts() {
    let (_root, cfg, mut db) = setup();
    let req = request(&cfg);
    assert_eq!(report(&mut db, &cfg, &req, 100).counts["sender"], 1);
    assert_eq!(report(&mut db, &cfg, &req, 101).counts["sender"], 1);
    assert!(!report(&mut db, &cfg, &request(&cfg), 102).defer());
    let r = report(&mut db, &cfg, &request(&cfg), 103);
    assert!(r.defer());
    assert_eq!(r.counts["sender"], 3);
    // Failed retries do not extend a fixed window.
    assert!(report(&mut db, &cfg, &request(&cfg), 399).defer());
    assert!(!report(&mut db, &cfg, &request(&cfg), 400).defer());
}
#[test]
fn spoofed_senders_cannot_consume_verified_sender_buckets() {
    let (_root, cfg, mut db) = setup();
    for _ in 0..5 {
        report(&mut db, &cfg, &request(&cfg), 100);
    }
    let mut genuine = request(&cfg);
    genuine.authenticated = true;
    assert_eq!(report(&mut db, &cfg, &genuine, 100).counts["sender"], 1);
    genuine.id = uuid::Uuid::new_v4().to_string();
    genuine.peer = "192.0.2.2".parse().unwrap();
    assert_eq!(report(&mut db, &cfg, &genuine, 100).counts["sender"], 2);
    genuine.id = uuid::Uuid::new_v4().to_string();
    assert!(report(&mut db, &cfg, &genuine, 100).defer());
}
#[test]
fn ipv6_rotation_within_subnet_does_not_reset_unauthenticated_quota() {
    let (_root, cfg, mut db) = setup();
    for n in 1..=3 {
        let mut r = request(&cfg);
        r.peer = format!("2001:db8::{n}").parse().unwrap();
        let result = report(&mut db, &cfg, &r, 100);
        assert_eq!(result.counts["sender"], n);
    }
}
#[test]
fn observation_isolated_from_enforcement_and_score_remains_unchanged() {
    let (_root, mut cfg, mut db) = setup();
    cfg.filter.mode = Mode::Observe;
    for _ in 0..3 {
        let r = report(&mut db, &cfg, &request(&cfg), 100);
        assert!(!r.defer() && !r.hold());
    }
    cfg.filter.mode = Mode::Enforce;
    assert_eq!(
        report(&mut db, &cfg, &request(&cfg), 100).counts["sender"],
        1
    );
    let mut applied = noisefence::actions::Applied {
        coverage: None,
        requested: noisefence::actions::Action::Deliver,
        effective: noisefence::actions::Action::Deliver,
        reason: "category".into(),
        quarantine_days: 7,
    };
    let r = Report {
        action: Action::Quarantine,
        enforced: true,
        ..Default::default()
    };
    r.apply(&mut applied);
    assert_eq!(applied.reason, "traffic_limit");
}
#[test]
fn recipient_and_duplicate_limits_catch_rotating_senders() {
    let (_root, mut cfg, mut db) = setup();
    let s = cfg
        .smtp_admission
        .as_mut()
        .unwrap()
        .traffic
        .as_mut()
        .unwrap();
    s.policy.sender_limit = 0;
    s.policy.duplicate_limit = 1;
    report(&mut db, &cfg, &request(&cfg), 100);
    let mut req = request(&cfg);
    req.sender = "another@different.test".into();
    req.peer = "198.51.100.3".parse().unwrap();
    assert!(
        report(&mut db, &cfg, &req, 100)
            .reasons
            .contains(&"duplicate_limit".into())
    );
    req.id = uuid::Uuid::new_v4().to_string();
    req.recipients = vec!["bob@example.test".into()];
    assert!(!check(&mut db, &cfg, &req, 100).unwrap()["bob@example.test"].defer());
}
#[test]
fn scope_and_authorized_personal_policy_take_precedence() {
    let (_root, mut cfg, _db) = setup();
    let s = cfg
        .smtp_admission
        .as_mut()
        .unwrap()
        .traffic
        .as_mut()
        .unwrap();
    s.scopes.insert(
        "*@example.test".into(),
        Policy {
            sender_limit: 10,
            ..Default::default()
        },
    );
    s.scopes.insert(
        "alice@example.test".into(),
        Policy {
            sender_limit: 3,
            ..Default::default()
        },
    );
    assert_eq!(
        traffic::settings(&cfg)
            .unwrap()
            .policy_for(&cfg, "alice@example.test")
            .sender_limit,
        3
    );
    cfg.preferences.mailboxes.insert(
        "alice@example.test".into(),
        noisefence::preferences::Preference {
            traffic: Some(Policy {
                sender_limit: 1,
                ..Default::default()
            }),
            profile: None,
            rules: vec![],
        },
    );
    let mut unmodified = cfg.clone();
    unmodified.preferences.mailboxes.clear();
    assert!(
        noisefence::preferences::validate_traffic_edit(
            &unmodified,
            "alice@example.test",
            cfg.preferences.mailboxes.get("alice@example.test")
        )
        .is_err()
    );
    cfg.preferences.validate(&cfg).unwrap();
    cfg.smtp_admission
        .as_mut()
        .unwrap()
        .traffic
        .as_mut()
        .unwrap()
        .allow_personal = true;
    cfg.preferences.validate(&cfg).unwrap();
    assert_eq!(
        traffic::settings(&cfg)
            .unwrap()
            .policy_for(&cfg, "alice@example.test")
            .sender_limit,
        1
    );
    assert!(!noisefence::preferences::permitted(
        "bob@example.test",
        false,
        &["alice@example.test".into()]
    ));
}
#[test]
fn stale_policy_and_unknown_recipient_do_not_charge_counters() {
    let (_root, cfg, mut db) = setup();
    let mut req = request(&cfg);
    req.policy_hash = "stale".into();
    assert!(check(&mut db, &cfg, &req, 100).is_err());
    req.policy_hash = policy_hash(&cfg);
    req.recipients = vec!["unknown@outside.test".into()];
    assert!(check(&mut db, &cfg, &req, 100).is_err());
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM traffic_buckets_v1", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
}
#[test]
fn captcha_checks_provider_result_hostname_action_and_binding() {
    let good = serde_json::json!({"success":true,"hostname":"mx.example.org","action":"sender_verification","cdata":"ticket"});
    assert!(verification::validate_captcha(&good, "mx.example.org", "ticket").is_ok());
    for (field, bad) in [
        ("hostname", serde_json::json!("evil.test")),
        ("action", serde_json::json!("login")),
        ("success", serde_json::json!(false)),
        ("cdata", serde_json::json!("different")),
    ] {
        let mut data = good.clone();
        data[field] = bad;
        assert!(verification::validate_captcha(&data, "mx.example.org", "ticket").is_err());
    }
}
#[test]
fn ticket_is_unarmed_and_scope_bound_and_grants_expire() {
    let (_root, _cfg, mut db) = setup();
    let s = verification::Settings::default();
    let tx = db.transaction().unwrap();
    let a = verification::ticket(&tx, &s, "sender@example.org", "alice@example.test", 100)
        .unwrap()
        .unwrap();
    let again = verification::ticket(&tx, &s, "sender@example.org", "alice@example.test", 101)
        .unwrap()
        .unwrap();
    assert_eq!(a, again);
    let b = verification::ticket(&tx, &s, "sender@example.org", "bob@example.test", 100)
        .unwrap()
        .unwrap();
    assert_ne!(a, b);
    assert_eq!(
        tx.query_row(
            "SELECT armed FROM sender_verification_v1 WHERE id=?1",
            [&a],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    tx.execute(
        "INSERT INTO sender_verification_grants_v1 VALUES(?1,?2,?3)",
        params!["sender@example.org", "alice@example.test", 200],
    )
    .unwrap();
    assert!(
        verification::ticket(&tx, &s, "sender@example.org", "alice@example.test", 150)
            .unwrap()
            .is_none()
    );
    assert!(
        verification::ticket(&tx, &s, "sender@example.org", "alice@example.test", 200)
            .unwrap()
            .is_some()
    );
}
#[test]
fn content_only_mail_is_never_eligible_for_invitation() {
    let (_root, cfg, _db) = setup();
    let scan = noisefence::engine::extract(common::MESSAGE, 1024 * 1024);
    assert!(!verification::eligible(
        common::MESSAGE,
        "sender@example.org",
        &scan,
        &cfg
    ));
    assert!(!verification::eligible(common::MESSAGE, "", &scan, &cfg));
}
#[test]
fn verification_settings_reject_insecure_or_injected_routes() {
    let mut s = verification::Settings {
        enabled: true,
        public_origin: "http://mx.example.org".into(),
        site_key: "12345678901234567890".into(),
        notification_from: "verify@example.org".into(),
        relay_hosts: vec!["relay.example.org:25".into()],
        ..Default::default()
    };
    assert!(s.validate().is_err());
    s.public_origin = "https://mx.example.org".into();
    s.validate().unwrap();
    s.notification_from = "verify@example.org\r\nBcc: victim@example.org".into();
    assert!(s.validate().is_err());
}
#[tokio::test]
async fn early_deferral_uses_existing_windows_without_extending_them() {
    let (_root, cfg, mut db) = setup();
    let root = tempfile::tempdir().unwrap();
    let store = noisefence::store::Store::open(root.path()).unwrap();
    let mut cfg = cfg;
    cfg.data_dir = root.path().into();
    // Seed the actual shared store through the same authority used by both MX nodes.
    for _ in 0..2 {
        traffic::runtime::local(&store, &cfg, request(&cfg))
            .await
            .unwrap();
    }
    let early = traffic::runtime::Early {
        peer: "192.0.2.1".parse().unwrap(),
        sender: "sender@example.org".into(),
        recipient: "alice@example.test".into(),
        policy_hash: policy_hash(&cfg),
    };
    assert!(
        traffic::runtime::early_local(&store, &cfg, early.clone())
            .await
            .unwrap()
    );
    let other = traffic::runtime::Early {
        peer: "192.0.2.2".parse().unwrap(),
        ..early
    };
    assert!(
        !traffic::runtime::early_local(&store, &cfg, other)
            .await
            .unwrap()
    );
    // Independent store has no authority state; it must not be used as a worker fallback.
    assert_eq!(
        report(&mut db, &cfg, &request(&cfg), 100).counts["sender"],
        1
    );
}
#[test]
fn observation_of_floods_does_not_bypass_explicit_verification_policy() {
    let (_root, mut cfg, mut db) = setup();
    let settings = cfg
        .smtp_admission
        .as_mut()
        .unwrap()
        .traffic
        .as_mut()
        .unwrap();
    settings.policy.action = Action::Observe;
    settings.policy.sender_limit = 1;
    settings.policy.verify_new_senders = true;
    settings.verification.enabled = true;
    cfg.provider_credentials = Some(std::sync::Arc::new(
        noisefence::credentials::Snapshot::from_map(std::collections::BTreeMap::from([(
            "turnstile".into(),
            "synthetic-test-secret-never-sent".into(),
        )]))
        .unwrap(),
    ));
    for _ in 0..3 {
        let mut req = request(&cfg);
        req.authenticated = true;
        req.verification_eligible = true;
        let r = report(&mut db, &cfg, &req, 100);
        assert!(r.hold());
        assert!(r.verification_id.is_some());
    }
}
#[test]
fn result_cache_is_bounded_and_capacity_failure_rolls_back_counters() {
    let (_root, cfg, mut db) = setup();
    db.execute("UPDATE traffic_cache_size_v1 SET bytes=16777216", [])
        .unwrap();
    assert!(check(&mut db, &cfg, &request(&cfg), 100).is_err());
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM traffic_buckets_v1", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
}
