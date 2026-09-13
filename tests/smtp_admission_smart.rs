use noisefence::smtp_admission::{
    Admission, Mode, Settings, Status,
    runtime::{self, Request},
};
use rusqlite::Connection;
fn request() -> Request {
    Request {
        peer: "192.0.2.7".parse().unwrap(),
        sender: "sender@example.net".into(),
        recipient: "alice@example.org".into(),
        listed_providers: 2,
        invalid_helo: false,
        charge_rate: true,
    }
}
fn setup(settings: Settings) -> (Admission, Connection) {
    let a = Admission::new(settings).unwrap();
    let mut db = Connection::open_in_memory().unwrap();
    a.initialize(&mut db).unwrap();
    db.execute_batch(runtime::SCHEMA).unwrap();
    (a, db)
}
fn settings() -> Settings {
    Settings {
        enabled: true,
        mode: Mode::Enforce,
        retry_delay_seconds: 10,
        rate_per_minute: 0,
        ..Default::default()
    }
}
#[test]
fn selects_only_concordant_risk_and_never_a_missing_result_or_helo_alone() {
    let (a, mut db) = setup(settings());
    let mut r = request();
    for (listed, helo, expected) in [
        (0, false, Status::NotSelected),
        (0, true, Status::NotSelected),
        (1, false, Status::NotSelected),
        (1, true, Status::FirstSeen),
    ] {
        r.listed_providers = listed;
        r.invalid_helo = helo;
        assert_eq!(
            runtime::check(&mut db, &a, &r, 1000).unwrap().status,
            expected
        );
    }
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM smtp_admission_entries_v1", [], |r| {
            r.get::<_, i64>(0)
        })
        .unwrap(),
        1
    );
}
#[test]
fn retries_share_sender_network_but_not_other_recipients_or_senders() {
    let (a, mut db) = setup(settings());
    let mut r = request();
    assert!(
        runtime::check(&mut db, &a, &r, 1000)
            .unwrap()
            .smtp_reply()
            .is_some()
    );
    r.peer = "192.0.2.89".parse().unwrap();
    assert_eq!(
        runtime::check(&mut db, &a, &r, 1005)
            .unwrap()
            .retry_after_seconds,
        Some(5)
    );
    assert_eq!(
        runtime::check(&mut db, &a, &r, 1010).unwrap().status,
        Status::RetryPassed
    );
    r.recipient = "bob@example.org".into();
    assert_eq!(
        runtime::check(&mut db, &a, &r, 1010).unwrap().status,
        Status::FirstSeen
    );
    r.recipient = "alice@example.org".into();
    r.sender = "other@example.net".into();
    assert_eq!(
        runtime::check(&mut db, &a, &r, 1010).unwrap().status,
        Status::FirstSeen
    );
}
#[test]
fn rate_limits_refill_without_sliding_and_observation_never_defers() {
    let (a, mut db) = setup(Settings {
        rate_per_minute: 60,
        rate_burst: 2,
        greylisting: false,
        ..settings()
    });
    let r = request();
    for expected in [
        Status::NotSelected,
        Status::NotSelected,
        Status::RateLimited,
        Status::RateLimited,
    ] {
        assert_eq!(
            runtime::check(&mut db, &a, &r, 1000).unwrap().status,
            expected
        );
    }
    assert_eq!(
        runtime::check(&mut db, &a, &r, 1001).unwrap().status,
        Status::NotSelected
    );
    let observed = a.with_mode(Mode::Observe);
    for _ in 0..4 {
        assert!(
            runtime::check(&mut db, &observed, &r, 1001)
                .unwrap()
                .smtp_reply()
                .is_none()
        );
    }
    assert_eq!(
        runtime::check(&mut db, &a, &r, 1001).unwrap().status,
        Status::RateLimited
    );
}
#[test]
fn exemptions_use_real_network_only_and_null_sender_still_has_a_rate_limit() {
    let (a, mut db) = setup(Settings {
        allow_networks: vec!["192.0.2.7/32".into()],
        rate_per_minute: 60,
        rate_burst: 1,
        ..settings()
    });
    let mut r = request();
    for _ in 0..3 {
        assert_eq!(
            runtime::check(&mut db, &a, &r, 1000).unwrap().status,
            Status::Exempt
        );
    }
    r.peer = "192.0.2.8".parse().unwrap();
    r.sender = String::new();
    assert_eq!(
        runtime::check(&mut db, &a, &r, 1000).unwrap().status,
        Status::Exempt
    );
    assert_eq!(
        runtime::check(&mut db, &a, &r, 1000).unwrap().status,
        Status::RateLimited
    );
    assert!(runtime::network("0.0.0.0/0").is_err());
    assert!(runtime::network("trusted.example.org").is_err());
}
#[test]
fn ipv6_rotation_shares_rate_but_ipv4_different_hosts_do_not() {
    let (a, mut db) = setup(Settings {
        greylisting: false,
        rate_per_minute: 60,
        rate_burst: 1,
        ..settings()
    });
    let mut r = request();
    r.peer = "2001:db8:1::1".parse().unwrap();
    assert_eq!(
        runtime::check(&mut db, &a, &r, 1000).unwrap().status,
        Status::NotSelected
    );
    r.peer = "2001:db8:1::2".parse().unwrap();
    assert_eq!(
        runtime::check(&mut db, &a, &r, 1000).unwrap().status,
        Status::RateLimited
    );
    r.peer = "192.0.2.1".parse().unwrap();
    assert_eq!(
        runtime::check(&mut db, &a, &r, 1000).unwrap().status,
        Status::NotSelected
    );
    r.peer = "192.0.2.2".parse().unwrap();
    assert_eq!(
        runtime::check(&mut db, &a, &r, 1000).unwrap().status,
        Status::NotSelected
    );
}
#[test]
fn saturation_never_evicts_pending_cycles_and_maintenance_removes_old_counters() {
    let (a, mut db) = setup(Settings {
        max_entries: 1,
        ..settings()
    });
    let mut r = request();
    assert_eq!(
        runtime::check(&mut db, &a, &r, 1000).unwrap().status,
        Status::FirstSeen
    );
    r.recipient = "bob@example.org".into();
    assert_eq!(
        runtime::check(&mut db, &a, &r, 1000).unwrap().status,
        Status::Capacity
    );
    r.recipient = "alice@example.org".into();
    assert_eq!(
        runtime::check(&mut db, &a, &r, 1010).unwrap().status,
        Status::RetryPassed
    );
    runtime::prune(&mut db, 40 * 86400).unwrap();
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM smtp_admission_counts_v2", [], |r| r
            .get::<_, i64>(
            0
        ))
        .unwrap(),
        0
    );
}
