use noisefence::smtp_admission::{
    Admission, Decision, DelayBudget, DelayOutcome, GREYLIST_REPLY, Mode, Settings, Status,
    UNAVAILABLE_REPLY, normalize_peer_ip,
};
use rusqlite::Connection;
use std::{
    future::Future,
    net::SocketAddr,
    path::Path,
    sync::{Arc, Barrier},
    task::Poll,
    time::Duration,
};

fn settings() -> Settings {
    Settings {
        enabled: true,
        mode: Mode::Enforce,
        retry_delay_seconds: 10,
        retry_max_age_seconds: 100,
        retention_seconds: 200,
        ..Settings::default()
    }
}
fn peer() -> SocketAddr {
    "192.0.2.7:2525".parse().unwrap()
}
fn db() -> Connection {
    Connection::open_in_memory().unwrap()
}
fn file_db(path: &Path) -> Connection {
    let db = Connection::open(path).unwrap();
    db.busy_timeout(Duration::from_secs(3)).unwrap();
    db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")
        .unwrap();
    db
}
fn check(admission: &Admission, db: &mut Connection, now: i64) -> Decision {
    admission
        .check(db, peer(), "sender@example.net", "one@example.org", now)
        .unwrap()
}
fn count(db: &Connection) -> usize {
    db.query_row("SELECT count(*) FROM smtp_admission_entries_v1", [], |r| {
        r.get(0)
    })
    .unwrap()
}
fn setup(config: Settings) -> (Admission, Connection) {
    let admission = Admission::new(config).unwrap();
    let mut db = db();
    admission.initialize(&mut db).unwrap();
    (admission, db)
}

#[test]
fn defaults_disable_all_effects_without_even_creating_tables() {
    let settings: Settings = toml::from_str("").unwrap();
    assert!(!settings.enabled);
    assert_eq!(settings.mode, Mode::Observe);
    assert_eq!(settings.tarpit_delay_ms, 0);
    let (admission, mut db) = setup(settings);
    let result = check(&admission, &mut db, 1000);
    assert_eq!(result.status, Status::Disabled);
    assert!(!result.would_defer);
    assert_eq!(result.smtp_reply(), None);
    assert_eq!(admission.unavailable().smtp_reply(), None);
    assert_eq!(admission.prune(&mut db, 1000).unwrap(), 0);
    let tables: usize = db
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE name LIKE 'smtp_admission_%'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(tables, 0);
}

#[test]
fn settings_reject_invalid_bounds_and_unknown_fields() {
    let mut cases = Vec::new();
    for delay in [0, 3601, u64::MAX] {
        cases.push(Settings {
            retry_delay_seconds: delay,
            ..settings()
        });
    }
    for age in [0, 10, 604801, u64::MAX] {
        cases.push(Settings {
            retry_max_age_seconds: age,
            ..settings()
        });
    }
    for retention in [0, 2592001, u64::MAX] {
        cases.push(Settings {
            retention_seconds: retention,
            ..settings()
        });
    }
    for capacity in [0, 100001, usize::MAX] {
        cases.push(Settings {
            max_entries: capacity,
            ..settings()
        });
    }
    for parallel in [0, 65, usize::MAX] {
        cases.push(Settings {
            tarpit_max_concurrent: parallel,
            ..settings()
        });
    }
    cases.push(Settings {
        tarpit_delay_ms: 5001,
        ..settings()
    });
    cases.push(Settings {
        tarpit_session_budget_ms: 10001,
        ..settings()
    });
    for config in cases {
        assert!(Admission::new(config).is_err());
    }
    assert!(toml::from_str::<Settings>("enabled = true\nmod = 'enforce'").is_err());
    assert!(toml::from_str::<Settings>("mode = 'tag'").is_err());
}

#[test]
fn pending_and_passed_state_survive_database_reopen_and_idempotent_setup() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("state.sqlite3");
    let admission = Admission::new(settings()).unwrap();
    {
        let mut db = file_db(&path);
        db.execute_batch("PRAGMA user_version=2; CREATE TABLE unrelated(value TEXT); INSERT INTO unrelated VALUES('keep');").unwrap();
        admission.initialize(&mut db).unwrap();
        assert_eq!(
            check(&admission, &mut db, 1000).smtp_reply(),
            Some(GREYLIST_REPLY)
        );
    }
    {
        let mut db = file_db(&path);
        admission.initialize(&mut db).unwrap();
        assert_eq!(check(&admission, &mut db, 1009).status, Status::TooSoon);
        assert_eq!(check(&admission, &mut db, 1010).status, Status::RetryPassed);
        assert_eq!(
            db.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            2
        );
        assert_eq!(
            db.query_row("SELECT value FROM unrelated", [], |r| r.get::<_, String>(0))
                .unwrap(),
            "keep"
        );
    }
    let mut db = file_db(&path);
    let restarted = Admission::new(settings()).unwrap();
    restarted.initialize(&mut db).unwrap();
    let decision = check(&restarted, &mut db, 1011);
    assert_eq!(decision.status, Status::Passed);
    assert_eq!(decision.smtp_reply(), None);
    assert_eq!(count(&db), 1);
}

#[test]
fn early_retries_never_slide_the_minimum_delay_and_deadline_is_inclusive() {
    let (admission, mut db) = setup(settings());
    assert_eq!(
        check(&admission, &mut db, 1000).retry_after_seconds,
        Some(10)
    );
    for now in 1001..1010 {
        let result = check(&admission, &mut db, now);
        assert_eq!(result.status, Status::TooSoon);
        assert_eq!(result.retry_after_seconds, Some((1010 - now) as u64));
        assert_eq!(result.smtp_reply(), Some(GREYLIST_REPLY));
    }
    let result = check(&admission, &mut db, 1010);
    assert_eq!(result.status, Status::RetryPassed);
    assert_eq!(result.smtp_reply(), None);
}

#[test]
fn retry_max_age_and_success_retention_are_fixed_and_expire_at_the_boundary() {
    let (admission, mut db) = setup(settings());
    check(&admission, &mut db, 1000);
    assert_eq!(check(&admission, &mut db, 1100).status, Status::FirstSeen);
    assert_eq!(check(&admission, &mut db, 1109).status, Status::TooSoon);
    assert_eq!(check(&admission, &mut db, 1110).status, Status::RetryPassed);
    for now in [1111, 1200, 1309] {
        assert_eq!(check(&admission, &mut db, now).status, Status::Passed);
    }
    assert_eq!(check(&admission, &mut db, 1310).status, Status::FirstSeen);
    let (other, mut other_db) = setup(settings());
    check(&other, &mut other_db, 1000);
    assert_eq!(
        check(&other, &mut other_db, 1099).status,
        Status::RetryPassed
    );
}

#[test]
fn recipients_senders_and_ipv6_hosts_do_not_share_retry_success() {
    let (admission, mut db) = setup(settings());
    check(&admission, &mut db, 1000);
    check(&admission, &mut db, 1010);
    for (source, sender, recipient) in [
        (peer(), "sender@example.net", "two@example.org"),
        (peer(), "sender@example.net", "one+tag@example.org"),
        (peer(), "other@example.net", "one@example.org"),
        (peer(), "", "one@example.org"),
        (
            "192.0.2.8:2525".parse().unwrap(),
            "sender@example.net",
            "one@example.org",
        ),
        (
            "[2001:db8::1]:2525".parse().unwrap(),
            "sender@example.net",
            "one@example.org",
        ),
        (
            "[2001:db8::2]:2525".parse().unwrap(),
            "sender@example.net",
            "one@example.org",
        ),
    ] {
        assert_eq!(
            admission
                .check(&mut db, source, sender, recipient, 1011)
                .unwrap()
                .status,
            Status::FirstSeen
        );
    }
    assert_eq!(count(&db), 8);
    assert_eq!(check(&admission, &mut db, 1012).status, Status::Passed);
}

#[test]
fn socket_identity_normalizes_mapped_ipv4_ipv6_spelling_and_source_ports_only() {
    let (admission, mut db) = setup(settings());
    check(&admission, &mut db, 1000);
    assert_eq!(
        admission
            .check(
                &mut db,
                "[::ffff:192.0.2.7]:54321".parse().unwrap(),
                "sender@EXAMPLE.NET",
                "one@EXAMPLE.ORG",
                1010
            )
            .unwrap()
            .status,
        Status::RetryPassed
    );
    assert_eq!(count(&db), 1);
    assert_eq!(
        normalize_peer_ip("::ffff:192.0.2.7".parse().unwrap()),
        peer().ip()
    );
    assert_ne!(
        normalize_peer_ip("::192.0.2.7".parse().unwrap()),
        peer().ip()
    );
    let a = "[2001:0db8:0000:0000:0000:0000:0000:000a]:25"
        .parse()
        .unwrap();
    let b = "[2001:db8::a]:54321".parse().unwrap();
    assert_eq!(
        admission
            .check(&mut db, a, "sender@example.net", "one@example.org", 1000)
            .unwrap()
            .status,
        Status::FirstSeen
    );
    assert_eq!(
        admission
            .check(&mut db, b, "sender@example.net", "one@example.org", 1010)
            .unwrap()
            .status,
        Status::RetryPassed
    );
    // SMTP local-part case is preserved, even though domains are case-folded.
    assert_eq!(
        admission
            .check(
                &mut db,
                peer(),
                "Sender@example.net",
                "one@example.org",
                1011
            )
            .unwrap()
            .status,
        Status::FirstSeen
    );
    assert_eq!(
        admission
            .check(
                &mut db,
                peer(),
                "sender@example.net",
                "One@example.org",
                1011
            )
            .unwrap()
            .status,
        Status::FirstSeen
    );
}

#[test]
fn observe_records_hypothetical_decisions_without_preapproving_enforcement() {
    let config = Settings {
        mode: Mode::Observe,
        max_entries: 1,
        tarpit_delay_ms: 5000,
        ..settings()
    };
    let (observe, mut db) = setup(config.clone());
    let first = check(&observe, &mut db, 1000);
    assert!(first.would_defer);
    assert_eq!(first.smtp_reply(), None);
    assert_eq!(first.candidate_delay_ms, 5000);
    assert_eq!(check(&observe, &mut db, 1010).status, Status::RetryPassed);
    assert_eq!(check(&observe, &mut db, 1011).smtp_reply(), None);
    let enforce = Admission::new(Settings {
        mode: Mode::Enforce,
        ..config
    })
    .unwrap();
    enforce.initialize(&mut db).unwrap();
    let first_live = check(&enforce, &mut db, 1011);
    assert_eq!(first_live.status, Status::FirstSeen);
    assert_eq!(first_live.smtp_reply(), Some(GREYLIST_REPLY));
    assert_eq!(check(&observe, &mut db, 1012).status, Status::Passed);
    assert_eq!(count(&db), 2);
}

#[test]
fn capacity_preserves_live_retry_state_and_reports_fail_open() {
    let (admission, mut db) = setup(Settings {
        max_entries: 1,
        ..settings()
    });
    check(&admission, &mut db, 1000);
    let overflow = admission
        .check(
            &mut db,
            peer(),
            "sender@example.net",
            "two@example.org",
            1001,
        )
        .unwrap();
    assert_eq!(overflow.status, Status::Capacity);
    assert!(!overflow.would_defer);
    assert_eq!(overflow.smtp_reply(), None);
    assert_eq!(count(&db), 1);
    assert_eq!(check(&admission, &mut db, 1010).status, Status::RetryPassed);
    assert_eq!(
        admission
            .check(
                &mut db,
                peer(),
                "sender@example.net",
                "two@example.org",
                1210
            )
            .unwrap()
            .status,
        Status::FirstSeen
    );
    assert_eq!(count(&db), 1);
}

#[test]
fn cleanup_is_bounded_runs_without_traffic_and_can_run_after_disabling() {
    let (admission, mut db) = setup(settings());
    for n in 0..600 {
        admission
            .check(
                &mut db,
                peer(),
                "sender@example.net",
                &format!("r{n}@example.org"),
                1000,
            )
            .unwrap();
    }
    assert_eq!(admission.prune(&mut db, 1099).unwrap(), 0);
    // Targeted expiration resets this tuple even behind a >256-row sweep backlog.
    assert_eq!(
        admission
            .check(
                &mut db,
                peer(),
                "sender@example.net",
                "r599@example.org",
                1100
            )
            .unwrap()
            .status,
        Status::FirstSeen
    );
    assert_eq!(count(&db), 344);
    let disabled = Admission::new(Settings::default()).unwrap();
    assert_eq!(disabled.prune(&mut db, 1100).unwrap(), 256);
    assert_eq!(disabled.prune(&mut db, 1100).unwrap(), 87);
    assert_eq!(count(&db), 1);
    assert_eq!(disabled.prune(&mut db, 1200).unwrap(), 1);
}

#[test]
fn concurrent_connections_initialize_once_insert_once_and_promote_once() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("state.sqlite3");
    drop(file_db(&path));
    for (now, unique_status, other_status) in [
        (1000, Status::FirstSeen, Status::TooSoon),
        (1010, Status::RetryPassed, Status::Passed),
    ] {
        let barrier = Arc::new(Barrier::new(8));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let path = path.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let admission = Admission::new(settings()).unwrap();
                    let mut db = file_db(&path);
                    barrier.wait();
                    admission.initialize(&mut db).unwrap();
                    check(&admission, &mut db, now).status
                })
            })
            .collect();
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert_eq!(results.iter().filter(|&&s| s == unique_status).count(), 1);
        assert_eq!(results.iter().filter(|&&s| s == other_status).count(), 7);
    }
    assert_eq!(count(&file_db(&path)), 1);
}

#[test]
fn capacity_is_atomic_across_independent_writers_with_distinct_recipients() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("state.sqlite3");
    let admission = Admission::new(Settings {
        max_entries: 2,
        ..settings()
    })
    .unwrap();
    admission.initialize(&mut file_db(&path)).unwrap();
    let barrier = Arc::new(Barrier::new(8));
    let handles: Vec<_> = (0..8)
        .map(|n| {
            let path = path.clone();
            let admission = admission.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let mut db = file_db(&path);
                barrier.wait();
                admission
                    .check(
                        &mut db,
                        peer(),
                        "sender@example.net",
                        &format!("r{n}@example.org"),
                        1000,
                    )
                    .unwrap()
                    .status
            })
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(
        results.iter().filter(|&&s| s == Status::FirstSeen).count(),
        2
    );
    assert_eq!(
        results.iter().filter(|&&s| s == Status::Capacity).count(),
        6
    );
    assert_eq!(count(&file_db(&path)), 2);
}

#[test]
fn failed_write_rolls_back_expiry_and_does_not_return_an_admission() {
    let (admission, mut db) = setup(settings());
    check(&admission, &mut db, 1000);
    db.execute_batch("CREATE TRIGGER reject_admission BEFORE INSERT ON smtp_admission_entries_v1 BEGIN SELECT RAISE(ABORT,'injected write failure'); END;").unwrap();
    assert!(
        admission
            .check(
                &mut db,
                peer(),
                "sender@example.net",
                "two@example.org",
                1100
            )
            .is_err()
    );
    // Even the expired deletion in that transaction has rolled back.
    assert_eq!(count(&db), 1);
    assert_eq!(
        admission.unavailable().smtp_reply(),
        Some(UNAVAILABLE_REPLY)
    );
    db.execute_batch("DROP TRIGGER reject_admission").unwrap();
    assert_eq!(check(&admission, &mut db, 1100).status, Status::FirstSeen);
    db.execute_batch("CREATE TRIGGER reject_promotion BEFORE UPDATE ON smtp_admission_entries_v1 BEGIN SELECT RAISE(ABORT,'injected promotion failure'); END;").unwrap();
    assert!(
        admission
            .check(
                &mut db,
                peer(),
                "sender@example.net",
                "one@example.org",
                1110
            )
            .is_err()
    );
    db.execute_batch("DROP TRIGGER reject_promotion").unwrap();
    assert_eq!(check(&admission, &mut db, 1110).status, Status::RetryPassed);
}

#[test]
fn unavailable_database_is_visible_but_never_enforces_in_observe_mode() {
    let observe = Admission::new(Settings {
        mode: Mode::Observe,
        ..settings()
    })
    .unwrap();
    let mut missing = db();
    assert!(
        observe
            .check(
                &mut missing,
                peer(),
                "sender@example.net",
                "one@example.org",
                1000
            )
            .is_err()
    );
    let unavailable = observe.unavailable();
    assert_eq!(unavailable.status, Status::Unavailable);
    assert!(unavailable.would_defer);
    assert_eq!(unavailable.smtp_reply(), None);
    assert_eq!(unavailable.candidate_delay_ms, 0);
}

#[test]
fn lock_contention_is_a_bounded_error_and_does_not_mutate_existing_state() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("state.sqlite3");
    let admission = Admission::new(settings()).unwrap();
    let mut writer = file_db(&path);
    admission.initialize(&mut writer).unwrap();
    let mut contender = file_db(&path);
    contender.busy_timeout(Duration::ZERO).unwrap();
    let tx = writer
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .unwrap();
    assert!(
        admission
            .check(
                &mut contender,
                peer(),
                "sender@example.net",
                "one@example.org",
                1000
            )
            .is_err()
    );
    assert_eq!(
        admission.unavailable().smtp_reply(),
        Some(UNAVAILABLE_REPLY)
    );
    tx.rollback().unwrap();
    assert_eq!(count(&writer), 0);
    assert_eq!(
        check(&admission, &mut contender, 1000).status,
        Status::FirstSeen
    );
}

#[test]
fn invalid_input_and_clock_rollback_never_grant_retry_success() {
    let (admission, mut db) = setup(settings());
    for (sender, recipient) in [
        ("<>", "one@example.org"),
        ("", ""),
        ("a@b\r\n", "one@example.org"),
        ("sender@example.net", "é@example.org"),
    ] {
        assert!(
            admission
                .check(&mut db, peer(), sender, recipient, 1000)
                .is_err()
        );
    }
    let huge = "x".repeat(255) + "@example.org";
    assert!(
        admission
            .check(&mut db, peer(), &huge, "one@example.org", 1000)
            .is_err()
    );
    for now in [-1, i64::MAX] {
        assert!(
            admission
                .check(
                    &mut db,
                    peer(),
                    "sender@example.net",
                    "one@example.org",
                    now
                )
                .is_err()
        );
    }
    assert_eq!(count(&db), 0);
    check(&admission, &mut db, 1000);
    assert_eq!(check(&admission, &mut db, 999).status, Status::ClockSkew);
    check(&admission, &mut db, 1010);
    assert_eq!(
        check(&admission, &mut db, 1009).smtp_reply(),
        Some(UNAVAILABLE_REPLY)
    );
    assert_eq!(check(&admission, &mut db, 1011).status, Status::Passed);
    assert_eq!(
        admission
            .check(&mut db, peer(), "", "POSTMASTER", 1000)
            .unwrap()
            .status,
        Status::FirstSeen
    );
    assert_eq!(
        admission
            .check(&mut db, peer(), "", "postmaster", 1010)
            .unwrap()
            .status,
        Status::RetryPassed
    );
}

#[test]
fn envelope_hashes_are_salted_role_separated_and_absent_from_observations() {
    let (admission, mut db) = setup(settings());
    let decision = admission
        .check(
            &mut db,
            peer(),
            "same@example.org",
            "same@example.org",
            1000,
        )
        .unwrap();
    let hashes = |db: &Connection| {
        db.query_row(
            "SELECT sender_hash,recipient_hash FROM smtp_admission_entries_v1",
            [],
            |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?)),
        )
        .unwrap()
    };
    let (sender, recipient) = hashes(&db);
    assert_eq!(sender.len(), 32);
    assert_eq!(recipient.len(), 32);
    assert_ne!(sender, recipient);
    let (other, mut other_db) = setup(settings());
    other
        .check(
            &mut other_db,
            peer(),
            "same@example.org",
            "same@example.org",
            1000,
        )
        .unwrap();
    assert_ne!(hashes(&db), hashes(&other_db));
    let observation = serde_json::to_string(&decision).unwrap();
    assert!(!observation.contains("same@example.org"));
    assert!(!observation.contains("192.0.2.7"));
    assert!(observation.contains("smtp-admission-1"));
}

#[tokio::test]
async fn observe_and_disabled_delays_complete_immediately_without_budget_use() {
    let (observe, mut db) = setup(Settings {
        mode: Mode::Observe,
        tarpit_delay_ms: 5000,
        ..settings()
    });
    let decision = check(&observe, &mut db, 1000);
    let mut budget = DelayBudget::default();
    let mut delay = Box::pin(observe.delay(&decision, &mut budget));
    std::future::poll_fn(|cx| {
        assert_eq!(delay.as_mut().poll(cx), Poll::Ready(DelayOutcome::Observe));
        Poll::Ready(())
    })
    .await;
    drop(delay);
    assert_eq!(budget.charged_ms(), 0);
    let disabled = Admission::new(Settings::default()).unwrap();
    assert_eq!(
        disabled.delay(&decision, &mut budget).await,
        DelayOutcome::NotNeeded
    );
    let enforce = Admission::new(settings()).unwrap();
    assert_eq!(
        enforce.delay(&decision, &mut budget).await,
        DelayOutcome::Observe
    );
}

#[tokio::test]
async fn tarpit_budget_clamps_each_sleep_and_is_not_reset_by_new_envelopes() {
    let (admission, mut db) = setup(Settings {
        tarpit_delay_ms: 10,
        tarpit_session_budget_ms: 12,
        ..settings()
    });
    let decision = check(&admission, &mut db, 1000);
    let mut budget = DelayBudget::default();
    assert_eq!(
        admission.delay(&decision, &mut budget).await,
        DelayOutcome::Slept { milliseconds: 10 }
    );
    let next = admission
        .check(
            &mut db,
            peer(),
            "other@example.net",
            "two@example.org",
            1000,
        )
        .unwrap();
    assert_eq!(
        admission.delay(&next, &mut budget).await,
        DelayOutcome::Slept { milliseconds: 2 }
    );
    assert_eq!(
        admission.delay(&next, &mut budget).await,
        DelayOutcome::BudgetExhausted
    );
    assert_eq!(budget.charged_ms(), 12);
    let passed = check(&admission, &mut db, 1010);
    assert_eq!(
        admission.delay(&passed, &mut budget).await,
        DelayOutcome::NotNeeded
    );
    assert_eq!(
        admission.delay(&admission.unavailable(), &mut budget).await,
        DelayOutcome::NotNeeded
    );
}

#[tokio::test]
async fn concurrent_sleepers_skip_queue_and_cancellation_releases_capacity() {
    let (admission, mut db) = setup(Settings {
        tarpit_delay_ms: 10,
        tarpit_max_concurrent: 1,
        ..settings()
    });
    let decision = check(&admission, &mut db, 1000);
    let mut first_budget = DelayBudget::default();
    let mut second_budget = DelayBudget::default();
    let mut first = Box::pin(admission.delay(&decision, &mut first_budget));
    std::future::poll_fn(|cx| {
        assert!(first.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    let clone = admission.clone();
    assert_eq!(
        clone.delay(&decision, &mut second_budget).await,
        DelayOutcome::Busy
    );
    assert_eq!(second_budget.charged_ms(), 0);
    // Database work can finish while a sleeper exists: the future owns no DB lock.
    assert_eq!(check(&admission, &mut db, 1001).status, Status::TooSoon);
    assert_eq!(decision.smtp_reply(), Some(GREYLIST_REPLY));
    drop(first);
    assert_eq!(first_budget.charged_ms(), 10);
    assert_eq!(
        clone.delay(&decision, &mut second_budget).await,
        DelayOutcome::Slept { milliseconds: 10 }
    );
}

#[tokio::test]
async fn reconfiguration_updates_policy_without_multiplying_sleeper_capacity() {
    let config = Settings {
        tarpit_delay_ms: 10,
        tarpit_max_concurrent: 1,
        ..settings()
    };
    let (admission, mut db) = setup(config.clone());
    let decision = check(&admission, &mut db, 1000);
    let mut budget = DelayBudget::default();
    let mut sleeping = Box::pin(admission.delay(&decision, &mut budget));
    std::future::poll_fn(|cx| {
        assert!(sleeping.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    let refreshed = admission.reconfigured(config.clone()).unwrap();
    let mut other_budget = DelayBudget::default();
    assert_eq!(
        refreshed.delay(&decision, &mut other_budget).await,
        DelayOutcome::Busy
    );
    let observe = admission
        .reconfigured(Settings {
            mode: Mode::Observe,
            ..config.clone()
        })
        .unwrap();
    let observed = check(&observe, &mut db, 1001);
    assert_eq!(observed.status, Status::FirstSeen);
    assert_eq!(observed.smtp_reply(), None);
    assert_eq!(
        observe.delay(&decision, &mut other_budget).await,
        DelayOutcome::Observe
    );
    let disabled = admission
        .reconfigured(Settings {
            enabled: false,
            ..config.clone()
        })
        .unwrap();
    assert_eq!(check(&disabled, &mut db, 1001).status, Status::Disabled);
    assert!(
        admission
            .reconfigured(Settings {
                tarpit_max_concurrent: 2,
                ..config
            })
            .is_err()
    );
    drop(sleeping);
    assert_eq!(
        refreshed.delay(&decision, &mut other_budget).await,
        DelayOutcome::Slept { milliseconds: 10 }
    );
}

#[tokio::test]
async fn mode_changes_keep_sleep_capacity_shared_with_live_sessions() {
    let (enforce, mut db) = setup(Settings {
        tarpit_delay_ms: 10,
        tarpit_max_concurrent: 1,
        ..settings()
    });
    let decision = check(&enforce, &mut db, 1000);
    let mut old_budget = DelayBudget::default();
    let mut old_session = Box::pin(enforce.delay(&decision, &mut old_budget));
    std::future::poll_fn(|cx| {
        assert!(old_session.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;

    let observe = enforce.with_mode(Mode::Observe);
    let mut new_budget = DelayBudget::default();
    let observed = check(&observe, &mut db, 1001);
    assert_eq!(observed.smtp_reply(), None);
    assert_eq!(
        observe.delay(&observed, &mut new_budget).await,
        DelayOutcome::Observe
    );
    assert_eq!(new_budget.charged_ms(), 0);
    let enforce_again = observe.with_mode(Mode::Enforce);
    let retry = check(&enforce_again, &mut db, 1001);
    assert_eq!(retry.status, Status::TooSoon);
    assert_eq!(retry.smtp_reply(), Some(GREYLIST_REPLY));
    assert_eq!(
        enforce_again.delay(&retry, &mut new_budget).await,
        DelayOutcome::Busy
    );
    drop(old_session);
    assert_eq!(
        enforce_again.delay(&retry, &mut new_budget).await,
        DelayOutcome::Slept { milliseconds: 10 }
    );
    assert_eq!(old_budget.charged_ms(), 10);

    // A mode change alone must never activate a disabled module.
    let disabled = Admission::new(Settings::default())
        .unwrap()
        .with_mode(Mode::Enforce);
    assert_eq!(check(&disabled, &mut db, 1002).status, Status::Disabled);
    assert_eq!(disabled.unavailable().smtp_reply(), None);
}
