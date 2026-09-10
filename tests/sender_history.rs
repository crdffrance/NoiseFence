#[allow(dead_code)]
mod common;

use noisefence::{
    antivirus::AntivirusStatus,
    config::Recipient,
    engine::{self, Scan},
    evidence::{Artifacts, AuthResult, Evidence, Source, State},
    sender_history::{
        self, Config, History, ManualEntry, ManualMatch, ManualSender, Mode, Report, Status,
    },
    store::Store,
};
use rusqlite::params;
use std::sync::Arc;

const ALICE: &str = "alice@tenant.test";
const BOB: &str = "bob@tenant.test";
const SENDER: &str = "sender@example.org";
const DAY: i64 = 86400;

fn recipient(address: &str) -> Recipient {
    Recipient {
        address: address.into(),
        destination: address.into(),
        hosts: vec![],
    }
}

fn sample(sender: &str, campaign: u64, simhash: u64, nonce: &str) -> (Vec<u8>, Scan) {
    let raw = format!("From: Innocent Display <{sender}>\r\nSubject: Transaction {nonce}\r\n\r\nVerified fixture {nonce}.\r\n").into_bytes();
    scan_raw(raw, sender, campaign, simhash)
}

fn scan_raw(raw: Vec<u8>, sender: &str, campaign: u64, simhash: u64) -> (Vec<u8>, Scan) {
    let config = common::config(std::path::Path::new("/tmp/sender-history-test-unused"));
    let mut scan = engine::extract(&raw, 1024 * 1024);
    scan.sender = sender.into();
    scan.fingerprint = format!("{campaign:064x}");
    scan.campaign_simhash = Some(format!("{simhash:016x}"));
    scan.evidence = Some(Evidence::new(
        &config,
        Artifacts::new(&config, None, None, false),
        false,
    ));
    let evidence = scan.evidence.as_mut().unwrap();
    evidence.source = Source::SmtpSession;
    let a = &mut evidence.authentication;
    a.state = State::Complete;
    a.spf_state = State::Complete;
    a.spf = Some(AuthResult::Pass);
    a.dkim_state = State::Complete;
    a.dkim = Some(vec![AuthResult::Pass]);
    a.dmarc_state = State::Complete;
    a.dmarc_spf = Some(AuthResult::Pass);
    a.dmarc_dkim = Some(AuthResult::Pass);
    (raw, scan)
}

struct Fixture {
    root: tempfile::TempDir,
    store: Store,
}

impl Fixture {
    async fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let store = Store::open(root.path()).unwrap();
        store
            .run(|db| {
                sender_history::install(db)?;
                sender_history::install(db)?;
                db.execute(
                    "INSERT INTO users(username,password,admin) VALUES
                ('alice','unused',0),('bob','unused',0),('admin','unused',1)",
                    [],
                )?;
                db.execute(
                    "INSERT INTO grants(username,address) VALUES('alice',?1),('bob',?2)",
                    params![ALICE, BOB],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        Self { root, store }
    }

    fn history(&self, mode: Mode) -> History {
        History::new(
            self.root.path(),
            Config {
                trusted_threshold: None,
                mode,
                manual: vec![],
            },
        )
    }

    fn manual(&self, sender: ManualSender, scope: Recipient) -> History {
        History::new(
            self.root.path(),
            Config {
                trusted_threshold: None,
                mode: Mode::CandidateCredit,
                manual: vec![ManualEntry {
                    recipient: scope.address,
                    destination: scope.destination,
                    sender,
                }],
            },
        )
    }

    async fn insert(
        &self,
        id: &str,
        received: i64,
        sample: (Vec<u8>, Scan),
        recipients: Vec<Recipient>,
    ) -> bool {
        let id = id.to_owned();
        self.store.run(move |db| {
            let tx = db.transaction()?;
            let (raw, scan) = sample;
            tx.execute("INSERT INTO messages(id,created,sender,scan) VALUES(?1,?2,'bounce@unrelated.test',?3)",
                params![id, received, serde_json::to_string(&scan)?])?;
            for r in recipients {
                tx.execute("INSERT INTO deliveries(message_id,address,destination,hosts,next_attempt) VALUES(?1,?2,?3,'[]',0)",
                    params![id, r.address, r.destination])?;
            }
            let recorded = sender_history::record_smtp(&tx, &id, &raw, &scan)?;
            tx.commit()?;
            Ok(recorded)
        }).await.unwrap()
    }

    async fn vote(&self, id: &str, user: &str, spam: bool) {
        self.store
            .feedback(user.into(), id.into(), spam)
            .await
            .unwrap();
    }

    async fn seed(&self) {
        let now = noisefence::now();
        for (i, simhash) in [0, u64::MAX, 0xaaaaaaaaaaaaaaaa].into_iter().enumerate() {
            let id = format!("legitimate-{i}");
            assert!(
                self.insert(
                    &id,
                    now - (5 - 2 * i as i64) * DAY,
                    sample(SENDER, i as u64 + 1, simhash, &id),
                    vec![recipient(ALICE)]
                )
                .await
            );
            self.vote(&id, "alice", false).await;
        }
    }

    async fn report(&self, history: &History, scope: &str) -> Report {
        let (raw, scan) = sample(SENDER, 999, 0x5555555555555555, "current");
        history
            .inspect(&raw, &scan, &[recipient(scope)])
            .await
            .shared_report()
            .unwrap()
            .clone()
    }

    async fn sql(&self, sql: &str) {
        let sql = sql.to_owned();
        self.store
            .run(move |db| {
                db.execute_batch(&sql)?;
                Ok(())
            })
            .await
            .unwrap();
    }
}

#[test]
fn config_defaults_are_observation_and_reject_broad_or_ambiguous_identities() {
    let config: sender_history::Settings = toml::from_str("").unwrap();
    assert_eq!(config.mode, Mode::Observation);
    assert!(config.manual.is_empty());
    config.validate().unwrap();
    assert!(toml::from_str::<Config>("allow_all = true").is_err());
    for identity in [
        "*@example.org",
        "Display <sender@example.org>",
        "a@@example.org",
        "a..b@example.org",
        "sender@example.org\r\nX: bad",
        "\"sender\"@example.org",
    ] {
        let c = Config {
            trusted_threshold: None,
            mode: Mode::Observation,
            manual: vec![ManualEntry {
                recipient: ALICE.into(),
                destination: ALICE.into(),
                sender: ManualSender::Exact(identity.into()),
            }],
        };
        let error = c.validate().unwrap_err().to_string();
        assert!(
            !error.contains(identity),
            "validation errors must not echo identities"
        );
    }
    for domain in [
        "*.example.org",
        ".example.org",
        "org",
        "example.org.",
        "exämple.org",
        "example.org@evil.test",
    ] {
        let c = Config {
            trusted_threshold: None,
            mode: Mode::Observation,
            manual: vec![ManualEntry {
                recipient: ALICE.into(),
                destination: ALICE.into(),
                sender: ManualSender::Domain(domain.into()),
            }],
        };
        assert!(c.validate().is_err());
    }
    let c = Config {
        trusted_threshold: None,
        mode: Mode::Observation,
        manual: vec![ManualEntry {
            recipient: "*@tenant.test".into(),
            destination: ALICE.into(),
            sender: ManualSender::Domain("example.org".into()),
        }],
    };
    // '*' is legal in a literal mailbox but wildcard scopes are not supported.
    assert!(c.validate().is_err());
}

#[tokio::test]
async fn durable_observation_and_explicit_candidate_mode_never_mutate_the_scan() {
    let f = Fixture::new().await;
    f.seed().await;
    let observed = f.report(&f.history(Mode::Observation), ALICE).await;
    assert_eq!(observed.status, Status::Complete);
    assert_eq!(
        (observed.distinct_campaigns, observed.distinct_days),
        (3, 3)
    );
    assert!(observed.learned_candidate);
    assert!(!observed.candidate_credit);
    let reopened = Store::open(f.root.path()).unwrap();
    reopened
        .run(|db| {
            sender_history::install(db)?;
            Ok(())
        })
        .await
        .unwrap();
    let history = History::new(
        &reopened.root,
        Config {
            trusted_threshold: None,
            mode: Mode::CandidateCredit,
            manual: vec![],
        },
    );
    let (raw, mut scan) = sample(SENDER, 999, 0x5555555555555555, "current");
    scan.score = 99.9;
    scan.tagged = true;
    let before = serde_json::to_value(&scan).unwrap();
    let report = history.inspect(&raw, &scan, &[recipient(ALICE)]).await;
    assert!(report.shared_report().unwrap().candidate_credit);
    assert_eq!(serde_json::to_value(&scan).unwrap(), before);
    let json = serde_json::to_string(report.shared_report().unwrap()).unwrap();
    for secret in [
        SENDER,
        ALICE,
        "legitimate-",
        "raw_hash",
        "recipient",
        "@",
        "Transaction",
    ] {
        assert!(!json.contains(secret));
    }
}

#[tokio::test]
async fn model_predictions_and_publicity_do_not_train_relationships() {
    let f = Fixture::new().await;
    for (i, simhash) in [0, u64::MAX, 0xaaaaaaaaaaaaaaaa].into_iter().enumerate() {
        let id = format!("model-{i}");
        let (raw, mut scan) = sample(SENDER, i as u64 + 1, simhash, &id);
        scan.score = 0.;
        assert!(
            f.insert(
                &id,
                noisefence::now() - (5 - i as i64 * 2) * DAY,
                (raw, scan),
                vec![recipient(ALICE)]
            )
            .await
        );
    }
    assert!(
        !f.report(&f.history(Mode::CandidateCredit), ALICE)
            .await
            .learned_candidate
    );
    for i in 0..3 {
        f.store
            .feedback_category(
                "alice".into(),
                format!("model-{i}"),
                noisefence::mailing::FeedbackCategory::Publicity,
            )
            .await
            .unwrap();
    }
    assert_eq!(
        f.report(&f.history(Mode::CandidateCredit), ALICE)
            .await
            .distinct_campaigns,
        0
    );
    for i in 0..3 {
        f.vote(&format!("model-{i}"), "alice", false).await;
    }
    assert!(
        f.report(&f.history(Mode::CandidateCredit), ALICE)
            .await
            .candidate_credit
    );
}

#[tokio::test]
async fn spoofed_headers_display_names_unaligned_and_non_smtp_sources_never_get_credit() {
    let f = Fixture::new().await;
    f.seed().await;
    let h = f.manual(ManualSender::Domain("example.org".into()), recipient(ALICE));
    for mutation in 0..10 {
        let (raw, mut scan) = sample(SENDER, 40, 0xcccccccccccccccc, &format!("auth-{mutation}"));
        match mutation {
            0 => scan.evidence = None,
            1 => scan.evidence.as_mut().unwrap().source = Source::ContentOnly,
            2 => scan.evidence.as_mut().unwrap().source = Source::SuppliedEnvelope,
            3 => scan.evidence.as_mut().unwrap().authentication.dmarc_state = State::Unavailable,
            4 => scan.evidence.as_mut().unwrap().authentication.state = State::Disabled,
            5 => {
                let a = &mut scan.evidence.as_mut().unwrap().authentication;
                a.dmarc_spf = Some(AuthResult::Fail);
                a.dmarc_dkim = Some(AuthResult::Fail);
            }
            6 => {
                let a = &mut scan.evidence.as_mut().unwrap().authentication;
                a.spf = Some(AuthResult::Fail);
                a.dkim = Some(vec![AuthResult::Fail]);
            }
            7 => scan.raw_sha256 = Some("0".repeat(64)),
            8 => scan.sender = "forged@example.org".into(),
            9 => {
                let a = &mut scan.evidence.as_mut().unwrap().authentication;
                a.dmarc_spf = None;
                a.dmarc_dkim = None;
                a.arc = Some(AuthResult::Pass);
            }
            _ => unreachable!(),
        }
        assert_eq!(
            h.inspect(&raw, &scan, &[recipient(ALICE)])
                .await
                .shared_report()
                .unwrap()
                .status,
            Status::NotRun
        );
        assert!(
            !f.insert(
                &format!("invalid-{mutation}"),
                noisefence::now(),
                (raw, scan),
                vec![recipient(ALICE)]
            )
            .await
        );
    }
    for from in [
        "Innocent <sender@example.org>, Other <attacker@evil.test>",
        "Group: sender@example.org;",
        "\"sender@example.org\" <attacker@evil.test>",
        "sender@example.org\r\nFrom: attacker@evil.test",
    ] {
        let raw = format!("From: {from}\r\nAuthentication-Results: mx; dmarc=pass header.from=example.org\r\n\r\nBody\r\n").into_bytes();
        let (raw, scan) = scan_raw(raw, SENDER, 50, 0xcccccccccccccccc);
        let report = h.inspect(&raw, &scan, &[recipient(ALICE)]).await;
        assert!(!report.shared_report().unwrap().candidate_credit);
        assert_eq!(report.shared_report().unwrap().status, Status::NotRun);
    }
    // A display name that merely names a trusted sender never changes identity.
    let raw = format!("From: \"{SENDER}\" <attacker@evil.test>\r\n\r\nBody\r\n").into_bytes();
    let (raw, scan) = scan_raw(raw, "attacker@evil.test", 60, 0);
    assert_eq!(
        h.inspect(&raw, &scan, &[recipient(ALICE)])
            .await
            .shared_report()
            .unwrap()
            .manual_match,
        ManualMatch::None
    );
}

#[tokio::test]
async fn aligned_spf_or_aligned_dkim_is_sufficient_but_arc_alone_is_not() {
    let f = Fixture::new().await;
    let h = f.manual(ManualSender::Exact(SENDER.into()), recipient(ALICE));
    for use_spf in [true, false] {
        let (raw, mut scan) = sample(SENDER, 10, 0, "one-auth-path");
        let a = &mut scan.evidence.as_mut().unwrap().authentication;
        if use_spf {
            a.dmarc_dkim = Some(AuthResult::Fail);
            a.dkim = None;
        } else {
            a.dmarc_spf = Some(AuthResult::Fail);
            a.spf = Some(AuthResult::Fail);
        }
        assert!(
            h.inspect(&raw, &scan, &[recipient(ALICE)])
                .await
                .shared_report()
                .unwrap()
                .candidate_credit
        );
    }
}

#[tokio::test]
async fn spam_contradictions_override_all_credit_and_track_current_authority() {
    let f = Fixture::new().await;
    f.seed().await;
    let h = f.manual(ManualSender::Exact(SENDER.into()), recipient(ALICE));
    f.vote("legitimate-0", "admin", true).await;
    let r = f.report(&h, ALICE).await;
    assert!(r.contradicted && !r.candidate_credit && !r.learned_candidate);
    f.sql("UPDATE users SET disabled=1 WHERE username='admin'")
        .await;
    assert!(f.report(&h, ALICE).await.candidate_credit);
    f.sql("UPDATE users SET disabled=0,admin=0 WHERE username='admin'")
        .await;
    assert!(f.report(&h, ALICE).await.candidate_credit);
    f.sql("UPDATE users SET admin=1 WHERE username='admin'")
        .await;
    assert!(f.report(&h, ALICE).await.contradicted);
    f.vote("legitimate-0", "admin", false).await;
    assert!(f.report(&h, ALICE).await.candidate_credit);
    f.vote("legitimate-1", "alice", true).await;
    assert!(f.report(&h, ALICE).await.contradicted);
    f.sql("DELETE FROM feedback WHERE message_id='legitimate-1' AND username='alice'")
        .await;
    assert!(f.report(&h, ALICE).await.candidate_credit);
}

#[tokio::test]
async fn grant_removal_disable_and_feedback_deletion_revoke_learned_credit_without_cache() {
    let f = Fixture::new().await;
    f.seed().await;
    let h = f.history(Mode::CandidateCredit);
    assert!(f.report(&h, ALICE).await.candidate_credit);
    f.sql("DELETE FROM grants WHERE username='alice'").await;
    assert_eq!(f.report(&h, ALICE).await.distinct_campaigns, 0);
    f.sql("INSERT INTO grants(username,address) VALUES('alice','alice@tenant.test')")
        .await;
    assert!(f.report(&h, ALICE).await.candidate_credit);
    f.sql("UPDATE users SET disabled=1 WHERE username='alice'")
        .await;
    assert!(!f.report(&h, ALICE).await.candidate_credit);
    f.sql("UPDATE users SET disabled=0 WHERE username='alice'")
        .await;
    assert!(f.report(&h, ALICE).await.candidate_credit);
    f.sql("DELETE FROM feedback WHERE message_id='legitimate-0'")
        .await;
    assert!(!f.report(&h, ALICE).await.candidate_credit);
}

#[tokio::test]
async fn expiry_is_strict_thirty_days_for_receipts_and_votes_without_refresh_on_replay() {
    let f = Fixture::new().await;
    f.seed().await;
    let h = f.history(Mode::CandidateCredit);
    let expired = noisefence::now() - sender_history::TTL_SECONDS;
    f.sql(&format!(
        "UPDATE messages SET created={expired} WHERE id='legitimate-0';
        UPDATE sender_history_receipts SET received={expired} WHERE message_id='legitimate-0';"
    ))
    .await;
    assert!(!f.report(&h, ALICE).await.candidate_credit);
    let deleted = f.store.run(|db| sender_history::prune(db)).await.unwrap();
    assert_eq!(deleted, 1);
    f.sql(&format!(
        "UPDATE feedback SET created={expired} WHERE message_id='legitimate-1'"
    ))
    .await;
    assert_eq!(f.report(&h, ALICE).await.distinct_campaigns, 1);
    f.sql(&format!(
        "UPDATE feedback SET created={} WHERE message_id='legitimate-2'",
        noisefence::now() + DAY
    ))
    .await;
    assert_eq!(f.report(&h, ALICE).await.distinct_campaigns, 0);
}

#[tokio::test]
async fn future_or_pre_receipt_feedback_and_dsn_cannot_train() {
    let f = Fixture::new().await;
    f.seed().await;
    let h = f.history(Mode::CandidateCredit);
    f.sql("UPDATE feedback SET created=0").await;
    assert_eq!(f.report(&h, ALICE).await.distinct_campaigns, 0);
    f.sql(&format!(
        "UPDATE feedback SET created={}; UPDATE messages SET is_dsn=1",
        noisefence::now()
    ))
    .await;
    assert_eq!(f.report(&h, ALICE).await.distinct_campaigns, 0);
    assert!(
        !f.insert(
            "future",
            noisefence::now() + DAY,
            sample(SENDER, 70, 0, "future"),
            vec![recipient(ALICE)]
        )
        .await
    );
    assert!(
        !f.insert(
            "old",
            noisefence::now() - sender_history::TTL_SECONDS,
            sample(SENDER, 71, 0, "old"),
            vec![recipient(ALICE)]
        )
        .await
    );
}

#[tokio::test]
async fn raw_replays_exact_campaigns_near_campaign_chains_and_bursts_do_not_create_diversity() {
    for scenario in 0..5 {
        let f = Fixture::new().await;
        for i in 0..4u64 {
            let (campaign, simhash, nonce, received) = match scenario {
                0 => (
                    1,
                    0,
                    "same".to_owned(),
                    noisefence::now() - (7 - i as i64 * 2) * DAY,
                ),
                1 => (
                    1,
                    i * 0x1111111111111111,
                    format!("copy-{i}"),
                    noisefence::now() - (7 - i as i64 * 2) * DAY,
                ),
                2 => (
                    i + 1,
                    (1u64 << (i * 3)) - 1,
                    format!("near-{i}"),
                    noisefence::now() - (7 - i as i64 * 2) * DAY,
                ),
                3 => (
                    i + 1,
                    i * 0x1111111111111111,
                    format!("burst-{i}"),
                    noisefence::now() - i as i64,
                ),
                _ => (
                    i + 1,
                    i * 0x1111111111111111,
                    format!("midnight-{i}"),
                    noisefence::now() - i as i64 * 3600,
                ),
            };
            let id = format!("poison-{i}");
            assert!(
                f.insert(
                    &id,
                    received,
                    sample(SENDER, campaign, simhash, &nonce),
                    vec![recipient(ALICE)]
                )
                .await
            );
            f.vote(&id, "alice", false).await;
        }
        let r = f.report(&f.history(Mode::CandidateCredit), ALICE).await;
        assert!(
            !r.learned_candidate && !r.candidate_credit,
            "scenario {scenario}"
        );
        if scenario < 3 {
            assert_eq!(r.distinct_campaigns, 1);
        } else {
            assert_eq!(r.distinct_days, 1);
        }
    }
}

#[tokio::test]
async fn current_message_cannot_teach_itself_and_missing_campaign_metadata_is_not_diversity() {
    let f = Fixture::new().await;
    f.seed().await;
    let (raw, scan) = sample(SENDER, 1, 0, "legitimate-0");
    let projection = f
        .history(Mode::CandidateCredit)
        .inspect(&raw, &scan, &[recipient(ALICE)])
        .await;
    assert!(!projection.shared_report().unwrap().candidate_credit);
    let (raw, mut scan) = sample(SENDER, 42, 0, "no-campaign");
    scan.campaign_simhash = None;
    scan.fingerprint.clear();
    assert!(
        f.insert(
            "missing",
            noisefence::now(),
            (raw, scan),
            vec![recipient(ALICE)]
        )
        .await
    );
    f.vote("missing", "alice", true).await;
    assert!(
        f.report(&f.history(Mode::CandidateCredit), ALICE)
            .await
            .contradicted,
        "missing campaign metadata must not hide a spam contradiction"
    );
}

#[tokio::test]
async fn exact_mailboxes_domains_plus_tags_and_tenant_scopes_do_not_bleed() {
    let f = Fixture::new().await;
    f.seed().await;
    let h = f.history(Mode::CandidateCredit);
    assert!(!f.report(&h, BOB).await.candidate_credit);
    assert!(!f.report(&h, "alice@other.test").await.candidate_credit);
    for sender in [
        "Sender@example.org",
        "sender+tag@example.org",
        "sender@sub.example.org",
        "other@example.org",
    ] {
        let (raw, scan) = sample(sender, 999, 0, "other-identity");
        assert!(
            !h.inspect(&raw, &scan, &[recipient(ALICE)])
                .await
                .shared_report()
                .unwrap()
                .candidate_credit
        );
    }
    let other = Fixture::new().await;
    assert!(
        !other
            .report(&other.history(Mode::CandidateCredit), ALICE)
            .await
            .candidate_credit
    );
    let manual = f.manual(ManualSender::Domain("EXAMPLE.ORG".into()), recipient(ALICE));
    for (sender, expected) in [
        ("another@EXAMPLE.ORG", true),
        ("sender@sub.example.org", false),
        ("sender@example.org.evil.test", false),
    ] {
        let (raw, scan) = sample(sender, 900, 0, "manual-domain");
        assert_eq!(
            manual
                .inspect(&raw, &scan, &[recipient(ALICE)])
                .await
                .shared_report()
                .unwrap()
                .candidate_credit,
            expected
        );
    }
    assert!(!f.report(&manual, BOB).await.candidate_credit);
}

#[tokio::test]
async fn domain_manual_entries_are_revoked_by_same_domain_spam_but_exact_entries_are_narrow() {
    let f = Fixture::new().await;
    let exact = f.manual(ManualSender::Exact(SENDER.into()), recipient(ALICE));
    let domain = f.manual(ManualSender::Domain("example.org".into()), recipient(ALICE));
    assert!(f.report(&exact, ALICE).await.candidate_credit);
    assert!(f.report(&domain, ALICE).await.candidate_credit);
    f.insert(
        "other-sender",
        noisefence::now(),
        sample("another@example.org", 1, 0, "spam"),
        vec![recipient(ALICE)],
    )
    .await;
    f.vote("other-sender", "alice", true).await;
    assert!(f.report(&domain, ALICE).await.contradicted);
    assert!(!f.report(&domain, ALICE).await.candidate_credit);
    assert!(f.report(&exact, ALICE).await.candidate_credit);
    assert!(
        !f.report(&f.history(Mode::CandidateCredit), ALICE)
            .await
            .candidate_credit,
        "removing manual config takes effect"
    );
}

#[tokio::test]
async fn feedback_requires_access_to_this_delivery_not_any_bcc_of_the_message() {
    let f = Fixture::new().await;
    for (i, simhash) in [0, u64::MAX, 0xaaaaaaaaaaaaaaaa].into_iter().enumerate() {
        let id = format!("bcc-{i}");
        f.insert(
            &id,
            noisefence::now() - (5 - i as i64 * 2) * DAY,
            sample(SENDER, i as u64 + 1, simhash, &id),
            vec![recipient(ALICE), recipient(BOB)],
        )
        .await;
        f.vote(&id, "alice", false).await;
    }
    let h = f.history(Mode::CandidateCredit);
    let (raw, scan) = sample(SENDER, 99, 0x5555555555555555, "bcc-current");
    let projection = h
        .inspect(&raw, &scan, &[recipient(ALICE), recipient(BOB)])
        .await;
    assert!(projection.shared_report().is_none());
    assert!(projection.for_recipient(0).unwrap().candidate_credit);
    assert_eq!(projection.for_recipient(1).unwrap().distinct_campaigns, 0);
    assert!(projection.for_recipient(2).is_none());
    f.vote("bcc-0", "bob", true).await;
    assert!(f.report(&h, ALICE).await.candidate_credit);
    assert!(f.report(&h, BOB).await.contradicted);
    // Even identical results are not exported as multi-recipient shared state.
    let empty = h
        .inspect(
            &raw,
            &scan,
            &[recipient("x@other.test"), recipient("y@other.test")],
        )
        .await;
    assert!(empty.shared_report().is_none());
}

#[tokio::test]
async fn alias_ingress_tenant_and_canonical_destination_are_both_part_of_scope() {
    let f = Fixture::new().await;
    f.sql("INSERT INTO grants(username,address) VALUES('alice','*@alias.test')")
        .await;
    let alias = Recipient {
        address: "sales@alias.test".into(),
        destination: BOB.into(),
        hosts: vec![],
    };
    for (i, simhash) in [0, u64::MAX, 0xaaaaaaaaaaaaaaaa].into_iter().enumerate() {
        let id = format!("alias-{i}");
        f.insert(
            &id,
            noisefence::now() - (5 - i as i64 * 2) * DAY,
            sample(SENDER, i as u64 + 1, simhash, &id),
            vec![alias.clone()],
        )
        .await;
        f.vote(&id, "alice", false).await;
    }
    let (raw, scan) = sample(SENDER, 999, 0x5555555555555555, "alias-current");
    let h = f.history(Mode::CandidateCredit);
    assert!(
        h.inspect(&raw, &scan, std::slice::from_ref(&alias))
            .await
            .shared_report()
            .unwrap()
            .candidate_credit
    );
    assert!(!f.report(&h, BOB).await.candidate_credit);
    let other = Recipient {
        address: "sales@other.test".into(),
        ..alias.clone()
    };
    assert!(
        !h.inspect(&raw, &scan, &[other])
            .await
            .shared_report()
            .unwrap()
            .candidate_credit
    );
    f.sql("DELETE FROM grants WHERE address='*@alias.test'")
        .await;
    assert!(
        !h.inspect(&raw, &scan, &[alias])
            .await
            .shared_report()
            .unwrap()
            .candidate_credit
    );
}

#[tokio::test]
async fn malware_incomplete_and_signature_detections_never_get_manual_or_learned_credit() {
    let f = Fixture::new().await;
    f.seed().await;
    let h = f.manual(ManualSender::Exact(SENDER.into()), recipient(ALICE));
    for kind in 0..4 {
        let (raw, mut scan) = sample(SENDER, 80, 0xcccccccccccccccc, &format!("blocked-{kind}"));
        match kind {
            0 => scan.antivirus.status = AntivirusStatus::Malware,
            1 => scan.signatures.status = AntivirusStatus::Malware,
            2 => scan.complete = false,
            _ => scan.features_complete = Some(false),
        }
        let before = serde_json::to_value(&scan).unwrap();
        let r = h.inspect(&raw, &scan, &[recipient(ALICE)]).await;
        assert_eq!(r.shared_report().unwrap().status, Status::NotRun);
        assert!(!r.shared_report().unwrap().candidate_credit);
        assert_eq!(serde_json::to_value(&scan).unwrap(), before);
        // Still record identity so a human spam contradiction cannot disappear.
        let id = format!("blocked-{kind}");
        assert!(
            f.insert(&id, noisefence::now(), (raw, scan), vec![recipient(ALICE)])
                .await
        );
        f.vote(&id, "alice", true).await;
    }
    assert!(f.report(&h, ALICE).await.contradicted);
}

#[tokio::test]
async fn enqueue_transaction_rollbacks_idempotence_and_cascades_preserve_receipt_integrity() {
    let f = Fixture::new().await;
    f.store.run(|db| {
        let (raw, scan) = sample(SENDER, 1, 0, "atomic");
        assert!(sender_history::record_smtp(db, "atomic", &raw, &scan).is_err());
        let tx = db.transaction()?;
        tx.execute("INSERT INTO messages(id,created,sender,scan) VALUES('atomic',?1,'sender',?2)",
            params![noisefence::now(), serde_json::to_string(&scan)?])?;
        tx.execute("INSERT INTO deliveries(message_id,address,destination,hosts,next_attempt) VALUES('atomic',?1,?1,'[]',0)",[ALICE])?;
        assert!(sender_history::record_smtp(&tx, "atomic", &raw, &scan)?);
        assert!(sender_history::record_smtp(&tx, "atomic", &raw, &scan)?);
        let count: usize = tx.query_row("SELECT records FROM sender_history_state", [], |r| r.get(0))?;
        assert_eq!(count, 1);
        tx.rollback()?;
        let count: usize = db.query_row("SELECT records FROM sender_history_state", [], |r| r.get(0))?;
        assert_eq!(count, 0);
        Ok(())
    }).await.unwrap();
    f.seed().await;
    f.sql("DELETE FROM messages WHERE id='legitimate-0'").await;
    let counts = f
        .store
        .run(|db| {
            Ok((
                db.query_row("SELECT COUNT(*) FROM sender_history_receipts", [], |r| {
                    r.get::<_, usize>(0)
                })?,
                db.query_row("SELECT records FROM sender_history_state", [], |r| {
                    r.get::<_, usize>(0)
                })?,
            ))
        })
        .await
        .unwrap();
    assert_eq!(counts, (2, 2));
}

#[tokio::test]
async fn different_raw_or_persisted_scan_cannot_be_attached_to_a_verified_receipt() {
    let f = Fixture::new().await;
    f.store.run(|db| {
        let (raw, mut scan) = sample(SENDER, 1, 0, "binding");
        let tx = db.transaction()?;
        tx.execute("INSERT INTO messages(id,created,sender,scan) VALUES('binding',?1,'sender',?2)",
            params![noisefence::now(), serde_json::to_string(&scan)?])?;
        tx.execute("INSERT INTO deliveries(message_id,address,destination,hosts,next_attempt) VALUES('binding',?1,?1,'[]',0)",[ALICE])?;
        assert!(!sender_history::record_smtp(&tx, "binding", b"From: forged@evil.test\r\n\r\nBody\r\n", &scan)?);
        scan.score += 1.;
        assert!(sender_history::record_smtp(&tx, "binding", &raw, &scan).is_err());
        tx.rollback()?;
        Ok(())
    }).await.unwrap();
}

#[tokio::test]
async fn opaque_original_proof_survives_queue_rewrite_and_projection_stays_delivery_private() {
    let f = Fixture::new().await;
    f.seed().await;
    let (original, mut scan) = sample(SENDER, 99, 0x5555555555555555, "rewritten");
    let proof = sender_history::prepare_receipt(&original, &scan).unwrap();
    let projection = f
        .history(Mode::CandidateCredit)
        .inspect(&original, &scan, &[recipient(ALICE), recipient(BOB)])
        .await;
    assert!(projection.shared_report().is_none());
    assert!(!format!("{proof:?} {projection:?}").contains('@'));
    // Final scoring/diagnostics may change after original-byte authentication.
    scan.score = 42.;
    scan.elapsed_ms = 55;
    let rewritten =
        noisefence::message::rewrite(&original, true, "X-NoiseFence-Test: verified\r\n").unwrap();
    assert_ne!(
        noisefence::message::digest(&rewritten),
        scan.raw_sha256.clone().unwrap()
    );
    f.store.run(move |db| {
        let tx = db.transaction()?;
        tx.execute("INSERT INTO messages(id,created,sender,scan) VALUES('rewritten',?1,'envelope',?2)",
            params![noisefence::now(),serde_json::to_string(&scan)?])?;
        for address in [ALICE, BOB] {
            tx.execute("INSERT INTO deliveries(message_id,address,destination,hosts,next_attempt) VALUES('rewritten',?1,?1,'[]',0)", [address])?;
        }
        assert!(!sender_history::record_smtp(&tx, "rewritten", &rewritten, &scan)?);
        assert!(sender_history::record_prepared(&tx, "rewritten", &scan, &proof)?);
        sender_history::record_projection(&tx, "rewritten", &scan, &projection)?;
        sender_history::record_projection(&tx, "rewritten", &scan, &projection)?;
        let count: usize = tx.query_row("SELECT COUNT(*) FROM recipient_research", [], |r| r.get(0))?;
        assert_eq!(count, 2);
        let mut q = tx.prepare("SELECT a.username,r.sender_history FROM recipient_research r
            JOIN console_access a ON a.delivery_id=r.delivery_id WHERE a.username IN ('alice','bob') ORDER BY a.username")?;
        let reports = q.query_map([], |r| Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        assert_eq!(reports.len(), 2);
        assert_eq!(reports[0].0, "alice");
        assert!(serde_json::from_str::<Report>(&reports[0].1)?.candidate_credit);
        assert!(!serde_json::from_str::<Report>(&reports[1].1)?.candidate_credit);
        assert!(reports.iter().all(|(_,json)| !json.contains('@')));
        drop(q);
        tx.commit()?;
        Ok(())
    }).await.unwrap();
    f.sql("DELETE FROM messages WHERE id='rewritten'").await;
    let count = f
        .store
        .run(|db| {
            Ok(
                db.query_row("SELECT COUNT(*) FROM recipient_research", [], |r| {
                    r.get::<_, usize>(0)
                })?,
            )
        })
        .await
        .unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn persisted_diagnostics_never_disclose_a_bcc_recipients_history_or_counts() {
    let f = Fixture::new().await;
    f.seed().await; // Alice has three legitimate campaigns; Bob has none.
    let id = "private-history-diagnostics";
    let original = format!(
        "From: {SENDER}\r\nTo: {BOB}\r\nSubject: Private history fixture\r\n\r\nOrdinary transaction.\r\n"
    ).into_bytes();
    assert!(!String::from_utf8_lossy(&original).contains(ALICE));
    let (original, mut scan) = scan_raw(original, SENDER, 99, 0x5555555555555555);
    let recipients = vec![recipient(BOB), recipient(ALICE)];
    let projection = f
        .history(Mode::CandidateCredit)
        .inspect(&original, &scan, &recipients)
        .await;
    let bob_report = projection.for_recipient(0).unwrap().clone();
    let alice_report = projection.for_recipient(1).unwrap().clone();
    assert_eq!(
        (bob_report.distinct_campaigns, bob_report.distinct_days),
        (0, 0)
    );
    assert!(!bob_report.candidate_credit);
    assert_eq!(
        (alice_report.distinct_campaigns, alice_report.distinct_days),
        (3, 3)
    );
    assert!(alice_report.candidate_credit);
    assert!(projection.shared_report().is_none());
    scan.sender_history_receipt = sender_history::prepare_receipt(&original, &scan);
    scan.sender_history_projection = Some(projection);
    let queued =
        noisefence::message::rewrite(&original, false, "X-NoiseFence-Test: diagnostics\r\n")
            .unwrap();
    f.store
        .enqueue(id.into(), SENDER.into(), recipients, scan, queued)
        .await
        .unwrap();

    // A fresh Store must read only the durable, delivery-keyed report rows.
    let reopened = Store::open(f.root.path()).unwrap();
    reopened
        .run(move |db| {
            let stored: String =
                db.query_row("SELECT scan FROM messages WHERE id=?1", [id], |r| r.get(0))?;
            assert!(
                !stored.contains("sender_history"),
                "shared Scan must not persist history"
            );
            let count: usize = db.query_row(
                "SELECT COUNT(*) FROM recipient_research r
            JOIN deliveries d ON d.id=r.delivery_id WHERE d.message_id=?1",
                [id],
                |r| r.get(0),
            )?;
            assert_eq!(count, 2);
            Ok(())
        })
        .await
        .unwrap();

    let bob = reopened
        .diagnostics("bob".into(), id.into())
        .await
        .unwrap()
        .unwrap();
    let alice = reopened
        .diagnostics("alice".into(), id.into())
        .await
        .unwrap()
        .unwrap();
    for (diagnostics, address, hidden, expected) in [
        (&bob, BOB, ALICE, &bob_report),
        (&alice, ALICE, BOB, &alice_report),
    ] {
        assert_eq!(diagnostics.recipients.len(), 1);
        let visible = &diagnostics.recipients[0];
        assert_eq!(visible.address, address);
        assert_eq!(visible.destination, address);
        assert_eq!(visible.sender_history.as_ref(), Some(expected));
        let json = serde_json::to_string(diagnostics).unwrap();
        assert!(
            !json.contains(hidden),
            "another recipient's identity leaked"
        );
        assert_eq!(json.matches("\"sender_history\"").count(), 1);
        // Counts and credit must appear only on this authorized recipient.
        let analysis = serde_json::to_string(&diagnostics.analysis).unwrap();
        for private in [
            "sender_history",
            "distinct_campaigns",
            "distinct_days",
            "candidate_credit",
        ] {
            assert!(!analysis.contains(private));
        }
        assert!(!serde_json::to_string(expected).unwrap().contains('@'));
    }
    let bob_id = bob.recipients[0].delivery_id;
    let alice_id = alice.recipients[0].delivery_id;
    // Knowing the message ID and hidden delivery ID cannot select its report.
    assert!(
        reopened
            .diagnostics_for("bob".into(), id.into(), Some(alice_id))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        reopened
            .diagnostics_for("alice".into(), id.into(), Some(bob_id))
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        reopened
            .diagnostics("unknown".into(), id.into())
            .await
            .unwrap()
            .is_none()
    );
    let own = reopened
        .diagnostics_for("bob".into(), id.into(), Some(bob_id))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(own.recipients.len(), 1);
    assert_eq!(own.recipients[0].sender_history.as_ref(), Some(&bob_report));
    let admin = reopened
        .diagnostics("admin".into(), id.into())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(admin.recipients.len(), 2);
    assert_eq!(
        admin.recipients[0].sender_history.as_ref(),
        Some(&bob_report)
    );
    assert_eq!(
        admin.recipients[1].sender_history.as_ref(),
        Some(&alice_report)
    );

    f.sql("DELETE FROM grants WHERE username='alice'; UPDATE users SET disabled=1 WHERE username='bob'").await;
    assert!(
        reopened
            .diagnostics("alice".into(), id.into())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        reopened
            .diagnostics("bob".into(), id.into())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        reopened
            .diagnostics_for("alice".into(), id.into(), Some(alice_id))
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        reopened
            .diagnostics("admin".into(), id.into())
            .await
            .unwrap()
            .unwrap()
            .recipients
            .len(),
        2,
        "reports remain persisted; revoked readers lose access immediately"
    );
}

#[tokio::test]
async fn prepared_proofs_reject_changed_authentication_hash_campaign_and_source() {
    let f = Fixture::new().await;
    for mutation in 0..6 {
        f.store.run(move |db| {
            let (raw, mut scan) = sample(SENDER, 1, 0, "proof-mismatch");
            let proof = sender_history::prepare_receipt(&raw, &scan).unwrap();
            match mutation {
                0 => scan.raw_sha256 = Some("f".repeat(64)),
                1 => scan.sender = "another@example.org".into(),
                2 => scan.fingerprint = "f".repeat(64),
                3 => scan.campaign_simhash = None,
                4 => scan.evidence.as_mut().unwrap().source = Source::SuppliedEnvelope,
                // Still authenticated by SPF, but proof describes different DKIM checks.
                _ => scan.evidence.as_mut().unwrap().authentication.dkim = None,
            }
            let tx = db.transaction()?;
            tx.execute("INSERT INTO messages(id,created,sender,scan) VALUES('proof-mismatch',?1,'envelope',?2)",
                params![noisefence::now(),serde_json::to_string(&scan)?])?;
            tx.execute("INSERT INTO deliveries(message_id,address,destination,hosts,next_attempt) VALUES('proof-mismatch',?1,?1,'[]',0)", [ALICE])?;
            assert!(sender_history::record_prepared(&tx, "proof-mismatch", &scan, &proof).is_err());
            tx.rollback()?;
            Ok(())
        }).await.unwrap();
    }
}

#[tokio::test]
async fn projection_cannot_be_rebound_to_another_message_or_recipient_and_rolls_back_atomically() {
    let f = Fixture::new().await;
    let (raw, scan) = sample(SENDER, 1, 0, "projection-mismatch");
    let projection = f
        .history(Mode::Observation)
        .inspect(&raw, &scan, &[recipient(ALICE)])
        .await;
    for wrong_hash in [true, false] {
        let projection = projection.clone();
        let mut scan = scan.clone();
        if wrong_hash {
            scan.raw_sha256 = Some("0".repeat(64));
        }
        f.store.run(move |db| {
            let tx = db.transaction()?;
            tx.execute("INSERT INTO messages(id,created,sender,scan) VALUES('projection-mismatch',?1,'envelope',?2)",
                params![noisefence::now(),serde_json::to_string(&scan)?])?;
            tx.execute("INSERT INTO deliveries(message_id,address,destination,hosts,next_attempt) VALUES('projection-mismatch',?1,?1,'[]',0)", [BOB])?;
            assert!(sender_history::record_projection(&tx, "projection-mismatch", &scan, &projection).is_err());
            tx.rollback()?;
            Ok(())
        }).await.unwrap();
    }
    let count = f
        .store
        .run(|db| {
            Ok(
                db.query_row("SELECT COUNT(*) FROM recipient_research", [], |r| {
                    r.get::<_, usize>(0)
                })?,
            )
        })
        .await
        .unwrap();
    assert_eq!(count, 0);
}

#[tokio::test]
async fn incomplete_history_limits_and_missing_storage_fail_closed_even_for_manual_entries() {
    let f = Fixture::new().await;
    for i in 0..=sender_history::MAX_PAIR_RECORDS {
        let id = format!("limit-{i}");
        f.insert(
            &id,
            noisefence::now() - DAY,
            sample(SENDER, 1, 0, &id),
            vec![recipient(ALICE)],
        )
        .await;
    }
    let h = f.manual(ManualSender::Exact(SENDER.into()), recipient(ALICE));
    assert_eq!(f.report(&h, ALICE).await.status, Status::Limited);
    assert!(!f.report(&h, ALICE).await.candidate_credit);
    let (raw, scan) = sample(SENDER, 999, 0, "too-many-recipients");
    let too_many = h
        .inspect(
            &raw,
            &scan,
            &vec![recipient(ALICE); sender_history::MAX_RECIPIENTS + 1],
        )
        .await;
    assert!(too_many.shared_report().is_none() && too_many.for_recipient(0).is_none());
    let absent = tempfile::tempdir().unwrap();
    let unavailable = History::new(absent.path(), Config::default());
    assert_eq!(
        f.report(&unavailable, ALICE).await.status,
        Status::Unavailable
    );
    assert!(
        !absent.path().join("state.sqlite3").exists(),
        "lookups never create storage"
    );
}

#[tokio::test]
async fn durable_global_capacity_breaker_prevents_eviction_from_restoring_credit() {
    let f = Fixture::new().await;
    f.seed().await;
    f.store.run(|db| {
        let tx = db.transaction()?;
        tx.execute("WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<?1)
            INSERT INTO deliveries(message_id,address,destination,hosts,next_attempt)
            SELECT 'legitimate-0','r'||x||'@capacity.test','r'||x||'@capacity.test','[]',0 FROM n",
            [sender_history::MAX_RECORDS-3])?;
        tx.execute("INSERT INTO sender_history_receipts
            (message_id,delivery_id,recipient,destination,sender,domain,received,raw_hash,campaign,simhash,eligible)
            SELECT d.message_id,d.id,d.address,d.destination,'other@capacity.test','capacity.test',?1,'hash',NULL,NULL,0
            FROM deliveries d WHERE d.address LIKE '%@capacity.test'", [noisefence::now()])?;
        let count: usize = tx.query_row("SELECT records FROM sender_history_state", [], |r| r.get(0))?;
        assert_eq!(count, sender_history::MAX_RECORDS);
        tx.commit()?;
        Ok(())
    }).await.unwrap();
    assert!(
        !f.insert(
            "overflow-spam",
            noisefence::now(),
            sample(SENDER, 8, 0, "overflow"),
            vec![recipient(ALICE)]
        )
        .await
    );
    f.vote("overflow-spam", "alice", true).await;
    let reopened = History::new(
        f.root.path(),
        Config {
            trusted_threshold: None,
            mode: Mode::CandidateCredit,
            manual: vec![],
        },
    );
    assert_eq!(f.report(&reopened, ALICE).await.status, Status::Limited);
    f.sql("DELETE FROM messages WHERE id='legitimate-0'").await;
    let manual = f.manual(ManualSender::Exact(SENDER.into()), recipient(ALICE));
    assert_eq!(
        f.report(&manual, ALICE).await.status,
        Status::Limited,
        "deleting rows must not erase the omitted contradiction window"
    );
    f.sql(&format!(
        "UPDATE sender_history_state SET overflow_until={}",
        noisefence::now()
    ))
    .await;
    assert_eq!(f.report(&manual, ALICE).await.status, Status::Complete);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_snapshots_never_mix_revoked_votes_and_positive_credit() {
    let f = Arc::new(Fixture::new().await);
    f.seed().await;
    let h = f.history(Mode::CandidateCredit);
    let writer = {
        let f = f.clone();
        tokio::spawn(async move {
            for i in 0..12 {
                f.store
                    .run(move |db| {
                        let tx = db.transaction()?;
                        tx.execute(
                            "UPDATE feedback SET spam=?1 WHERE username='alice'",
                            [i % 2],
                        )?;
                        tx.commit()?;
                        Ok(())
                    })
                    .await
                    .unwrap();
                tokio::task::yield_now().await;
            }
        })
    };
    let mut readers = Vec::new();
    for _ in 0..16 {
        let f = f.clone();
        let h = h.clone();
        readers.push(tokio::spawn(async move {
            for _ in 0..4 {
                let r = f.report(&h, ALICE).await;
                assert!(!(r.contradicted && r.candidate_credit));
                if r.status == Status::Complete {
                    assert!(r.contradicted || r.candidate_credit);
                } else {
                    assert!(matches!(r.status, Status::Limited | Status::Unavailable));
                    assert!(!r.candidate_credit);
                }
            }
        }));
    }
    writer.await.unwrap();
    for reader in readers {
        reader.await.unwrap();
    }
    assert!(f.report(&h, ALICE).await.contradicted);
    f.sql("UPDATE feedback SET spam=0").await;
    assert!(f.report(&h, ALICE).await.candidate_credit);
}

#[tokio::test]
async fn empty_projection_never_gates_real_enqueue_even_without_an_observation_hash() {
    for (case, recipients) in [
        (
            "quoted-recipient",
            vec![recipient("\"quoted key\"@tenant.test")],
        ),
        (
            "quoted-destination",
            vec![Recipient {
                address: ALICE.into(),
                destination: "\"quoted key\"@tenant.test".into(),
                hosts: vec![],
            }],
        ),
        (
            "mixed-recipients",
            vec![recipient(ALICE), recipient("\"quoted key\"@tenant.test")],
        ),
        (
            "oversized-recipients",
            (0..=sender_history::MAX_RECIPIENTS)
                .map(|i| recipient(&format!("r{i}@tenant.test")))
                .collect(),
        ),
    ] {
        for missing_hash in [false, true] {
            let f = Fixture::new().await;
            for r in &recipients {
                assert!(noisefence::config::valid_address(&r.address));
                assert!(noisefence::config::valid_address(&r.destination));
            }
            let id = format!("{case}-{missing_hash}");
            let (raw, mut scan) = sample(SENDER, 1, 0, &id);
            let proof = sender_history::prepare_receipt(&raw, &scan).unwrap();
            let mut observation_scan = scan.clone();
            if missing_hash {
                observation_scan.raw_sha256 = None;
            }
            let projection = f
                .history(Mode::CandidateCredit)
                .inspect(&raw, &observation_scan, &recipients)
                .await;
            assert!(projection.for_recipient(0).is_none());
            assert!(projection.shared_report().is_none());
            scan.sender_history_receipt = Some(proof);
            scan.sender_history_projection = Some(projection);
            let rewritten =
                noisefence::message::rewrite(&raw, false, "X-NoiseFence-Test: enqueue\r\n")
                    .unwrap();
            f.store
                .enqueue(
                    id.clone(),
                    SENDER.into(),
                    recipients.clone(),
                    scan,
                    rewritten.clone(),
                )
                .await
                .unwrap_or_else(|e| panic!("{id}: optional history rejected enqueue: {e}"));
            assert_eq!(std::fs::read(f.store.raw_path(&id)).unwrap(), rewritten);
            let expected = recipients.len();
            f.store
                .run(move |db| {
                    let deliveries: usize = db.query_row(
                        "SELECT COUNT(*) FROM deliveries WHERE message_id=?1",
                        [&id],
                        |r| r.get(0),
                    )?;
                    assert_eq!(deliveries, expected);
                    let reports: usize =
                        db.query_row("SELECT COUNT(*) FROM recipient_research", [], |r| r.get(0))?;
                    assert_eq!(
                        reports, 0,
                        "an empty projection must persist no report or credit"
                    );
                    Ok(())
                })
                .await
                .unwrap();
        }
    }
}

#[tokio::test]
async fn unsupported_sender_identity_enqueues_a_bound_not_run_report_without_receipt() {
    let f = Fixture::new().await;
    let sender = "\"quoted sender\"@example.org";
    assert!(noisefence::config::valid_address(sender));
    let (raw, mut scan) = sample(sender, 1, 0, "unsupported-from");
    assert!(sender_history::prepare_receipt(&raw, &scan).is_none());
    let projection = f
        .history(Mode::CandidateCredit)
        .inspect(&raw, &scan, &[recipient(ALICE)])
        .await;
    let report = projection.shared_report().unwrap();
    assert_eq!(report.status, Status::NotRun);
    assert!(!report.candidate_credit);
    scan.sender_history_projection = Some(projection);
    let rewritten =
        noisefence::message::rewrite(&raw, false, "X-NoiseFence-Test: enqueue\r\n").unwrap();
    f.store
        .enqueue(
            "unsupported-from".into(),
            sender.into(),
            vec![recipient(ALICE)],
            scan,
            rewritten,
        )
        .await
        .unwrap();
    let diagnostics = f
        .store
        .diagnostics("alice".into(), "unsupported-from".into())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(diagnostics.recipients.len(), 1);
    assert_eq!(
        diagnostics.recipients[0]
            .sender_history
            .as_ref()
            .unwrap()
            .status,
        Status::NotRun
    );
    assert!(
        f.store
            .diagnostics("bob".into(), "unsupported-from".into())
            .await
            .unwrap()
            .is_none()
    );
    f.store
        .run(|db| {
            let receipts: usize =
                db.query_row("SELECT COUNT(*) FROM sender_history_receipts", [], |r| {
                    r.get(0)
                })?;
            assert_eq!(receipts, 0);
            Ok(())
        })
        .await
        .unwrap();
}

/// Real SMTP parsing -> process_smtp -> rewritten spool -> Store::enqueue.
/// Authentication is disabled: these acceptance regressions require no DNS.
async fn smtp_history_acceptance(recipients: Vec<String>, from: &str, expected_reports: usize) {
    use noisefence::{engine::Engine, relay, smtp};
    use tokio::{
        io::{AsyncWriteExt, BufReader},
        net::{TcpListener, TcpStream},
        sync::{Semaphore, watch},
    };

    let root = tempfile::tempdir().unwrap();
    let mut config = (*common::config(root.path())).clone();
    config.sender_history = Some(Config {
        trusted_threshold: None,
        mode: Mode::CandidateCredit,
        manual: vec![],
    });
    config.smtp.max_recipients = sender_history::MAX_RECIPIENTS + 1;
    config.domains[0].accept_all_recipients = true;
    config.validate().unwrap();
    let config = Arc::new(config);
    let store = Store::open(root.path()).unwrap();
    let engine = Arc::new(Engine::new(config.clone()).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, stopped) = watch::channel(false);
    let server = tokio::spawn(smtp::serve(
        listener,
        smtp::State {
            config,
            store: store.clone(),
            engine,
            processing: Arc::new(Semaphore::new(2)),
        },
        stopped,
    ));

    let exchange = async {
        let mut io: smtp::Wire =
            BufReader::new(Box::new(TcpStream::connect(address).await.unwrap()));
        assert_eq!(relay::response(&mut io).await.unwrap().code, 220);
        for command in [
            "EHLO sender.example.org\r\n",
            "MAIL FROM:<sender@example.org>\r\n",
        ] {
            smtp::reply(&mut io, command).await.unwrap();
            assert_eq!(relay::response(&mut io).await.unwrap().code, 250);
        }
        for recipient in &recipients {
            smtp::reply(&mut io, &format!("RCPT TO:<{recipient}>\r\n"))
                .await
                .unwrap();
            assert_eq!(
                relay::response(&mut io).await.unwrap().code,
                250,
                "SMTP must accept its supported RCPT syntax"
            );
        }
        smtp::reply(&mut io, "DATA\r\n").await.unwrap();
        assert_eq!(relay::response(&mut io).await.unwrap().code, 354);
        let raw = format!(
            "From: {from}\r\nSubject: Sender history acceptance\r\n\r\nOrdinary transaction.\r\n"
        );
        io.write_all(raw.as_bytes()).await.unwrap();
        io.write_all(b".\r\n").await.unwrap();
        io.flush().await.unwrap();
        let reply = relay::response(&mut io).await.unwrap();
        assert_eq!(
            reply.code, 250,
            "history must not turn a valid DATA transaction into a persistence failure"
        );
        smtp::reply(&mut io, "QUIT\r\n").await.unwrap();
        assert_eq!(relay::response(&mut io).await.unwrap().code, 221);
        noisefence::message::digest(raw.as_bytes())
    };
    let original_hash = tokio::time::timeout(std::time::Duration::from_secs(10), exchange).await;
    stop.send(true).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let original_hash = original_hash.expect("SMTP acceptance timed out");
    // Reopen the real durable store; a 250 must mean both metadata and spool exist.
    let reopened = Store::open(root.path()).unwrap();
    let (id, destinations, reports) = reopened
        .run(move |db| {
            let (id, json): (String, String) =
                db.query_row("SELECT id,scan FROM messages", [], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })?;
            let scan: Scan = serde_json::from_str(&json)?;
            assert_eq!(scan.raw_sha256.as_deref(), Some(original_hash.as_str()));
            assert_eq!(scan.evidence.as_ref().unwrap().source, Source::SmtpSession);
            assert!(
                scan.sender_history_projection.is_none() && scan.sender_history_receipt.is_none()
            );
            assert!(
                !json.contains("sender_history"),
                "shared Scan must not persist delivery history"
            );
            let mut q =
                db.prepare("SELECT destination FROM deliveries WHERE message_id=?1 ORDER BY id")?;
            let destinations = q
                .query_map([&id], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let mut q = db.prepare("SELECT sender_history FROM recipient_research")?;
            let reports = q
                .query_map([], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok((id, destinations, reports))
        })
        .await
        .unwrap();
    assert_eq!(destinations, recipients);
    assert_eq!(reports.len(), expected_reports);
    for json in reports {
        let report: Report = serde_json::from_str(&json).unwrap();
        assert_eq!(report.status, Status::NotRun);
        assert!(!report.candidate_credit);
        assert!(!json.contains('@'));
    }
    assert!(reopened.raw_path(&id).is_file());
}

#[tokio::test]
async fn real_smtp_quoted_rcpt_and_mixed_unsupported_scope_are_durably_accepted() {
    smtp_history_acceptance(vec!["\"quoted key\"@example.test".into()], SENDER, 0).await;
    smtp_history_acceptance(
        vec![
            "alice@example.test".into(),
            "\"quoted > @ key\"@example.test".into(),
        ],
        SENDER,
        0,
    )
    .await;
}

#[tokio::test]
async fn real_smtp_unsupported_from_identity_is_durably_accepted_without_history_credit() {
    smtp_history_acceptance(
        vec!["alice@example.test".into()],
        "\"quoted sender\"@example.org",
        1,
    )
    .await;
}

#[tokio::test]
async fn real_smtp_recipient_count_over_history_budget_is_durably_accepted() {
    smtp_history_acceptance(
        (0..=sender_history::MAX_RECIPIENTS)
            .map(|i| format!("recipient{i}@example.test"))
            .collect(),
        SENDER,
        0,
    )
    .await;
}
