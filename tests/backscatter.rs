mod common;
#[path = "common/backscatter.rs"]
mod fixture;
use noisefence::{
    antivirus::AntivirusStatus,
    backscatter,
    engine::{Engine, Scan},
    evidence::{AuthResult, Source, State},
    fusion::runtime::Outcome,
    llm::{Category, LlmStatus},
    relay,
    store::Store,
};

#[test]
fn missing_conflicting_or_authenticated_evidence_never_suppresses_a_notice() {
    let root = tempfile::tempdir().unwrap();
    let original = fixture::scan(common::config(root.path()));
    let remote = fixture::rejection();
    assert!(backscatter::suppression_reason(&original, &remote).is_some());
    let variations: &[fn(&mut Scan)] = &[
        |s| s.complete = false,
        |s| s.decision = None,
        |s| s.decision.as_mut().unwrap().outcome = Outcome::Undetermined,
        |s| s.decision.as_mut().unwrap().outcome = Outcome::Legitimate,
        |s| s.delivery_classification = Some(noisefence::mailing::Category::Legitimate),
        |s| s.delivery_classification = Some(noisefence::mailing::Category::Publicity),
        |s| s.delivery_classification = Some(noisefence::mailing::Category::Undetermined),
        |s| s.score = 98.99,
        |s| s.score = f64::NAN,
        |s| s.score = f64::INFINITY,
        |s| s.signatures.status = AntivirusStatus::Unavailable,
        |s| s.signatures.signature = None,
        |s| s.signatures.signature = Some("Sanesecurity.Junk.FIXTURE".into()),
        |s| s.llm.status = LlmStatus::Unavailable,
        |s| s.llm.verdict = None,
        |s| s.llm.verdict.as_mut().unwrap().category = Category::Legitimate,
        |s| s.llm.verdict.as_mut().unwrap().category = Category::Ambiguous,
        |s| s.llm.verdict.as_mut().unwrap().confidence = 0.89,
        |s| s.llm.verdict.as_mut().unwrap().spam_probability = 0.89,
        |s| s.evidence = None,
        |s| s.evidence.as_mut().unwrap().source = Source::ContentOnly,
        |s| s.evidence.as_mut().unwrap().source = Source::SuppliedEnvelope,
        |s| s.evidence.as_mut().unwrap().authentication.spf = Some(AuthResult::Pass),
        |s| s.evidence.as_mut().unwrap().authentication.spf = Some(AuthResult::None),
        |s| s.evidence.as_mut().unwrap().authentication.spf_state = State::Unavailable,
        |s| s.evidence.as_mut().unwrap().authentication.dkim = None,
        |s| s.evidence.as_mut().unwrap().authentication.dkim = Some(vec![AuthResult::Pass]),
        |s| s.evidence.as_mut().unwrap().authentication.dkim = Some(vec![AuthResult::TempError]),
        |s| s.evidence.as_mut().unwrap().authentication.dmarc_dkim = Some(AuthResult::Pass),
        |s| s.evidence.as_mut().unwrap().authentication.arc = Some(AuthResult::Pass),
    ];
    for (i, change) in variations.iter().enumerate() {
        let mut scan = original.clone();
        change(&mut scan);
        assert_eq!(
            backscatter::suppression_reason(&scan, &remote),
            None,
            "case {i}"
        );
    }
    let mut malware = original.clone();
    malware.antivirus.status = AntivirusStatus::Malware;
    malware.score = 0.;
    malware.llm.verdict = None;
    assert_eq!(
        backscatter::suppression_reason(&malware, &remote),
        Some("malware_and_upstream_rejection")
    );
    for case in 0..8 {
        let mut trace = remote.clone();
        match case {
            0 => trace.events.last_mut().unwrap().phase = "rcpt_to".into(),
            1 => trace.events.last_mut().unwrap().code = Some(451),
            2 => trace.events.last_mut().unwrap().enhanced_code = Some("5.1.1".into()),
            3 => trace.events.last_mut().unwrap().response = Some("554 5.7.1 policy error".into()),
            4 => trace.outcome = "temporary".into(),
            5 => trace.truncated = true,
            6 => {
                trace.events.remove(0);
            }
            _ => trace.events.clear(),
        }
        assert_eq!(backscatter::suppression_reason(&original, &trace), None);
    }
}

#[tokio::test]
async fn rejected_hostile_mail_is_terminal_audited_and_cannot_bounce_after_restart() {
    let root = tempfile::tempdir().unwrap();
    let config = common::config(root.path());
    let store = Store::open(root.path()).unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    store
        .enqueue(
            id.clone(),
            "alice@example.test".into(),
            vec![
                config.recipient("alice@example.test").unwrap(),
                config.recipient("bob@example.test").unwrap(),
            ],
            fixture::scan(config.clone()),
            common::MESSAGE.to_vec(),
        )
        .await
        .unwrap();
    let failed = store.claim().await.unwrap().unwrap();
    let other = store.claim().await.unwrap().unwrap();
    let trace = fixture::rejection();
    store
        .finish_with_attempts(
            &failed,
            "failed",
            trace.events.last().unwrap().response.as_deref().unwrap(),
            0,
            std::slice::from_ref(&trace),
        )
        .await
        .unwrap();
    let engine = Engine::new(config.clone()).unwrap();
    relay::notifications(&config, &store, &engine)
        .await
        .unwrap();
    assert!(!store.suppress_hostile_dsn(&failed).await.unwrap());
    store
        .enqueue_dsn(
            failed.clone(),
            b"must never be written".to_vec(),
            vec!["127.0.0.1".into()],
        )
        .await
        .unwrap();
    store.cleanup().await.unwrap();
    assert!(store.raw_path(&id).exists());
    store.finish(&other, "delivered", "", 0).await.unwrap();
    store.cleanup().await.unwrap();
    assert!(!store.raw_path(&id).exists());
    drop(store);
    let store = Store::open(root.path()).unwrap();
    store.recover().await.unwrap();
    relay::notifications(&config, &store, &engine)
        .await
        .unwrap();
    assert!(store.claim().await.unwrap().is_none());
    assert!(store.failed().await.unwrap().is_empty());
    store
        .read(move |db| {
            assert_eq!(
                db.query_row(
                    "SELECT status FROM deliveries WHERE id=?1",
                    [failed.delivery_id],
                    |r| r.get::<_, String>(0)
                )?,
                backscatter::STATUS
            );
            assert_eq!(
                db.query_row("SELECT COUNT(*) FROM messages WHERE is_dsn=1", [], |r| r
                    .get::<_, i64>(0))?,
                0
            );
            assert_eq!(
                db.query_row(
                    "SELECT COUNT(*) FROM audit WHERE action='dsn_suppressed'",
                    [],
                    |r| r.get::<_, i64>(0)
                )?,
                1
            );
            assert_eq!(
                db.query_row("SELECT COUNT(*) FROM delivery_attempts", [], |r| r
                    .get::<_, i64>(0))?,
                1
            );
            Ok(())
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn normal_failures_still_get_one_durable_dsn_with_the_real_diagnostic() {
    let root = tempfile::tempdir().unwrap();
    let config = common::config(root.path());
    let store = Store::open(root.path()).unwrap();
    let mut scan = fixture::scan(config.clone());
    scan.evidence.as_mut().unwrap().authentication.spf = Some(AuthResult::Pass);
    store
        .enqueue(
            uuid::Uuid::new_v4().to_string(),
            "alice@example.test".into(),
            vec![config.recipient("bob@example.test").unwrap()],
            scan,
            common::MESSAGE.to_vec(),
        )
        .await
        .unwrap();
    let job = store.claim().await.unwrap().unwrap();
    let trace = fixture::rejection();
    store
        .finish_with_attempts(
            &job,
            "failed",
            trace.events.last().unwrap().response.as_deref().unwrap(),
            0,
            std::slice::from_ref(&trace),
        )
        .await
        .unwrap();
    let engine = Engine::new(config.clone()).unwrap();
    relay::notifications(&config, &store, &engine)
        .await
        .unwrap();
    let dsn = store.claim().await.unwrap().unwrap();
    assert!(dsn.is_dsn);
    assert!(dsn.sender.is_empty());
    let raw = std::fs::read(store.raw_path(&dsn.message_id)).unwrap();
    let text = String::from_utf8(raw.clone()).unwrap();
    assert!(text.contains(
        "Status: 5.7.1\r\nDiagnostic-Code: smtp; 554 5.7.1 rejected by rspamd filter\r\n"
    ));
    assert!(mail_parser::MessageParser::default().parse(&raw).is_some());
    store
        .enqueue_dsn(
            job,
            b"must not replace existing DSN".to_vec(),
            vec!["127.0.0.1".into()],
        )
        .await
        .unwrap();
    assert_eq!(std::fs::read(store.raw_path(&dsn.message_id)).unwrap(), raw);
    store
        .finish(&dsn, "failed", "550 mailbox failure", 0)
        .await
        .unwrap();
    relay::notifications(&config, &store, &engine)
        .await
        .unwrap();
    assert!(store.failed().await.unwrap().is_empty());
    assert!(store.claim().await.unwrap().is_none());
}

#[test]
fn diagnostics_keep_codes_but_do_not_allow_header_injection_or_identifiers() {
    let mut trace = fixture::rejection();
    trace.events.last_mut().unwrap().enhanced_code = Some("5.1.1\r\nInjected: true".into());
    trace.events.last_mut().unwrap().response =
        Some("550 private@example.org\r\nInjected: true\u{202e}".into());
    let (code, text) = backscatter::failure_diagnostic("", Some(&trace));
    assert_eq!(code, "5.0.0");
    assert!(!text.contains(['\r', '\n', '@']));
    assert!(text.is_ascii());
    assert!(text.len() <= 400);
    assert_eq!(
        backscatter::failure_diagnostic("5.4.7 Delivery time expired", Some(&trace)).0,
        "5.4.7"
    );
}

#[tokio::test]
async fn a_legitimate_correction_during_retry_preserves_the_failure_notice() {
    let root = tempfile::tempdir().unwrap();
    let cfg = common::config(root.path());
    let store = Store::open(root.path()).unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    store
        .enqueue(
            id.clone(),
            "alice@example.test".into(),
            vec![cfg.recipient("bob@example.test").unwrap()],
            fixture::scan(cfg.clone()),
            common::MESSAGE.to_vec(),
        )
        .await
        .unwrap();
    let job = store.claim().await.unwrap().unwrap();
    let trace = fixture::rejection();
    store
        .finish_with_attempts(
            &job,
            "failed",
            trace.events.last().unwrap().response.as_deref().unwrap(),
            0,
            std::slice::from_ref(&trace),
        )
        .await
        .unwrap();
    store
        .run(move |db| {
            db.execute(
                "INSERT INTO users(username,password) VALUES('reviewer','synthetic-test-hash')",
                [],
            )?;
            db.execute(
                "INSERT INTO feedback(username,message_id,spam,created) VALUES('reviewer',?1,0,?2)",
                rusqlite::params![id, noisefence::now()],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    let engine = Engine::new(cfg.clone()).unwrap();
    relay::notifications(&cfg, &store, &engine).await.unwrap();
    assert!(store.claim().await.unwrap().unwrap().is_dsn);
    store
        .read(|db| {
            assert_eq!(
                db.query_row(
                    "SELECT COUNT(*) FROM audit WHERE action='dsn_suppressed'",
                    [],
                    |r| r.get::<_, i64>(0)
                )?,
                0
            );
            Ok(())
        })
        .await
        .unwrap();
}
