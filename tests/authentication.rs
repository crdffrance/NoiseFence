mod common;
use mail_auth::{
    AuthenticatedMessage, DkimResult, MessageAuthenticator, Parameters, ResolverCache, Txt,
    common::{
        crypto::{RsaKey, Sha256},
        headers::HeaderWriter,
        parse::TxtRecordParser,
        verify::DomainKey,
    },
    dkim::DkimSigner,
};
use noisefence::{config::Mode, engine::Engine, message};
use std::{
    borrow::Borrow,
    collections::HashMap,
    hash::Hash,
    sync::{Arc, Mutex},
};

// A deterministic local DNS cache: an unexpected network query fails the test.
struct TestDns(Mutex<HashMap<Box<str>, Txt>>);
impl ResolverCache<Box<str>, Txt> for TestDns {
    fn get<Q>(&self, key: &Q) -> Option<Txt>
    where
        Box<str>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        Some(
            self.0
                .lock()
                .unwrap()
                .get(key)
                .cloned()
                .expect("unexpected DNS name"),
        )
    }
    fn remove<Q>(&self, key: &Q) -> Option<Txt>
    where
        Box<str>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.0.lock().unwrap().remove(key)
    }
    fn insert(&self, key: Box<str>, value: Txt, _: std::time::Instant) {
        self.0.lock().unwrap().insert(key, value);
    }
}

#[tokio::test]
async fn original_dkim_survives_observation_subject_tag_breaks_dkim_and_arc_seals_modified_body() {
    let key =
        rustls_pemfile::private_key(&mut include_bytes!("fixtures/public-test-key.txt").as_slice())
            .unwrap()
            .unwrap();
    let signature = DkimSigner::from_key(RsaKey::<Sha256>::from_key_der(key).unwrap())
        .domain("example.org")
        .selector("test")
        .headers(["From", "To", "Subject", "Date", "Message-ID"])
        .sign(common::MESSAGE)
        .unwrap();
    let original = [signature.to_header().as_bytes(), common::MESSAGE].concat();
    let dns = TestDns(Mutex::new(HashMap::from([(
        "test._domainkey.example.org.".into(),
        Txt::DomainKey(Arc::new(
            DomainKey::parse(include_bytes!("fixtures/public-test-key.dns")).unwrap(),
        )),
    )])));
    let authenticator = MessageAuthenticator::new_system_conf().unwrap();
    let parsed = AuthenticatedMessage::parse(&original).unwrap();
    let results = authenticator
        .verify_dkim(Parameters::new(&parsed).with_txt_cache(&dns))
        .await;
    assert_eq!(*results[0].result(), DkimResult::Pass);
    let observed = message::rewrite(&original, false, "X-NoiseFence-Score: 0\r\n").unwrap();
    let parsed_observed = AuthenticatedMessage::parse(&observed).unwrap();
    let results = authenticator
        .verify_dkim(Parameters::new(&parsed_observed).with_txt_cache(&dns))
        .await;
    assert_eq!(*results[0].result(), DkimResult::Pass);

    let dir = tempfile::tempdir().unwrap();
    let mut cfg = (*common::config(dir.path())).clone();
    // Force the tagging branch for this isolated unit test without a live DNS resolver.
    cfg.filter.mode = Mode::Tag;
    cfg.filter.threshold = 0.0;
    cfg.filter.arc_domain = Some("example.org".into());
    cfg.filter.arc_selector = Some("test".into());
    cfg.filter.arc_key = Some(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/public-test-key.txt"),
    );
    let engine = Engine::new(Arc::new(cfg)).unwrap();
    let (scan, marked) = engine
        .process(
            &original,
            "192.0.2.1".parse().unwrap(),
            "mail.example.org",
            "sender@example.org",
            &uuid::Uuid::new_v4().to_string(),
        )
        .await
        .unwrap();
    assert!(scan.complete && scan.tagged);
    assert_eq!(
        message::fields(&original).unwrap().1,
        message::fields(&marked).unwrap().1
    );
    let parsed = AuthenticatedMessage::parse(&marked).unwrap();
    let results = authenticator
        .verify_dkim(Parameters::new(&parsed).with_txt_cache(&dns))
        .await;
    assert_ne!(*results[0].result(), DkimResult::Pass);
    let arc = authenticator
        .verify_arc(Parameters::new(&parsed).with_txt_cache(&dns))
        .await;
    assert_eq!(*arc.result(), DkimResult::Pass);
    let tampered = [marked.as_slice(), b"tampered\r\n"].concat();
    let parsed = AuthenticatedMessage::parse(&tampered).unwrap();
    let arc = authenticator
        .verify_arc(Parameters::new(&parsed).with_txt_cache(&dns))
        .await;
    assert_ne!(*arc.result(), DkimResult::Pass);
}

#[tokio::test]
async fn excessive_signature_work_fails_open_without_a_subject_change() {
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::new(common::config(dir.path())).unwrap();
    let raw = [
        "DKIM-Signature: invalid\r\n".repeat(17).as_bytes(),
        common::MESSAGE,
    ]
    .concat();
    let (scan, output) = engine
        .process(
            &raw,
            "192.0.2.1".parse().unwrap(),
            "mail.example.org",
            "sender@example.org",
            &uuid::Uuid::new_v4().to_string(),
        )
        .await
        .unwrap();
    assert!(!scan.complete && !scan.tagged);
    assert!(scan.reasons.iter().any(|r| r.id == "signature_budget"));
    assert!(!String::from_utf8_lossy(&output).contains("[SPAM]"));
}

#[tokio::test]
async fn received_policy_headers_cannot_supply_a_trusted_smtp_identity_or_score() {
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::new(common::config(dir.path())).unwrap();
    let forged = [b"X-NoiseFence-Policy: ptr_verified; weight=-100\r\nX-NoiseFence-Evidence: {\"source\":\"smtp_session\",\"spf\":\"pass\"}\r\nAuthentication-Results: trusted.example; spf=pass; dmarc=pass\r\nReceived: from trusted.example.org [192.0.2.99]\r\n".as_slice(), common::MESSAGE].concat();
    let (original, _) = engine
        .process(
            common::MESSAGE,
            "192.0.2.1".parse().unwrap(),
            "actual.example.org",
            "sender@example.org",
            "original",
        )
        .await
        .unwrap();
    let (scan, output) = engine
        .process(
            &forged,
            "192.0.2.1".parse().unwrap(),
            "actual.example.org",
            "sender@example.org",
            "forged",
        )
        .await
        .unwrap();
    assert_eq!(
        scan.smtp_policy.status,
        noisefence::smtp_policy::PolicyStatus::Disabled
    );
    assert_eq!(scan.score, original.score);
    assert!(scan.smtp_policy.checks.is_empty());
    let evidence = scan.evidence.as_ref().unwrap();
    assert_eq!(
        evidence.source,
        noisefence::evidence::Source::SuppliedEnvelope
    );
    assert_eq!(
        evidence.authentication.state,
        noisefence::evidence::State::Disabled
    );
    assert!(evidence.authentication.spf.is_none());
    assert_eq!(
        serde_json::to_value(evidence).unwrap(),
        serde_json::to_value(original.evidence.unwrap()).unwrap()
    );
    assert!(!String::from_utf8_lossy(&output).contains("X-NoiseFence-Policy:"));
    assert!(!String::from_utf8_lossy(&output).contains("X-NoiseFence-Evidence:"));
}

#[tokio::test]
async fn pub_tag_is_arc_sealed_and_spam_priority_is_preserved() {
    let raw=b"From: sender@example.org\r\nTo: alice@example.test\r\nSubject: Weekly newsletter\r\nList-ID: News <news.example.org>\r\nDate: Wed, 09 Sep 2026 12:00:00 +0000\r\nMessage-ID: <news@example.org>\r\n\r\nWeekly digest. News from the team.\r\n";
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = (*common::config(dir.path())).clone();
    // Exercise the wire implementation only; config gate tests separately require live evidence.
    cfg.filter.mode = Mode::Tag;
    cfg.mailing = Some(noisefence::mailing::Settings::default());
    cfg.filter.arc_domain = Some("example.org".into());
    cfg.filter.arc_selector = Some("test".into());
    cfg.filter.arc_key = Some(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/public-test-key.txt"),
    );
    let dns = TestDns(Mutex::new(HashMap::from([(
        "test._domainkey.example.org.".into(),
        Txt::DomainKey(Arc::new(
            DomainKey::parse(include_bytes!("fixtures/public-test-key.dns")).unwrap(),
        )),
    )])));
    let authenticator = MessageAuthenticator::new_system_conf().unwrap();
    for spam in [false, true] {
        cfg.filter.threshold = if spam { 0. } else { 95. };
        let engine = Engine::new(Arc::new(cfg.clone())).unwrap();
        let (scan, marked) = engine
            .process(
                raw,
                "192.0.2.1".parse().unwrap(),
                "mail.example.org",
                "sender@example.org",
                "pub-test",
            )
            .await
            .unwrap();
        assert!(scan.complete);
        assert_eq!(scan.tagged, spam);
        assert_eq!(scan.pub_tagged, !spam);
        let parsed = AuthenticatedMessage::parse(&marked).unwrap();
        assert_eq!(
            *authenticator
                .verify_arc(Parameters::new(&parsed).with_txt_cache(&dns))
                .await
                .result(),
            DkimResult::Pass
        );
        assert_eq!(
            message::fields(raw).unwrap().1,
            message::fields(&marked).unwrap().1
        );
        let subject = mail_parser::MessageParser::default()
            .parse(&marked)
            .unwrap()
            .subject()
            .unwrap()
            .to_string();
        assert_eq!(
            subject,
            if spam {
                "[SPAM] Weekly newsletter"
            } else {
                "[PUB] Weekly newsletter"
            }
        );
        let tampered = String::from_utf8(marked)
            .unwrap()
            .replace("X-NoiseFence-Category:", "X-NoiseFence-Forged-Category:");
        let parsed = AuthenticatedMessage::parse(tampered.as_bytes()).unwrap();
        assert_ne!(
            *authenticator
                .verify_arc(Parameters::new(&parsed).with_txt_cache(&dns))
                .await
                .result(),
            DkimResult::Pass
        );
    }
    cfg.filter.threshold = 95.;
    cfg.mailing.as_mut().unwrap().policy.tag_subject = false;
    let engine = Engine::new(Arc::new(cfg.clone())).unwrap();
    let (scan, _) = engine
        .process(
            raw,
            "192.0.2.1".parse().unwrap(),
            "mail.example.org",
            "sender@example.org",
            "disabled",
        )
        .await
        .unwrap();
    assert!(!scan.pub_tagged);
    cfg.mailing.as_mut().unwrap().policy.tag_subject = true;
    let engine = Engine::new(Arc::new(cfg)).unwrap();
    let malformed = ["DKIM-Signature: invalid\r\n".repeat(17).as_bytes(), raw].concat();
    let (scan, wire) = engine
        .process(
            &malformed,
            "192.0.2.1".parse().unwrap(),
            "mail.example.org",
            "sender@example.org",
            "limited",
        )
        .await
        .unwrap();
    assert!(!scan.complete && !scan.pub_tagged && !scan.tagged);
    assert!(!String::from_utf8_lossy(&wire).contains("Subject: [PUB]"));
}
