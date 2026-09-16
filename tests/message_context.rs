mod common;
use noisefence::{
    decision,
    engine::{Engine, Scan},
    evidence::{AuthResult, Source, State},
    fusion::runtime::{Decision, DecisionSource, Outcome},
    llm::{Category, LlmResult, LlmStatus, Verdict},
};

const NOTICE: &[u8] = b"From: Shipping <shipping@example.org>\r\nSubject: Your package has been received\r\n\r\nThe buyer received your package, order STORAGE-2. They have 3 days to confirm it; your payment is then released automatically.\r\n";
const REPORT: &[u8] = b"From: Research <research@example.org>\r\nSubject: Example URL feed\r\n\r\nhxxps://bad.example/a\r\nhxxps://bad.example/b\r\nhxxps://bad.example/c\r\n";
fn candidate(raw: &[u8]) -> Scan {
    let root = tempfile::tempdir().unwrap();
    let mut scan = Engine::new(common::config(root.path()))
        .unwrap()
        .offline(raw);
    scan.complete = true;
    scan.score = 99.;
    scan.llm = LlmResult {
        status: LlmStatus::Complete,
        verdict: Some(Verdict {
            category: Category::Phishing,
            spam_probability: 0.8,
            confidence: 0.8,
            explanation: "Synthetic erroneous opinion".into(),
        }),
        ..Default::default()
    };
    scan.decision = Some(Decision::legacy(&scan, 95.));
    scan
}
fn aligned(scan: &mut Scan) {
    let e = scan.evidence.as_mut().unwrap();
    e.source = Source::SmtpSession;
    e.authentication.dmarc_state = State::Complete;
    e.authentication.dmarc_spf = Some(AuthResult::Pass);
}
#[test]
fn authenticated_receipts_and_security_feeds_are_reviewed_without_fake_rescoring() {
    for raw in [NOTICE, REPORT] {
        for with_llm in [true, false] {
            let mut scan = candidate(raw);
            if !with_llm {
                scan.llm = LlmResult::default();
            }
            aligned(&mut scan);
            decision::apply(&mut scan, false);
            assert_eq!(
                scan.decision.as_ref().unwrap().outcome,
                Outcome::Undetermined
            );
            assert!(
                scan.reasons
                    .iter()
                    .any(|r| r.id == decision::CONTEXT_REASON)
            );
            assert_eq!(scan.score, 99.);
            assert!(!scan.tagged && !scan.pub_tagged);
            let once = serde_json::to_value(&scan).unwrap();
            decision::apply(&mut scan, false);
            assert_eq!(serde_json::to_value(&scan).unwrap(), once);
        }
    }
}
#[test]
fn context_never_overrides_malware_validated_fusion_or_supplies_authentication() {
    let mut unverified = candidate(REPORT);
    decision::apply(&mut unverified, false);
    assert_eq!(unverified.decision.unwrap().outcome, Outcome::Unwanted);
    for mode in ["malware", "fusion", "authentication_failure"] {
        let mut scan = candidate(NOTICE);
        aligned(&mut scan);
        match mode {
            "malware" => scan.antivirus.status = noisefence::antivirus::AntivirusStatus::Malware,
            "fusion" => scan.decision.as_mut().unwrap().source = DecisionSource::Fusion,
            _ => {
                let auth = &mut scan.evidence.as_mut().unwrap().authentication;
                auth.dmarc_spf = Some(AuthResult::Fail);
                auth.dmarc_dkim = Some(AuthResult::Fail);
            }
        }
        decision::apply(&mut scan, false);
        assert_eq!(scan.decision.unwrap().outcome, Outcome::Unwanted);
    }
}
#[test]
fn encrypted_original_keeps_a_numeric_diagnostic_but_not_a_complete_content_claim() {
    let root = tempfile::tempdir().unwrap();
    let engine = Engine::new(common::config(root.path())).unwrap();
    assert!(engine.offline(common::MESSAGE).complete);
    let scan = engine.offline(b"From: sender@example.org\r\nSubject: Service update\r\nContent-Type: multipart/encrypted; boundary=x\r\n\r\n--x\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n--x--\r\n");
    assert!(!scan.complete);
    assert!(scan.score.is_finite());
    assert!(scan.reasons.iter().any(|r| r.id == "encrypted_content"));
    assert_eq!(scan.decision.unwrap().outcome, Outcome::Undetermined);
}
#[test]
fn semantic_deadline_is_web_editable_but_model_paths_are_not() {
    use noisefence::{config::SemanticFilter, management::Detection};
    let root = tempfile::tempdir().unwrap();
    let mut cfg = (*common::config(root.path())).clone();
    cfg.filter.semantic = Some(SemanticFilter {
        encoder_dir: "encoder".into(),
        combination: "combination.json".into(),
        max_parallel: 1,
        timeout_ms: 500,
    });
    let mut settings = Detection::from_config(&cfg);
    settings.modules.get_mut("semantic").unwrap()["timeout_ms"] = 1500.into();
    settings.apply(&mut cfg).unwrap();
    assert_eq!(cfg.filter.semantic.as_ref().unwrap().timeout_ms, 1500);
    for value in [
        serde_json::json!({"timeout_ms":5001}),
        serde_json::json!({"encoder_dir":"other"}),
        serde_json::json!({"max_parallel":10}),
    ] {
        settings.modules.insert("semantic".into(), value);
        assert!(settings.apply(&mut cfg).is_err());
    }
}

#[test]
fn newsletters_and_scheduled_service_updates_keep_distinct_purposes() {
    use noisefence::mailing::{self, Policy, Verdict};
    let distribution = "From: news@example.org\r\nList-ID: <news.example.org>\r\nList-Unsubscribe: <https://example.org/unsubscribe>\r\n";
    let news = format!(
        "{distribution}Subject: Events and special offers\r\n\r\nThis edition has a special offer and our upcoming events.\r\n"
    );
    assert_eq!(
        mailing::inspect(news.as_bytes(), &Policy::default(), 10000).verdict,
        Verdict::Newsletter
    );
    let notice = format!(
        "{distribution}Subject: Mise a jour du Cloud\r\n\r\nLa mise a jour est prevue pour le 20 septembre de 13h a 15h. Newsletter footer.\r\n"
    );
    assert_eq!(
        mailing::inspect(notice.as_bytes(), &Policy::default(), 10000).verdict,
        Verdict::Transactional
    );
}

#[test]
fn abuse_submissions_and_completed_payments_are_not_attacks_by_context_alone() {
    let examples = [
        "Subject: Pre-weaponized EXAMPLE squat / decoy shell\r\n\r\nURL: https://bad.example\r\nPlease keep the URL in your feed. Reporter: Example security team",
        "Subject: Phishing / Trademark - Example\r\n\r\nPlease retain the URL in your feed. Reporter: Example security team",
        "Subject: Reçu pour votre paiement au marchand\r\n\r\nVous avez payé 10 EUR. Date de la transaction. Afficher les détails du paiement.",
        "Subject: Notification de paiement automatique\r\n\r\nVotre paiement a été traitée avec succès. Pour plus d'informations contactez le support.",
        "Subject: Payment receipt\r\n\r\nYou paid 10 EUR. No action is needed.",
    ];
    for mail in examples {
        let raw = format!("From: notices@example.org\r\n{mail}\r\n");
        let mut scan = candidate(raw.as_bytes());
        aligned(&mut scan);
        let context = scan.message_context.as_ref().unwrap();
        assert!(
            context.threat_report || context.transaction_notice,
            "{mail}"
        );
        assert!(!context.action_demand);
        decision::apply(&mut scan, false);
        assert_eq!(
            scan.decision.as_ref().unwrap().outcome,
            Outcome::Undetermined
        );
        assert_eq!(scan.score, 99.);
    }
}

#[test]
fn a_forged_receipt_or_report_with_an_action_demand_gets_no_context_safeguard() {
    for body in [
        "You paid 10 EUR. Verify your account and enter your password now.",
        "You paid 10 EUR. Send bitcoin to cancel this charge.",
        "Please keep the URL in your feed. Reporter: Security. Install this software to read the report.",
    ] {
        let raw = format!(
            "From: notices@example.org\r\nSubject: Payment receipt - Phishing report\r\n\r\n{body}\r\n"
        );
        let mut scan = candidate(raw.as_bytes());
        aligned(&mut scan);
        assert!(scan.message_context.as_ref().unwrap().action_demand);
        assert!(!noisefence::message_context::needs_review(&scan));
        decision::apply(&mut scan, false);
        assert_eq!(scan.decision.unwrap().outcome, Outcome::Unwanted);
    }
}
