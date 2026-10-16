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

#[test]
fn shadow_and_unusable_provider_findings_cannot_veto_a_context_guard() {
    use noisefence::{
        antivirus::AntivirusStatus as Av,
        protection::{self, ProviderObservation, ProviderReport, Status},
    };
    let notices = [
        NOTICE,
        REPORT,
        b"Subject: Firmware update\r\n\r\nThis firmware update will be installed automatically.",
        b"Subject: Payment receipt\r\n\r\nYou paid EUR 10.00. No action is needed.",
    ];
    for raw in notices {
        for (observe, status, matched, expected) in [
            (true, Status::Complete, true, Outcome::Legitimate),
            (false, Status::Complete, true, Outcome::Unwanted),
            (false, Status::Quota, true, Outcome::Unwanted),
            (false, Status::Stale, true, Outcome::Legitimate),
            (false, Status::Disabled, true, Outcome::Legitimate),
            (false, Status::Complete, false, Outcome::Legitimate),
        ] {
            let mut scan = candidate(raw);
            scan.llm = LlmResult::default();
            scan.antivirus.status = Av::Clean;
            scan.signatures.status = Av::Clean;
            aligned(&mut scan);
            scan.protection = Some(protection::Report {
                version: protection::VERSION.into(),
                observation_only: observe,
                virustotal: ProviderReport {
                    status,
                    captured_at: Some(1000),
                    checked: 1,
                    malicious: 1,
                    observations: vec![ProviderObservation {
                        indicator_sha256: "a".repeat(64),
                        scope: "domain".into(),
                        verdict: "malicious".into(),
                        queried_at: 1000,
                        cached: false,
                        cache_max_age_seconds: 0,
                        analysis_max_age_seconds: Some(3600),
                    }],
                    ..Default::default()
                },
                findings: vec![protection::Finding {
                    id: "known_malicious_indicator".into(),
                    family: "link_reputation".into(),
                    indicator: if matched { "a" } else { "b" }.repeat(64),
                    sources: vec!["virustotal".into()],
                    detail: "Synthetic reputation finding".into(),
                }],
                ..Default::default()
            });
            decision::apply(&mut scan, false);
            decision::finalize(&mut scan, 95.);
            assert_eq!(
                scan.decision.as_ref().unwrap().outcome,
                expected,
                "observe={observe}, matched={matched}"
            );
            assert_eq!(scan.score, 99.); // No fake recalibration to explain a policy decision.
            if expected == Outcome::Legitimate {
                assert_eq!(
                    scan.score_resolution.as_ref().unwrap().guard.as_deref(),
                    Some("authenticated_benign_conflict")
                );
            }
            let once = serde_json::to_value(&scan).unwrap();
            decision::apply(&mut scan, false);
            decision::finalize(&mut scan, 95.);
            assert_eq!(serde_json::to_value(&scan).unwrap(), once);
        }
        // The same authentic-looking template with a credential demand never
        // qualifies; a clean sender domain does not authenticate the request.
        let mut attack = raw.to_vec();
        attack.extend_from_slice(b"\r\nVerify your account and enter your password now.");
        let mut scan = candidate(&attack);
        aligned(&mut scan);
        scan.llm = LlmResult::default();
        scan.antivirus.status = Av::Clean;
        scan.signatures.status = Av::Clean;
        decision::apply(&mut scan, false);
        decision::finalize(&mut scan, 95.);
        assert_eq!(scan.decision.as_ref().unwrap().outcome, Outcome::Unwanted);
    }
}

#[test]
fn reported_url_tokens_are_not_recipient_activation_demands() {
    for indicator in [
        "hxxps://blocked.example/activation",
        "https://blocked.example/activation",
        "blocked.example/activation",
        "blocked[.]example/activation",
        "activation-blocked.example",
        "activation@blocked.example",
    ] {
        let raw = format!(
            "Subject: Example URL feed\r\n\r\nhxxps://bad.example/a\r\nhxxps://bad.example/b\r\nhxxps://bad.example/c\r\n{indicator}\r\n"
        );
        let context = noisefence::message_context::inspect(raw.as_bytes());
        assert!(context.threat_report);
        assert!(!context.action_demand, "{indicator}");
    }
    let raw = format!(
        "Subject: Backup job failed\r\n\r\nThe backup job failed. Activation is logged. {} A separate process was blocked.",
        "Historical event. ".repeat(25)
    );
    assert!(
        !noisefence::message_context::inspect(raw.as_bytes()).action_demand,
        "{:?}",
        noisefence::features::text(raw.as_bytes())
    );
}

#[test]
fn completed_receipts_and_passive_operations_need_matching_body_evidence() {
    for (subject, body, receipt, service) in [
        (
            "Express Reçu du paiement",
            "Montant payé EUR 42.00. Référence de la transaction : TEST.",
            true,
            false,
        ),
        (
            "Payment portal - Récépissé",
            "Votre paiement a bien été pris en compte.",
            true,
            false,
        ),
        (
            "2e paiement reçu pour Example",
            "Votre paiement de 42 euros a été effectué avec succès.",
            true,
            false,
        ),
        (
            "Payment confirmation",
            "Payment for shipment TEST has been successfully completed.",
            true,
            false,
        ),
        (
            "Payment confirmation",
            "Payment for shipment TEST has not been successfully completed.",
            false,
            false,
        ),
        (
            "Votre facture est disponible",
            "Veuillez payer cette facture.",
            false,
            false,
        ),
        (
            "Échec de la tâche de sauvegarde TEST",
            "La tâche de sauvegarde TEST a échoué.",
            false,
            true,
        ),
        (
            "La vérification de l’intégrité a échoué",
            "La vérification de l’intégrité a échoué sur le serveur.",
            false,
            true,
        ),
        (
            "Backup job failed",
            "Your backup job failed on the storage server.",
            false,
            true,
        ),
        (
            "Backup job failed",
            "Buy our new storage offer!",
            false,
            false,
        ),
        (
            "Mise à jour du logiciel interne",
            "Les appareils reçoivent automatiquement des mises à jour.",
            false,
            true,
        ),
        (
            "Firmware update",
            "The update will be installed automatically.",
            false,
            true,
        ),
        (
            "Firmware update",
            "Install our application immediately.",
            false,
            false,
        ),
    ] {
        let raw =
            format!("Subject: {subject}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{body}");
        let c = noisefence::message_context::inspect(raw.as_bytes());
        assert_eq!(c.transaction_notice, receipt, "{subject}: {body}");
        assert_eq!(c.passive_service_notice, service, "{subject}: {body}");
    }
}

#[test]
fn receipt_or_service_wrapper_does_not_hide_bank_activation_or_callback_demands() {
    for demand in [
        "Activez votre service pour éviter le blocage de votre compte.",
        "Mise à jour obligatoire, vos opérations seront bloquées.",
        "Activate security before your account is suspended.",
        "Un débit sur votre carte. Contactez immédiatement le service opposition.",
        "A card payment was made. Call our fraud team immediately.",
        "Renseignez vos identifiants et votre code de sécurité.",
        "Provide your security code.",
    ] {
        let raw = format!(
            "Subject: Payment receipt\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nYou paid 42 euros. {demand}"
        );
        let context = noisefence::message_context::inspect(raw.as_bytes());
        assert!(context.transaction_notice);
        assert!(context.action_demand, "{demand}");
        let mut scan = candidate(raw.as_bytes());
        aligned(&mut scan);
        scan.llm = Default::default();
        scan.antivirus.status = noisefence::antivirus::AntivirusStatus::Clean;
        scan.signatures.status = noisefence::antivirus::AntivirusStatus::Clean;
        decision::apply(&mut scan, false);
        decision::finalize(&mut scan, 95.);
        assert_eq!(
            scan.decision.unwrap().outcome,
            Outcome::Unwanted,
            "{demand}"
        );
    }
}

#[test]
fn smtp_dns_gap_does_not_turn_an_authenticated_passive_notice_into_spam() {
    use noisefence::{antivirus::AntivirusStatus as Av, engine::Signal};
    let raw = b"Subject: Backup job failed\r\n\r\nThe backup job failed on the storage server.\r\n";
    for gap in [
        None,
        Some("smtp_policy_unavailable"),
        Some("vision_incomplete"),
        Some("llm_unavailable"),
    ] {
        let mut scan = candidate(raw);
        aligned(&mut scan);
        scan.llm = Default::default();
        scan.antivirus.status = Av::Clean;
        scan.signatures.status = Av::Clean;
        if let Some(id) = gap {
            scan.complete = false;
            scan.reasons.push(Signal {
                id: id.into(),
                detail: "Synthetic missing check".into(),
                weight: 0.,
            });
        }
        scan.decision = Some(Decision::legacy(&scan, 95.));
        decision::apply(&mut scan, false);
        decision::finalize(&mut scan, 95.);
        let eligible = gap.is_none() || gap == Some("smtp_policy_unavailable");
        assert_eq!(
            scan.decision.as_ref().unwrap().outcome,
            if eligible {
                Outcome::Legitimate
            } else {
                Outcome::Unwanted
            }
        );
        assert_eq!(scan.score, 99.);
        assert_eq!(scan.complete, gap.is_none());
        if eligible {
            assert_eq!(
                scan.score_resolution.as_ref().unwrap().guard.as_deref(),
                Some("authenticated_benign_conflict")
            );
        }
        let once = serde_json::to_value(&scan).unwrap();
        decision::apply(&mut scan, false);
        decision::finalize(&mut scan, 95.);
        assert_eq!(serde_json::to_value(&scan).unwrap(), once);
    }
}

#[test]
fn replay_is_digest_bound_private_and_never_changes_the_original() {
    let raw = b"Subject: Payment receipt\r\n\r\nAmount paid: EUR 42.\r\n";
    let mut scan = candidate(raw);
    aligned(&mut scan);
    scan.llm = Default::default();
    scan.antivirus.status = noisefence::antivirus::AntivirusStatus::Clean;
    scan.signatures.status = noisefence::antivirus::AntivirusStatus::Clean;
    scan.message_context = Some(Default::default());
    // Reproduce the historical unrecognised receipt, with recorded policy.
    let root = tempfile::tempdir().unwrap();
    scan.analysis_policy = Some(noisefence::diagnostics::AnalysisPolicy::capture(
        &common::config(root.path()),
    ));
    scan.raw_sha256 = Some(noisefence::message::digest(raw));
    let before = serde_json::to_value(&scan).unwrap();
    let report = decision::replay::compare(raw, &scan).unwrap();
    assert_eq!(serde_json::to_value(&scan).unwrap(), before);
    assert_eq!(report.recorded, noisefence::mailing::Category::Spam);
    assert_eq!(report.baseline, noisefence::mailing::Category::Spam);
    assert_eq!(report.candidate, noisefence::mailing::Category::Legitimate);
    let output = serde_json::to_string(&report).unwrap();
    assert!(!output.contains("EUR") && !output.contains("Payment receipt"));
    assert!(decision::replay::compare(b"Substituted body", &scan).is_err());
    scan.raw_sha256 = None;
    assert!(decision::replay::compare(raw, &scan).is_err());
}

#[test]
fn conditional_notices_require_a_completed_security_event_and_keep_current_demands() {
    for (subject, body, expected, demand) in [
        (
            "Your password was changed",
            "If this was you, no action is required.",
            true,
            false,
        ),
        (
            "Modification du mot de passe du compte",
            "Si c'était vous, vous pouvez ignorer ce message.",
            true,
            false,
        ),
        (
            "Security information was added",
            "If this was you, ignore this notice.",
            true,
            false,
        ),
        (
            "Urgent security alert",
            "If this was you, ignore this notice.",
            false,
            false,
        ),
        (
            "Your password was changed",
            "Enter your password to verify your account. If this was you, ignore this notice.",
            true,
            true,
        ),
        (
            "Your password was changed",
            "A security change was recorded.",
            false,
            false,
        ),
        (
            "Your password was changed",
            "If this was you, visit our portal. Do not ignore this payment demand.",
            false,
            false,
        ),
        (
            "Your password was changed",
            "If this was you, do not ignore this message.",
            false,
            false,
        ),
        (
            "Modification du mot de passe",
            "Si c'était vous, ne pas ignorer cette demande.",
            false,
            false,
        ),
    ] {
        let raw =
            format!("Subject: {subject}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{body}");
        let context = noisefence::message_context::inspect(raw.as_bytes());
        assert_eq!(
            context.conditional_security_notice, expected,
            "{subject}: {body}"
        );
        assert_eq!(context.action_demand, demand);
    }
}
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
    e.authentication.state = State::Complete;
    e.authentication.dmarc_state = State::Complete;
    e.authentication.dmarc_dkim = Some(AuthResult::None);
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
    assert_eq!(scan.decision.unwrap().outcome, Outcome::Legitimate);
    assert!(scan.score_resolution.is_some());
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

#[test]
fn opaque_mail_cannot_inherit_an_extreme_content_model_score() {
    use noisefence::{
        engine::{Algorithm, Model},
        features,
    };
    let root = tempfile::tempdir().unwrap();
    let mut config = (*common::config(root.path())).clone();
    let model = Model {
        version: "synthetic-high-bias".into(),
        algorithm: Algorithm::Logistic,
        feature_version: features::VERSION,
        bias: 30.,
        weights: vec![0.; features::DIMENSION],
        idf: vec![1.; features::DIMENSION],
        trained_at: 0,
        examples: 1,
    };
    let path = root.path().join("model.json");
    std::fs::write(&path, serde_json::to_vec(&model).unwrap()).unwrap();
    config.filter.model = Some(path);
    let engine = Engine::new(std::sync::Arc::new(config)).unwrap();
    assert!(engine.offline(common::MESSAGE).score > 99.);
    for kind in [
        "application/pkcs7-mime",
        "application/x-pkcs7-mime",
        "multipart/encrypted; boundary=x",
    ] {
        let raw = format!(
            "From: notices@example.org\r\nSubject: Account notice\r\nContent-Type: {kind}\r\n\r\nOpaque data\r\n"
        );
        let scan = engine.offline(raw.as_bytes());
        assert!(!scan.complete && !scan.features_complete.unwrap());
        assert!(scan.score.is_finite() && scan.score < 95.);
        assert_eq!(scan.model, "rules-partial-1");
        assert!(noisefence::detection_diagnostics::breakdown(&scan).matches_recorded_score);
        let e = scan.evidence.unwrap();
        assert_eq!(e.lexical_state, State::Limited);
        assert!(e.lexical_logit.is_none());
        assert_eq!(scan.decision.unwrap().outcome, Outcome::Legitimate);
        assert!(scan.score_resolution.is_some());
        assert!(!scan.reasons.iter().any(|r| r.id == "model_contribution"));
        assert!(scan.reasons.iter().any(|r| r.id == "content_model_skipped"));
    }
}

const EXTORTION: &str = "I gained access to your email account and camera. I can share this material with your friends and relatives. I am demanding USD 1250 in cryptocurrency. Payment address (btc wallet): bc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq. You have 48 hours.";
#[test]
fn direct_extortion_requires_all_components_and_excludes_quoted_incidents() {
    use noisefence::message_context::inspect;
    assert!(
        inspect(format!("Subject: Security alert\r\n\r\n{EXTORTION}").as_bytes()).direct_extortion
    );
    for body in [
        EXTORTION.replace("I gained access", "A service has access"),
        EXTORTION.replace(
            "I can share this material with your friends and relatives.",
            "I respect your privacy.",
        ),
        EXTORTION.replace(
            "I am demanding USD 1250 in cryptocurrency.",
            "No payment is required.",
        ),
        EXTORTION.replace("bc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", "[redacted]"),
        format!("I received this suspicious message: {EXTORTION}"),
        format!("> {EXTORTION}"),
        "You paid 10 EUR in bitcoin. Your payment receipt is available. We never share your files."
            .into(),
    ] {
        assert!(!inspect(format!("Subject: Example\r\n\r\n{body}").as_bytes()).direct_extortion);
    }
    for subject in [
        "Fwd: Security alert",
        "Re: extortion incident",
        "Sextortion report",
    ] {
        assert!(
            !inspect(format!("Subject: {subject}\r\n\r\n{EXTORTION}").as_bytes()).direct_extortion
        );
    }
    assert!(!inspect(format!("Subject: Incident\r\nContent-Type: text/html\r\n\r\n<p>For investigation:</p><blockquote>{EXTORTION}</blockquote>").as_bytes()).direct_extortion);
}

#[tokio::test]
async fn opaque_content_keeps_bounded_transport_checks_without_reenabling_content_learning() {
    let root = tempfile::tempdir().unwrap();
    let engine = Engine::new(common::config(root.path())).unwrap();
    let raw = b"From: sender@example.org\r\nTo: alice@example.test\r\nSubject: Encrypted notice\r\nContent-Type: multipart/encrypted; boundary=x\r\n\r\n--x\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n--x\r\nContent-Type: application/octet-stream\r\n\r\nopaque\r\n--x--\r\n";
    let (scan, wire) = engine
        .process(
            raw,
            "127.0.0.1".parse().unwrap(),
            "sender.example.org",
            "sender@example.org",
            "encrypted-fixture",
        )
        .await
        .unwrap();
    assert!(!scan.complete && !scan.features_complete.unwrap());
    assert_eq!(
        scan.evidence.unwrap().authentication.arc_state,
        State::Complete
    );
    assert_eq!(scan.decision.unwrap().outcome, Outcome::Legitimate);
    assert!(scan.score_resolution.is_some());
    assert!(!scan.tagged && !String::from_utf8_lossy(&wire).contains("[SPAM]"));
}

#[test]
fn subscription_field_injection_requires_a_localized_off_site_reward_lure() {
    use noisefence::message_context::inspect;
    let body = "Your subscription to our list has been confirmed. For your records, here is the information you submitted to us...\nFirst Name: YOUR 120000.50 USDT REWARD AWAITS. COLLECT NOW www.claim-example.pages.dev\nUnsubscribe here.";
    let raw = |body: &str| {
        format!(
            "From: service@newsletter.example.org\r\nSubject: Subscription confirmed\r\n\r\n{body}"
        )
    };
    assert!(inspect(raw(body).as_bytes()).injected_reward_lure);
    for text in [
        body.replace("120000.50 USDT REWARD AWAITS. COLLECT NOW", "Alice"),
        body.replace("www.claim-example.pages.dev", "www.newsletter.example.org"),
        body.replace(
            "www.claim-example.pages.dev",
            "hxxps://www.claim-example.pages.dev",
        ),
        body.replace("First Name:", "Our reported incident:"),
        body.replace("information you submitted", "newsletter update"),
        format!("Received the following scam analysis:\n{body}"),
        body.replace("COLLECT NOW", "transaction complete"),
    ] {
        assert!(
            !inspect(raw(&text).as_bytes()).injected_reward_lure,
            "{text}"
        );
    }
    assert!(
        !inspect(
            raw(body)
                .replace("Subject: Subscription", "Subject: Fwd: Subscription")
                .as_bytes()
        )
        .injected_reward_lure
    );
    let html = format!(
        "From: service@example.org\r\nSubject: Incident\r\nContent-Type: text/html\r\n\r\n<blockquote>{body}</blockquote>"
    );
    assert!(!inspect(html.as_bytes()).injected_reward_lure);
}

#[test]
fn completed_transfers_and_trip_receipts_supply_context_but_not_a_trust_override() {
    for (subject, body) in [
        (
            "Votre virement est en route !",
            "Montant du virement 30 EUR. Vers compte bancaire. L'argent sera disponible sous 3 jours.",
        ),
        (
            "Your Friday evening trip with Example",
            "Thanks for riding. Trip fare 30 EUR. Payments. Download the receipt.",
        ),
    ] {
        let raw = format!("From: notices@example.org\r\nSubject: {subject}\r\n\r\n{body}\r\n");
        let context = noisefence::message_context::inspect(raw.as_bytes());
        assert!(context.transaction_notice);
        assert!(!context.action_demand);
        let mut scan = candidate(raw.as_bytes());
        decision::apply(&mut scan, false);
        assert_eq!(scan.decision.as_ref().unwrap().outcome, Outcome::Unwanted);
        aligned(&mut scan);
        decision::apply(&mut scan, false);
        assert_eq!(
            scan.decision.as_ref().unwrap().outcome,
            Outcome::Undetermined
        );
        assert_eq!(scan.score, 99.);
        // An injected sensitive request defeats the apparent receipt context.
        let lure = format!("{raw}Please verify your account and enter your password.\r\n");
        let mut scan = candidate(lure.as_bytes());
        aligned(&mut scan);
        assert!(scan.message_context.as_ref().unwrap().action_demand);
        decision::apply(&mut scan, false);
        assert_eq!(scan.decision.as_ref().unwrap().outcome, Outcome::Unwanted);
    }
    let bare = noisefence::message_context::inspect(
        b"Subject: Your bank transfer is on the way\r\n\r\nClick here to claim a prize.",
    );
    assert!(!bare.transaction_notice);
}
