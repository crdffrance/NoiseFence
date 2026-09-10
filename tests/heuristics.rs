// Keep the R&D contract executable before shared lib/config/engine wiring lands.
#[path = "../src/heuristics.rs"]
mod heuristics;

use base64::{Engine, engine::general_purpose::STANDARD};
use heuristics::{
    Calibration, LimitHit, Mode, PATTERN_VERSION, Report, Rule, Runtime, Scope, Settings, Status,
    VERSION,
};

fn rule(id: &str, pattern: &str, scopes: &[Scope]) -> Rule {
    Rule {
        id: id.into(),
        label: "Research test rule".into(),
        family: "test".into(),
        pattern: pattern.into(),
        scopes: scopes.into(),
        candidate_weight: 1.5,
    }
}

fn settings(pattern: &str, scopes: &[Scope]) -> Settings {
    Settings {
        rules: vec![rule("test.one", pattern, scopes)],
        ..Settings::default()
    }
}

fn raw(subject: &str, body: &str) -> Vec<u8> {
    format!("From: Alice <alice@example.test>\r\nSubject: {subject}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{body}\r\n").into_bytes()
}

fn html(body: &str) -> Vec<u8> {
    format!("From: a@example.test\r\nSubject: Routine\r\nContent-Type: text/html; charset=utf-8\r\n\r\n{body}\r\n").into_bytes()
}

fn multipart(parts: &[&str]) -> Vec<u8> {
    let mut raw = "From: a@example.test\r\nSubject: Routine\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=outer\r\n\r\n".to_owned();
    for part in parts {
        raw.push_str(&format!("--outer\r\n{part}\r\n"));
    }
    raw.push_str("--outer--\r\n");
    raw.into_bytes()
}

fn calibrated(mut settings: Settings) -> Settings {
    settings.calibration = Some(Calibration {
        pattern_version: PATTERN_VERSION.into(),
        rules_digest: settings.rules_digest().unwrap(),
        artifact_sha256: "a".repeat(64),
        scale: 0.5,
        max_contribution: 1.0,
    });
    settings.mode = Mode::Contribute;
    settings
}

fn assert_limited(report: &Report, limit: LimitHit) {
    assert_eq!(report.status, Status::Limited, "{report:?}");
    assert!(report.limits_hit.contains(&limit), "{report:?}");
    assert_eq!(report.contribution, 0.0);
}

#[test]
fn builtins_detect_meaningful_french_english_lures_and_stay_observations() {
    let settings = Settings::default();
    settings.validate().unwrap();
    let runtime = Runtime::new(settings).unwrap();
    for (subject, body, expected) in [
        (
            "Vérifiez votre compte",
            "Votre compte sera suspendu",
            "fr.credentials",
        ),
        (
            "Verify your account",
            "Your account has been suspended",
            "en.credentials",
        ),
        (
            "Une opportunité",
            "Rendements garantis et vous avez gagné",
            "fr.guaranteed_returns",
        ),
        (
            "An opportunity",
            "Guaranteed profits. Claim your prize.",
            "en.guaranteed_returns",
        ),
        (
            "Paiement",
            "Changement de RIB, virement urgent",
            "fr.payment_change",
        ),
        (
            "Payment",
            "Updated bank details: urgent wire transfer",
            "en.payment_change",
        ),
    ] {
        let report = runtime.inspect(&raw(subject, body));
        assert_eq!(report.status, Status::Complete, "{report:?}");
        assert!(
            report.findings.iter().any(|f| f.id == expected),
            "{report:?}"
        );
        assert!(report.candidate_weight > 0.0);
        assert_eq!(report.contribution, 0.0);
        assert_eq!(report.mode, Mode::Observation);
    }
    assert!(
        runtime
            .inspect(&raw(
                "Réunion demain",
                "Bonjour, voici le compte rendu. Merci !"
            ))
            .findings
            .is_empty()
    );
}

#[test]
fn decoded_folded_subject_from_reply_to_and_quoted_printable_latin1() {
    let encoded = STANDARD.encode("Service sécurité");
    let raw = format!(
        "From: =?UTF-8?B?{encoded}?= <desk@example.test>\r\nReply-To: =?UTF-8?Q?V=C3=A9rifiez_votre_identit=C3=A9?= <reply@example.test>\r\nSubject: =?UTF-8?Q?V=C3=A9rifiez?=\r\n\t=?UTF-8?Q?_votre_compte?=\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=iso-8859-1\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nR=E9clamez votre r=E9compense\r\n"
    );
    let mut config = Settings::default();
    config.rules.push(rule(
        "reply.decoded",
        r"(?i)vérifiez votre identité",
        &[Scope::ReplyTo],
    ));
    let report = Runtime::new(config).unwrap().inspect(raw.as_bytes());
    assert_eq!(report.status, Status::Complete, "{report:?}");
    for (id, scope) in [
        ("fr.credentials", Scope::Subject),
        ("fr.prize", Scope::Body),
        ("identity.security_desk", Scope::From),
        ("reply.decoded", Scope::ReplyTo),
    ] {
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.id == id && f.scopes.contains(&scope)),
            "missing {id}: {report:?}"
        );
    }
}

#[test]
fn base64_html_entities_inline_fragments_and_blocks_are_visible() {
    let body = "<html><body><p>V&eacute;ri<b>fiez</b>&nbsp;votre compte</p><div>Claim</div><div>your prize</div></body></html>";
    let raw = format!(
        "Subject: Hello\r\nContent-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n",
        STANDARD.encode(body)
    );
    let report = Runtime::new(Settings::default())
        .unwrap()
        .inspect(raw.as_bytes());
    assert_eq!(report.status, Status::Complete, "{report:?}");
    for id in ["fr.credentials", "en.prize"] {
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.id == id && f.scopes == [Scope::Body]),
            "{report:?}"
        );
    }
}

#[test]
fn hidden_html_comments_attributes_and_scripts_are_not_body_features() {
    let raw = html(
        r#"<html><head><title>SENSITIVE</title><style>SENSITIVE</style></head><body>
        <!-- SENSITIVE --><script>"SENSITIVE"</script><template><p>SENSITIVE</p></template>
        <div hidden>SENSITIVE</div><div hidden="false">SENSITIVE</div>
        <span style="DISPLAY : NONE !important"><b>SENSITIVE</b></span>
        <div style="visibility: hidden">SENSITIVE</div><div style="opacity:0.00">SENSITIVE</div>
        <noscript>SENSITIVE</noscript><svg><text>SENSITIVE</text></svg>
        <a href="https://example.test/SENSITIVE" title="SENSITIVE">A routine link</a>
        <img alt="SENSITIVE" src="SENSITIVE"><input value="SENSITIVE">
        Visible routine text</body></html>"#,
    );
    let report = Runtime::new(settings("SENSITIVE", &[Scope::Body]))
        .unwrap()
        .inspect(&raw);
    assert_eq!(report.status, Status::Complete);
    assert!(report.findings.is_empty(), "{report:?}");
}

#[test]
fn malformed_html_is_parsed_without_regex_tag_stripping() {
    let report = Runtime::new(settings("verify your account", &[Scope::Body])).unwrap()
        .inspect(&html("<div title='> misleading'><b>verify</b> your <em>account</div><!-- verify your account"));
    assert_eq!(report.status, Status::Complete);
    assert_eq!(report.findings[0].matches, 1);
}

#[test]
fn text_html_inline_named_and_nested_message_attachments_are_excluded() {
    let raw = multipart(&[
        "Content-Type: text/plain\r\n\r\nRoutine text",
        "Content-Type: text/plain\r\nContent-Disposition: attachment\r\n\r\nSENSITIVE",
        "Content-Type: text/html; name=notes.html\r\nContent-Disposition: inline\r\n\r\n<p>SENSITIVE</p>",
        "Content-Type: text/plain\r\nContent-Disposition: inline; filename*=utf-8''notes.txt\r\n\r\nSENSITIVE",
        "Content-Type: application/octet-stream\r\n\r\nSENSITIVE",
        "Content-Type: message/rfc822\r\n\r\nFrom: SENSITIVE <a@example.test>\r\nSubject: SENSITIVE\r\nContent-Type: text/plain\r\n\r\nSENSITIVE",
        "Content-Type: multipart/mixed; boundary=attached\r\nContent-Disposition: attachment\r\n\r\n--attached\r\nContent-Type: text/plain\r\n\r\nSENSITIVE\r\n--attached--",
    ]);
    let report = Runtime::new(settings(
        "SENSITIVE",
        &[Scope::Body, Scope::Subject, Scope::From],
    ))
    .unwrap()
    .inspect(&raw);
    assert_eq!(report.status, Status::Complete, "{report:?}");
    assert!(report.findings.is_empty(), "{report:?}");
    let top = b"Subject: Routine\r\nContent-Type: text/plain; name=file.txt\r\n\r\nSENSITIVE\r\n";
    assert!(
        Runtime::new(settings("SENSITIVE", &[Scope::Body]))
            .unwrap()
            .inspect(top)
            .findings
            .is_empty()
    );
}

#[test]
fn scopes_never_search_historical_headers_or_cross_field_boundaries() {
    let raw = b"From: SENDER <a@example.test>\r\nReply-To: REPLY <b@example.test>\r\nSubject: SUBJECT\r\nX-Spam-Status: SECRET\r\nX-Noisefence-Score: SECRET\r\nAuthentication-Results: SECRET\r\nReceived: SECRET\r\nTo: SECRET <secret@example.test>\r\n\r\nBODY\r\n";
    let mut config = settings(
        "SECRET",
        &[Scope::Subject, Scope::From, Scope::ReplyTo, Scope::Body],
    );
    config.rules.extend([
        rule("subject.only", "SUBJECT", &[Scope::Subject]),
        rule("from.only", "SENDER", &[Scope::From]),
        rule("reply.only", "REPLY", &[Scope::ReplyTo]),
        rule("body.only", "BODY", &[Scope::Body]),
        rule(
            "cross.fields",
            "(?s)SUBJECT.*BODY",
            &[Scope::Subject, Scope::Body],
        ),
        rule("wrong.scope", "SENDER|REPLY|SUBJECT", &[Scope::Body]),
    ]);
    let report = Runtime::new(config).unwrap().inspect(raw);
    assert_eq!(report.status, Status::Complete);
    assert_eq!(
        report
            .findings
            .iter()
            .map(|f| f.id.as_str())
            .collect::<Vec<_>>(),
        ["subject.only", "from.only", "reply.only", "body.only"]
    );
}

#[test]
fn individual_mailboxes_and_mime_parts_do_not_form_synthetic_matches() {
    let runtime = Runtime::new(settings("(?s)START.*END", &[Scope::From, Scope::Body])).unwrap();
    let raw = multipart(&[
        "Content-Type: text/plain\r\n\r\nSTART",
        "Content-Type: text/plain\r\n\r\nEND",
    ]);
    assert!(runtime.inspect(&raw).findings.is_empty());
    let raw = b"From: START <a@example.test>, END <b@example.test>\r\nSubject: Routine\r\n\r\nRoutine\r\n";
    assert!(runtime.inspect(raw).findings.is_empty());
}

#[test]
fn injected_decoded_controls_duplicates_and_bad_headers_are_invalid() {
    let runtime = Runtime::new(calibrated(settings("(?s).+", &[Scope::Subject]))).unwrap();
    for raw in [
        b"Subject: one\r\nsUbJeCt: two\r\n\r\nbody\r\n".as_slice(),
        b"Reply-To: a@b.test\r\nReply-To: c@d.test\r\n\r\nbody\r\n",
        b"Subject: =?UTF-8?Q?OK=0D=0AX-Injected:_secret?=\r\n\r\nbody\r\n",
        b"From: =?UTF-8?Q?OK=00secret?= <a@b.test>\r\n\r\nbody\r\n",
        b" orphan\r\n\r\nbody\r\n",
        b"Subject: hello\r\nmalformed\r\n\r\nbody\r\n",
        b"Subject: hello\r\n",
        b"Subject: hi\0\r\n\r\nbody\r\n",
        b"Subject: hi\rX-Forged: yes\r\n\r\nbody\r\n",
        b"",
    ] {
        let report = runtime.inspect(raw);
        assert_eq!(report.status, Status::InvalidMessage, "{raw:?}: {report:?}");
        assert!(report.findings.is_empty());
        assert_eq!(report.contribution, 0.0);
    }
}

#[test]
fn reports_do_not_retain_excerpts_addresses_patterns_or_injected_text() {
    let report = Runtime::new(settings(
        "(?s).+",
        &[Scope::Subject, Scope::From, Scope::ReplyTo, Scope::Body],
    ))
    .unwrap()
    .inspect(&raw("PRIVATE_SUBJECT", "<script>PRIVATE_TOKEN</script>"));
    assert!(!report.findings.is_empty());
    let serialized = serde_json::to_string(&report).unwrap();
    let debug = format!("{report:?}");
    for secret in [
        "PRIVATE_SUBJECT",
        "PRIVATE_TOKEN",
        "alice@example.test",
        "<script>",
        "(?s).+",
    ] {
        assert!(!serialized.contains(secret));
        assert!(!debug.contains(secret));
    }
    assert_eq!(report, serde_json::from_str::<Report>(&serialized).unwrap());
}

#[test]
fn all_limits_are_validated_and_invalid_patterns_do_not_echo_pattern_text() {
    let invalid_patterns = ["", "(", r"(?=secret)", r"(a)\1", "a{1000000000}", "a*"];
    for pattern in invalid_patterns {
        let config = settings(pattern, &[Scope::Body]);
        assert!(config.validate().is_err(), "{pattern}");
        assert!(Runtime::new(config).is_err());
    }
    let error = settings("PRIVATE_SECRET(?=)", &[Scope::Body])
        .validate()
        .unwrap_err()
        .to_string();
    assert!(!error.contains("PRIVATE_SECRET"));
    let base = settings("a", &[Scope::Body]);
    let mut value = serde_json::to_value(&base).unwrap();
    let names: Vec<String> = value["limits"]
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    for name in names {
        for bad in [0u64, 1_000_000_000] {
            value["limits"][&name] = bad.into();
            let invalid: Settings = serde_json::from_value(value.clone()).unwrap();
            assert!(invalid.validate().is_err(), "{name}: {bad}");
        }
        value["limits"][&name] = serde_json::to_value(&base).unwrap()["limits"][&name].clone();
    }
    let mut too_deep = base.clone();
    too_deep.rules[0].pattern = format!("{}a{}", "(".repeat(80), ")".repeat(80));
    assert!(too_deep.validate().is_err());
    let mut huge = base.clone();
    huge.rules[0].pattern = "x".repeat(4097);
    assert!(huge.validate().is_err());
    let mut aggregate = base.clone();
    aggregate.limits.max_total_pattern_bytes = 1;
    aggregate.rules[0].pattern = "ab".into();
    assert!(aggregate.validate().is_err());
    let mut count = base.clone();
    count.limits.max_rules = 1;
    count.rules.push(rule("test.two", "b", &[Scope::Body]));
    assert!(count.validate().is_err());
    let mut memory = base;
    memory.limits.regex_size_limit = 2 * 1024 * 1024;
    assert!(memory.validate().is_err());
}

#[test]
fn metadata_scopes_weights_and_unknown_settings_are_rejected() {
    let base = settings("a", &[Scope::Body]);
    for weight in [-1.0, 10.1, f64::NAN, f64::INFINITY] {
        let mut invalid = base.clone();
        invalid.rules[0].candidate_weight = weight;
        assert!(invalid.validate().is_err());
    }
    for scopes in [
        vec![],
        vec![Scope::Body, Scope::Body],
        vec![Scope::Body; 100],
    ] {
        let mut invalid = base.clone();
        invalid.rules[0].scopes = scopes;
        assert!(invalid.validate().is_err());
    }
    for (field, bad) in [
        ("id", "bad\r\nid"),
        ("family", "<img>"),
        ("label", "<script>alert(1)</script>"),
        ("label", "x\u{202e}y"),
        ("label", ""),
    ] {
        let mut value = serde_json::to_value(&base).unwrap();
        value["rules"][0][field] = bad.into();
        assert!(
            serde_json::from_value::<Settings>(value)
                .unwrap()
                .validate()
                .is_err()
        );
    }
    let mut duplicate = base.clone();
    duplicate.rules.push(duplicate.rules[0].clone());
    assert!(duplicate.validate().is_err());
    assert!(serde_json::from_str::<Settings>(r#"{"enable_rejection":true}"#).is_err());
    assert!(serde_json::from_str::<Settings>(r#"{"rules":[{"id":"a","label":"a","family":"a","pattern":"a","candidate_weight":1,"scopes":["headers"]}]}"#).is_err());
}

#[test]
fn resource_limits_are_explicit_and_never_apply_partial_weights() {
    let source = raw("hit", "hit");
    for (field, limit) in [
        ("max_raw_bytes", LimitHit::RawBytes),
        ("max_header_bytes", LimitHit::HeaderBytes),
        ("max_headers", LimitHit::Headers),
        ("max_part_bytes", LimitHit::PartBytes),
        ("max_input_bytes", LimitHit::InputBytes),
        ("max_segments", LimitHit::Segments),
    ] {
        let mut value =
            serde_json::to_value(settings("hit", &[Scope::Subject, Scope::Body])).unwrap();
        value["limits"][field] = 1.into();
        let config = calibrated(serde_json::from_value(value).unwrap());
        assert_limited(&Runtime::new(config).unwrap().inspect(&source), limit);
    }
    let mut config = settings("hit", &[Scope::Body]);
    config.limits.max_parts = 1;
    let data = multipart(&[
        "Content-Type: text/plain\r\n\r\nhit",
        "Content-Type: text/plain\r\n\r\nhit",
    ]);
    assert_limited(
        &Runtime::new(calibrated(config)).unwrap().inspect(&data),
        LimitHit::Parts,
    );
    let mut config = settings("hit", &[Scope::Body]);
    config.limits.max_html_nodes = 4;
    assert_limited(
        &Runtime::new(calibrated(config))
            .unwrap()
            .inspect(&html("<p>hit</p>")),
        LimitHit::HtmlNodes,
    );
}

#[test]
fn exact_budget_boundaries_are_complete_and_truncation_cannot_create_anchored_matches() {
    let data = b"Subject: hit\r\n\r\nhit";
    let mut config = settings("^hit$", &[Scope::Subject, Scope::Body]);
    config.limits.max_raw_bytes = data.len();
    config.limits.max_header_bytes = 16;
    config.limits.max_headers = 1;
    config.limits.max_input_bytes = 6;
    config.limits.max_part_bytes = 3;
    config.limits.max_segments = 2;
    config.limits.max_matches_per_rule = 2;
    config.limits.max_total_matches = 2;
    config.limits.max_findings = 1;
    let runtime = Runtime::new(calibrated(config)).unwrap();
    let exact = runtime.inspect(data);
    assert_eq!(exact.status, Status::Complete, "{exact:?}");
    assert_eq!(exact.findings[0].matches, 2);
    assert_eq!(exact.contribution, 0.75);
    let mut config = settings("^hit$", &[Scope::Body]);
    config.limits.max_part_bytes = 3;
    let report = Runtime::new(config)
        .unwrap()
        .inspect(b"Subject: x\r\n\r\nhitSuffix");
    assert_limited(&report, LimitHit::PartBytes);
    assert!(report.findings.is_empty());
}

#[test]
fn occurrence_global_and_finding_caps_bound_work_without_weight_multiplication() {
    let data = raw("", &"hit ".repeat(1000));
    let mut config = settings("hit", &[Scope::Body]);
    config.limits.max_matches_per_rule = 3;
    let report = Runtime::new(calibrated(config)).unwrap().inspect(&data);
    assert_limited(&report, LimitHit::MatchesPerRule);
    assert_eq!(report.findings[0].matches, 3);
    assert_eq!(report.candidate_weight, 1.5);
    let mut config = settings("hit", &[Scope::Body]);
    config.limits.max_total_matches = 2;
    let report = Runtime::new(calibrated(config)).unwrap().inspect(&data);
    assert_limited(&report, LimitHit::TotalMatches);
    assert_eq!(report.findings[0].matches, 2);
    let mut config = settings("hit", &[Scope::Body]);
    config.rules.push(rule("test.two", "hit", &[Scope::Body]));
    config.limits.max_findings = 1;
    let report = Runtime::new(calibrated(config))
        .unwrap()
        .inspect(&raw("", "hit"));
    assert_limited(&report, LimitHit::Findings);
    assert_eq!(report.findings.len(), 1);
}

#[test]
fn adversarial_nested_quantifiers_and_empty_matches_remain_bounded() {
    let mut config = settings(r"^(a+)+$", &[Scope::Body]);
    config.limits.max_input_bytes = 128 * 1024;
    let runtime = Runtime::new(config).unwrap();
    let data = raw("Routine", &format!("{}!", "a".repeat(60_000)));
    let started = std::time::Instant::now();
    for _ in 0..3 {
        let report = runtime.inspect(&data);
        assert_eq!(report.status, Status::Complete);
        assert!(report.findings.is_empty());
    }
    // Broad smoke bound, not a throughput claim; a backtracking implementation
    // cannot finish this fixture in any practical test timeout.
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
    let runtime = Runtime::new(calibrated(settings(r"\b", &[Scope::Body]))).unwrap();
    assert_limited(&runtime.inspect(&raw("", "hello")), LimitHit::EmptyMatch);
}

#[test]
fn malformed_mime_encoding_is_limited_without_decoding_raw_fallback() {
    let data = b"Subject: Routine\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n%%%INVALID%%%\r\n";
    let report = Runtime::new(calibrated(settings("INVALID", &[Scope::Body])))
        .unwrap()
        .inspect(data);
    assert_limited(&report, LimitHit::Encoding);
    assert!(report.findings.is_empty());
}

#[test]
fn observation_and_disabled_modes_never_apply_weights() {
    let observed = calibrated(settings("hit", &[Scope::Body]));
    for mode in [Mode::Observation, Mode::Disabled] {
        let mut config = observed.clone();
        config.mode = mode;
        let report = Runtime::new(config).unwrap().inspect(&raw("", "hit"));
        assert_eq!(report.contribution, 0.0);
        if mode == Mode::Disabled {
            assert_eq!(report.status, Status::Disabled);
            assert!(report.findings.is_empty());
        } else {
            assert_eq!(report.candidate_weight, 1.5);
        }
    }
    let config = Settings {
        mode: Mode::Disabled,
        ..Settings::default()
    };
    assert_eq!(
        Runtime::new(config).unwrap().inspect(b"malformed").status,
        Status::Disabled
    );
    let empty = Settings {
        rules: vec![],
        ..Settings::default()
    };
    assert!(
        Runtime::new(empty)
            .unwrap()
            .inspect(&raw("Claim your prize", ""))
            .findings
            .is_empty()
    );
}

#[test]
fn contribution_requires_exact_calibration_and_is_capped() {
    let base = settings("hit", &[Scope::Subject, Scope::Body]);
    let mut missing = base.clone();
    missing.mode = Mode::Contribute;
    assert!(missing.validate().is_err());
    let mut config = calibrated(base);
    config.rules.push(rule("test.two", "hit", &[Scope::Body]));
    assert!(config.validate().is_err());
    config.calibration.as_mut().unwrap().rules_digest = config.rules_digest().unwrap();
    let report = Runtime::new(config.clone())
        .unwrap()
        .inspect(&raw("hit", "hit hit"));
    assert_eq!(report.status, Status::Complete);
    assert_eq!(report.candidate_weight, 3.0);
    assert_eq!(report.contribution, 1.0);
    let mut changed = config.clone();
    changed.limits.max_input_bytes -= 1;
    assert!(changed.validate().is_err());
    for field in ["pattern_version", "rules_digest", "artifact_sha256"] {
        let mut value = serde_json::to_value(&config).unwrap();
        value["calibration"][field] = "wrong".into();
        assert!(
            serde_json::from_value::<Settings>(value)
                .unwrap()
                .validate()
                .is_err()
        );
    }
    for value in [-1.0, 2.0, f64::NAN, f64::INFINITY] {
        let mut changed = config.clone();
        changed.calibration.as_mut().unwrap().scale = value;
        assert!(changed.validate().is_err());
    }
    let mut cap = settings("hit", &[Scope::Body]);
    cap.max_candidate_weight = 0.5;
    assert_eq!(
        Runtime::new(calibrated(cap))
            .unwrap()
            .inspect(&raw("", "hit"))
            .contribution,
        0.25
    );
}

#[test]
fn version_and_digests_are_stable_across_round_trips_and_detect_semantic_changes() {
    let config = Settings::default();
    assert_eq!(VERSION, "heuristics-1");
    assert_eq!(PATTERN_VERSION, "heuristics-fr-en-1");
    let json = serde_json::to_string(&config).unwrap();
    let roundtrip: Settings = serde_json::from_str(&json).unwrap();
    let toml = toml::to_string(&config).unwrap();
    let from_toml: Settings = toml::from_str(&toml).unwrap();
    assert_eq!(
        config.settings_digest().unwrap(),
        roundtrip.settings_digest().unwrap()
    );
    assert_eq!(
        config.settings_digest().unwrap(),
        from_toml.settings_digest().unwrap()
    );
    assert_eq!(config.settings_digest().unwrap().len(), 64);
    // Golden digests also detect accidental built-in/normalization-contract drift.
    assert_eq!(
        config.rules_digest().unwrap(),
        "e52b7f8c6e1e1f13010185b886901f94aa8ae1b377eb48f93dbb4bc47b7252b5"
    );
    assert_eq!(
        config.settings_digest().unwrap(),
        "106d3e80342c48bc9aead0ff515df637bec6065a1fa347e2bc864388ea54c56e"
    );
    let mut changed = config.clone();
    changed.rules[0].pattern.push('x');
    assert_ne!(
        config.rules_digest().unwrap(),
        changed.rules_digest().unwrap()
    );
    changed = config.clone();
    changed.rules[0].candidate_weight += 0.25;
    assert_ne!(
        config.rules_digest().unwrap(),
        changed.rules_digest().unwrap()
    );
    changed = config.clone();
    changed.rules[0].scopes = vec![Scope::From];
    assert_ne!(
        config.rules_digest().unwrap(),
        changed.rules_digest().unwrap()
    );
    changed = config.clone();
    changed.rules.swap(0, 1);
    assert_ne!(
        config.rules_digest().unwrap(),
        changed.rules_digest().unwrap()
    );
    changed = calibrated(config.clone());
    assert_eq!(
        config.rules_digest().unwrap(),
        changed.rules_digest().unwrap()
    );
    assert_ne!(
        config.settings_digest().unwrap(),
        changed.settings_digest().unwrap()
    );
    let before = changed.settings_digest().unwrap();
    changed.calibration.as_mut().unwrap().scale = 0.25;
    assert_ne!(before, changed.settings_digest().unwrap());
}

#[test]
fn runtime_is_reusable_send_sync_and_deterministic() {
    fn thread_safe<T: Send + Sync>() {}
    thread_safe::<Runtime>();
    let runtime = std::sync::Arc::new(Runtime::new(Settings::default()).unwrap());
    let source = raw("Verify your account", "Your account is suspended");
    let before = runtime.inspect(&source);
    std::thread::scope(|scope| {
        let tasks: Vec<_> = (0..4)
            .map(|_| scope.spawn(|| runtime.inspect(&source)))
            .collect();
        for task in tasks {
            assert_eq!(before, task.join().unwrap());
        }
    });
    assert_eq!(
        source,
        raw("Verify your account", "Your account is suspended")
    );
}

#[test]
fn unicode_input_expansion_and_multibyte_limits_are_charged_without_slicing() {
    let body = "&nGt;".repeat(200);
    let data = format!("Subject: x\r\nContent-Type: text/html\r\n\r\n{body}");
    let mut config = settings("≫", &[Scope::Body]);
    config.limits.max_input_bytes = body.len() + 1;
    let report = Runtime::new(calibrated(config))
        .unwrap()
        .inspect(data.as_bytes());
    assert_limited(&report, LimitHit::InputBytes);
    assert!(report.findings.is_empty());
    let mut config = settings("é", &[Scope::Body]);
    config.limits.max_part_bytes = 1;
    let report = Runtime::new(config)
        .unwrap()
        .inspect(b"Subject: x\r\n\r\n\xc3\xa9");
    assert_limited(&report, LimitHit::PartBytes);
    assert!(report.findings.is_empty());
}

#[test]
fn compiled_program_budget_is_enforced_even_for_short_pattern_text() {
    let mut config = settings("(?:ab|cd){100}", &[Scope::Body]);
    config.limits.regex_size_limit = 64;
    assert!(config.validate().is_err());
    assert!(Runtime::new(config).is_err());
}

#[test]
fn candidate_and_contribution_caps_reject_nonfinite_and_out_of_range_settings() {
    for value in [-0.1, 100.1, f64::INFINITY, f64::NAN] {
        let mut config = settings("hit", &[Scope::Body]);
        config.max_candidate_weight = value;
        assert!(config.validate().is_err());
    }
    for value in [-0.1, 10.1, f64::INFINITY, f64::NAN] {
        let mut config = calibrated(settings("hit", &[Scope::Body]));
        config.calibration.as_mut().unwrap().max_contribution = value;
        assert!(config.validate().is_err());
    }
}

#[test]
fn configuration_example_is_executable_and_replaces_builtin_rules() {
    let document = include_str!("../docs/heuristics.md");
    let example = document
        .split("```toml\n")
        .nth(1)
        .unwrap()
        .split("```")
        .next()
        .unwrap();
    #[derive(serde::Deserialize)]
    struct Config {
        heuristics: Settings,
    }
    let config: Config = toml::from_str(example).unwrap();
    assert_eq!(config.heuristics.rules.len(), 2);
    let runtime = Runtime::new(config.heuristics).unwrap();
    let report = runtime.inspect(&raw("Vérifiez votre compte", "Claim your prize"));
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].id, "custom.fr.account");
    assert_eq!(report.contribution, 0.0);
}
