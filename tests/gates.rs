mod common;
use noisefence::config::{CompatibilityCase, CompatibilityReport, Mode, PROTON_CASES};
#[test]
fn tagging_requires_matching_recent_evidence() {
    let root = tempfile::tempdir().unwrap();
    let mut cfg = (*common::config(root.path())).clone();
    cfg.filter.mode = Mode::Tag;
    assert!(cfg.validate().is_err());
    cfg.filter.authentication = true;
    cfg.filter.arc_key = Some(root.path().join("key.pem"));
    cfg.filter.arc_domain = Some("example.test".into());
    cfg.filter.arc_selector = Some("test".into());
    let path = root.path().join("report.json");
    cfg.filter.proton_report = Some(path.clone());
    let mut report = CompatibilityReport {
        hostname: cfg.hostname.clone(),
        domains: vec!["example.test".into()],
        tested_at: noisefence::now(),
        prefix: "[SPAM]".into(),
        cases: PROTON_CASES
            .iter()
            .map(|s| {
                (
                    s.to_string(),
                    CompatibilityCase {
                        passed: true,
                        evidence: "Synthetic evidence for a unit test only".into(),
                    },
                )
            })
            .collect(),
        bypass_limit_accepted: true,
    };
    std::fs::write(&path, serde_json::to_vec(&report).unwrap()).unwrap();
    assert!(cfg.validate().is_ok());
    report.cases.get_mut("dmarc_reject").unwrap().passed = false;
    std::fs::write(&path, serde_json::to_vec(&report).unwrap()).unwrap();
    assert!(cfg.validate().is_err());
    report.cases.get_mut("dmarc_reject").unwrap().passed = true;
    report.tested_at = 0;
    std::fs::write(&path, serde_json::to_vec(&report).unwrap()).unwrap();
    assert!(cfg.validate().is_err());
}
#[test]
fn bounded_malformed_message_smoke() {
    let base = common::MESSAGE;
    let mut state = 0xdecafbad_u64;
    for _ in 0..5000 {
        let mut mutated = base.to_vec();
        for _ in 0..4 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let index = (state as usize) % mutated.len();
            mutated[index] = (state >> 32) as u8;
        }
        let _ = noisefence::message::validate(&mutated);
        let _ = noisefence::message::rewrite(&mutated, true, "");
        let scan = noisefence::engine::extract(&mutated, 2048);
        assert!(
            scan.features
                .iter()
                .all(|(i, x)| *i < noisefence::engine::FEATURE_COUNT && x.is_finite())
        );
    }
}

#[test]
fn quoted_reverse_paths_and_postmaster_do_not_introduce_command_injection() {
    use noisefence::smtp::parse_path;
    assert_eq!(
        parse_path(
            "FROM:<\"name> with space\"@example.org> SIZE=200",
            "FROM:",
            true
        )
        .unwrap(),
        ("\"name> with space\"@example.org", "SIZE=200")
    );
    assert!(parse_path("FROM:<\"name\\\" test\"@example.org>", "FROM:", true).is_ok());
    assert_eq!(
        parse_path("TO:<Postmaster>", "TO:", false).unwrap().0,
        "Postmaster"
    );
    for value in [
        "FROM:<a@example.org>\r\nRCPT TO:<b@elsewhere.test>",
        "FROM:<\"unterminated@example.org>",
        "FROM:<\"a\r\nb\"@example.org>",
        "FROM:<a..b@example.org>",
    ] {
        assert!(parse_path(value, "FROM:", true).is_err());
    }
}

#[test]
fn pub_tag_needs_its_own_proton_evidence_and_can_be_disabled_independently() {
    let root = tempfile::tempdir().unwrap();
    let mut cfg = (*common::config(root.path())).clone();
    cfg.filter.mode = Mode::Tag;
    cfg.filter.authentication = true;
    cfg.filter.arc_key = Some(root.path().join("key.pem"));
    cfg.filter.arc_domain = Some("example.test".into());
    cfg.filter.arc_selector = Some("test".into());
    let spam = root.path().join("spam.json");
    let publicity = root.path().join("pub.json");
    let mut report = CompatibilityReport {
        hostname: cfg.hostname.clone(),
        domains: vec!["example.test".into()],
        tested_at: noisefence::now(),
        prefix: "[SPAM]".into(),
        cases: PROTON_CASES
            .iter()
            .map(|s| {
                (
                    s.to_string(),
                    CompatibilityCase {
                        passed: true,
                        evidence: "SYNTHETIC SOFTWARE TEST ONLY; NOT LIVE PROTON EVIDENCE".into(),
                    },
                )
            })
            .collect(),
        bypass_limit_accepted: true,
    };
    std::fs::write(&spam, serde_json::to_vec(&report).unwrap()).unwrap();
    cfg.filter.proton_report = Some(spam.clone());
    assert!(cfg.validate().is_ok());
    cfg.mailing = Some(noisefence::mailing::Settings::default());
    assert!(cfg.validate().is_err());
    cfg.mailing.as_mut().unwrap().proton_report = Some(spam);
    assert!(cfg.validate().is_err());
    report.prefix = "[PUB]".into();
    std::fs::write(&publicity, serde_json::to_vec(&report).unwrap()).unwrap();
    cfg.mailing.as_mut().unwrap().proton_report = Some(publicity.clone());
    assert!(cfg.validate().is_ok());
    report.tested_at = 0;
    std::fs::write(&publicity, serde_json::to_vec(&report).unwrap()).unwrap();
    assert!(cfg.validate().is_err());
    cfg.mailing.as_mut().unwrap().policy.tag_subject = false;
    assert!(cfg.validate().is_ok());
}
