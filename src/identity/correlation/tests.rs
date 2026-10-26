use super::*;
use crate::{
    config::Config,
    evidence::{AuthResult, Evidence},
    identity::learning,
};

pub(crate) fn scan() -> Scan {
    let config = Config::load(std::path::Path::new("config/development.toml")).unwrap();
    let mut evidence = Evidence::new(
        &config,
        crate::evidence::Artifacts::new(&config, None, None, false),
        false,
    );
    evidence.source = Source::SmtpSession;
    evidence.authentication.dmarc_state = State::Complete;
    evidence.authentication.dmarc_dkim = Some(AuthResult::Pass);
    evidence.authentication.dmarc_spf = Some(AuthResult::Pass);
    let mut native = crate::native_filter::Runtime::new(Default::default())
        .unwrap()
        .offline(
            b"From: sender@example.org\r\nSubject: hello\r\n\r\nHello",
            &[],
        );
    native
        .local_symbols
        .push(crate::native_filter::rules::Symbol {
            id: "NF_CREDENTIALS".into(),
            label: "Credential request".into(),
            family: crate::native_filter::rules::Family::Content,
            weight: 1.,
            absorbed_by: vec![],
        });
    Scan {
        evidence: Some(evidence),
        features_complete: Some(true),
        native_filter: Some(native),
        contact_learning: Some(learning::Observation {
            sample: None,
            report: learning::Report {
                status: "regular".into(),
                observation_only: true,
                regular: true,
                campaigns: 6,
                observed_days: 4,
                minimum_campaigns: 5,
                minimum_days: 3,
                retention_days: 30,
                changes: vec!["reply_destination".into()],
                ..Default::default()
            },
        }),
        ..Default::default()
    }
}
fn scoring() -> Settings {
    Settings {
        mode: Mode::Contribute,
        ..Default::default()
    }
}
#[test]
fn observation_never_changes_score_and_recurring_address_is_not_safe() {
    let s = scan();
    let r = inspect(&Settings::default(), &s);
    assert!(r.corroborated && r.recurrence_available);
    assert_eq!(r.proposed_weight, 1.);
    assert_eq!(r.applied_weight, 0.);
    assert_eq!(inspect(&scoring(), &s).applied_weight, 1.);
    let visible = serde_json::to_string(&r).unwrap();
    assert!(!visible.contains("@") && !visible.contains("sample"));
}
#[test]
fn new_contacts_unavailable_checks_and_human_veto_never_supply_weight() {
    let mutations: &[fn(&mut Scan)] = &[
        |s| s.contact_learning = None,
        |s| s.contact_learning.as_mut().unwrap().report.regular = false,
        |s| {
            s.contact_learning
                .as_mut()
                .unwrap()
                .report
                .blocked_by_feedback = true
        },
        |s| s.contact_learning.as_mut().unwrap().report.status = "limited".into(),
        |s| s.contact_learning.as_mut().unwrap().report.campaigns = 4,
        |s| s.contact_learning.as_mut().unwrap().report.observed_days = 2,
        |s| s.contact_learning.as_mut().unwrap().report.changes.clear(),
        |s| s.native_filter.as_mut().unwrap().local_symbols.clear(),
        |s| s.native_filter.as_mut().unwrap().report.status = crate::native_filter::Status::Limited,
        |s| s.features_complete = Some(false),
        |s| s.evidence.as_mut().unwrap().source = Source::SuppliedEnvelope,
        |s| s.evidence.as_mut().unwrap().authentication.dmarc_state = State::Unavailable,
        |s| {
            let a = &mut s.evidence.as_mut().unwrap().authentication;
            a.dmarc_dkim = Some(AuthResult::TempError);
            a.dmarc_spf = Some(AuthResult::None);
        },
    ];
    for (i, mutate) in mutations.iter().enumerate() {
        let mut s = scan();
        mutate(&mut s);
        assert_eq!(inspect(&scoring(), &s).applied_weight, 0., "case {i}");
    }
}
#[test]
fn name_link_request_novelty_are_not_independent_votes() {
    let mut s = scan();
    s.contact_learning.as_mut().unwrap().report.changes = vec![
        "display_name".into(),
        "link_domain".into(),
        "sensitive_request".into(),
    ];
    s.contact_learning
        .as_mut()
        .unwrap()
        .report
        .content_comparison_available = true;
    let r = inspect(&scoring(), &s);
    assert_eq!(r.signals.len(), 4);
    assert!(!r.corroborated);
    assert_eq!(r.applied_weight, 0.);
}
#[test]
fn structured_weight_is_bounded_rebuilt_and_idempotently_deduplicated() {
    let mut s = scan();
    s.identity_correlation = Some(inspect(&scoring(), &s));
    for (id, weight) in [(RULE, 99.), ("reply_to", 0.5), ("credential_request", 1.5)] {
        s.reasons.push(crate::engine::Signal {
            id: id.into(),
            detail: "fixture".into(),
            weight,
        });
    }
    let r = crate::scoring::combine(&s, None, false);
    assert_eq!(r.rules_total, Some(2.5));
    assert_eq!(
        r.contributions
            .iter()
            .find(|c| c.id == "reply_to")
            .unwrap()
            .subsumed_by
            .as_deref(),
        Some(RULE)
    );
    s.scoring = Some(r.clone());
    s.reasons.push(s.reasons[0].clone());
    let repeated = crate::scoring::combine(&s, None, false);
    assert_eq!(r.score, repeated.score);
    s.reasons
        .iter_mut()
        .filter(|r| r.id == "reply_to")
        .for_each(|r| r.weight = 2.);
    assert_eq!(
        crate::scoring::combine(&s, None, false).rules_total,
        Some(3.5)
    );
    s.contact_learning = None;
    assert_eq!(weight(&s), Some(0.));
    s.identity_correlation.as_mut().unwrap().applied_weight = f64::NAN;
    assert_eq!(weight(&s), None);
}
#[test]
fn policy_rejects_negative_excessive_and_nonfinite_weights() {
    for w in [-1., 1.1, f64::NAN, f64::INFINITY] {
        assert!(
            Settings {
                maximum_weight: w,
                ..scoring()
            }
            .validate()
            .is_err()
        );
    }
    assert!(
        Settings {
            maximum_weight: 0.,
            ..scoring()
        }
        .validate()
        .is_ok()
    );
}

#[test]
fn directory_claim_requires_fresh_unambiguous_context_demand_and_failed_alignment() {
    use crate::identity::{directory, runtime};
    const NOW: i64 = 1_800_000_010;
    let source: directory::Snapshot = serde_json::from_str(include_str!(
        "../../../tests/fixtures/identity/directory.json"
    ))
    .unwrap();
    let loaded = runtime::Loaded {
        sha256: "a".repeat(64),
        catalog: directory::Catalog::new(vec![source], NOW).unwrap(),
    };
    let raw =
        b"From: Alice Finance <impostor@elsewhere.test>\r\nSubject: Please pay\r\n\r\nSend payment";
    let mut s = scan();
    s.contact_learning = None;
    let auth = &mut s.evidence.as_mut().unwrap().authentication;
    auth.dmarc_dkim = Some(AuthResult::Fail);
    auth.dmarc_spf = Some(AuthResult::Fail);
    s.identity = Some(loaded.inspect_message(raw, "bob@example.test", &s, NOW));
    assert!(s.identity.as_ref().unwrap().sensitive_requests_available);
    assert_eq!(inspect(&scoring(), &s).applied_weight, 1.);
    for status in ["stale", "limited", "unavailable", "not_configured"] {
        let mut changed = s.clone();
        changed.identity.as_mut().unwrap().observation.status = status.into();
        assert_eq!(inspect(&scoring(), &changed).applied_weight, 0.);
    }
    let mut ambiguous = s.clone();
    ambiguous
        .identity
        .as_mut()
        .unwrap()
        .observation
        .ambiguous_identity = true;
    assert_eq!(inspect(&scoring(), &ambiguous).applied_weight, 0.);
    // Legitimate forwarding/auth failures without a novel identity claim cannot
    // add the same authentication weight again.
    s.identity.as_mut().unwrap().observation.signals.clear();
    assert_eq!(inspect(&scoring(), &s).applied_weight, 0.);
}

#[test]
fn receipt_binds_observation_policy_even_when_index_and_verdict_are_unchanged() {
    let config = Config::load(std::path::Path::new("config/development.toml")).unwrap();
    let mut first = scan();
    first.complete = true;
    first.score = 30.;
    first.identity_correlation = Some(inspect(&Settings::default(), &first));
    crate::decision_record::record_recipient(&mut first, &config, None, 1_800_000_000);
    let mut second = first.clone();
    second.recipient_decision = None;
    second.identity_correlation = Some(inspect(
        &Settings {
            maximum_weight: 0.25,
            ..Default::default()
        },
        &second,
    ));
    crate::decision_record::record_recipient(&mut second, &config, None, 1_800_000_000);
    assert_eq!(first.score, second.score);
    assert_ne!(
        first.recipient_decision.as_ref().unwrap().policy_sha256,
        second.recipient_decision.as_ref().unwrap().policy_sha256
    );
}
