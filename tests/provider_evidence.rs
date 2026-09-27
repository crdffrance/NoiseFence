use noisefence::protection::{
    Provider, ProviderObservation, ProviderReport, Status,
    evidence::{self, Exclusion},
};

fn target(scope: &str, verdict: &str) -> ProviderObservation {
    ProviderObservation {
        indicator_sha256: "a".repeat(64),
        scope: scope.into(),
        verdict: verdict.into(),
        queried_at: 1234,
        cached: true,
        cache_max_age_seconds: 1800,
        analysis_max_age_seconds: None,
    }
}
fn report(scope: &str, verdict: &str) -> ProviderReport {
    ProviderReport {
        status: Status::Complete,
        captured_at: Some(1234),
        checked: 1,
        observations: vec![target(scope, verdict)],
        ..Default::default()
    }
}
#[test]
fn eligibility_uses_frozen_time_and_preserves_independently_completed_targets() {
    for status in [
        Status::Complete,
        Status::Limited,
        Status::Unavailable,
        Status::Quota,
        Status::Busy,
    ] {
        let mut p = report("host_lookup", "malicious");
        p.status = status;
        let before = serde_json::to_value(&p).unwrap();
        assert!(evidence::evaluate(Provider::Crdf, &p).targets[0].malicious());
        let restored = serde_json::from_value(before.clone()).unwrap();
        assert!(evidence::evaluate(Provider::Crdf, &restored).targets[0].malicious());
        assert_eq!(serde_json::to_value(p).unwrap(), before);
    }
    for status in [
        Status::Disabled,
        Status::NotConfigured,
        Status::NotRun,
        Status::Unknown,
    ] {
        let mut p = report("host_lookup", "malicious");
        p.status = status;
        assert_eq!(
            evidence::evaluate(Provider::Crdf, &p).targets[0].exclusion,
            Some(Exclusion::UnavailableProvider)
        );
    }
}
#[test]
fn malformed_missing_and_stale_targets_cannot_be_used() {
    type Case = (fn(&mut ProviderReport), Exclusion);
    let cases: &[Case] = &[
        (|p| p.status = Status::Stale, Exclusion::StaleResult),
        (|p| p.captured_at = None, Exclusion::MissingCaptureTime),
        (|p| p.captured_at = Some(0), Exclusion::MissingCaptureTime),
        (
            |p| p.observations[0].queried_at = 0,
            Exclusion::InvalidObservationTime,
        ),
        (
            |p| p.observations[0].queried_at = 933,
            Exclusion::InvalidObservationTime,
        ),
        (
            |p| p.observations[0].queried_at = 1295,
            Exclusion::InvalidObservationTime,
        ),
        (
            |p| p.observations[0].verdict = "stale".into(),
            Exclusion::StaleResult,
        ),
        (
            |p| p.observations[0].verdict = "clean".into(),
            Exclusion::InvalidResult,
        ),
        (
            |p| p.observations[0].scope = "file".into(),
            Exclusion::InvalidTarget,
        ),
        (
            |p| p.observations[0].indicator_sha256 = "invalid".into(),
            Exclusion::InvalidTarget,
        ),
    ];
    for (mutate, expected) in cases {
        let mut p = report("host_lookup", "malicious");
        mutate(&mut p);
        let e = evidence::evaluate(Provider::Crdf, &p);
        assert_eq!(e.targets[0].exclusion, Some(*expected));
        assert!(matches!(e.status, Status::Limited | Status::Stale));
        assert!(!e.targets[0].malicious());
    }
    for at in [934, 1294] {
        let mut p = report("host_lookup", "no_hit");
        p.observations[0].queried_at = at;
        let e = evidence::evaluate(Provider::Crdf, &p);
        assert!(e.targets[0].usable());
        assert!(!e.targets[0].malicious());
    }
}
#[test]
fn overlap_requires_distinct_providers_and_the_same_target_kind() {
    let mut a = report("host_lookup", "malicious");
    a.observations.push(a.observations[0].clone());
    let mut b = report("file", "malicious");
    let ea = evidence::evaluate(Provider::Crdf, &a);
    assert_eq!(ea.targets.iter().filter(|t| t.malicious()).count(), 1);
    assert_eq!(ea.targets[1].exclusion, Some(Exclusion::DuplicateTarget));
    assert_eq!(
        evidence::shared_malicious_targets(&ea, &evidence::evaluate(Provider::Virustotal, &b)),
        0
    );
    b.observations[0].scope = "domain".into();
    b.observations.push(b.observations[0].clone());
    assert_eq!(
        evidence::shared_malicious_targets(&ea, &evidence::evaluate(Provider::Virustotal, &b)),
        1
    );
    b.observations[0].indicator_sha256 = "b".repeat(64);
    assert_eq!(
        evidence::shared_malicious_targets(&ea, &evidence::evaluate(Provider::Virustotal, &b)),
        1
    );
}
#[test]
fn conflicts_are_order_independent_and_bounds_are_explicit() {
    let mut p = report("host_lookup", "malicious");
    p.observations.push(target("host_lookup", "no_hit"));
    for _ in 0..2 {
        let e = evidence::evaluate(Provider::Crdf, &p);
        assert!(
            e.targets
                .iter()
                .all(|t| t.exclusion == Some(Exclusion::ConflictingTarget))
        );
        assert_eq!(e.status, Status::Limited);
        p.observations.reverse();
    }
    p.observations = (0..1000)
        .map(|_| target("host_lookup", "malicious"))
        .collect();
    let e = evidence::evaluate(Provider::Crdf, &p);
    assert_eq!(e.targets.len(), evidence::MAX_TARGETS);
    assert_eq!(e.omitted, 1000 - evidence::MAX_TARGETS);
    assert_eq!(e.targets.iter().filter(|t| t.malicious()).count(), 1);
    assert_eq!(e.status, Status::Limited);
}
#[test]
fn training_protocol_binds_the_provider_evidence_contract() {
    let protocol: serde_json::Value =
        serde_json::from_str(include_str!("../research/quality-protocol.json")).unwrap();
    assert_eq!(protocol["provider_evidence_contract"], evidence::VERSION);
}
