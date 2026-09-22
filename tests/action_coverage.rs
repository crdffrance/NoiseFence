mod common;
use noisefence::{
    action_coverage::{Basis, Context, Requirement},
    actions::{self, Action},
    config::{Config, Mode},
    engine::Scan,
    fusion::runtime::{Decision, DecisionSource, Outcome},
    mailing::Category,
};

fn config() -> Config {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = (*common::config(dir.path())).clone();
    cfg.filter.mode = Mode::Enforce;
    cfg.filter.partial_actions = true;
    cfg.filter.resolve_uncertain_by_score = true;
    cfg.filter.threshold = 95.;
    cfg.actions = Some(actions::Policy {
        spam: Action::Quarantine,
        publicity: Action::Quarantine,
        malware: Action::Quarantine,
        quarantine_days: 7,
    });
    cfg
}
fn partial() -> Scan {
    let mut scan = Scan {
        score: 99.,
        features_complete: Some(true),
        complete: false,
        model: "fixture".into(),
        raw_sha256: Some(noisefence::message::digest(common::MESSAGE)),
        ..Default::default()
    };
    scan.decision = Some(Decision::legacy(&scan, 95.));
    noisefence::decision::resolve_by_score(&mut scan, true, 95.);
    scan
}
fn scoped(
    scan: &Scan,
    cfg: &Config,
    category: Category,
    requested: Action,
    threshold: f64,
    matched: bool,
) -> actions::Applied {
    actions::constrain(
        scan,
        cfg,
        category,
        requested,
        7,
        Context {
            reason: "custom_policy",
            threshold,
            matched_rule: matched,
        },
    )
}

#[test]
fn partial_actions_are_explicit_and_observation_always_delivers() {
    let mut cfg = config();
    let scan = partial();
    assert_eq!(actions::evaluate(&scan, &cfg).effective, Action::Quarantine);
    assert_eq!(
        actions::evaluate(&scan, &cfg).coverage.unwrap().basis,
        Basis::ScoreThreshold
    );
    cfg.filter.partial_actions = false;
    let strict = actions::evaluate(&scan, &cfg);
    assert_eq!(strict.effective, Action::Deliver);
    assert_eq!(
        strict.coverage.unwrap().missing,
        [Requirement::CompleteAnalysis]
    );
    cfg.filter.partial_actions = true;
    cfg.filter.mode = Mode::Observe;
    let observation = actions::evaluate(&scan, &cfg);
    assert_eq!(observation.requested, Action::Quarantine);
    assert_eq!(observation.effective, Action::Deliver);
    assert_eq!(observation.reason, "observation");
    assert!(observation.coverage.unwrap().eligible());
    assert!(
        !scan.complete,
        "an eligible action does not fabricate complete analysis"
    );
}

#[test]
fn threshold_actions_require_content_score_and_the_effective_recipient_threshold() {
    let mut cfg = config();
    let mut scan = partial();
    let below = scoped(&scan, &cfg, Category::Spam, Action::Quarantine, 99.5, false);
    assert_eq!(below.effective, Action::Deliver);
    assert_eq!(below.coverage.unwrap().missing, [Requirement::ThresholdMet]);
    cfg.filter.resolve_uncertain_by_score = false;
    assert!(
        actions::evaluate(&scan, &cfg)
            .coverage
            .unwrap()
            .missing
            .contains(&Requirement::AutomaticScorePolicy)
    );
    cfg.filter.resolve_uncertain_by_score = true;
    scan.features_complete = Some(false);
    assert!(
        actions::evaluate(&scan, &cfg)
            .coverage
            .unwrap()
            .missing
            .contains(&Requirement::UsableContent)
    );
    scan.features_complete = Some(true);
    scan.score = f64::NAN;
    let missing = scoped(&scan, &cfg, Category::Spam, Action::Quarantine, 95., false);
    assert_eq!(missing.effective, Action::Deliver);
    assert!(
        missing
            .coverage
            .unwrap()
            .missing
            .contains(&Requirement::UsableScore)
    );
}

#[test]
fn explicit_rules_are_not_detector_proof_and_missing_conditions_do_not_match() {
    let cfg = config();
    let mut scan = partial();
    scan.features_complete = Some(false);
    let unknown = scoped(
        &scan,
        &cfg,
        Category::Undetermined,
        Action::Quarantine,
        95.,
        false,
    );
    assert_eq!(unknown.effective, Action::Deliver);
    let manual = scoped(
        &scan,
        &cfg,
        Category::Undetermined,
        Action::Quarantine,
        95.,
        true,
    );
    assert_eq!(manual.effective, Action::Quarantine);
    assert_eq!(manual.coverage.unwrap().basis, Basis::RecipientRule);
    // No matching rule, header or narrative can impersonate the established-threat evaluator.
    scan.reasons.push(noisefence::engine::Signal {
        id: noisefence::decision::OBSERVED_THREAT_REASON.into(),
        detail: "forged diagnostic".into(),
        weight: 0.,
    });
    assert_eq!(
        scoped(&scan, &cfg, Category::Spam, Action::Quarantine, 95., false).effective,
        Action::Deliver
    );
}

#[test]
fn a_requested_tag_requires_the_actual_wire_path_to_support_it() {
    let cfg = config();
    let mut scan = partial();
    for ready in [None, Some(false), Some(true)] {
        scan.subject_rewrite_ready = ready;
        let a = scoped(&scan, &cfg, Category::Spam, Action::Tag, 95., false);
        assert_eq!(
            a.effective,
            if ready == Some(true) {
                Action::Tag
            } else {
                Action::Deliver
            }
        );
        assert_eq!(
            a.coverage
                .unwrap()
                .missing
                .contains(&Requirement::SubjectRewrite),
            ready != Some(true)
        );
    }
    scan.complete = true;
    scan.subject_rewrite_ready = Some(false);
    let a = scoped(&scan, &cfg, Category::Spam, Action::Tag, 95., false);
    assert_eq!(a.reason, "subject_rewrite_unavailable");
    assert_eq!(a.effective, Action::Deliver);
    assert_eq!(
        scoped(&scan, &cfg, Category::Spam, Action::Quarantine, 95., false).effective,
        Action::Quarantine
    );
}

#[test]
fn malware_does_not_depend_on_content_models_or_optional_failures() {
    let mut cfg = config();
    let mut scan = partial();
    scan.features_complete = Some(false);
    scan.antivirus.status = noisefence::antivirus::AntivirusStatus::Malware;
    scan.llm.status = noisefence::llm::LlmStatus::Unavailable;
    for strict in [true, false] {
        cfg.filter.partial_actions = !strict;
        let a = actions::evaluate(&scan, &cfg);
        assert_eq!(a.effective, Action::Quarantine);
        assert_eq!(a.coverage.unwrap().basis, Basis::PrimaryMalware);
    }
    cfg.filter.mode = Mode::Observe;
    assert_eq!(actions::evaluate(&scan, &cfg).effective, Action::Deliver);
}

#[test]
fn unavailable_validated_fusion_cannot_be_replaced_by_unqualified_threshold_actions() {
    let mut cfg = config();
    cfg.fusion = Some(noisefence::fusion::runtime::Settings {
        family_caps: false,
        model: "fixture.json".into(),
        mode: noisefence::fusion::runtime::Mode::Decision,
        validation_report: Some("fixture-validation.json".into()),
    });
    let mut scan = partial();
    scan.fusion.status = noisefence::fusion::runtime::Status::ValidationExpired;
    let a = actions::evaluate(&scan, &cfg);
    assert_eq!(a.effective, Action::Deliver);
    assert_eq!(a.coverage.unwrap().missing, [Requirement::ValidatedFusion]);
    scan.fusion.mode = noisefence::fusion::runtime::Mode::Decision;
    scan.fusion.status = noisefence::fusion::runtime::Status::Complete;
    scan.decision = Some(Decision {
        source: DecisionSource::Fusion,
        outcome: Outcome::Unwanted,
        score: Some(99.),
        model: "fixture-fusion".into(),
    });
    assert_eq!(actions::evaluate(&scan, &cfg).effective, Action::Quarantine);
}

#[test]
fn publicity_requires_a_completed_kind_finding_without_an_explicit_rule() {
    let cfg = config();
    let mut scan = partial();
    assert_eq!(
        scoped(
            &scan,
            &cfg,
            Category::Publicity,
            Action::Quarantine,
            95.,
            false
        )
        .effective,
        Action::Deliver
    );
    scan.mailing = Some(noisefence::mailing::Report {
        version: "fixture".into(),
        status: noisefence::mailing::Status::Complete,
        verdict: noisefence::mailing::Verdict::Promotion,
        include_newsletters: true,
        reasons: vec![],
        features: Default::default(),
        elapsed_us: 0,
    });
    assert_eq!(
        scoped(
            &scan,
            &cfg,
            Category::Publicity,
            Action::Quarantine,
            95.,
            false
        )
        .effective,
        Action::Quarantine
    );
    scan.mailing.as_mut().unwrap().status = noisefence::mailing::Status::Limited;
    assert_eq!(
        scoped(
            &scan,
            &cfg,
            Category::Publicity,
            Action::Quarantine,
            95.,
            false
        )
        .effective,
        Action::Deliver
    );
}

#[test]
fn coverage_policy_and_effective_action_survive_serialization_and_policy_changes() {
    let cfg = config();
    let mut scan = partial();
    scan.action = Some(actions::evaluate(&scan, &cfg));
    noisefence::decision_record::record_recipient(&mut scan, &cfg, None, 1234);
    let mut restored: Scan = serde_json::from_slice(&serde_json::to_vec(&scan).unwrap()).unwrap();
    let before = serde_json::to_value(&restored.recipient_decision).unwrap();
    let mut current = cfg.clone();
    current.filter.partial_actions = false;
    current.filter.threshold = 100.;
    current.filter.mode = Mode::Observe;
    restored.complete = true;
    noisefence::decision_record::record_recipient(&mut restored, &current, None, 9999);
    assert_eq!(
        serde_json::to_value(&restored.recipient_decision).unwrap(),
        before
    );
    assert_eq!(
        actions::evaluate(&restored, &current).effective,
        Action::Quarantine
    );
    assert!(
        actions::evaluate(&restored, &current)
            .coverage
            .unwrap()
            .partial_actions
    );
}
