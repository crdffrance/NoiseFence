use noisefence::{
    confirmation,
    engine::{Scan, Signal},
    evidence::{
        Artifacts, AuthResult as A, DomainQuery, DomainRole, Evidence, Query, Source, State,
        eligibility::{self, AuthCheck, Exclusion},
    },
    message_context::{self, Context},
    observations::{self, ReputationResult, ResultValue},
    scoring,
};

fn scan(rule: &str) -> Scan {
    let c: noisefence::config::Config =
        toml::from_str(include_str!("../config/development.toml")).unwrap();
    let mut e = Evidence::new(&c, Artifacts::new(&c, None, None, false), false);
    e.source = Source::SmtpSession;
    e.authentication.state = State::Unavailable;
    e.reputation.state = State::Unavailable;
    if rule == "dmarc_fail" {
        e.authentication.dmarc_state = State::Complete;
        e.authentication.dmarc_spf = Some(A::Fail);
        e.authentication.dmarc_dkim = Some(A::Fail);
    } else if rule == "ip_reputation" {
        e.reputation.ip = Query {
            state: State::Complete,
            codes: vec!["127.0.0.2".parse().unwrap()],
        };
    }
    Scan {
        evidence: Some(e),
        reasons: vec![Signal {
            id: rule.into(),
            weight: if rule == "dmarc_fail" { 2. } else { 4. },
            detail: "software fixture".into(),
        }],
        ..Default::default()
    }
}
fn assert_eligible(s: &Scan, id: &str, allowed: bool) {
    let before = serde_json::to_value(s).unwrap();
    let score = scoring::combine(s, Some(-2.), false);
    assert_eq!(score.contributions[0].retained.unwrap() > 0., allowed);
    assert_eq!(confirmation::corroborated(s), allowed);
    let report = observations::capture(s);
    let o = report.observations.iter().find(|o| o.id == id).unwrap();
    assert_eq!(
        o.state == observations::State::Complete && o.exclusion.is_none(),
        allowed
    );
    assert_eq!(serde_json::to_value(s).unwrap(), before);
}
#[test]
fn score_confirmation_and_diagnostics_share_parent_and_context_eligibility() {
    for (rule, id) in [("dmarc_fail", "dmarc"), ("ip_reputation", "dqs.ip")] {
        for parent in [
            State::Complete,
            State::Limited,
            State::Unavailable,
            State::Disabled,
            State::NotRun,
            State::Busy,
            State::Skipped,
        ] {
            let mut s = scan(rule);
            let e = s.evidence.as_mut().unwrap();
            if rule == "dmarc_fail" {
                e.authentication.state = parent;
            } else {
                e.reputation.state = parent;
            }
            assert_eligible(
                &s,
                id,
                matches!(
                    parent,
                    State::Complete | State::Limited | State::Unavailable
                ),
            );
        }
        for invalid_schema in [false, true] {
            let mut s = scan(rule);
            let e = s.evidence.as_mut().unwrap();
            if invalid_schema {
                e.schema = "unsupported".into();
            } else {
                e.source = Source::ContentOnly;
            }
            assert_eligible(&s, id, false);
        }
    }
}
#[test]
fn mixed_dns_codes_and_unknown_versions_are_excluded_by_all_consumers() {
    let mut s = scan("ip_reputation");
    for code in ["127.255.255.254", "127.0.1.4", "192.0.2.2"] {
        s.evidence.as_mut().unwrap().reputation.ip.codes =
            vec!["127.0.0.2".parse().unwrap(), code.parse().unwrap()];
        assert_eligible(&s, "dqs.ip", false);
    }
    let mut s = scan("ip_reputation");
    s.evidence.as_mut().unwrap().reputation.version = "unknown".into();
    assert_eligible(&s, "dqs.ip", false);
}
#[test]
fn policy_and_negative_dns_answers_remain_observations_not_confirmation() {
    for codes in [vec![], vec!["127.0.0.10", "127.0.0.11", "127.0.0.30"]] {
        let mut s = scan("ip_reputation");
        s.evidence.as_mut().unwrap().reputation.ip.codes =
            codes.iter().map(|v| v.parse().unwrap()).collect();
        assert!(!confirmation::corroborated(&s));
        assert_eq!(
            scoring::combine(&s, None, false).contributions[0].retained,
            Some(0.)
        );
        let r = observations::capture(&s);
        let o = r.observations.iter().find(|o| o.id == "dqs.ip").unwrap();
        assert_eq!(o.state, observations::State::Complete);
        assert!(matches!(
            o.result,
            Some(ResultValue::Reputation(
                ReputationResult::NotListed | ReputationResult::Policy
            ))
        ));
    }
}
#[test]
fn domain_bound_is_identical_for_score_confirmation_and_diagnostics() {
    let mut s = scan("domain_reputation");
    let r = &mut s.evidence.as_mut().unwrap().reputation;
    r.domains = (0..13)
        .map(|i| DomainQuery {
            roles: vec![DomainRole::Body],
            result: Query {
                state: State::Complete,
                codes: if i == 12 {
                    vec!["127.0.1.4".parse().unwrap()]
                } else {
                    vec![]
                },
            },
        })
        .collect();
    assert!(!confirmation::corroborated(&s));
    assert_eq!(
        scoring::combine(&s, None, false).contributions[0].retained,
        Some(0.)
    );
    let report = observations::capture(&s);
    assert_eq!(report.omitted, 1);
    assert_eq!(
        report
            .observations
            .iter()
            .filter(|o| o.id.starts_with("dqs.domain."))
            .count(),
        12
    );
}
#[test]
fn authentication_passes_require_valid_context_but_arc_remains_independent() {
    let mut s = scan("dmarc_fail");
    s.message_context = Some(Context {
        transaction_notice: true,
        ..Default::default()
    });
    let a = &mut s.evidence.as_mut().unwrap().authentication;
    a.dmarc_spf = Some(A::Pass);
    a.dmarc_dkim = Some(A::None);
    assert!(eligibility::dmarc_pass(s.evidence.as_ref().unwrap()));
    assert!(message_context::needs_review(&s));
    s.evidence.as_mut().unwrap().authentication.state = State::Disabled;
    assert!(!eligibility::dmarc_pass(s.evidence.as_ref().unwrap()));
    assert!(!message_context::needs_review(&s));
    let a = &mut s.evidence.as_mut().unwrap().authentication;
    a.arc_state = State::Complete;
    a.arc = Some(A::Pass);
    a.arc_can_seal = Some(false);
    assert_eq!(
        eligibility::authentication(s.evidence.as_ref().unwrap(), AuthCheck::Arc),
        Ok(())
    );
    let r = observations::capture(&s);
    assert_eq!(
        r.observations.iter().find(|o| o.id == "arc").unwrap().state,
        observations::State::Complete
    );
    s.evidence.as_mut().unwrap().authentication.arc = Some(A::SoftFail);
    assert_eq!(
        eligibility::authentication(s.evidence.as_ref().unwrap(), AuthCheck::Arc),
        Err(Exclusion::InvalidResult)
    );
    s.evidence.as_mut().unwrap().authentication.state = State::Complete;
    s.evidence.as_mut().unwrap().authentication.dmarc_dkim = Some(A::TempError);
    assert!(!eligibility::dmarc_pass(s.evidence.as_ref().unwrap()));
    assert!(!message_context::needs_review(&s));
}
#[test]
fn content_confirmation_uses_retained_contributions_and_never_raw_conflicts() {
    let mut s = scan("injected_reward_lure");
    s.message_context = Some(Context {
        injected_reward_lure: true,
        ..Default::default()
    });
    assert!(!confirmation::corroborated(&s));
    s.scoring = Some(scoring::combine(&s, Some(-2.), false));
    assert!(confirmation::corroborated(&s));
    s.reasons.push(Signal {
        id: "injected_reward_lure".into(),
        weight: 0.,
        detail: "conflicting input".into(),
    });
    s.scoring = Some(scoring::combine(&s, Some(-2.), false));
    assert!(!confirmation::corroborated(&s));
    s.reasons.remove(0);
    s.scoring = Some(scoring::combine(&s, Some(-2.), false));
    assert!(!confirmation::corroborated(&s));
}

#[test]
fn authentication_bounds_and_decision_specific_strength_are_explicit() {
    let mut s = scan("dmarc_fail");
    let e = s.evidence.as_mut().unwrap();
    e.authentication.dkim_state = State::Complete;
    e.authentication.dkim = Some(vec![]);
    assert_eq!(eligibility::authentication(e, AuthCheck::Dkim), Ok(()));
    e.authentication.dkim = Some(vec![A::Fail; 17]);
    assert_eq!(
        eligibility::authentication(e, AuthCheck::Dkim),
        Err(Exclusion::InvalidResult)
    );
    e.authentication.dkim = Some(vec![A::TempError]);
    assert_eq!(
        eligibility::authentication(e, AuthCheck::Dkim),
        Err(Exclusion::TemporaryFailure)
    );
    e.authentication.spf_state = State::Complete;
    assert_eq!(
        eligibility::authentication(e, AuthCheck::Spf),
        Err(Exclusion::InvalidResult)
    );
    e.authentication.dmarc_dkim = None;
    assert_eq!(
        eligibility::authentication(e, AuthCheck::Dmarc),
        Err(Exclusion::InvalidResult)
    );
    e.authentication.dmarc_dkim = Some(A::SoftFail);
    assert_eq!(
        eligibility::authentication(e, AuthCheck::Dmarc),
        Err(Exclusion::InvalidResult)
    );
    // A completed failure branch can affect the index, while confirmation keeps
    // its stronger two-failed-branches policy. Eligibility is not a second vote.
    for branch in [A::None, A::PermError] {
        s.evidence.as_mut().unwrap().authentication.dmarc_dkim = Some(branch);
        assert_eq!(
            scoring::combine(&s, None, false).contributions[0].retained,
            Some(2.)
        );
        assert!(!confirmation::corroborated(&s));
        let r = observations::capture(&s);
        assert_eq!(
            r.observations
                .iter()
                .find(|o| o.id == "dmarc")
                .unwrap()
                .state,
            observations::State::Complete
        );
    }
}
