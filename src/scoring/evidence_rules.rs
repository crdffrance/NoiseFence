//! Fixed dependencies between structured detector results and their legacy rule
//! contributions. No provider requests, prose parsing or historical rescoring.
use super::{Adjustment, Contribution};
use crate::{
    engine::Scan,
    evidence::{self, AuthResult as A, Dataset, Source, State},
    smtp_policy::{self, PolicyStatus},
};

enum Weight {
    Unmanaged,
    Unavailable,
    Observed(f64),
}

fn transport(scan: &Scan) -> Option<&evidence::Evidence> {
    scan.evidence
        .as_ref()
        .filter(|e| e.schema == evidence::SCHEMA && e.source != Source::ContentOnly)
}

fn weight(scan: &Scan, id: &str) -> Weight {
    if !matches!(
        id,
        "spf_fail"
            | "dmarc_fail"
            | "ip_reputation"
            | "domain_reputation"
            | "smtp_policy_contribution"
    ) {
        return Weight::Unmanaged;
    }
    let Some(e) = transport(scan) else {
        return Weight::Unavailable;
    };
    let a = &e.authentication;
    if matches!(id, "spf_fail" | "dmarc_fail")
        && !matches!(
            a.state,
            State::Complete | State::Limited | State::Unavailable
        )
    {
        return Weight::Unavailable;
    }
    let result = match id {
        "spf_fail" => (a.spf_state == State::Complete && a.spf == Some(A::Fail)).then_some(1.),
        "dmarc_fail" => {
            // Both alignment branches must be recorded, with no successful or
            // temporarily failed branch. A signature-only or missing result is
            // not a completed DMARC failure.
            let failed = [a.dmarc_spf, a.dmarc_dkim];
            (a.dmarc_state == State::Complete
                && failed
                    .iter()
                    .all(|v| matches!(v, Some(A::Fail | A::None | A::PermError)))
                && failed.contains(&Some(A::Fail)))
            .then_some(2.)
        }
        "ip_reputation" | "domain_reputation" => {
            let r = &e.reputation;
            if r.version != evidence::REPUTATION_VERSION
                || !matches!(
                    r.state,
                    State::Complete | State::Limited | State::Unavailable
                )
            {
                return Weight::Unavailable;
            }
            let observed = |q: &evidence::Query, dataset| {
                q.state == State::Complete
                    && evidence::dqs_codes(&q.codes, dataset).is_ok()
                    && match dataset {
                        Dataset::Zen => evidence::malicious_ip(&q.codes),
                        Dataset::Dbl => evidence::malicious_domain(&q.codes),
                    }
            };
            // A later failed target does not erase an independently completed
            // positive query; a no-hit or policy-only listing is not malicious.
            let positive = if id == "ip_reputation" {
                observed(&r.ip, Dataset::Zen)
            } else {
                r.domains
                    .iter()
                    .take(12)
                    .any(|q| observed(&q.result, Dataset::Dbl))
            };
            positive.then_some(4.)
        }
        "smtp_policy_contribution" => {
            let p = &scan.smtp_policy;
            (p.version == smtp_policy::VERSION
                && p.status == PolicyStatus::Complete
                && p.applied_weight.is_finite()
                && (-0.25..=1.5).contains(&p.applied_weight)
                && (p.scoring_enabled || p.applied_weight == 0.))
                .then_some(p.applied_weight)
        }
        _ => unreachable!(),
    };
    result.map_or(Weight::Unavailable, Weight::Observed)
}

pub(super) fn reconcile(scan: &Scan, entries: &mut [Contribution]) {
    for entry in entries.iter_mut() {
        // Invalid/conflicting inputs still invalidate the index. Dependency
        // handling must not conceal corruption by choosing a convenient weight.
        if entry.retained.is_none() {
            continue;
        }
        match weight(scan, &entry.id) {
            Weight::Unmanaged => (),
            Weight::Unavailable => {
                entry.retained = Some(0.);
                entry.adjustment = Adjustment::UnavailableEvidence;
            }
            Weight::Observed(actual) if entry.retained != Some(actual) => {
                entry.retained = Some(actual);
                entry.adjustment = Adjustment::DetectorPolicy;
            }
            Weight::Observed(_) => (),
        }
    }
    let dmarc = entries
        .iter()
        .any(|e| e.id == "dmarc_fail" && e.retained == Some(2.));
    let failed_spf_branch =
        transport(scan).is_some_and(|e| e.authentication.dmarc_spf == Some(A::Fail));
    if dmarc && failed_spf_branch {
        for entry in entries
            .iter_mut()
            .filter(|e| e.id == "spf_fail" && e.retained == Some(1.))
        {
            entry.retained = Some(0.);
            entry.adjustment = Adjustment::SubsumedEvidence;
            entry.subsumed_by = Some("dmarc_fail".into());
        }
    }
}
