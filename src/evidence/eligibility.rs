//! Shared interpretation of captured SMTP authentication and DQS facts.
//! This validates availability, not sender trust or statistical independence.
use super::{AuthResult as A, Dataset, Evidence, Query, Source, State};

pub const VERSION: &str = "transport-evidence-1";
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exclusion {
    MissingEnvelopeContext,
    UnsupportedSchema,
    InactiveParent,
    IncompleteCheck,
    InvalidResult,
    TemporaryFailure,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthCheck {
    Spf,
    Dkim,
    Dmarc,
    Arc,
}

pub fn context(e: &Evidence) -> Result<(), Exclusion> {
    if e.schema != super::SCHEMA {
        return Err(Exclusion::UnsupportedSchema);
    }
    if e.source == Source::ContentOnly {
        return Err(Exclusion::MissingEnvelopeContext);
    }
    Ok(())
}
pub fn parent(state: State) -> bool {
    matches!(state, State::Complete | State::Limited | State::Unavailable)
}
pub fn authentication(e: &Evidence, check: AuthCheck) -> Result<(), Exclusion> {
    context(e)?;
    let a = &e.authentication;
    // ARC is verified independently of the configured SPF/DKIM/DMARC group.
    if check != AuthCheck::Arc && !parent(a.state) {
        return Err(Exclusion::InactiveParent);
    }
    let dmarc = a.dmarc_spf.zip(a.dmarc_dkim).map(|(spf, dkim)| [spf, dkim]);
    let (state, values) = match check {
        AuthCheck::Spf => (a.spf_state, a.spf.as_ref().map(std::slice::from_ref)),
        AuthCheck::Dkim => (a.dkim_state, a.dkim.as_deref()),
        AuthCheck::Dmarc => (a.dmarc_state, dmarc.as_ref().map(|v| v.as_slice())),
        AuthCheck::Arc => (a.arc_state, a.arc.as_ref().map(std::slice::from_ref)),
    };
    if state != State::Complete {
        return Err(Exclusion::IncompleteCheck);
    }
    let values = values.ok_or(Exclusion::InvalidResult)?;
    if values.len() > 16
        || values.iter().any(|v| match check {
            AuthCheck::Dmarc => matches!(v, A::SoftFail | A::Neutral),
            AuthCheck::Dkim | AuthCheck::Arc => *v == A::SoftFail,
            AuthCheck::Spf => false,
        })
    {
        return Err(Exclusion::InvalidResult);
    }
    if values.contains(&A::TempError) {
        return Err(Exclusion::TemporaryFailure);
    }
    Ok(())
}
pub fn dmarc_pass(e: &Evidence) -> bool {
    authentication(e, AuthCheck::Dmarc).is_ok()
        && [e.authentication.dmarc_spf, e.authentication.dmarc_dkim].contains(&Some(A::Pass))
}
pub fn query(e: &Evidence, q: &Query, dataset: Dataset) -> Result<(), Exclusion> {
    context(e)?;
    if e.reputation.version != super::REPUTATION_VERSION {
        return Err(Exclusion::UnsupportedSchema);
    }
    if !parent(e.reputation.state) {
        return Err(Exclusion::InactiveParent);
    }
    if q.state != State::Complete {
        return Err(Exclusion::IncompleteCheck);
    }
    // Complete + empty is the producer's verified negative answer contract.
    if !q.codes.is_empty() && super::dqs_codes(&q.codes, dataset).is_err() {
        return Err(Exclusion::InvalidResult);
    }
    Ok(())
}
pub fn malicious_query(e: &Evidence, q: &Query, dataset: Dataset) -> bool {
    query(e, q, dataset).is_ok()
        && match dataset {
            Dataset::Zen => super::malicious_ip(&q.codes),
            Dataset::Dbl => super::malicious_domain(&q.codes),
        }
}
