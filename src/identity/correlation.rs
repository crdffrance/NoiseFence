//! Recipient-scoped corroboration. Recurrence is context, never a safe-sender
//! exemption, a training label, or an independent spam verdict.
use super::{
    detection::{Authentication, Signal as DirectorySignal},
    relationships::Request,
};
use crate::{
    engine::Scan,
    evidence::{Source, State},
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const PROTOCOL: &str = "identity-correlation-1";
pub const RULE: &str = "identity_change";
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Observation,
    Contribute,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub mode: Mode,
    pub maximum_weight: f64,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            mode: Mode::Observation,
            maximum_weight: 1.0,
        }
    }
}
impl Settings {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.maximum_weight.is_finite() && (0.0..=1.0).contains(&self.maximum_weight),
            "Identity contribution must be between 0 and 1 log-odds unit"
        );
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Signal {
    ProtectedIdentityMismatch,
    RecurringReplyChanged,
    RecurringNameChanged,
    RecurringLinksChanged,
    NewSensitiveRequest,
    SensitiveRequest,
    AuthenticationFailed,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub protocol: String,
    pub policy_sha256: String,
    pub mode: Mode,
    pub status: String,
    pub content_available: bool,
    pub recurrence_available: bool,
    pub authentication: Authentication,
    pub signals: BTreeSet<Signal>,
    pub corroborated: bool,
    /// Absolute additional identity-family input, not percentage points. The
    /// scoring ledger reconciles overlapping Reply-To evidence separately.
    pub proposed_weight: f64,
    pub applied_weight: f64,
}

/// These are current local content observations, never LLM/Rspamd opinions or
/// user-supplied Authentication-Results. Incomplete input supplies no demand.
pub fn requests(scan: &Scan) -> Option<BTreeSet<Request>> {
    if scan.features_complete != Some(true)
        || scan.message_context.as_ref().is_some_and(|c| c.encrypted)
        || !scan
            .evidence
            .as_ref()
            .is_some_and(|e| e.source == Source::SmtpSession)
    {
        return None;
    }
    let native = scan
        .native_filter
        .as_ref()
        .filter(|n| n.report.status == crate::native_filter::Status::Complete)?;
    let mut requests = BTreeSet::new();
    for symbol in &native.local_symbols {
        match symbol.id.as_str() {
            "NF_CREDENTIALS" => {
                requests.insert(Request::Credentials);
            }
            "NF_FINANCIAL" => {
                requests.insert(Request::Payment);
            }
            "NF_WALLET_SECRET" => {
                requests.insert(Request::Secret);
            }
            // A form alone is not a request for credentials or payment.
            _ => (),
        }
    }
    Some(requests)
}

pub fn inspect(settings: &Settings, scan: &Scan) -> Report {
    let content = requests(scan);
    let mut out = Report {
        protocol: PROTOCOL.into(),
        policy_sha256: crate::message::digest(&serde_json::to_vec(settings).unwrap_or_default()),
        mode: settings.mode,
        status: "unavailable".into(),
        content_available: content.is_some(),
        recurrence_available: false,
        authentication: super::detection::authentication(scan.evidence.as_ref()),
        signals: BTreeSet::new(),
        corroborated: false,
        proposed_weight: 0.,
        applied_weight: 0.,
    };
    if settings.validate().is_err()
        || !scan.evidence.as_ref().is_some_and(|e| {
            e.source == Source::SmtpSession && e.authentication.dmarc_state == State::Complete
        })
    {
        return out;
    }
    let directory = scan
        .identity
        .as_ref()
        .map(|r| &r.observation)
        .filter(|r| r.status == "complete" && !r.ambiguous_identity);
    let memory = scan
        .contact_learning
        .as_ref()
        .map(|m| &m.report)
        .filter(|m| {
            m.status == "regular"
                && m.regular
                && !m.blocked_by_feedback
                && m.campaigns >= m.minimum_campaigns
                && m.minimum_campaigns >= 5
                && m.observed_days >= m.minimum_days
                && m.minimum_days >= 3
        });
    out.recurrence_available = memory.is_some();
    if directory.is_none() && memory.is_none() {
        return out;
    }
    out.status = if content.is_some() {
        "complete"
    } else {
        "limited"
    }
    .into();
    if directory.is_some_and(|r| {
        r.signals.contains(&DirectorySignal::ProtectedNameMismatch)
            || r.signals.contains(&DirectorySignal::ProtectedGroupMismatch)
    }) {
        out.signals.insert(Signal::ProtectedIdentityMismatch);
    }
    if let Some(m) = memory {
        for (name, signal, content_required) in [
            ("reply_destination", Signal::RecurringReplyChanged, false),
            ("display_name", Signal::RecurringNameChanged, false),
            ("link_domain", Signal::RecurringLinksChanged, true),
            ("sensitive_request", Signal::NewSensitiveRequest, true),
        ] {
            if m.changes.iter().any(|s| s == name)
                && (!content_required || m.content_comparison_available)
            {
                out.signals.insert(signal);
            }
        }
    }
    if content.as_ref().is_some_and(|r| !r.is_empty()) {
        out.signals.insert(Signal::SensitiveRequest);
    }
    if out.authentication == Authentication::Failed {
        out.signals.insert(Signal::AuthenticationFailed);
    }
    // Name/link novelty or authentication failure alone never incurs weight.
    // Unavailable alignment and homonyms cannot strengthen directory claims.
    // For automatic recurrence, require both a concrete changed reply target
    // and a current sensitive request. A compromised aligned account can meet
    // this combination; alignment is not a safety exemption.
    let demand = out.signals.contains(&Signal::SensitiveRequest);
    let directory_change = out.signals.contains(&Signal::ProtectedIdentityMismatch)
        && out.authentication == Authentication::Failed;
    let reply_change = out.signals.contains(&Signal::RecurringReplyChanged)
        && out.authentication != Authentication::Unavailable;
    out.corroborated = demand && (directory_change || reply_change);
    if out.corroborated {
        out.proposed_weight = settings.maximum_weight;
        if settings.mode == Mode::Contribute {
            out.applied_weight = out.proposed_weight;
        }
    }
    out
}

/// A stored/native symbol cannot supply an arbitrary rule weight. This gate is
/// used by the common accounting path, including repeated scoring.
pub(crate) fn weight(scan: &Scan) -> Option<f64> {
    let r = scan.identity_correlation.as_ref()?;
    if r.protocol != PROTOCOL
        || !crate::compatibility::valid_hash(&r.policy_sha256)
        || !r.applied_weight.is_finite()
        || !(0.0..=1.0).contains(&r.applied_weight)
        || !r.proposed_weight.is_finite()
        || !(0.0..=1.0).contains(&r.proposed_weight)
    {
        return None;
    }
    let expected = inspect(
        &Settings {
            mode: r.mode,
            maximum_weight: r.proposed_weight,
        },
        scan,
    );
    // Rebuild eligibility from structured inputs, not the serialized claim.
    Some(
        if r.corroborated
            && expected.corroborated
            && r.mode == Mode::Contribute
            && expected.policy_sha256 == r.policy_sha256
        {
            r.applied_weight.min(expected.applied_weight)
        } else {
            0.
        },
    )
}

#[cfg(test)]
pub(crate) mod tests;
