//! Correlated identity observations. No directory/HTTP calls, no allowlisting,
//! no Rspamd input and no independent message verdict in this module.
use super::{
    directory::{Catalog, Match},
    mailbox,
    relationships::{Report as RelationshipReport, Request},
};
use crate::evidence::{AuthResult, Evidence, Source, State};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Authentication {
    Aligned,
    Failed,
    Unavailable,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Signal {
    ProtectedNameMismatch,
    ProtectedGroupMismatch,
    KnownAddressAuthenticationFailed,
    KnownContactReplyChanged,
    KnownContactNewSensitiveRequest,
    SensitiveRequest,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub protocol: String,
    pub status: String,
    pub observation_only: bool,
    /// Counts only: shared message details never expose other people, groups,
    /// addresses, IdP object IDs or recipient-specific relationship join keys.
    pub fresh_sources: usize,
    pub applicable_sources: usize,
    pub authentication: Authentication,
    pub directory_address_match: bool,
    pub ambiguous_identity: bool,
    pub signals: BTreeSet<Signal>,
    pub corroborated: bool,
}
fn authentication(evidence: Option<&Evidence>) -> Authentication {
    let Some(e) = evidence.filter(|e| {
        e.source == Source::SmtpSession && e.authentication.dmarc_state == State::Complete
    }) else {
        return Authentication::Unavailable;
    };
    let a = &e.authentication;
    if a.dmarc_dkim == Some(AuthResult::Pass) || a.dmarc_spf == Some(AuthResult::Pass) {
        return Authentication::Aligned;
    }
    let final_result = |r| matches!(r, Some(AuthResult::Fail | AuthResult::None));
    if final_result(a.dmarc_dkim)
        && final_result(a.dmarc_spf)
        && (a.dmarc_dkim == Some(AuthResult::Fail) || a.dmarc_spf == Some(AuthResult::Fail))
    {
        Authentication::Failed
    } else {
        Authentication::Unavailable
    }
}

pub fn inspect(
    directory: &Catalog,
    raw: &[u8],
    envelope_recipients: &[String],
    evidence: Option<&Evidence>,
    requests: &BTreeSet<Request>,
    relationship: Option<&RelationshipReport>,
    now: i64,
) -> Report {
    let mut result = Report {
        protocol: "identity-detection-1".into(),
        status: "unavailable".into(),
        observation_only: true,
        fresh_sources: 0,
        applicable_sources: 0,
        authentication: authentication(evidence),
        directory_address_match: false,
        ambiguous_identity: false,
        signals: BTreeSet::new(),
        corroborated: false,
    };
    // This primitive accepts exactly one recipient. The engine projects each
    // report before grouping wire variants; a common multi-recipient scan may
    // never carry another tenant's directory or Bcc relationship observations.
    if envelope_recipients.len() != 1 || raw.len() > 2 * 1024 * 1024 {
        return result;
    }
    let Ok(recipient) = mailbox(&envelope_recipients[0]) else {
        return result;
    };
    let Some((_, scope)) = recipient.rsplit_once('@') else {
        return result;
    };
    (result.fresh_sources, result.applicable_sources) = directory.coverage(scope, now);
    if result.applicable_sources == 0 {
        result.status = "not_configured".into();
        return result;
    }
    if result.fresh_sources == 0 {
        result.status = "stale".into();
        return result;
    }
    let Some(parsed) = mail_parser::MessageParser::default().parse(raw) else {
        return result;
    };
    if parsed.header_values(mail_parser::HeaderName::From).count() != 1 {
        return result;
    }
    let Some(from) = parsed
        .from()
        .filter(|a| a.iter().count() == 1)
        .and_then(|a| a.first())
    else {
        return result;
    };
    let Some(address) = from.address().and_then(|a| mailbox(a).ok()) else {
        return result;
    };
    let name = from.name().unwrap_or_default();
    result.status = if result.fresh_sources == result.applicable_sources {
        "complete"
    } else {
        "limited"
    }
    .into();
    match directory.address(&address, scope, now) {
        Match::Unique(_) => result.directory_address_match = true,
        Match::Ambiguous => result.ambiguous_identity = true,
        Match::None => (),
    }
    match directory.name(name, scope, now) {
        Match::Unique(key) => {
            if let Some(person) = directory.person(&key, scope, now)
                && !person.protected_roles.is_empty()
                && !person.addresses.is_empty()
                && !person.addresses.contains(&address)
            {
                result.signals.insert(Signal::ProtectedNameMismatch);
            }
        }
        Match::Ambiguous => result.ambiguous_identity = true,
        Match::None => (),
    }
    match directory.group_name(name, scope, now) {
        Match::Unique(key) => {
            if let Some(group) = directory.group(&key, scope, now)
                && !group.addresses.is_empty()
                && !group.addresses.contains(&address)
            {
                result.signals.insert(Signal::ProtectedGroupMismatch);
            }
        }
        Match::Ambiguous => result.ambiguous_identity = true,
        Match::None => (),
    }
    if result.directory_address_match && result.authentication == Authentication::Failed {
        result
            .signals
            .insert(Signal::KnownAddressAuthenticationFailed);
    }
    if !requests.is_empty() {
        result.signals.insert(Signal::SensitiveRequest);
    }
    if let Some(history) = relationship.filter(|r| r.status == "complete" && !r.limited) {
        if history.new_reply_to {
            result.signals.insert(Signal::KnownContactReplyChanged);
        }
        if history.new_sensitive_request && !requests.is_empty() {
            result
                .signals
                .insert(Signal::KnownContactNewSensitiveRequest);
        }
    }
    // The identity family counts once even when both a protected person and a
    // group match; the sensitive request novelty is not another content vote.
    let identity = result.signals.contains(&Signal::ProtectedNameMismatch)
        || result.signals.contains(&Signal::ProtectedGroupMismatch);
    let auth_failure = result
        .signals
        .contains(&Signal::KnownAddressAuthenticationFailed);
    let relationship_change = result.signals.contains(&Signal::KnownContactReplyChanged)
        || result
            .signals
            .contains(&Signal::KnownContactNewSensitiveRequest);
    let demand = result.signals.contains(&Signal::SensitiveRequest);
    result.corroborated = result.status == "complete"
        && ((identity
            && (demand || relationship_change || result.authentication == Authentication::Failed))
            || (demand && (auth_failure || relationship_change)));
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::directory::{
        Activity, Group, Kind, Person, Provider, Role, SCHEMA, Snapshot, Source as DirectorySource,
    };
    const NOW: i64 = 1_800_000_000;
    fn directory() -> Snapshot {
        Snapshot {
            schema: SCHEMA.into(),
            source: DirectorySource {
                id: "manual".into(),
                provider: Provider::Manual,
                label: "People".into(),
                authority: "local".into(),
                scopes: BTreeSet::from(["example.test".into()]),
                stale_after_seconds: 86400,
            },
            generation: 1,
            completed_at: NOW - 10,
            people: vec![Person {
                id: "alice-id".into(),
                display_name: "Alice Finance".into(),
                kind: Kind::Person,
                activity: Activity::Active,
                addresses: BTreeSet::from([
                    "alice@example.test".into(),
                    "alice.alias@example.test".into(),
                ]),
                protected_roles: BTreeSet::from([Role::Finance]),
            }],
            groups: vec![],
            memberships: BTreeSet::new(),
            delegations: BTreeSet::new(),
        }
    }
    fn message(from: &str, extra: &str) -> Vec<u8> {
        format!("From: {from}\r\nTo: bob@example.test\r\nSubject: hello\r\n{extra}\r\nHello")
            .into_bytes()
    }
    fn scan(snapshot: Snapshot, from: &str, requests: BTreeSet<Request>) -> Report {
        inspect(
            &Catalog::new(vec![snapshot], NOW).unwrap(),
            &message(from, ""),
            &["bob@example.test".into()],
            None,
            &requests,
            None,
            NOW,
        )
    }
    #[test]
    fn new_contacts_and_single_name_mismatches_do_not_supply_a_verdict() {
        let new = scan(
            directory(),
            "New Person <new@external.test>",
            BTreeSet::new(),
        );
        assert_eq!(new.status, "complete");
        assert!(new.signals.is_empty());
        assert!(!new.corroborated);
        let impersonation = scan(
            directory(),
            "Alice Finance <attacker@external.test>",
            BTreeSet::new(),
        );
        assert!(
            impersonation
                .signals
                .contains(&Signal::ProtectedNameMismatch)
        );
        assert!(!impersonation.corroborated);
        assert!(impersonation.observation_only);
        let correlated = scan(
            directory(),
            "Alice Finance <attacker@external.test>",
            BTreeSet::from([Request::Payment]),
        );
        assert!(correlated.corroborated);
    }
    #[test]
    fn known_alias_does_not_mean_authenticated_or_safe() {
        let report = scan(
            directory(),
            "Alice Finance <alice.alias@example.test>",
            BTreeSet::from([Request::Credentials]),
        );
        assert!(report.directory_address_match);
        assert_eq!(report.authentication, Authentication::Unavailable);
        assert!(!report.signals.contains(&Signal::ProtectedNameMismatch));
        assert!(!report.corroborated);
    }
    #[test]
    fn forged_authentication_headers_never_supply_observed_authentication() {
        let raw = message(
            "Alice Finance <alice@example.test>",
            "Authentication-Results: example.test; dmarc=pass; dkim=pass\r\nX-Noisefence-Identity: trusted\r\n",
        );
        let report = inspect(
            &Catalog::new(vec![directory()], NOW).unwrap(),
            &raw,
            &["bob@example.test".into()],
            None,
            &BTreeSet::new(),
            None,
            NOW,
        );
        assert_eq!(report.authentication, Authentication::Unavailable);
        assert!(!report.corroborated);
    }
    #[test]
    fn stale_cross_tenant_and_ambiguous_sources_do_not_make_identity_claims() {
        let mut stale = directory();
        stale.completed_at -= 90000;
        let report = scan(
            stale,
            "Alice Finance <attacker@external.test>",
            BTreeSet::from([Request::Payment]),
        );
        assert_eq!(report.status, "stale");
        assert!(report.signals.is_empty());
        let mut other = directory();
        other.source.id = "other".into();
        let catalog = Catalog::new(vec![directory(), other], NOW).unwrap();
        let raw = message("Alice Finance <attacker@external.test>", "");
        let report = inspect(
            &catalog,
            &raw,
            &["bob@example.test".into()],
            None,
            &BTreeSet::new(),
            None,
            NOW,
        );
        assert!(report.ambiguous_identity);
        assert!(report.signals.is_empty());
        let report = inspect(
            &catalog,
            &raw,
            &["bob@other.test".into()],
            None,
            &BTreeSet::new(),
            None,
            NOW,
        );
        assert_eq!(report.status, "not_configured");
        assert!(report.signals.is_empty());
        assert!(!serde_json::to_string(&report).unwrap().contains("alice"));
    }
    #[test]
    fn duplicate_from_and_multi_scope_transactions_are_unavailable() {
        let catalog = Catalog::new(vec![directory()], NOW).unwrap();
        let raw = message(
            "Alice Finance <attacker@external.test>",
            "From: other@example.test\r\n",
        );
        let report = inspect(
            &catalog,
            &raw,
            &["bob@example.test".into()],
            None,
            &BTreeSet::new(),
            None,
            NOW,
        );
        assert_eq!(report.status, "unavailable");
        let report = inspect(
            &catalog,
            &raw,
            &["bob@example.test".into(), "private@example.test".into()],
            None,
            &BTreeSet::new(),
            None,
            NOW,
        );
        assert_eq!(report.applicable_sources, 0);
    }
    #[test]
    fn ordinary_groups_do_not_invent_email_addresses() {
        let mut snapshot = directory();
        snapshot.groups.push(Group {
            id: "finance".into(),
            display_name: "Finance Team".into(),
            activity: Activity::Active,
            addresses: BTreeSet::new(),
            protected: true,
        });
        let report = scan(
            snapshot.clone(),
            "Finance Team <new@external.test>",
            BTreeSet::from([Request::Payment]),
        );
        assert!(!report.corroborated);
        snapshot.groups[0]
            .addresses
            .insert("finance@example.test".into());
        let report = scan(
            snapshot,
            "Finance Team <new@external.test>",
            BTreeSet::from([Request::Payment]),
        );
        assert!(report.signals.contains(&Signal::ProtectedGroupMismatch));
        assert!(report.corroborated);
    }
    #[test]
    fn authentication_requires_observed_alignment_not_a_known_name() {
        let cfg =
            crate::config::Config::load(std::path::Path::new("config/development.toml")).unwrap();
        let mut evidence = Evidence::new(
            &cfg,
            crate::evidence::Artifacts::new(&cfg, None, None, false),
            false,
        );
        evidence.authentication.dmarc_state = State::Complete;
        evidence.authentication.dmarc_dkim = Some(AuthResult::Pass);
        evidence.authentication.dmarc_spf = Some(AuthResult::Fail);
        assert_eq!(authentication(Some(&evidence)), Authentication::Unavailable);
        evidence.source = Source::SmtpSession;
        assert_eq!(authentication(Some(&evidence)), Authentication::Aligned);
        evidence.authentication.dmarc_dkim = Some(AuthResult::TempError);
        assert_eq!(authentication(Some(&evidence)), Authentication::Unavailable);
        evidence.authentication.dmarc_dkim = Some(AuthResult::Fail);
        assert_eq!(authentication(Some(&evidence)), Authentication::Failed);
        let directory = Catalog::new(vec![directory()], NOW).unwrap();
        let raw = message("Alice Finance <alice@example.test>", "");
        let alone = inspect(
            &directory,
            &raw,
            &["bob@example.test".into()],
            Some(&evidence),
            &BTreeSet::new(),
            None,
            NOW,
        );
        assert!(
            alone
                .signals
                .contains(&Signal::KnownAddressAuthenticationFailed)
        );
        assert!(!alone.corroborated);
        let demand = inspect(
            &directory,
            &raw,
            &["bob@example.test".into()],
            Some(&evidence),
            &BTreeSet::from([Request::Payment]),
            None,
            NOW,
        );
        assert!(demand.corroborated);
    }
    #[test]
    fn partial_directory_and_unknown_activity_are_not_positive_identity_evidence() {
        let mut stale = directory();
        stale.source.id = "stale".into();
        stale.completed_at -= 90000;
        let directory = Catalog::new(vec![directory(), stale.clone()], NOW).unwrap();
        let report = inspect(
            &directory,
            &message("Alice Finance <attacker@external.test>", ""),
            &["bob@example.test".into()],
            None,
            &BTreeSet::from([Request::Payment]),
            None,
            NOW,
        );
        assert_eq!(report.status, "limited");
        assert!(!report.corroborated);
        stale.completed_at = NOW;
        stale.people[0].activity = Activity::Unknown;
        let report = scan(
            stale,
            "Alice Finance <attacker@external.test>",
            BTreeSet::from([Request::Payment]),
        );
        assert!(!report.signals.contains(&Signal::ProtectedNameMismatch));
        assert!(!report.corroborated);
    }
}
