//! Shared transport controls. Traffic never contributes to the content score.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub mod runtime;
pub mod verification;

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    #[default]
    Observe,
    Defer,
    Quarantine,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    pub action: Action,
    pub window_seconds: u32,
    pub sender_limit: u32,
    pub domain_limit: u32,
    pub recipient_limit: u32,
    pub duplicate_limit: u32,
    pub verify_new_senders: bool,
    pub trusted_senders: Vec<String>,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            action: Action::Observe,
            window_seconds: 300,
            sender_limit: 60,
            domain_limit: 300,
            recipient_limit: 300,
            duplicate_limit: 20,
            verify_new_senders: false,
            trusted_senders: Vec::new(),
        }
    }
}
impl Policy {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (10..=3600).contains(&self.window_seconds),
            "Traffic window must be 10..3600 seconds"
        );
        ensure!(
            [
                self.sender_limit,
                self.domain_limit,
                self.recipient_limit,
                self.duplicate_limit
            ]
            .iter()
            .all(|v| *v <= 100_000),
            "Traffic quota exceeds 100000"
        );
        ensure!(
            self.trusted_senders.len() <= 128
                && self
                    .trusted_senders
                    .iter()
                    .all(|s| crate::config::valid_address(s)),
            "Invalid authenticated sender exceptions"
        );
        Ok(())
    }
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub enabled: bool,
    pub policy: Policy,
    pub scopes: BTreeMap<String, Policy>,
    pub allow_personal: bool,
    pub verification: verification::Settings,
}
impl Settings {
    pub fn validate(&self) -> Result<()> {
        self.policy.validate()?;
        ensure!(self.scopes.len() <= 1000, "Too many traffic scopes");
        for (scope, p) in &self.scopes {
            ensure!(
                crate::config::valid_address(scope)
                    || scope
                        .strip_prefix("*@")
                        .is_some_and(crate::config::valid_domain),
                "Invalid traffic scope"
            );
            p.validate()?;
        }
        self.verification.validate()
    }
    pub fn policy_for(&self, cfg: &crate::config::Config, recipient: &str) -> Policy {
        let domain = recipient.rsplit_once('@').map(|(_, d)| format!("*@{d}"));
        let policy = self
            .scopes
            .get(recipient)
            .or_else(|| domain.as_ref().and_then(|d| self.scopes.get(d)))
            .unwrap_or(&self.policy);
        if self.allow_personal
            && cfg.preferences.enabled
            && let Some(p) = cfg
                .preferences
                .mailboxes
                .get(recipient)
                .or_else(|| {
                    domain
                        .as_ref()
                        .and_then(|d| cfg.preferences.mailboxes.get(d))
                })
                .and_then(|p| p.traffic.as_ref())
        {
            return p.clone();
        }
        policy.clone()
    }
}
pub fn settings(cfg: &crate::config::Config) -> Option<&Settings> {
    cfg.smtp_admission
        .as_ref()
        .and_then(|s| s.traffic.as_deref())
        .filter(|s| s.enabled)
}
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Report {
    pub status: String,
    pub reasons: Vec<String>,
    pub action: Action,
    pub enforced: bool,
    pub window_seconds: u32,
    pub counts: BTreeMap<String, u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_id: Option<String>,
}
impl Report {
    pub fn hold(&self) -> bool {
        self.enforced && (self.action == Action::Quarantine || self.verification_id.is_some())
    }
    pub fn defer(&self) -> bool {
        self.enforced && self.action == Action::Defer
    }
    pub fn apply(&self, action: &mut crate::actions::Applied) {
        if self.hold() && action.effective != crate::actions::Action::Quarantine {
            action.coverage = Some(crate::action_coverage::Evaluation {
                version: crate::action_coverage::VERSION.into(),
                partial_actions: false,
                basis: crate::action_coverage::Basis::TrafficPolicy,
                required: vec![crate::action_coverage::Requirement::TransportPolicyMet],
                missing: vec![],
            });
            action.requested = crate::actions::Action::Quarantine;
            action.effective = crate::actions::Action::Quarantine;
            action.reason = if self.verification_id.is_some() {
                "sender_verification"
            } else {
                "traffic_limit"
            }
            .into();
            action.quarantine_days = action.quarantine_days.clamp(1, 7);
        }
    }
}
