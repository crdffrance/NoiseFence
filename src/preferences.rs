//! Mailbox-owned policy; all edits require a current grant, including aliases and domain scopes.
use crate::{
    actions::Action,
    config::{Config, Recipient},
    custom_filtering::{Binding, Policy, Profile, Rule},
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, collections::BTreeMap};
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub enabled: bool,
    pub minimum_threshold: f64,
    pub maximum_threshold: f64,
    pub max_rules: usize,
    pub allowed_actions: Vec<Action>,
    pub mailboxes: BTreeMap<String, Preference>,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            enabled: true,
            minimum_threshold: 85.,
            maximum_threshold: 100.,
            max_rules: 20,
            allowed_actions: vec![Action::Deliver, Action::Tag, Action::Quarantine],
            mailboxes: BTreeMap::new(),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Preference {
    pub profile: Option<Profile>,
    pub rules: Vec<Rule>,
}
pub fn permitted(scope: &str, admin: bool, grants: &[String]) -> bool {
    scope != "*"
        && (admin
            || grants.iter().any(|g| {
                g == scope
                    || g.strip_prefix("*@")
                        .is_some_and(|d| scope.rsplit_once('@').is_some_and(|(_, s)| s == d))
            }))
}
impl Preference {
    fn policy(&self, scope: &str) -> Policy {
        Policy {
            profiles: self.profile.iter().cloned().collect(),
            bindings: self
                .profile
                .iter()
                .map(|p| Binding {
                    scope: scope.into(),
                    profile: p.id.clone(),
                })
                .collect(),
            rules: self.rules.clone(),
            ..Default::default()
        }
    }
}
impl Settings {
    pub fn validate(&self, cfg: &Config) -> Result<()> {
        ensure!(
            self.minimum_threshold.is_finite()
                && self.maximum_threshold.is_finite()
                && 50. <= self.minimum_threshold
                && self.minimum_threshold <= self.maximum_threshold
                && self.maximum_threshold <= 100.,
            "Impaired personal thresholds."
        );
        ensure!(
            self.max_rules <= 20
                && self.mailboxes.len() <= 1000
                && !self.allowed_actions.is_empty(),
            "Limits of invalid preferences."
        );
        for (scope, p) in &self.mailboxes {
            ensure!(scope != "*", "A preference requires an address or domain.");
            // A binding validates the scope even when the preference has no profile or rules.
            ensure!(
                (scope
                    .strip_prefix("*@")
                    .is_some_and(|d| cfg.domains.iter().any(|v| v.name == d))
                    || cfg.recipient(scope).is_some_and(|r| r.address == *scope)),
                "Unknown personal scope."
            );
            ensure!(p.rules.len() <= self.max_rules, "Too many personal rules.");
            for r in &p.rules {
                ensure!(
                    r.scope == *scope
                        && !r.stop
                        && r.action.is_none_or(|a| self.allowed_actions.contains(&a)),
                    "Personal rule out of reach or unauthorized action."
                );
            }
            if let Some(profile) = &p.profile {
                ensure!(
                    profile.threshold.is_none_or(|t| (self.minimum_threshold
                        ..=self.maximum_threshold)
                        .contains(&t))
                        && profile.require_corroboration,
                    "Out-of-limit threshold or substantiation disabled."
                );
                ensure!(
                    [profile.spam, profile.publicity, profile.review]
                        .iter()
                        .all(|a| self.allowed_actions.contains(a)),
                    "Unauthorized personal action."
                );
            }
            p.policy(scope).validate(cfg)?;
        }
        Ok(())
    }
    pub fn tags(&self) -> (bool, bool) {
        if !self.enabled {
            return (false, false);
        }
        self.mailboxes
            .iter()
            .fold((false, false), |(a, b), (s, p)| {
                let t = p.policy(s).tags();
                (a || t.0, b || t.1)
            })
    }
    pub fn policy<'a>(&self, base: &'a Policy, recipient: &Recipient) -> Cow<'a, Policy> {
        if !self.enabled {
            return Cow::Borrowed(base);
        }
        if base.ordering == crate::custom_filtering::Ordering::Scoped {
            return self.scoped_policy(base, recipient);
        }
        let selected = self
            .mailboxes
            .iter()
            .filter_map(|(scope, p)| {
                crate::custom_filtering::scope_rank(scope, recipient).map(|r| (r, p))
            })
            .max_by_key(|(rank, _)| *rank);
        let Some((_, personal)) = selected else {
            return Cow::Borrowed(base);
        };
        let mut combined = base.clone();
        if let Some(profile) = &personal.profile {
            let mut profile = profile.clone();
            if profile.threshold.is_none() {
                let mut inherited: Vec<_> = base
                    .bindings
                    .iter()
                    .filter_map(|b| {
                        Some((
                            crate::custom_filtering::scope_rank(&b.scope, recipient)?,
                            base.profiles.iter().find(|p| p.id == b.profile)?,
                        ))
                    })
                    .collect();
                inherited.sort_by_key(|(rank, _)| std::cmp::Reverse(*rank));
                profile.threshold = inherited.iter().find_map(|(_, p)| p.threshold);
            }

            profile.id = (0..)
                .map(|i| format!("__mailbox_{i}"))
                .find(|id| !base.profiles.iter().any(|p| &p.id == id))
                .unwrap();
            combined
                .bindings
                .retain(|b| b.scope != recipient.address.clone());
            combined.bindings.push(Binding {
                scope: recipient.address.clone(),
                profile: profile.id.clone(),
            });
            combined.origins.profiles.insert(
                profile.id.clone(),
                personal.profile.as_ref().unwrap().id.clone(),
            );
            combined.profiles.push(profile);
        }
        // Administrator rules run last and remain authoritative. Personal rules cannot stop them.
        combined
            .rules
            .sort_by(|a, b| (a.priority, &a.id).cmp(&(b.priority, &b.id)));
        let mut rules = personal.rules.clone();
        rules.sort_by(|a, b| (a.priority, &a.id).cmp(&(b.priority, &b.id)));
        for (i, r) in rules.iter_mut().enumerate() {
            let original = r.id.clone();
            r.id = (i..)
                .map(|n| format!("mailbox-{n}"))
                .find(|id| {
                    !base.rules.iter().any(|r| &r.id == id)
                        && !combined.origins.rules.contains_key(id)
                })
                .unwrap();
            combined.origins.rules.insert(r.id.clone(), original);
            r.stop = false;
        }
        rules.extend(combined.rules);
        for (i, r) in rules.iter_mut().enumerate() {
            r.priority = i as u16;
        }
        combined.rules = rules;
        Cow::Owned(combined)
    }
    fn scoped_policy<'a>(&self, base: &'a Policy, recipient: &Recipient) -> Cow<'a, Policy> {
        let mut selected: Vec<_> = self
            .mailboxes
            .iter()
            .filter_map(|(scope, p)| {
                crate::custom_filtering::scope_rank(scope, recipient).map(|rank| (rank, scope, p))
            })
            .collect();
        if selected.is_empty() {
            return Cow::Borrowed(base);
        }
        selected.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
        let mut combined = base.clone();
        for (_, scope, preference) in selected {
            if let Some(profile) = &preference.profile {
                let mut copy = profile.clone();
                copy.id = (0..)
                    .map(|n| format!("__personal_profile_{n}"))
                    .find(|id| !combined.profiles.iter().any(|p| &p.id == id))
                    .unwrap();
                combined
                    .origins
                    .profiles
                    .insert(copy.id.clone(), profile.id.clone());
                combined.bindings.push(Binding {
                    scope: scope.clone(),
                    profile: copy.id.clone(),
                });
                combined.profiles.push(copy);
            }
            for rule in &preference.rules {
                let mut copy = rule.clone();
                copy.id = (0..)
                    .map(|n| format!("__personal_rule_{n}"))
                    .find(|id| !combined.rules.iter().any(|r| &r.id == id))
                    .unwrap();
                copy.stop = false;
                combined
                    .origins
                    .rules
                    .insert(copy.id.clone(), rule.id.clone());
                combined.rules.push(copy);
            }
        }
        Cow::Owned(combined)
    }
}
