//! Metadata-only policy inspection. No detector facts, message content or rule values.
use crate::{
    actions::{Action, Policy as Actions},
    config::{Config, Recipient},
    custom_filtering::{self, Policy},
    policy_trace::Origin,
};
use serde::Serialize;

#[derive(Serialize)]
pub struct Source {
    pub name: String,
    pub scope: Option<String>,
    pub origin: Option<Origin>,
}
#[derive(Serialize)]
pub struct Profile {
    pub source: Source,
    pub threshold: Option<f64>,
    pub selected: bool,
}
#[derive(Serialize)]
pub struct Rule {
    pub name: String,
    pub scope: String,
    pub origin: Origin,
    pub priority: u16,
    pub stop: bool,
}
#[derive(Serialize)]
pub struct Traffic {
    pub action: crate::traffic::Action,
    pub window_seconds: u32,
    pub sender_limit: u32,
    pub domain_limit: u32,
    pub recipient_limit: u32,
    pub duplicate_limit: u32,
    pub verify_new_senders: bool,
    pub trusted_sender_count: usize,
}
#[derive(Serialize)]
pub struct View {
    pub ordering: custom_filtering::Ordering,
    pub personal_enabled: bool,
    pub threshold: Option<f64>,
    pub threshold_source: Source,
    pub threshold_locked: bool,
    pub action_source: Source,
    pub spam: Action,
    pub publicity: Action,
    pub unassessed: Action,
    pub quarantine_days: u16,
    pub require_corroboration: bool,
    pub profiles: Vec<Profile>,
    pub rules: Vec<Rule>,
    pub traffic: Option<Traffic>,
}
fn global(name: &str) -> Source {
    Source {
        name: name.into(),
        scope: None,
        origin: None,
    }
}
/// Intended profile mappings before content rules and operational action constraints.
/// Never label these mappings as a final verdict or delivery action.
pub fn inspect(cfg: &Config, recipient: &Recipient, at: i64) -> View {
    let empty = Policy::default();
    let policy = cfg
        .preferences
        .policy(cfg.custom_filtering.as_ref().unwrap_or(&empty), recipient);
    let profiles = custom_filtering::applicable_profiles(&policy, recipient);
    let selected = profiles.first().map(|(_, p, _)| *p);
    let source = |p: &custom_filtering::Profile, scope: &str| Source {
        name: p.name.clone(),
        scope: Some(scope.into()),
        origin: Some(if policy.origins.profiles.contains_key(&p.id) {
            Origin::Personal
        } else {
            Origin::Administrator
        }),
    };
    let threshold_locked = custom_filtering::sensitivity_locked(cfg);
    let explicit = profiles.iter().find(|(_, p, _)| p.threshold.is_some());
    // Legacy policy materializes an inherited threshold into its personal profile.
    // Report the original administrator source rather than attributing that value to the user.
    let legacy_inherited = if policy.ordering == custom_filtering::Ordering::LegacyPriority
        && explicit.is_some_and(|(_, p, _)| policy.origins.profiles.contains_key(&p.id))
        && cfg
            .preferences
            .legacy_preference(recipient)
            .and_then(|(_, p)| p.profile.as_ref())
            .is_some_and(|p| p.threshold.is_none())
    {
        super::inherited_threshold_profile(
            cfg.custom_filtering.as_ref().unwrap_or(&empty),
            recipient,
        )
    } else {
        None
    };
    let actions = Actions::from_config(cfg);
    let traffic = crate::traffic::settings(cfg).map(|s| s.policy_for(cfg, &recipient.address));
    View {
        ordering: policy.ordering,
        personal_enabled: cfg.preferences.enabled,
        threshold: if threshold_locked {
            None
        } else {
            Some(
                explicit
                    .and_then(|(_, p, _)| p.threshold)
                    .unwrap_or(cfg.filter.threshold),
            )
        },
        threshold_source: if threshold_locked {
            global("Qualified fusion operating point")
        } else if let Some((p, scope)) = legacy_inherited {
            Source {
                name: p.name.clone(),
                scope: Some(scope.into()),
                origin: Some(Origin::Administrator),
            }
        } else {
            explicit
                .map(|(_, p, scope)| source(p, scope))
                .unwrap_or_else(|| global("Global content threshold"))
        },
        threshold_locked,
        action_source: profiles
            .first()
            .map(|(_, p, scope)| source(p, scope))
            .unwrap_or_else(|| global("Global action policy")),
        spam: selected.map(|p| p.spam).unwrap_or(actions.spam),
        publicity: selected.map(|p| p.publicity).unwrap_or(actions.publicity),
        unassessed: selected.map(|p| p.review).unwrap_or(Action::Deliver),
        quarantine_days: selected
            .map(|p| p.quarantine_days)
            .unwrap_or(actions.quarantine_days),
        require_corroboration: cfg.filter.require_corroboration
            || selected.is_some_and(|p| p.require_corroboration)
            || (!threshold_locked && explicit.is_some()),
        profiles: profiles
            .iter()
            .enumerate()
            .map(|(i, (_, p, scope))| Profile {
                source: source(p, scope),
                threshold: p.threshold,
                selected: i == 0,
            })
            .collect(),
        rules: custom_filtering::applicable_rules(&policy, recipient, at)
            .iter()
            .map(|(_, r)| Rule {
                name: r.name.clone(),
                scope: r.scope.clone(),
                origin: if policy.origins.rules.contains_key(&r.id) {
                    Origin::Personal
                } else {
                    Origin::Administrator
                },
                priority: r.priority,
                stop: r.stop,
            })
            .collect(),
        traffic: traffic.map(|p| Traffic {
            action: p.action,
            window_seconds: p.window_seconds,
            sender_limit: p.sender_limit,
            domain_limit: p.domain_limit,
            recipient_limit: p.recipient_limit,
            duplicate_limit: p.duplicate_limit,
            verify_new_senders: p.verify_new_senders,
            trusted_sender_count: p.trusted_senders.len(),
        }),
    }
}
