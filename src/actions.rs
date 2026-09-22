//! Delivery policy is evaluated after classification, independently of the score.
use crate::{
    antivirus::AntivirusStatus,
    config::{Config, Mode},
    engine::Scan,
    mailing::Category,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    #[default]
    Deliver,
    Tag,
    Quarantine,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub spam: Action,
    pub publicity: Action,
    pub malware: Action,
    pub quarantine_days: u16,
}
impl Policy {
    /// Preserve installations created before actions were configurable.
    pub fn from_config(config: &Config) -> Self {
        config.actions.clone().unwrap_or(Self {
            spam: Action::Tag,
            malware: Action::Tag,
            publicity: if config
                .mailing
                .as_ref()
                .is_some_and(|m| m.policy.tag_subject)
            {
                Action::Tag
            } else {
                Action::Deliver
            },
            quarantine_days: 14,
        })
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (1..=30).contains(&self.quarantine_days),
            "Quarantine storage: 1 to 30 days."
        );
        Ok(())
    }
    pub fn spam_tag(&self) -> bool {
        self.spam == Action::Tag || self.malware == Action::Tag
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Applied {
    pub requested: Action,
    pub effective: Action,
    pub reason: String,
    pub quarantine_days: u16,
}

pub fn evaluate(scan: &Scan, config: &Config) -> Applied {
    if let Some(action) = scan
        .recipient_decision
        .as_ref()
        .and_then(|r| r.assessment.action.as_ref())
    {
        return action.clone();
    }
    let policy = Policy::from_config(config);
    let malware = scan.antivirus.status == AntivirusStatus::Malware;
    let requested = if malware {
        policy.malware
    } else {
        match crate::mailing::category(scan, config.filter.threshold) {
            Category::Spam => policy.spam,
            Category::Publicity => policy.publicity,
            _ => Action::Deliver,
        }
    };
    constrain(
        scan,
        config,
        crate::mailing::category(scan, config.filter.threshold),
        requested,
        policy.quarantine_days,
        if malware {
            "malware_priority"
        } else {
            "category"
        },
    )
}

/// The common operational restrictions for global and scoped policies.
pub fn constrain(
    scan: &Scan,
    config: &Config,
    category: Category,
    requested: Action,
    quarantine_days: u16,
    requested_reason: &str,
) -> Applied {
    let malware = scan.antivirus.status == AntivirusStatus::Malware;
    let (effective, reason) = if config.filter.mode == Mode::Observe {
        (Action::Deliver, "observation")
    } else if !scan.complete && !(malware && requested == Action::Quarantine) {
        (Action::Deliver, "incomplete")
    } else if requested == Action::Tag && !matches!(category, Category::Spam | Category::Publicity)
    {
        (Action::Deliver, "category_without_prefix")
    } else {
        (requested, requested_reason)
    };
    Applied {
        requested,
        effective,
        reason: reason.into(),
        quarantine_days,
    }
}
