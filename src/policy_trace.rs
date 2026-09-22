//! Recipient-scoped receipt trace; contains no rule values or message content.
use crate::{
    actions::Action,
    custom_filtering::{Field, Ordering},
    mailing::Category,
};
use serde::{Deserialize, Serialize};

pub const VERSION: &str = "recipient-policy-trace-1";
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    Administrator,
    Personal,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Matched,
    NoMatch,
    MissingFacts,
    Stopped,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub scope: String,
    pub origin: Origin,
    pub threshold: Option<f64>,
    pub selected: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub scope: String,
    pub origin: Origin,
    pub priority: u16,
    pub outcome: Outcome,
    pub unavailable: Vec<Field>,
    pub category_before: Category,
    pub category_after: Category,
    pub action_before: Action,
    pub action_after: Action,
    pub stop: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Trace {
    pub version: String,
    pub ordering: Ordering,
    /// Most specific first; personal profile wins equal-scope ties in scoped mode.
    pub profiles: Vec<Profile>,
    pub threshold_profile: Option<String>,
    pub threshold_locked: bool,
    pub rules: Vec<Rule>,
    pub stopped_by: Option<String>,
    pub category_rule: Option<String>,
    pub action_rule: Option<String>,
    pub malware_override: bool,
}
