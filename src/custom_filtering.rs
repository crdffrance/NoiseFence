//! Bounded administrator rules, evaluated after the common detector pipeline.
//! Facts are ephemeral; recipient assessments contain no message body or rule values.
use crate::{
    actions::{Action, Applied},
    config::{Config, Recipient},
    engine::Scan,
    mailing::Category,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

/// Operating policies over the existing score, not model calibrations or probabilities.
/// Persist only the existing profile threshold so revisions keep their wire format.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct Level {
    pub id: &'static str,
    pub label: &'static str,
    pub threshold: f64,
    pub description: &'static str,
}
pub const LEVELS: [Level; 5] = [
    Level {
        id: "very_lenient",
        label: "Very tolerant",
        threshold: 99.5,
        description: "Reserves the Spam ranking to the highest and confirmed indices.",
    },
    Level {
        id: "lenient",
        label: "Lenient",
        threshold: 98.0,
        description: "Limit spam rankings; more messages remain below the threshold.",
    },
    Level {
        id: "balanced",
        label: "Balanced",
        threshold: 95.0,
        description: "Starting point to adjust with your message corrections.",
    },
    Level {
        id: "strict",
        label: "Strict",
        threshold: 90.0,
        description: "Examine more suspicious messages; watch for false positives.",
    },
    Level {
        id: "very_strict",
        label: "Very strict",
        threshold: 85.0,
        description: "Maximum sensitivity of presettings; requires error tracking.",
    },
];

pub fn sensitivity_locked(cfg: &Config) -> bool {
    cfg.fusion
        .as_ref()
        .is_some_and(|f| f.mode == crate::fusion::runtime::Mode::Decision)
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Ordering {
    #[default]
    LegacyPriority,
    Scoped,
}
impl Ordering {
    pub fn is_legacy(&self) -> bool {
        *self == Self::LegacyPriority
    }
}
/// Trusted, ephemeral composition metadata. It is never accepted in Web or disk
/// policies: personal authority is assigned only by preferences::Settings.
#[derive(Clone, Debug, Default, Serialize, PartialEq)]
pub struct Origins {
    pub rules: BTreeMap<String, String>,
    pub profiles: BTreeMap<String, String>,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default, skip_serializing_if = "Ordering::is_legacy")]
    pub ordering: Ordering,
    #[serde(skip)]
    pub origins: Origins,
    #[serde(default)]
    pub profiles: Vec<Profile>,
    #[serde(default)]
    pub bindings: Vec<Binding>,
    #[serde(default)]
    pub rules: Vec<Rule>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub id: String,
    pub name: String,
    /// None inherits the next less-specific threshold, then the model threshold.
    /// This post-analysis operating point never changes model or LLM selection.
    pub threshold: Option<f64>,
    pub require_corroboration: bool,
    pub spam: Action,
    pub publicity: Action,
    pub review: Action,
    pub quarantine_days: u16,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub scope: String,
    pub profile: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub priority: u16,
    pub scope: String,
    pub expires: Option<i64>,
    pub any: bool,
    pub conditions: Vec<Condition>,
    pub category: Option<Category>,
    pub action: Option<Action>,
    pub stop: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Condition {
    pub field: Field,
    pub op: Operator,
    pub value: String,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Field {
    EnvelopeFrom,
    FromDomain,
    HeaderFrom,
    Subject,
    Body,
    Recipient,
    RecipientDomain,
    Size,
    Score,
    Category,
    Signal,
    Dmarc,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Operator {
    Equals,
    Contains,
    StartsWith,
    EndsWith,
    Present,
    Absent,
    AtLeast,
    AtMost,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Facts {
    pub values: BTreeMap<Field, Vec<String>>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Hit {
    pub id: String,
    pub name: String,
    pub fields: Vec<Field>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Assessment {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace: Option<crate::policy_trace::Trace>,
    pub policy: String,
    pub profile: Option<String>,
    pub threshold: f64,
    pub original_category: Category,
    pub category: Category,
    pub matched: Vec<Hit>,
    pub unavailable_conditions: usize,
    pub action: Applied,
}
pub(crate) fn scope_rank(scope: &str, recipient: &Recipient) -> Option<u8> {
    if scope == "*" {
        return Some(0);
    }
    let original = recipient.address.clone();
    let destination = recipient.destination.clone();
    if scope == original {
        return Some(4);
    }
    if scope == destination {
        return Some(3);
    }
    if let Some(domain) = scope.strip_prefix("*@") {
        if original.rsplit_once('@').is_some_and(|(_, d)| d == domain) {
            return Some(2);
        }
        if destination
            .rsplit_once('@')
            .is_some_and(|(_, d)| d == domain)
        {
            return Some(1);
        }
    }
    None
}
fn valid_scope(scope: &str, cfg: &Config) -> bool {
    scope == "*"
        || if let Some(d) = scope.strip_prefix("*@") {
            cfg.domains.iter().any(|domain| domain.name == d)
        } else {
            cfg.recipient(scope).is_some_and(|r| r.address == scope)
        }
}

fn text_valid(s: &str, max: usize) -> bool {
    !s.trim().is_empty() && s.len() <= max && !s.chars().any(char::is_control)
}
impl Policy {
    pub fn validate(&self, cfg: &Config) -> Result<()> {
        ensure!(
            self.profiles.len() <= 32 && self.bindings.len() <= 1000 && self.rules.len() <= 100,
            "Maximum: 32 profiles, 1,000 assignments, 100 rules."
        );
        let mut ids = HashSet::new();
        for p in &self.profiles {
            ensure!(
                text_valid(&p.id, 64) && text_valid(&p.name, 100) && ids.insert(&p.id),
                "Profile invalid or duplicated."
            );
            ensure!(
                (1..=30).contains(&p.quarantine_days),
                "Quarantine: 1 to 30 days."
            );
            ensure!(
                p.review != Action::Tag,
                "A classification to be examined cannot be marked SPAM/PUB."
            );
            if let Some(t) = p.threshold {
                ensure!(
                    t.is_finite() && (50.0..=100.0).contains(&t),
                    "Threshold: 50 to 100."
                );
                ensure!(
                    !sensitivity_locked(cfg),
                    "Validated fusion has its own threshold: choose Inherit."
                );
            }
        }
        let mut scopes = HashSet::new();
        for b in &self.bindings {
            ensure!(
                valid_scope(&b.scope, cfg) && scopes.insert(&b.scope) && ids.contains(&b.profile),
                "Unknown, invalid or duplicated assignment."
            );
        }
        ids.clear();
        for r in &self.rules {
            ensure!(
                text_valid(&r.id, 64)
                    && text_valid(&r.name, 100)
                    && ids.insert(&r.id)
                    && valid_scope(&r.scope, cfg),
                "Invalid/duplicated rule or scope."
            );
            ensure!(
                (1..=8).contains(&r.conditions.len())
                    && (r.category.is_some() || r.action.is_some()),
                "A rule requires 1 to 8 conditions and an effect."
            );
            ensure!(r.expires.is_none_or(|e| e > 0), "Expiration invalide.");
            ensure!(
                !(r.action == Some(Action::Tag)
                    && r.category
                        .is_some_and(|c| !matches!(c, Category::Spam | Category::Publicity))),
                "Marking requires SPAM or PUB."
            );
            for c in &r.conditions {
                ensure!(
                    c.value.len() <= 256 && !c.value.chars().any(char::is_control),
                    "Invalid condition value (maximum 256 bytes)."
                );
                if matches!(c.op, Operator::AtLeast | Operator::AtMost) {
                    ensure!(
                        matches!(c.field, Field::Score | Field::Size)
                            && c.value
                                .parse::<f64>()
                                .is_ok_and(|n| n.is_finite() && n >= 0.0),
                        "Invalid numerical comparison."
                    );
                } else if !matches!(c.op, Operator::Present | Operator::Absent) {
                    ensure!(!c.value.is_empty(), "Condition value is empty.");
                }
            }
        }
        Ok(())
    }
    pub fn tags(&self) -> (bool, bool) {
        let rule_tag = |category| {
            self.rules.iter().any(|r| {
                r.enabled
                    && r.action == Some(Action::Tag)
                    && (r.category.is_none() || r.category == Some(category))
            })
        };
        (
            rule_tag(Category::Spam) || self.profiles.iter().any(|p| p.spam == Action::Tag),
            rule_tag(Category::Publicity)
                || self.profiles.iter().any(|p| p.publicity == Action::Tag),
        )
    }
}
impl Facts {
    pub fn message(raw: &[u8], sender: &str, scan: &Scan, limit: usize) -> Self {
        let mut f = Self::metadata(sender, scan);
        f.put(Field::Size, &raw.len().to_string());
        if raw.len() <= limit
            && let Some(m) = mail_parser::MessageParser::default().parse(raw)
            && m.parts.len() <= 200
        {
            f.put(Field::Subject, m.subject().unwrap_or(""));
            f.put(
                Field::HeaderFrom,
                m.from()
                    .and_then(|a| a.first())
                    .and_then(|a| a.address())
                    .unwrap_or(""),
            );
            let mut body = String::new();
            let mut complete =
                m.text_body_count() <= 20 && (m.text_body_count() > 0 || m.html_body_count() == 0);
            for i in 0..m.text_body_count().min(20) {
                if let Some(text) = m.body_text(i) {
                    if body.len() + text.len() > 100_000 {
                        complete = false;
                        break;
                    }
                    body.push_str(&text);
                    body.push('\n');
                }
            }
            if complete {
                f.put(Field::Body, &body);
            }
        }
        f
    }
    /// Retained metadata only. Missing body/size/header facts stay unknown;
    /// absence of a retained field must not satisfy a negative rule.
    pub fn metadata(sender: &str, scan: &Scan) -> Self {
        let mut f = Self::default();
        f.put(Field::EnvelopeFrom, sender);
        f.put(
            Field::FromDomain,
            sender.rsplit_once('@').map(|(_, d)| d).unwrap_or(""),
        );
        if crate::assessment::valid_score(Some(scan.score)).is_some()
            && scan.features_complete != Some(false)
        {
            f.put(Field::Score, &scan.score.to_string());
        }
        f.put(
            Field::Category,
            crate::mailing::category(scan, 95.0).as_str(),
        );
        // Missing checks remain unknown, including negative conditions.
        if scan.complete {
            f.values.insert(
                Field::Signal,
                scan.reasons.iter().map(|s| s.id.clone()).collect(),
            );
        }
        if let Some(e) = &scan.evidence {
            use crate::evidence::{AuthResult, State};
            let a = &e.authentication;
            if a.dmarc_state == State::Complete {
                let results = [a.dmarc_spf, a.dmarc_dkim];
                let result = if results.contains(&Some(AuthResult::Pass)) {
                    Some("pass")
                } else if results.iter().all(|r| *r == Some(AuthResult::Fail)) {
                    Some("fail")
                } else {
                    None
                };
                if let Some(result) = result {
                    f.put(Field::Dmarc, result);
                }
            }
        }

        if scan.features_complete == Some(true) {
            // Engine history keeps at most 500 subject characters. At the bound
            // it is unknown whether a suffix was discarded; do not use it as a
            // complete fact for equals/ends_with or negative conditions.
            if scan.subject.chars().count() < 500 {
                f.put(Field::Subject, &scan.subject);
            }
            f.put(Field::HeaderFrom, &scan.sender);
        }
        f
    }
    pub fn put(&mut self, field: Field, value: &str) {
        self.values.insert(field, vec![value.to_owned()]);
    }
    pub fn matches(&self, c: &Condition) -> Option<bool> {
        let values = self.values.get(&c.field)?;
        if c.op == Operator::Present {
            return Some(values.iter().any(|s| !s.is_empty()));
        }
        if c.op == Operator::Absent {
            return Some(values.iter().all(|s| s.is_empty()));
        }
        let target = c.value.to_lowercase();
        Some(values.iter().any(|v| {
            let value = v.to_lowercase();
            match c.op {
                Operator::Equals => value == target,
                Operator::Contains => value.contains(&target),
                Operator::StartsWith => value.starts_with(&target),
                Operator::EndsWith => value.ends_with(&target),
                Operator::AtLeast | Operator::AtMost => value
                    .parse::<f64>()
                    .ok()
                    .zip(target.parse::<f64>().ok())
                    .is_some_and(|(v, t)| {
                        if c.op == Operator::AtLeast {
                            v >= t
                        } else {
                            v <= t
                        }
                    }),
                _ => false,
            }
        }))
    }
}
/// Common conditions (including MIME text) are matched once for the whole SMTP transaction.
pub struct Prepared {
    matches: Vec<Vec<Option<bool>>>,
    digest: String,
}
impl Prepared {
    pub fn new(policy: &Policy, facts: &Facts) -> Self {
        Self {
            matches: policy
                .rules
                .iter()
                .map(|r| r.conditions.iter().map(|c| facts.matches(c)).collect())
                .collect(),
            digest: crate::message::digest(&serde_json::to_vec(&serde_json::json!({"evaluator":crate::policy_trace::VERSION,"policy":policy,"origins":policy.origins})).expect("typed policy")),
        }
    }
}
pub fn assess(
    policy: &Policy,
    cfg: &Config,
    scan: &Scan,
    facts: &Facts,
    recipient: &Recipient,
    at: i64,
) -> Assessment {
    let prepared = Prepared::new(policy, facts);
    assess_prepared(policy, cfg, scan, &prepared, recipient, at)
}
pub fn assess_prepared(
    policy: &Policy,
    cfg: &Config,
    scan: &Scan,
    prepared: &Prepared,
    recipient: &Recipient,
    at: i64,
) -> Assessment {
    let mut f = Facts::default();
    f.put(Field::Recipient, &recipient.address);
    f.put(
        Field::RecipientDomain,
        recipient
            .address
            .rsplit_once('@')
            .map(|(_, d)| d)
            .unwrap_or(""),
    );
    let mut resolved = scan.clone();
    crate::decision::finalize(&mut resolved, cfg.filter.threshold);
    let original = crate::mailing::category(&resolved, cfg.filter.threshold);
    f.put(Field::Category, original.as_str());
    if policy.ordering == Ordering::Scoped
        && let Some(score) = crate::assessment::assess(scan, cfg.filter.threshold)
            .score
            .value
    {
        // Scoped policies use the same selected index as the receipt and UI.
        // Legacy rules retain their original content-index semantics.
        f.put(Field::Score, &score.to_string());
    }
    let mut profiles: Vec<_> = policy
        .bindings
        .iter()
        .filter_map(|b| {
            Some((
                scope_rank(&b.scope, recipient)?,
                policy.profiles.iter().find(|p| p.id == b.profile)?,
                b.scope.as_str(),
            ))
        })
        .collect();
    profiles.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then_with(|| {
                if policy.ordering == Ordering::Scoped {
                    policy
                        .origins
                        .profiles
                        .contains_key(&b.1.id)
                        .cmp(&policy.origins.profiles.contains_key(&a.1.id))
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .then_with(|| a.1.id.cmp(&b.1.id))
    });
    let profile = profiles.first().map(|(_, p, _)| *p);
    // Defensive runtime guard as well as configuration validation: never turn a
    // fusion abstention into a legacy decision, even with an unchecked policy.
    let override_threshold = profiles
        .iter()
        .find_map(|(_, p, _)| p.threshold)
        .filter(|t| {
            !sensitivity_locked(cfg)
                && scan
                    .decision
                    .as_ref()
                    .is_none_or(|d| d.source == crate::fusion::runtime::DecisionSource::Legacy)
                && t.is_finite()
                && (50.0..=100.0).contains(t)
                && scan.score.is_finite()
                && (0.0..=100.0).contains(&scan.score)
        });
    let threshold = override_threshold.unwrap_or(cfg.filter.threshold);
    let mut trace = crate::policy_trace::Trace {
        version: crate::policy_trace::VERSION.into(),
        ordering: policy.ordering,
        profiles: profiles
            .iter()
            .enumerate()
            .map(|(i, (_, p, scope))| crate::policy_trace::Profile {
                id: p.id.clone(),
                name: p.name.clone(),
                scope: (*scope).into(),
                origin: if policy.origins.profiles.contains_key(&p.id) {
                    crate::policy_trace::Origin::Personal
                } else {
                    crate::policy_trace::Origin::Administrator
                },
                threshold: p.threshold,
                selected: i == 0,
            })
            .collect(),
        threshold_profile: override_threshold.and_then(|_| {
            profiles
                .iter()
                .find(|(_, p, _)| p.threshold.is_some())
                .map(|(_, p, _)| p.id.clone())
        }),
        threshold_locked: sensitivity_locked(cfg)
            || scan
                .decision
                .as_ref()
                .is_some_and(|d| d.source != crate::fusion::runtime::DecisionSource::Legacy),
        rules: Vec::new(),
        stopped_by: None,
        category_rule: None,
        action_rule: None,
        malware_override: false,
    };
    let mut category = original;
    if let Some(p) = profile {
        let mut candidate = scan.clone();
        if override_threshold.is_some() {
            candidate.arbitration = None;
            candidate.score_resolution = None;
            candidate.delivery_classification = None;
            candidate.decision = Some(crate::fusion::runtime::Decision::legacy(scan, threshold));
        }
        crate::decision::apply(
            &mut candidate,
            cfg.filter.require_corroboration
                || p.require_corroboration
                || override_threshold.is_some(),
        );
        crate::decision::finalize(&mut candidate, threshold);
        category = crate::mailing::category(&candidate, threshold);
    }
    let global = crate::actions::Policy::from_config(cfg);
    let choose = |c| match (profile, c) {
        (Some(p), Category::Spam) => p.spam,
        (Some(p), Category::Publicity) => p.publicity,
        (Some(p), Category::Undetermined) => p.review,
        (_, Category::Spam) => global.spam,
        (_, Category::Publicity) => global.publicity,
        _ => Action::Deliver,
    };
    let mut requested = choose(category);
    let mut matched = Vec::new();
    let mut unavailable_conditions = 0;
    let mut rules: Vec<_> = policy
        .rules
        .iter()
        .enumerate()
        .filter(|(_, r)| {
            r.enabled
                && r.expires.is_none_or(|t| t > at)
                && scope_rank(&r.scope, recipient).is_some()
        })
        .collect();
    rules.sort_by(|(_, a), (_, b)| {
        let scope_order = if policy.ordering == Ordering::Scoped {
            // Personal rules cannot stop administrator rules or override them.
            (
                !policy.origins.rules.contains_key(&a.id),
                scope_rank(&a.scope, recipient),
            )
                .cmp(&(
                    !policy.origins.rules.contains_key(&b.id),
                    scope_rank(&b.scope, recipient),
                ))
        } else {
            std::cmp::Ordering::Equal
        };
        scope_order.then_with(|| {
            (a.priority, policy.origins.rules.get(&a.id).unwrap_or(&a.id))
                .cmp(&(b.priority, policy.origins.rules.get(&b.id).unwrap_or(&b.id)))
                .then_with(|| a.id.cmp(&b.id))
        })
    });
    for (index, r) in rules {
        let mut step = crate::policy_trace::Rule {
            id: r.id.clone(),
            name: r.name.clone(),
            scope: r.scope.clone(),
            origin: if policy.origins.rules.contains_key(&r.id) {
                crate::policy_trace::Origin::Personal
            } else {
                crate::policy_trace::Origin::Administrator
            },
            priority: r.priority,
            outcome: crate::policy_trace::Outcome::Stopped,
            unavailable: Vec::new(),
            category_before: category,
            category_after: category,
            action_before: requested,
            action_after: requested,
            stop: r.stop,
        };
        if trace.stopped_by.is_some() {
            trace.rules.push(step);
            continue;
        }
        let values: Vec<_> = r
            .conditions
            .iter()
            .enumerate()
            .map(|(i, c)| {
                if matches!(
                    c.field,
                    Field::Recipient | Field::RecipientDomain | Field::Category
                ) || (policy.ordering == Ordering::Scoped && c.field == Field::Score)
                {
                    f.matches(c)
                } else {
                    prepared.matches[index][i]
                }
            })
            .collect();
        unavailable_conditions += values.iter().filter(|v| v.is_none()).count();
        let hit = if r.any {
            values.contains(&Some(true))
        } else {
            values.iter().all(|v| *v == Some(true))
        };
        step.unavailable = r
            .conditions
            .iter()
            .zip(&values)
            .filter(|(_, v)| v.is_none())
            .map(|(c, _)| c.field)
            .collect();
        if !hit {
            step.outcome = if step.unavailable.is_empty() {
                crate::policy_trace::Outcome::NoMatch
            } else {
                crate::policy_trace::Outcome::MissingFacts
            };
            trace.rules.push(step);
            continue;
        }
        step.outcome = crate::policy_trace::Outcome::Matched;
        if let Some(c) = r.category {
            trace.category_rule = Some(r.id.clone());
            trace.action_rule = Some(r.id.clone());
            category = if c == Category::Undetermined {
                let mut candidate = scan.clone();
                candidate.score_resolution = None;
                candidate.delivery_classification = Some(Category::Undetermined);
                crate::decision::resolve_by_score(&mut candidate, true, threshold);
                crate::mailing::category(&candidate, threshold)
            } else {
                c
            };
            requested = choose(category);
        }
        if let Some(a) = r.action {
            trace.action_rule = Some(r.id.clone());
            requested = a;
        }
        matched.push(Hit {
            id: r.id.clone(),
            name: r.name.clone(),
            fields: r.conditions.iter().map(|c| c.field).collect(),
        });
        step.category_after = category;
        step.action_after = requested;
        trace.rules.push(step);
        if r.stop {
            trace.stopped_by = Some(r.id.clone());
        }
    }
    let malware = scan.antivirus.status == crate::antivirus::AntivirusStatus::Malware;
    if malware {
        trace.malware_override = true;
        trace.category_rule = None;
        trace.action_rule = None;
        category = Category::Spam;
        requested = global.malware;
    }
    let action = crate::actions::constrain(
        scan,
        cfg,
        category,
        requested,
        profile
            .map(|p| p.quarantine_days)
            .unwrap_or(global.quarantine_days),
        crate::action_coverage::Context {
            threshold,
            matched_rule: !matched.is_empty(),
            reason: if malware {
                "malware_priority"
            } else {
                "custom_policy"
            },
        },
    );
    Assessment {
        trace: Some(trace),
        policy: prepared.digest.clone(),
        profile: profile.map(|p| p.name.clone()),
        threshold,
        original_category: original,
        category,
        matched,
        unavailable_conditions,
        action,
    }
}

/// A separate what-if result. The caller supplies frozen available facts and an
/// evaluation time; no detector, DNS query, delivery or history mutation occurs.
pub fn simulate(
    policy: &Policy,
    cfg: &Config,
    received: &Scan,
    sender: &str,
    recipient: &Recipient,
    at: i64,
) -> Assessment {
    let mut candidate = received.clone();
    if let Some(record) = &received.analysis_result {
        candidate.score = record.score.raw.unwrap_or(-1.);
        candidate.reasons = record.reasons.clone();
        candidate.decision = Some(record.detector_decision.clone());
    }
    candidate.analysis_result = None;
    candidate.recipient_decision = None;
    candidate.delivery_classification = None;
    candidate.action = None;
    candidate.arbitration = None;
    candidate.score_resolution = None;
    candidate.tagged = false;
    candidate.pub_tagged = false;
    if candidate
        .decision
        .as_ref()
        .is_none_or(|d| d.source == crate::fusion::runtime::DecisionSource::Legacy)
    {
        candidate.decision = Some(crate::fusion::runtime::Decision::legacy(
            &candidate,
            cfg.filter.threshold,
        ));
    }
    crate::decision::apply(&mut candidate, cfg.filter.require_corroboration);
    crate::decision::finalize(&mut candidate, cfg.filter.threshold);
    let facts = Facts::metadata(sender, &candidate);
    let effective = cfg.preferences.policy(policy, recipient);
    assess(&effective, cfg, &candidate, &facts, recipient, at)
}
