//! Bounded administrator rules, evaluated after the common detector pipeline.
//! Facts are ephemeral; recipient assessments contain no message body or rule values.
use crate::{
    actions::{Action, Applied},
    config::{Config, Mode, Recipient},
    engine::Scan,
    mailing::Category,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Policy {
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
    /// None inherits the validated global threshold. Never override fusion calibration.
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
    pub policy: String,
    pub profile: Option<String>,
    pub threshold: f64,
    pub original_category: Category,
    pub category: Category,
    pub matched: Vec<Hit>,
    pub unavailable_conditions: usize,
    pub action: Applied,
}
fn scope_rank(scope: &str, recipient: &Recipient) -> Option<u8> {
    if scope == "*" {
        return Some(0);
    }
    let original = recipient.address.to_ascii_lowercase();
    let destination = recipient.destination.to_ascii_lowercase();
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
        || (scope == scope.to_ascii_lowercase()
            && if let Some(d) = scope.strip_prefix("*@") {
                cfg.domains.iter().any(|domain| domain.name == d)
            } else {
                cfg.recipient(scope).is_some()
            })
}
fn text_valid(s: &str, max: usize) -> bool {
    !s.trim().is_empty() && s.len() <= max && !s.chars().any(char::is_control)
}
impl Policy {
    pub fn validate(&self, cfg: &Config) -> Result<()> {
        ensure!(
            self.profiles.len() <= 32 && self.bindings.len() <= 1000 && self.rules.len() <= 100,
            "Maximum : 32 profils, 1 000 affectations, 100 règles."
        );
        let mut ids = HashSet::new();
        for p in &self.profiles {
            ensure!(
                text_valid(&p.id, 64) && text_valid(&p.name, 100) && ids.insert(&p.id),
                "Profil invalide ou dupliqué."
            );
            ensure!(
                (1..=30).contains(&p.quarantine_days),
                "Quarantaine : 1 à 30 jours."
            );
            ensure!(
                p.review != Action::Tag,
                "Un classement à examiner ne peut pas être marqué SPAM/PUB."
            );
            if let Some(t) = p.threshold {
                ensure!(
                    t.is_finite() && (50.0..=100.0).contains(&t),
                    "Seuil : 50 à 100."
                );
                ensure!(
                    cfg.filter.semantic.is_none()
                        && !cfg
                            .fusion
                            .as_ref()
                            .is_some_and(|f| f.mode == crate::fusion::runtime::Mode::Decision),
                    "Le seuil du modèle calibré doit être hérité."
                );
            }
        }
        let mut scopes = HashSet::new();
        for b in &self.bindings {
            ensure!(
                valid_scope(&b.scope, cfg) && scopes.insert(&b.scope) && ids.contains(&b.profile),
                "Affectation inconnue, invalide ou dupliquée."
            );
        }
        ids.clear();
        for r in &self.rules {
            ensure!(
                text_valid(&r.id, 64)
                    && text_valid(&r.name, 100)
                    && ids.insert(&r.id)
                    && valid_scope(&r.scope, cfg),
                "Règle ou portée invalide/dupliquée."
            );
            ensure!(
                (1..=8).contains(&r.conditions.len())
                    && (r.category.is_some() || r.action.is_some()),
                "Une règle nécessite 1 à 8 conditions et un effet."
            );
            ensure!(r.expires.is_none_or(|e| e > 0), "Expiration invalide.");
            ensure!(
                !(r.action == Some(Action::Tag)
                    && r.category
                        .is_some_and(|c| !matches!(c, Category::Spam | Category::Publicity))),
                "Le marquage nécessite SPAM ou PUB."
            );
            for c in &r.conditions {
                ensure!(
                    c.value.len() <= 256 && !c.value.chars().any(char::is_control),
                    "Valeur de condition invalide (256 octets maximum)."
                );
                if matches!(c.op, Operator::AtLeast | Operator::AtMost) {
                    ensure!(
                        matches!(c.field, Field::Score | Field::Size)
                            && c.value
                                .parse::<f64>()
                                .is_ok_and(|n| n.is_finite() && n >= 0.0),
                        "Comparaison numérique invalide."
                    );
                } else if !matches!(c.op, Operator::Present | Operator::Absent) {
                    ensure!(!c.value.is_empty(), "Valeur de condition vide.");
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
        let mut f = Self::default();
        f.put(Field::EnvelopeFrom, sender);
        f.put(
            Field::FromDomain,
            sender.rsplit_once('@').map(|(_, d)| d).unwrap_or(""),
        );
        f.put(Field::Size, &raw.len().to_string());
        f.put(Field::Score, &scan.score.to_string());
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
            digest: crate::message::digest(&serde_json::to_vec(policy).unwrap_or_default()),
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
    let original = crate::mailing::category(scan, cfg.filter.threshold);
    f.put(Field::Category, original.as_str());
    let profile = policy
        .bindings
        .iter()
        .filter_map(|b| scope_rank(&b.scope, recipient).map(|rank| (rank, b)))
        .max_by_key(|(rank, _)| *rank)
        .and_then(|(_, b)| policy.profiles.iter().find(|p| p.id == b.profile));
    let threshold = profile
        .and_then(|p| p.threshold)
        .unwrap_or(cfg.filter.threshold);
    let mut category = original;
    if scan.complete
        && let Some(p) = profile
    {
        let mut candidate = scan.clone();
        if p.threshold.is_some() {
            candidate.decision = Some(crate::fusion::runtime::Decision::legacy(scan, threshold));
        }
        crate::decision::apply(
            &mut candidate,
            cfg.filter.require_corroboration || p.require_corroboration,
        );
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
    rules.sort_by(|(_, a), (_, b)| (a.priority, &a.id).cmp(&(b.priority, &b.id)));
    for (index, r) in rules {
        let values: Vec<_> = r
            .conditions
            .iter()
            .enumerate()
            .map(|(i, c)| {
                if matches!(
                    c.field,
                    Field::Recipient | Field::RecipientDomain | Field::Category
                ) {
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
        if !hit {
            continue;
        }
        if let Some(c) = r.category {
            category = c;
            requested = choose(category);
        }
        if let Some(a) = r.action {
            requested = a;
        }
        matched.push(Hit {
            id: r.id.clone(),
            name: r.name.clone(),
            fields: r.conditions.iter().map(|c| c.field).collect(),
        });
        if r.stop {
            break;
        }
    }
    let malware = scan.antivirus.status == crate::antivirus::AntivirusStatus::Malware;
    if malware {
        category = Category::Spam;
        requested = global.malware;
    }
    let (effective, reason) = if cfg.filter.mode == Mode::Observe {
        (Action::Deliver, "observation")
    } else if !scan.complete && !(malware && requested == Action::Quarantine) {
        (Action::Deliver, "incomplete")
    } else if requested == Action::Tag && !matches!(category, Category::Spam | Category::Publicity)
    {
        (Action::Deliver, "category_without_prefix")
    } else {
        (
            requested,
            if malware {
                "malware_priority"
            } else {
                "custom_policy"
            },
        )
    };
    Assessment {
        policy: prepared.digest.clone(),
        profile: profile.map(|p| p.name.clone()),
        threshold,
        original_category: original,
        category,
        matched,
        unavailable_conditions,
        action: Applied {
            requested,
            effective,
            reason: reason.into(),
            quarantine_days: profile
                .map(|p| p.quarantine_days)
                .unwrap_or(global.quarantine_days),
        },
    }
}
