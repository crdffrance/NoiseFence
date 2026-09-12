//! Named symbols, compiled multi-pattern matching and deterministic composites.
use super::input::Input;
use anyhow::{Result, ensure};
use regex::{Regex, RegexBuilder, RegexSet, RegexSetBuilder};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Family {
    Lexical,
    Semantic,
    Content,
    Authentication,
    Reputation,
    Smtp,
    Llm,
    Campaign,
    Bayes,
    Other,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Bounds {
    pub min: f64,
    pub max: f64,
}
pub fn default_caps() -> BTreeMap<Family, Bounds> {
    use Family::*;
    [
        (Lexical, -1.5, 1.5),
        (Semantic, -0.5, 0.5),
        (Content, -0.5, 1.5),
        (Authentication, -0.5, 1.0),
        (Reputation, 0.0, 3.0),
        (Smtp, -0.5, 0.5),
        (Llm, -1.0, 1.0),
        (Campaign, -0.5, 1.5),
        (Bayes, -1.0, 1.0),
        (Other, 0.0, 0.5),
    ]
    .into_iter()
    .map(|(family, min, max)| (family, Bounds { min, max }))
    .collect()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Symbol {
    pub id: String,
    pub label: String,
    pub family: Family,
    pub weight: f64,
    pub absorbed_by: Vec<String>,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Target {
    Subject,
    Body,
    Html,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Pattern {
    pub id: String,
    pub label: String,
    pub family: Family,
    pub weight: f64,
    pub target: Target,
    pub pattern: String,
    /// Ignore individually negated requests in French/English; never an allowlist.
    #[serde(default)]
    pub exclude_negated: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Composite {
    pub id: String,
    pub label: String,
    pub family: Family,
    pub weight: f64,
    #[serde(default)]
    pub all: Vec<String>,
    #[serde(default)]
    pub any: Vec<String>,
    #[serde(default)]
    pub none: Vec<String>,
    #[serde(default)]
    pub replace: Vec<String>,
}

fn name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}
fn metadata(id: &str, label: &str, weight: f64) -> Result<()> {
    ensure!(
        name(id)
            && label.chars().count() <= 160
            && !label.chars().any(char::is_control)
            && weight.is_finite()
            && (-5.0..=5.0).contains(&weight),
        "invalid native rule metadata"
    );
    Ok(())
}
pub fn default_patterns() -> Vec<Pattern> {
    [
        ("NF_URGENCY", "Vocabulaire d’urgence", 0.3, Target::Body, r"(?i)\b(?:urgent|immediately|immédiatement)\b"),
        ("NF_CREDENTIALS", "Demande de vérification de compte", 0.6, Target::Body, r"(?i)verify your account|confirmez votre compte|password expires|mot de passe expire"),
        ("NF_FINANCIAL", "Promesse de rendement", 0.5, Target::Body, r"(?i)guaranteed profit|profit garanti|million dollars|\blot(?:tery|erie)\b"),
        ("NF_WALLET_SECRET", "Demande liée à une phrase de récupération", 0.8, Target::Body, r"(?i)(?:enter|provide|saisir|saisissez|communiqu\p{L}*)[^.\n]{0,100}(?:seed phrase|recovery phrase|phrase de récupération)"),
        ("NF_FORM", "Formulaire HTML", 0.5, Target::Html, r"(?i)<\s*form\b"),
        ("NF_UNSUBSCRIBE", "Mention de désabonnement", 0.0, Target::Body, r"(?i)\bunsubscribe\b|désabonn\p{L}*"),
    ].into_iter().map(|(id,label,weight,target,pattern)| Pattern {
        id:id.into(), label:label.into(), family:Family::Content, weight, target, pattern:pattern.into(),
        exclude_negated:id=="NF_WALLET_SECRET"
    }).collect()
}
pub fn default_composites() -> Vec<Composite> {
    vec![
        Composite {
            id: "NF_AUTH_FAILURE".into(),
            label: "Échecs SPF et DMARC regroupés".into(),
            family: Family::Authentication,
            weight: 1.0,
            all: vec!["spf_fail".into(), "dmarc_fail".into()],
            any: vec![],
            none: vec![],
            replace: vec!["spf_fail".into(), "dmarc_fail".into()],
        },
        Composite {
            id: "NF_CREDENTIAL_LINK".into(),
            label: "Demande d’identifiants et lien suspect".into(),
            family: Family::Content,
            weight: 1.5,
            all: vec!["NF_CREDENTIALS".into()],
            any: vec!["ip_url".into(), "NF_DECEPTIVE_LINK".into()],
            none: vec![],
            replace: vec![
                "NF_CREDENTIALS".into(),
                "ip_url".into(),
                "NF_DECEPTIVE_LINK".into(),
            ],
        },
        Composite {
            id: "NF_WALLET_URGENCY".into(),
            label: "Phrase de récupération demandée avec urgence".into(),
            family: Family::Content,
            weight: 1.5,
            all: vec!["NF_WALLET_SECRET".into(), "NF_URGENCY".into()],
            any: vec![],
            none: vec![],
            replace: vec!["NF_WALLET_SECRET".into(), "NF_URGENCY".into()],
        },
    ]
}

/// A bounded matching view; original content and trained lexical features stay intact.
/// Do not collapse multilingual joiners or confusable alphabets into Latin letters.
fn match_text(text: &str) -> String {
    text.chars()
        .filter_map(|c| match c {
            '\u{200b}' | '\u{feff}' | '\u{00ad}' | '\u{2060}' => None,
            '\u{ff01}'..='\u{ff5e}' => char::from_u32(c as u32 - 0xfee0),
            '\u{00a0}' => Some(' '),
            '\u{2019}' => Some('\''),
            _ => Some(c),
        })
        .collect()
}
fn negated(text: &str, start: usize, matched: &str) -> bool {
    static BEFORE: OnceLock<Regex> = OnceLock::new();
    static INSIDE: OnceLock<Regex> = OnceLock::new();
    let before: String = text[..start]
        .chars()
        .rev()
        .take(80)
        .take_while(|c| !matches!(c, '.' | '!' | '?' | ';' | ':' | '\n'))
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    BEFORE
        .get_or_init(|| {
            Regex::new(
                r"(?i)\b(?:never(?:\s+ever)?|do\s+not|don't|ne\s+pas)\s+(?:[\p{L}']+\s+){0,4}$",
            )
            .unwrap()
        })
        .is_match(&before)
        || INSIDE
            .get_or_init(|| Regex::new(r"(?i)^\p{L}+\s+(?:jamais|pas)\b").unwrap())
            .is_match(matched)
}

type MatchGroup = (Target, RegexSet, Vec<(Pattern, Option<Regex>)>);
pub struct Matcher {
    sets: Vec<MatchGroup>,
}
impl Matcher {
    pub fn compile(patterns: &[Pattern]) -> Result<Self> {
        ensure!(patterns.len() <= 256, "native pattern count limit");
        let mut ids = BTreeSet::new();
        let mut groups: BTreeMap<Target, Vec<Pattern>> = BTreeMap::new();
        for rule in patterns {
            metadata(&rule.id, &rule.label, rule.weight)?;
            ensure!(
                rule.pattern.len() <= 512 && ids.insert(&rule.id),
                "duplicate or oversized native pattern"
            );
            groups.entry(rule.target).or_default().push(rule.clone());
        }
        let mut sets = Vec::new();
        for (target, rules) in groups {
            let set = RegexSetBuilder::new(rules.iter().map(|r| &r.pattern))
                .size_limit(4 * 1024 * 1024)
                .dfa_size_limit(2 * 1024 * 1024)
                .nest_limit(32)
                .build()?;
            let rules = rules
                .into_iter()
                .map(|rule| {
                    let context = if rule.exclude_negated {
                        ensure!(
                            target == Target::Body,
                            "negation context requires a body pattern"
                        );
                        Some(
                            RegexBuilder::new(&rule.pattern)
                                .size_limit(4 * 1024 * 1024)
                                .dfa_size_limit(2 * 1024 * 1024)
                                .nest_limit(32)
                                .build()?,
                        )
                    } else {
                        None
                    };
                    Ok((rule, context))
                })
                .collect::<Result<Vec<_>>>()?;
            sets.push((target, set, rules));
        }
        Ok(Self { sets })
    }
    pub fn inspect(&self, input: &Input) -> Vec<Symbol> {
        let mut out = Vec::new();
        let subject = match_text(&input.subject);
        let body = match_text(&input.body);
        for (target, set, rules) in &self.sets {
            let text = match target {
                Target::Subject => &subject,
                Target::Body => &body,
                Target::Html => &input.html,
            };
            for index in set.matches(text) {
                let (rule, context) = &rules[index];
                if context.as_ref().is_some_and(|regex| {
                    !regex
                        .find_iter(text)
                        .any(|m| !negated(text, m.start(), m.as_str()))
                }) {
                    continue;
                }
                out.push(Symbol {
                    id: rule.id.clone(),
                    label: rule.label.clone(),
                    family: rule.family,
                    weight: rule.weight,
                    absorbed_by: vec![],
                });
            }
        }
        out
    }
}

pub struct Composites {
    ordered: Vec<Composite>,
}
impl Composites {
    pub fn compile(rules: &[Composite], patterns: &[Pattern]) -> Result<Self> {
        ensure!(rules.len() <= 64, "native composite count limit");
        let mut ids: BTreeSet<_> = patterns.iter().map(|r| r.id.clone()).collect();
        let reserved = context_symbols();
        ensure!(
            ids.iter().all(|id| !reserved.contains(id.as_str())),
            "pattern uses a reserved native symbol"
        );
        for rule in rules {
            metadata(&rule.id, &rule.label, rule.weight)?;
            ensure!(
                ids.insert(rule.id.clone()) && !reserved.contains(rule.id.as_str()),
                "duplicate native symbol"
            );
            ensure!(
                !rule.all.is_empty() || !rule.any.is_empty(),
                "composite needs positive evidence"
            );
            ensure!(
                rule.all.len() + rule.any.len() + rule.none.len() + rule.replace.len() <= 32,
                "native composite complexity limit"
            );
            let positive: BTreeSet<_> = rule.all.iter().chain(&rule.any).collect();
            ensure!(
                rule.replace.iter().all(|id| positive.contains(id))
                    && rule.none.iter().all(|id| !positive.contains(id)),
                "invalid composite replacement or contradictory condition"
            );
            ensure!(
                rule.none
                    .iter()
                    .all(|id| patterns.iter().any(|p| &p.id == id)),
                "negative conditions require a completed local pattern, never an unavailable external check"
            );
        }
        for rule in rules {
            ensure!(
                rule.all
                    .iter()
                    .chain(&rule.any)
                    .chain(&rule.none)
                    .all(|id| ids.contains(id) || reserved.contains(id.as_str())),
                "unknown native composite dependency"
            );
        }
        let mut pending: BTreeMap<_, _> = rules.iter().map(|r| (r.id.clone(), r.clone())).collect();
        let mut ordered = Vec::new();
        while !pending.is_empty() {
            let ready: Vec<_> = pending
                .values()
                .filter(|r| {
                    r.all
                        .iter()
                        .chain(&r.any)
                        .chain(&r.none)
                        .all(|id| !pending.contains_key(id))
                })
                .map(|r| r.id.clone())
                .collect();
            ensure!(!ready.is_empty(), "cyclic native composites");
            for id in ready {
                ordered.push(pending.remove(&id).unwrap());
            }
        }
        Ok(Self { ordered })
    }
    pub fn apply(&self, symbols: Vec<Symbol>, caps: &BTreeMap<Family, Bounds>) -> Score {
        let mut map: BTreeMap<String, Symbol> = BTreeMap::new();
        for mut symbol in symbols {
            if !symbol.weight.is_finite() {
                continue;
            }
            symbol.absorbed_by.clear();
            // Idempotent evidence: repetitions do not increase the contribution.
            if map
                .get(&symbol.id)
                .is_none_or(|old| old.weight.abs() < symbol.weight.abs())
            {
                map.insert(symbol.id.clone(), symbol);
            }
        }
        for rule in &self.ordered {
            if rule.all.iter().all(|id| map.contains_key(id))
                && (rule.any.is_empty() || rule.any.iter().any(|id| map.contains_key(id)))
                && rule.none.iter().all(|id| !map.contains_key(id))
            {
                // Keep absorbed symbols available for dependency evaluation and
                // explanations; remove their weight exactly once in the final sum.
                for id in &rule.replace {
                    if let Some(symbol) = map.get_mut(id) {
                        symbol.absorbed_by.push(rule.id.clone());
                    }
                }
                map.insert(
                    rule.id.clone(),
                    Symbol {
                        id: rule.id.clone(),
                        label: rule.label.clone(),
                        family: rule.family,
                        weight: rule.weight,
                        absorbed_by: vec![],
                    },
                );
            }
        }
        let mut families: BTreeMap<Family, FamilyScore> = BTreeMap::new();
        for symbol in map.values().filter(|s| s.absorbed_by.is_empty()) {
            families.entry(symbol.family).or_default().raw += symbol.weight;
        }
        for (family, score) in &mut families {
            let bound = caps.get(family).expect("validated complete native caps");
            score.effective = score.raw.clamp(bound.min, bound.max);
            score.capped = score.raw != score.effective;
        }
        Score {
            total: families.values().map(|f| f.effective).sum(),
            symbols: map.into_values().collect(),
            families,
        }
    }
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FamilyScore {
    pub raw: f64,
    pub effective: f64,
    pub capped: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Score {
    pub total: f64,
    pub symbols: Vec<Symbol>,
    pub families: BTreeMap<Family, FamilyScore>,
}

fn context_symbols() -> BTreeSet<&'static str> {
    [
        "NF_LEXICAL",
        "NF_SEMANTIC",
        "NF_LLM",
        "NF_SMTP",
        "NF_FUZZY_SPAM",
        "NF_BAYES",
        "NF_DECEPTIVE_LINK",
        "NF_MALICIOUS_INDICATOR",
        "spf_fail",
        "dmarc_fail",
        "ip_reputation",
        "domain_reputation",
        "abused_domain_body",
        "idn_url",
        "ip_url",
        "reply_to",
        "caps_subject",
    ]
    .into_iter()
    .collect()
}
pub fn context(scan: &crate::engine::Scan) -> Vec<Symbol> {
    use Family::*;
    let mut out = Vec::new();
    let mut add = |id: &str, label: &str, family, weight| {
        out.push(Symbol {
            id: id.into(),
            label: label.into(),
            family,
            weight,
            absorbed_by: vec![],
        })
    };
    if let Some(logit) = scan.evidence.as_ref().and_then(|e| e.lexical_logit) {
        add("NF_LEXICAL", "Modèle lexical", Lexical, logit);
    }
    if scan.semantic.status == crate::engine::SemanticStatus::Complete
        && let Some(weight) = scan.semantic.contribution
    {
        add("NF_SEMANTIC", "Modèle sémantique", Semantic, weight);
    }
    for reason in &scan.reasons {
        let (id, family) = match reason.id.as_str() {
            "spf_fail" | "dmarc_fail" => (reason.id.as_str(), Authentication),
            "ip_reputation" | "domain_reputation" | "abused_domain_body" => {
                (reason.id.as_str(), Reputation)
            }
            "idn_url" | "ip_url" | "reply_to" | "caps_subject" => (reason.id.as_str(), Content),
            "llm_advisory" => ("NF_LLM", Llm),
            "smtp_policy_contribution" => ("NF_SMTP", Smtp),
            _ => continue,
        };
        // Do not expose untrusted provider excerpts through the new report.
        add(id, id, family, reason.weight);
    }
    if let Some(report) = &scan.protection {
        if report.findings.iter().any(|f| {
            matches!(
                f.id.as_str(),
                "known_phishing_url" | "known_malicious_indicator"
            )
        }) {
            add(
                "NF_MALICIOUS_INDICATOR",
                "Indicateur de réputation malveillante",
                Reputation,
                2.0,
            );
        }
        if report.findings.iter().any(|f| f.id == "misleading_link") {
            add(
                "NF_DECEPTIVE_LINK",
                "Destination de lien trompeuse",
                Content,
                0.8,
            );
        }
    }
    out
}
