//! Offline FR/EN regex observations. No delivery policy, I/O, or raw-text reports.
use anyhow::{Result, ensure};
use mail_parser::{HeaderName, MessageParser, MimeHeaders, PartType};
use regex::{Regex, RegexBuilder};
use scraper::{Html, Node};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const VERSION: &str = "heuristics-1";
/// Bump when built-ins, extraction, normalization, or matching semantics change.
pub const PATTERN_VERSION: &str = "heuristics-fr-en-1";

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Disabled,
    #[default]
    Observation,
    Contribute,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    Subject,
    From,
    ReplyTo,
    Body,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub label: String,
    pub family: String,
    pub scopes: Vec<Scope>,
    /// Rust regex syntax; case sensitive unless the pattern includes (?i).
    pub pattern: String,
    /// Applied once per matching rule, never multiplied by occurrences.
    pub candidate_weight: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub max_rules: usize,
    pub max_pattern_bytes: usize,
    pub max_total_pattern_bytes: usize,
    pub regex_size_limit: usize,
    pub regex_dfa_size_limit: usize,
    pub regex_nest_limit: u32,
    pub max_raw_bytes: usize,
    pub max_header_bytes: usize,
    pub max_headers: usize,
    pub max_parts: usize,
    pub max_part_bytes: usize,
    pub max_input_bytes: usize,
    pub max_segments: usize,
    pub max_html_nodes: usize,
    pub max_matches_per_rule: usize,
    pub max_total_matches: usize,
    pub max_findings: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_rules: 64,
            max_pattern_bytes: 2048,
            max_total_pattern_bytes: 32 * 1024,
            regex_size_limit: 1024 * 1024,
            regex_dfa_size_limit: 256 * 1024,
            regex_nest_limit: 32,
            max_raw_bytes: 1024 * 1024,
            max_header_bytes: 32 * 1024,
            max_headers: 200,
            max_parts: 128,
            max_part_bytes: 128 * 1024,
            max_input_bytes: 64 * 1024,
            max_segments: 64,
            max_html_nodes: 16_384,
            max_matches_per_rule: 8,
            max_total_matches: 128,
            max_findings: 64,
        }
    }
}

impl Limits {
    fn validate(&self) -> Result<()> {
        for (value, ceiling) in [
            (self.max_rules, 64),
            (self.max_pattern_bytes, 4096),
            (self.max_total_pattern_bytes, 64 * 1024),
            (self.regex_size_limit, 2 * 1024 * 1024),
            (self.regex_dfa_size_limit, 1024 * 1024),
            (self.regex_nest_limit as usize, 64),
            (self.max_raw_bytes, 4 * 1024 * 1024),
            (self.max_header_bytes, 64 * 1024),
            (self.max_headers, 1000),
            (self.max_parts, 256),
            (self.max_part_bytes, 256 * 1024),
            (self.max_input_bytes, 256 * 1024),
            (self.max_segments, 128),
            (self.max_html_nodes, 32_768),
            (self.max_matches_per_rule, 32),
            (self.max_total_matches, 512),
            (self.max_findings, 64),
        ] {
            ensure!(
                (1..=ceiling).contains(&value),
                "heuristics limit outside permitted range"
            );
        }
        ensure!(
            self.max_rules * self.regex_size_limit <= 64 * 1024 * 1024
                && self.max_rules * self.regex_dfa_size_limit <= 32 * 1024 * 1024,
            "heuristics aggregate regex budget exceeded"
        );
        Ok(())
    }
}

/// Operator-supplied calibration attestation, not proof that a corpus was evaluated.
/// The integrator must verify the pinned artifact and its operating point offline.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Calibration {
    pub pattern_version: String,
    pub rules_digest: String,
    pub artifact_sha256: String,
    pub scale: f64,
    pub max_contribution: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub mode: Mode,
    /// The complete rule set. A supplied list replaces the built-ins; [] is valid.
    pub rules: Vec<Rule>,
    pub limits: Limits,
    pub max_candidate_weight: f64,
    pub calibration: Option<Calibration>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            mode: Mode::Observation,
            rules: builtin_rules(),
            limits: Limits::default(),
            max_candidate_weight: 10.0,
            calibration: None,
        }
    }
}

fn digest(value: &impl Serialize) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(value)?)))
}

fn token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

fn sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl Settings {
    /// Full validation, including compiling patterns under the configured budgets.
    /// The temporary validation regexes are discarded; Runtime owns its own set.
    pub fn validate(&self) -> Result<()> {
        self.compile().map(|_| ())
    }

    /// Ordered evaluation configuration, excluding mode/calibration to avoid a
    /// circular binding and allow an observed ruleset to be calibrated offline.
    pub fn rules_digest(&self) -> Result<String> {
        digest(&(
            VERSION,
            PATTERN_VERSION,
            &self.rules,
            &self.limits,
            self.max_candidate_weight,
        ))
    }

    /// Includes mode, calibration coefficients and artifact pin, as well as rules.
    /// Stable for the same typed settings, independent of JSON/TOML key order.
    pub fn settings_digest(&self) -> Result<String> {
        digest(&(VERSION, PATTERN_VERSION, self))
    }

    fn compile(&self) -> Result<Vec<Regex>> {
        self.limits.validate()?;
        ensure!(
            self.rules.len() <= self.limits.max_rules,
            "too many heuristic rules"
        );
        ensure!(
            self.max_candidate_weight.is_finite()
                && (0.0..=100.0).contains(&self.max_candidate_weight),
            "invalid heuristic candidate cap"
        );
        let mut ids = BTreeSet::new();
        let mut total = 0usize;
        // Check all metadata/lengths before compiling or serializing any patterns.
        for rule in &self.rules {
            ensure!(
                token(&rule.id) && token(&rule.family) && ids.insert(&rule.id),
                "invalid or duplicate heuristic id/family"
            );
            ensure!(
                !rule.label.trim().is_empty()
                    && rule.label.len() <= 160
                    && rule
                        .label
                        .chars()
                        .all(|c| c.is_alphanumeric() || " .,:;!?()-_/'’".contains(c)),
                "invalid heuristic label"
            );
            ensure!(
                !rule.scopes.is_empty()
                    && rule.scopes.len() <= 4
                    && rule.scopes.iter().collect::<BTreeSet<_>>().len() == rule.scopes.len(),
                "invalid heuristic scopes"
            );
            ensure!(
                rule.candidate_weight.is_finite() && (0.0..=10.0).contains(&rule.candidate_weight),
                "invalid heuristic weight"
            );
            ensure!(
                !rule.pattern.is_empty() && rule.pattern.len() <= self.limits.max_pattern_bytes,
                "invalid heuristic pattern length"
            );
            total += rule.pattern.len();
        }
        ensure!(
            total <= self.limits.max_total_pattern_bytes,
            "heuristic pattern budget exceeded"
        );
        if let Some(calibration) = &self.calibration {
            ensure!(
                calibration.pattern_version == PATTERN_VERSION
                    && sha256(&calibration.rules_digest)
                    && calibration.rules_digest == self.rules_digest()?
                    && sha256(&calibration.artifact_sha256),
                "heuristics calibration binding mismatch"
            );
            ensure!(
                calibration.scale.is_finite()
                    && (0.0..=1.0).contains(&calibration.scale)
                    && calibration.max_contribution.is_finite()
                    && (0.0..=10.0).contains(&calibration.max_contribution),
                "invalid heuristic calibration coefficients"
            );
        }
        ensure!(
            self.mode != Mode::Contribute || self.calibration.is_some(),
            "heuristics contribution requires bound calibration"
        );
        self.rules
            .iter()
            .map(|rule| {
                let regex = RegexBuilder::new(&rule.pattern)
                    .size_limit(self.limits.regex_size_limit)
                    .dfa_size_limit(self.limits.regex_dfa_size_limit)
                    .nest_limit(self.limits.regex_nest_limit)
                    .build()
                    // Do not propagate regex errors, which echo the pattern.
                    .map_err(|_| {
                        anyhow::anyhow!("invalid or over-budget heuristic regex: {}", rule.id)
                    })?;
                ensure!(
                    !regex.is_match(""),
                    "heuristic regex matches empty input: {}",
                    rule.id
                );
                Ok(regex)
            })
            .collect()
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Disabled,
    Complete,
    Limited,
    InvalidMessage,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LimitHit {
    RawBytes,
    HeaderBytes,
    Headers,
    Parts,
    PartBytes,
    InputBytes,
    Segments,
    HtmlNodes,
    Encoding,
    EmptyMatch,
    MatchesPerRule,
    TotalMatches,
    Findings,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Finding {
    pub id: String,
    pub label: String,
    pub family: String,
    pub scopes: Vec<Scope>,
    pub matches: usize,
    pub candidate_weight: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Report {
    pub version: String,
    pub pattern_version: String,
    pub settings_digest: String,
    pub mode: Mode,
    pub status: Status,
    pub findings: Vec<Finding>,
    pub candidate_weight: f64,
    pub contribution: f64,
    pub limits_hit: Vec<LimitHit>,
}

impl Report {
    fn limited(&mut self, limit: LimitHit) {
        self.status = Status::Limited;
        if !self.limits_hit.contains(&limit) {
            self.limits_hit.push(limit);
        }
    }
}

/// Immutable configuration and compiled regexes; Send + Sync, reusable via Arc.
/// Compilation and hashing never occur inside inspect().
pub struct Runtime {
    settings: Settings,
    regexes: Vec<Regex>,
    settings_digest: String,
    parser: MessageParser,
}

impl Runtime {
    pub fn new(settings: Settings) -> Result<Self> {
        let regexes = settings.compile()?;
        let settings_digest = settings.settings_digest()?;
        Ok(Self {
            settings,
            regexes,
            settings_digest,
            parser: MessageParser::default(),
        })
    }

    pub fn inspect(&self, raw: &[u8]) -> Report {
        let mut report = Report {
            version: VERSION.into(),
            pattern_version: PATTERN_VERSION.into(),
            settings_digest: self.settings_digest.clone(),
            mode: self.settings.mode,
            status: Status::Complete,
            findings: Vec::new(),
            candidate_weight: 0.0,
            contribution: 0.0,
            limits_hit: Vec::new(),
        };
        if self.settings.mode == Mode::Disabled {
            report.status = Status::Disabled;
            return report;
        }
        let limits = &self.settings.limits;
        if raw.len() > limits.max_raw_bytes {
            report.limited(LimitHit::RawBytes);
            return report;
        }
        if !check_headers(raw, limits, &mut report) {
            return report;
        }
        let Some(message) = self.parser.parse(raw) else {
            report.status = Status::InvalidMessage;
            return report;
        };
        if message.parts.len() > limits.max_parts {
            report.limited(LimitHit::Parts);
            return report;
        }
        let mut inputs = Inputs::default();
        for header in message.headers() {
            let scope = match header.name {
                HeaderName::Subject => Scope::Subject,
                HeaderName::From => Scope::From,
                HeaderName::ReplyTo => Scope::ReplyTo,
                _ => continue,
            };
            if scope == Scope::Subject {
                if let Some(text) = header.value.as_text() {
                    if !safe_header(text) {
                        report.status = Status::InvalidMessage;
                        return report;
                    }
                    inputs.push(scope, normalize(text), text.len(), limits, &mut report);
                }
            } else if let Some(addresses) = header.value.as_address() {
                for address in addresses.iter() {
                    let name = address.name.as_deref().unwrap_or("");
                    let email = address.address.as_deref().unwrap_or("");
                    if !safe_header(name) || !safe_header(email) {
                        report.status = Status::InvalidMessage;
                        return report;
                    }
                    let text = if email.is_empty() {
                        name.to_owned()
                    } else if name.is_empty() {
                        email.to_owned()
                    } else {
                        format!("{name} <{email}>")
                    };
                    inputs.push(scope, normalize(&text), text.len(), limits, &mut report);
                }
            } else {
                // No raw fallback for malformed address headers.
                report.status = Status::InvalidMessage;
                return report;
            }
        }
        // Walk the MIME tree instead of assuming every text part is visible.
        // Skipping a multipart attachment also skips all of its descendants.
        let mut pending = vec![0usize];
        while let Some(index) = pending.pop() {
            let Some(part) = message.parts.get(index) else {
                report.limited(LimitHit::Encoding);
                break;
            };
            if part.attachment_name().is_some()
                || part
                    .content_disposition()
                    .is_some_and(|c| !c.c_type.eq_ignore_ascii_case("inline"))
            {
                continue;
            }
            if part.is_encoding_problem {
                report.limited(LimitHit::Encoding);
                continue;
            }
            match &part.body {
                PartType::Multipart(children) => {
                    pending.extend(children.iter().rev().map(|i| *i as usize))
                }
                PartType::Text(text) | PartType::Html(text)
                    if (message.text_body.contains(&(index as u32))
                        || message.html_body.contains(&(index as u32)))
                        && (part.content_type().is_none()
                            || part.is_content_type("text", "plain")
                            || part.is_content_type("text", "html")) =>
                {
                    if !inputs.reserve(text.len(), limits, &mut report) {
                        continue;
                    }
                    let visible = if matches!(&part.body, PartType::Html(_)) {
                        match visible_html(text, limits) {
                            Ok(text) => text,
                            Err(limit) => {
                                report.limited(limit);
                                continue;
                            }
                        }
                    } else {
                        normalize(text)
                    };
                    // Entity decoding can expand UTF-8. Charge the larger of
                    // decoded MIME source and final regex input, not just HTML.
                    let extra = visible.len().saturating_sub(text.len());
                    if inputs.bytes + extra > limits.max_input_bytes {
                        report.limited(LimitHit::InputBytes);
                        continue;
                    }
                    inputs.bytes += extra;
                    inputs.segments.push((Scope::Body, visible));
                }
                // No attachment text, message/rfc822, binary, PDF or OCR search.
                _ => {}
            }
        }
        let mut total_matches = 0;
        for (rule, regex) in self.settings.rules.iter().zip(&self.regexes) {
            let mut count = 0;
            let mut scopes = BTreeSet::new();
            'segments: for (scope, text) in &inputs.segments {
                if !rule.scopes.contains(scope) {
                    continue;
                }
                // At most the configured count plus ONE overflow probe. An
                // unbounded find_iter can be quadratic even with a linear engine.
                for found in regex.find_iter(text) {
                    if found.is_empty() {
                        report.limited(LimitHit::EmptyMatch);
                        break 'segments;
                    }
                    if count == limits.max_matches_per_rule {
                        report.limited(LimitHit::MatchesPerRule);
                        break 'segments;
                    }
                    if total_matches == limits.max_total_matches {
                        report.limited(LimitHit::TotalMatches);
                        break 'segments;
                    }
                    count += 1;
                    total_matches += 1;
                    scopes.insert(*scope);
                }
            }
            if count > 0 {
                if report.findings.len() == limits.max_findings {
                    report.limited(LimitHit::Findings);
                    break;
                }
                report.findings.push(Finding {
                    id: rule.id.clone(),
                    label: rule.label.clone(),
                    family: rule.family.clone(),
                    scopes: scopes.into_iter().collect(),
                    matches: count,
                    candidate_weight: rule.candidate_weight,
                });
                report.candidate_weight = (report.candidate_weight + rule.candidate_weight)
                    .min(self.settings.max_candidate_weight);
            }
            if report.limits_hit.contains(&LimitHit::TotalMatches) {
                break;
            }
        }
        if report.status == Status::Complete
            && self.settings.mode == Mode::Contribute
            && let Some(calibration) = &self.settings.calibration
        {
            report.contribution =
                (report.candidate_weight * calibration.scale).min(calibration.max_contribution);
        }
        report
    }
}

fn safe_header(text: &str) -> bool {
    text.chars().all(|c| !c.is_control() || c == '\t')
}

/// Validate the top-level field boundary before the permissive MIME parser.
/// Accept CRLF and LF mail archives, but reject orphan folds, duplicate target
/// fields, NULs, and bare CR. Never scan arbitrary headers for heuristic matches.
fn check_headers(raw: &[u8], limits: &Limits, report: &mut Report) -> bool {
    let mut bytes = 0;
    let mut fields = 0;
    let mut selected = BTreeSet::new();
    for line in raw.split_inclusive(|b| *b == b'\n') {
        bytes += line.len();
        if bytes > limits.max_header_bytes {
            report.limited(LimitHit::HeaderBytes);
            return false;
        }
        let line = line.strip_suffix(b"\n").unwrap_or(line);
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            return true;
        }
        if line.iter().any(|b| b.is_ascii_control() && *b != b'\t') {
            report.status = Status::InvalidMessage;
            return false;
        }
        if line[0] == b' ' || line[0] == b'\t' {
            if fields != 0 {
                continue;
            }
        } else if let Some(colon) = line.iter().position(|b| *b == b':') {
            let name = &line[..colon];
            if !name.is_empty() && name.iter().all(|b| (33..=126).contains(b)) {
                fields += 1;
                if fields > limits.max_headers {
                    report.limited(LimitHit::Headers);
                    return false;
                }
                for target in [b"subject".as_slice(), b"from", b"reply-to"] {
                    if name.eq_ignore_ascii_case(target) && !selected.insert(target) {
                        report.status = Status::InvalidMessage;
                        return false;
                    }
                }
                continue;
            }
        }
        report.status = Status::InvalidMessage;
        return false;
    }
    report.status = Status::InvalidMessage;
    false
}

#[derive(Default)]
struct Inputs {
    segments: Vec<(Scope, String)>,
    bytes: usize,
}

impl Inputs {
    fn reserve(&mut self, bytes: usize, limits: &Limits, report: &mut Report) -> bool {
        if bytes > limits.max_part_bytes {
            report.limited(LimitHit::PartBytes);
            return false;
        }
        if self.bytes + bytes > limits.max_input_bytes {
            report.limited(LimitHit::InputBytes);
            return false;
        }
        if self.segments.len() >= limits.max_segments {
            report.limited(LimitHit::Segments);
            return false;
        }
        self.bytes += bytes;
        true
    }

    fn push(
        &mut self,
        scope: Scope,
        text: String,
        bytes: usize,
        limits: &Limits,
        report: &mut Report,
    ) {
        if self.reserve(bytes.max(text.len()), limits, report) {
            self.segments.push((scope, text));
        }
    }
}

/// Unicode whitespace folding, preserving accents/case and inline word fragments.
fn normalize(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut space = false;
    for c in text.chars() {
        if c.is_whitespace() || c.is_control() {
            space = !result.is_empty();
        } else {
            if space {
                result.push(' ');
                space = false;
            }
            result.push(c);
        }
    }
    result
}

fn hidden(element: &scraper::node::Element) -> bool {
    if matches!(
        element.name(),
        "head"
            | "script"
            | "style"
            | "template"
            | "noscript"
            | "iframe"
            | "object"
            | "svg"
            | "canvas"
    ) || element.attr("hidden").is_some()
    {
        return true;
    }
    // Static inline CSS only. No CSS cascade, scripts, fetches, or layout engine.
    element.attr("style").is_some_and(|style| {
        style.split(';').any(|declaration| {
            let Some((name, value)) = declaration.split_once(':') else {
                return false;
            };
            let name = name.trim();
            let value = value.split('!').next().unwrap_or("").trim();
            (name.eq_ignore_ascii_case("display") && value.eq_ignore_ascii_case("none"))
                || (name.eq_ignore_ascii_case("visibility")
                    && (value.eq_ignore_ascii_case("hidden")
                        || value.eq_ignore_ascii_case("collapse")))
                || (name.eq_ignore_ascii_case("opacity")
                    && value.parse::<f32>().is_ok_and(|n| n == 0.0))
        })
    })
}

fn block(name: &str) -> bool {
    matches!(
        name,
        "address"
            | "article"
            | "aside"
            | "blockquote"
            | "br"
            | "div"
            | "dl"
            | "dt"
            | "dd"
            | "footer"
            | "form"
            | "h1"
            | "h2"
            | "h3"
            | "h4"
            | "h5"
            | "h6"
            | "header"
            | "hr"
            | "li"
            | "main"
            | "nav"
            | "ol"
            | "p"
            | "pre"
            | "section"
            | "table"
            | "td"
            | "th"
            | "tr"
            | "ul"
    )
}

fn visible_html(text: &str, limits: &Limits) -> std::result::Result<String, LimitHit> {
    let document = Html::parse_document(text);
    if document.tree.nodes().count() > limits.max_html_nodes {
        return Err(LimitHit::HtmlNodes);
    }
    let mut output = String::new();
    let mut pending = vec![(document.tree.root(), false)];
    while let Some((node, exiting)) = pending.pop() {
        match node.value() {
            Node::Element(element) => {
                if hidden(element) {
                    continue;
                }
                if block(element.name()) {
                    output.push(' ');
                }
            }
            Node::Text(text) if !exiting => output.push_str(text),
            _ => {}
        }
        if output.len() > limits.max_part_bytes {
            return Err(LimitHit::PartBytes);
        }
        if !exiting {
            pending.push((node, true));
            pending.extend(node.children().rev().map(|child| (child, false)));
        }
    }
    Ok(normalize(&output))
}

/// Illustrative research candidates, not calibrated spam probabilities.
pub fn builtin_rules() -> Vec<Rule> {
    let content = vec![Scope::Subject, Scope::Body];
    [
        ("fr.credentials", "Demande de vérification de compte", "credentials", r"(?i)\b(?:v[ée]rifiez|confirmez|validez)\s+votre\s+(?:compte|identit[ée]|mot\s+de\s+passe)\b", 1.5),
        ("en.credentials", "Account credential verification request", "credentials", r"(?i)\b(?:verify|confirm|validate)\s+your\s+(?:account|identity|password)\b", 1.5),
        ("fr.account_threat", "Menace de suspension de compte", "account_pressure", r"(?i)\b(?:votre\s+)?compte\s+(?:sera\s+|est\s+)?(?:suspendu|bloqu[ée]|d[ée]sactiv[ée])\b", 1.0),
        ("en.account_threat", "Account suspension pressure", "account_pressure", r"(?i)\byour\s+account\s+(?:will\s+be\s+|has\s+been\s+|is\s+)?(?:suspended|blocked|disabled)\b", 1.0),
        ("fr.guaranteed_returns", "Promesse de rendement garanti", "financial_lure", r"(?i)\b(?:profits?|gains?|rendements?)\s+garantis?\b|\bsans\s+risque\s+.{0,32}\binvestissement\b", 1.5),
        ("en.guaranteed_returns", "Guaranteed investment returns", "financial_lure", r"(?i)\bguaranteed\s+(?:profits?|returns?|income)\b|\brisk[ -]free\s+investments?\b", 1.5),
        ("fr.prize", "Annonce de gain à réclamer", "prize_lure", r"(?i)\b(?:vous\s+avez\s+gagn[ée]|r[ée]clamez\s+votre\s+(?:prix|gain|r[ée]compense))\b", 1.0),
        ("en.prize", "Prize claim request", "prize_lure", r"(?i)\b(?:you(?:'ve|\s+have)\s+won|claim\s+your\s+(?:prize|reward|winnings))\b", 1.0),
        ("fr.payment_change", "Demande de changement bancaire", "payment_diversion", r"(?i)\b(?:nouvelles?\s+coordonn[ée]es\s+bancaires|changement\s+de\s+rib|virement\s+urgent)\b", 1.0),
        ("en.payment_change", "Bank transfer change request", "payment_diversion", r"(?i)\b(?:updated?\s+bank\s+details|new\s+bank\s+account|urgent\s+wire\s+transfer)\b", 1.0),
    ].into_iter().map(|(id, label, family, pattern, candidate_weight)| Rule {
        id: id.into(), label: label.into(), family: family.into(), scopes: content.clone(),
        pattern: pattern.into(), candidate_weight,
    }).chain(std::iter::once(Rule {
        id: "identity.security_desk".into(), label: "Security or account desk display name".into(),
        family: "sender_identity".into(), scopes: vec![Scope::From, Scope::ReplyTo],
        pattern: r"(?i)\b(?:account\s+security|security\s+team|service\s+(?:s[ée]curit[ée]|v[ée]rification))\b".into(),
        candidate_weight: 0.25,
    })).collect()
}
