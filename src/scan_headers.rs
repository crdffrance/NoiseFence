//! Versioned, bounded SMTP diagnostics. No free-form detector/provider text,
//! message identities, URLs, features or recipient policies belong on the wire.
use crate::{assessment, config::Config, engine::Scan};
use serde::Serialize;
use std::net::IpAddr;

pub(crate) const FIELDS: &[&str] = &[
    "X-NoiseFence-Header-Version",
    "X-NoiseFence-Id",
    "X-NoiseFence-Version",
    "X-NoiseFence-Verdict",
    "X-NoiseFence-Classification",
    "X-NoiseFence-Coverage",
    "X-NoiseFence-Score",
    "X-NoiseFence-Score-Type",
    "X-NoiseFence-Mode",
    "X-NoiseFence-Score-Details",
    "X-NoiseFence-Score-Boundary",
    "X-NoiseFence-Policy",
    "X-NoiseFence-Delivery-Policy",
    "X-NoiseFence-Analysis",
    "X-NoiseFence-Checks",
    "X-NoiseFence-Authentication",
    "X-NoiseFence-Rules",
    "X-NoiseFence-Arbitration",
    "X-NoiseFence-Score-Resolution",
    "X-NoiseFence-LLM",
    "X-NoiseFence-Antivirus",
    "X-NoiseFence-Vision",
    "X-NoiseFence-Reputation",
    "X-NoiseFence-RBL",
    "X-NoiseFence-Native",
];

pub(crate) fn signed_fields() -> impl Iterator<Item = &'static str> {
    [
        "From",
        "To",
        "Subject",
        "Date",
        "Message-ID",
        "MIME-Version",
        "Content-Type",
        "Content-Transfer-Encoding",
        "DKIM-Signature",
    ]
    .into_iter()
    .chain(FIELDS.iter().copied())
}

const MAX_RULES: usize = 24;

fn token(value: &str) -> Option<&str> {
    (!value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c)))
    .then_some(value)
}

// Called only for typed enum variants, never for a complete report or free text.
fn word(value: &impl Serialize) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().and_then(token).map(str::to_owned))
        .unwrap_or_else(|| "unknown".into())
}
fn yes(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}
fn score(value: Option<f64>) -> Option<f64> {
    assessment::valid_score(value)
}
fn number(value: Option<f64>) -> String {
    score(value)
        .map(|v| format!("{v:.1}"))
        .unwrap_or_else(|| "unavailable".into())
}

struct Writer(std::collections::BTreeMap<&'static str, String>);
fn precise(value: f64) -> String {
    if !value.is_finite() {
        return "unavailable".into();
    }
    let text = value.to_string();
    if text.len() <= 32 {
        text
    } else {
        format!("{value:e}")
    }
}
impl Writer {
    fn field(&mut self, name: &'static str, value: impl AsRef<str>) {
        debug_assert!(FIELDS.contains(&name));
        let mut line = String::new();
        line.push_str(name);
        line.push(':');
        let mut column = name.len() + 1;
        for atom in value.as_ref().split_ascii_whitespace() {
            // All callers supply generated ASCII atoms. This is also a final
            // boundary against accidental future CR/LF or oversized values.
            let atom = if atom.len() <= 256 && atom.bytes().all(|b| (33..=126).contains(&b)) {
                atom
            } else {
                "invalid"
            };
            if column + atom.len() + 1 > 78 {
                line.push_str("\r\n\t");
                column = 1;
            } else {
                line.push(' ');
                column += 1;
            }
            line.push_str(atom);
            column += atom.len();
        }
        line.push_str("\r\n");
        assert!(
            self.0.insert(name, line).is_none(),
            "duplicate diagnostic header"
        );
    }
}

fn rules<'a>(
    items: impl Iterator<Item = (&'a str, f64)>,
    total: usize,
    unit: &str,
    prefix: &str,
) -> String {
    let mut shown = 0;
    let mut values = String::new();
    for (id, weight) in items.take(MAX_RULES) {
        if let Some(id) = token(id).filter(|id| id.len() <= 64)
            && weight.is_finite()
        {
            let weight = if weight.abs() < 10_000. {
                format!("{weight:+.4}")
            } else {
                format!("{weight:+.4e}")
            };
            values.push_str(&format!(" {prefix}.{id}={weight};"));
            shown += 1;
        }
    }
    format!(
        "{prefix}-unit={unit}; {prefix}-total={total}; {prefix}-shown={shown}; {prefix}-omitted={};{values}",
        total.saturating_sub(shown)
    )
}

fn rule_adjustments(report: &crate::scoring::Report) -> String {
    use crate::scoring::Adjustment;
    let entries: Vec<_> = report
        .contributions
        .iter()
        .filter(|c| c.adjustment != Adjustment::None)
        .collect();
    let mut values = Vec::new();
    for c in entries.iter().take(MAX_RULES) {
        let Some(id) = token(&c.id).filter(|v| v.len() <= 64) else {
            continue;
        };
        let by = c
            .subsumed_by
            .as_deref()
            .and_then(token)
            .filter(|v| v.len() <= 64)
            .map(|v| format!(":{v}"))
            .unwrap_or_default();
        values.push(format!("adjustment.{id}:{}{by};", word(&c.adjustment)));
    }
    format!(
        "adjustment-total={}; adjustment-shown={}; adjustment-omitted={}; {}",
        entries.len(),
        values.len(),
        entries.len().saturating_sub(values.len()),
        values.join(" ")
    )
}

fn provider(name: &str, p: &crate::protection::ProviderReport) -> String {
    format!(
        "{name}={}; {name}.checked={}; {name}.malicious={}; {name}.suspicious={}; {name}.unknown={}; {name}.cached={}; {name}.omitted={}; {name}.failure={};",
        word(&p.status),
        p.checked,
        p.malicious,
        p.suspicious,
        p.unknown,
        p.cache_hits,
        p.omitted,
        p.failure
            .as_ref()
            .map(word)
            .unwrap_or_else(|| "none".into())
    )
}

pub(crate) fn render(
    config: &Config,
    ip: IpAddr,
    id: &str,
    scan: &Scan,
    early_rbl: Option<&crate::rbl::Report>,
) -> String {
    let id = token(id).unwrap_or("invalid");
    let received = format!(
        "Received: from [{}] by {} with ESMTP id {};\r\n\t{}\r\n",
        ip,
        config.hostname,
        id,
        mail_parser::DateTime::from_timestamp(crate::now()).to_rfc822()
    );
    let mut h = Writer(Default::default());
    let report = assessment::assess(scan, config.filter.threshold);
    let record = scan.recipient_decision.as_ref();
    h.field(
        "X-NoiseFence-Classification",
        record
            .map(|r| word(&r.classification))
            .unwrap_or_else(|| "not_recorded".into()),
    );
    h.field(
        "X-NoiseFence-Coverage",
        record
            .map(|r| word(&r.coverage))
            .unwrap_or_else(|| "not_recorded".into()),
    );
    h.field(
        "X-NoiseFence-Policy",
        format!(
            "record-version={}; assessment-version={}; policy-version={}; classification-source={}; decision-outcome={}; decision-source={}; decision-recorded={}; policy-sha256={}; activation-sequence={}; activation-revision={}; activation-sha256={};",
            record
                .map(|r| r.version.to_string())
                .unwrap_or_else(|| "not_recorded".into()),
            report.version,
            report
                .policy_version
                .as_deref()
                .and_then(token)
                .unwrap_or("not_recorded"),
            word(&report.classification_source),
            word(&report.decision.outcome),
            word(&report.decision.source),
            yes(report.decision_recorded),
            record
                .map(|r| r.policy_sha256.as_str())
                .filter(|h| crate::compatibility::valid_hash(h))
                .unwrap_or("not_recorded"),
            crate::decision_record::recorded_activation(scan)
                .map(|epoch| epoch.sequence.to_string())
                .unwrap_or_else(|| "not_recorded".into()),
            crate::decision_record::recorded_activation(scan)
                .map(|epoch| epoch.revision.to_string())
                .unwrap_or_else(|| "not_recorded".into()),
            crate::decision_record::recorded_activation(scan)
                .map(|epoch| epoch.digest)
                .unwrap_or_else(|| "not_recorded".into())
        ),
    );
    h.field(
        "X-NoiseFence-Score-Details",
        format!(
            "scale=0-100; source={}; model={}; content={}; decision={}; threshold={};",
            word(&report.score.source),
            token(&report.score.model).unwrap_or("unavailable"),
            number(report.score.raw),
            number(report.score.decision),
            number(report.content_threshold)
        ),
    );
    let action_coverage = if let Some(coverage) = report.action.as_ref().and_then(|a| a.coverage.as_ref()) {
        let list = |items: &[crate::action_coverage::Requirement]| {
            if items.is_empty() {
                "none".into()
            } else {
                items
                    .iter()
                    .take(16)
                    .map(word)
                    .collect::<Vec<_>>()
                    .join(",")
            }
        };
        format!(
                "action-version={}; action-partial-policy={}; action-basis={}; action-eligible={}; action-required={}; action-missing={};",
                token(&coverage.version).unwrap_or("unknown"),
                yes(coverage.partial_actions),
                word(&coverage.basis),
                yes(coverage.eligible()),
                list(&coverage.required),
                list(&coverage.missing)
            )
    } else {
        "not_recorded".into()
    };
    if let Some(r) = &report.score_resolution {
        h.field(
            "X-NoiseFence-Score-Resolution",
            format!(
                "policy={}; score={}; threshold={}; previous={}; outcome={}; partial={};",
                token(&r.version).unwrap_or("unknown"),
                number(r.score),
                number(Some(r.threshold)),
                word(&r.previous.outcome),
                word(&r.decision.outcome),
                yes(r.partial)
            ),
        );
    } else {
        h.field("X-NoiseFence-Score-Resolution", "none");
    }
    let supplementary_gaps = if report.supplementary_gaps.is_empty() {
            "none".into()
        } else {
            report.supplementary_gaps.join("; ")
        };

    h.field("X-NoiseFence-Id", id);
    h.field("X-NoiseFence-Header-Version", "11");
    h.field("X-NoiseFence-Version", env!("CARGO_PKG_VERSION"));
    h.field(
        "X-NoiseFence-Mode",
        word(&report.mode.unwrap_or(config.filter.mode)),
    );
    h.field("X-NoiseFence-Score", number(report.score.value));
    h.field("X-NoiseFence-Score-Type", word(&report.score.kind));

    h.field("X-NoiseFence-Score-Boundary", report.score_boundary.as_ref().map_or_else(
        || if report.score.value.is_some() { "not_recorded" } else { "unavailable" }.into(),
        |b| format!("version={}; unit={}; value={}; cutoff={}; index-cutoff={}; above={}; model-sha256={};",
            b.version, match b.source { crate::score_boundary::Source::Content => "content_index", crate::score_boundary::Source::Fusion => "fusion_logit" },
            precise(b.value), precise(b.cutoff), precise(b.index_cutoff), b.above,
            b.model_sha256.as_deref().filter(|h| crate::compatibility::valid_hash(h)).unwrap_or("not_recorded"))));

    let delivery_policy = report
            .action
            .as_ref()
            .map(|a| {
                format!(
                    "requested={}; effective={}; reason={}; subject-tag={}; {}",
                    word(&a.requested),
                    word(&a.effective),
                    token(&a.reason).unwrap_or("unknown"),
                    word(&report.subject_tag),
                    action_coverage
                )
            })
            .unwrap_or_else(|| "not_recorded".into());
    h.field("X-NoiseFence-Delivery-Policy", delivery_policy);

    h.field("X-NoiseFence-Verdict", report.verdict());
    h.field(
        "X-NoiseFence-Analysis",
        format!(
            "complete={}; elapsed-ms={}; incomplete={}; supplementary-gaps={};",
            yes(report.complete),
            scan.elapsed_ms,
            if report.incomplete_reasons.is_empty() { "none".into() } else { report.incomplete_reasons.join(",") },
            supplementary_gaps.replace(' ', "")
        ),
    );

    let e = scan.evidence.as_ref();
    let state = |value: Option<crate::evidence::State>| {
        value.map(|v| word(&v)).unwrap_or_else(|| "unknown".into())
    };
    h.field("X-NoiseFence-Checks", format!(
        "lexical={}; authentication={}; spf={}; dkim={}; dmarc={}; arc={}; dns-reputation={}; semantic={}; antivirus={}; signatures={}; smtp={}; llm={}; vision={}; fusion={};",
        state(e.map(|e| e.lexical_state)), state(e.map(|e| e.authentication.state)),
        state(e.map(|e| e.authentication.spf_state)), state(e.map(|e| e.authentication.dkim_state)),
        state(e.map(|e| e.authentication.dmarc_state)), state(e.map(|e| e.authentication.arc_state)),
        state(e.map(|e| e.reputation.state)), state(e.map(|e| e.semantic_state)),
        state(e.map(|e| e.antivirus_state)), state(e.map(|e| e.signatures_state)),
        state(e.map(|e| e.smtp_policy_state)), state(e.map(|e| e.llm.state)),
        word(&scan.vision.status), word(&scan.fusion.status)));
    h.field(
        "X-NoiseFence-Authentication",
        e.map(|e| {
            use crate::evidence::eligibility::{self, AuthCheck};
            let eligible = |check| eligibility::authentication(e, check).is_ok();
            let result = |v: Option<crate::evidence::AuthResult>| {
                v.map(|v| word(&v)).unwrap_or_else(|| "not_recorded".into())
            };
            let dkim = eligible(AuthCheck::Dkim)
                .then_some(e.authentication.dkim.as_ref())
                .flatten()
                .map(|results| {
                    if results.is_empty() {
                        "none".into()
                    } else {
                        results
                            .iter()
                            .take(16)
                            .map(word)
                            .collect::<Vec<_>>()
                            .join(",")
                    }
                })
                .unwrap_or_else(|| "not_recorded".into());
            format!(
                "eligibility={}; spf={}; dkim={dkim}; dmarc-spf={}; dmarc-dkim={}; arc={};",
                eligibility::VERSION,
                result(
                    eligible(AuthCheck::Spf)
                        .then_some(e.authentication.spf)
                        .flatten()
                ),
                result(
                    eligible(AuthCheck::Dmarc)
                        .then_some(e.authentication.dmarc_spf)
                        .flatten()
                ),
                result(
                    eligible(AuthCheck::Dmarc)
                        .then_some(e.authentication.dmarc_dkim)
                        .flatten()
                ),
                result(
                    eligible(AuthCheck::Arc)
                        .then_some(e.authentication.arc)
                        .flatten()
                )
            )
        })
        .unwrap_or_else(|| "not_recorded".into()),
    );
    h.field(
        "X-NoiseFence-Arbitration",
        scan.arbitration
            .as_ref()
            .map(|a| {
                format!(
                    "resolution={}; baseline={}; opinion={};",
                    word(&a.resolution),
                    word(&a.baseline.outcome),
                    word(&a.opinion)
                )
            })
            .unwrap_or_else(|| "none".into()),
    );
    if let Some(scoring) = crate::scoring::recorded(scan) {
        let combination = format!(
            "combination-policy={}; rules-retained={}; total-logit={};",
            token(&scoring.version).unwrap_or("unknown"),
            scoring
                .rules_total
                .map(precise)
                .unwrap_or_else(|| "unavailable".into()),
            scoring
                .total_logit
                .map(precise)
                .unwrap_or_else(|| "unavailable".into()),
        );
        let adjustments = rule_adjustments(scoring);
        let ledger = rules(
            scoring
                .contributions
                .iter()
                .filter_map(|c| Some((c.id.as_str(), c.retained?))),
            scoring.contributions.len(),
            "logit",
            "rule",
        );
        h.field(
            "X-NoiseFence-Rules",
            format!("{combination} {adjustments} {ledger}"),
        );
    } else {
        h.field(
            "X-NoiseFence-Rules",
            format!("combination-policy=not_recorded adjustment-total=not_recorded {}", rules(
                scan.reasons.iter().map(|r| (r.id.as_str(), r.weight)),
                scan.reasons.len(),
                "logit",
                "rule",
            )),
        );
    }
    h.field(
        "X-NoiseFence-LLM",
        format!(
            "status={}; verdict={}; coherent={}; opinion={}; grounding={}; response-issue={}; failure={}; elapsed-ms={}; advisory=yes;",
            word(&scan.llm.status),
            scan.llm
                .verdict
                .as_ref()
                .map(|v| word(&v.category))
                .unwrap_or_else(|| "none".into()),
            scan.llm.coherent.map(yes).unwrap_or("not_recorded"),
            scan.llm.opinion().map(|v| word(&v)).unwrap_or_else(|| "none".into()),
            scan.llm.grounding.as_ref().map(|g| if g.supported {"supported"} else {"unsupported"}).unwrap_or("not_recorded"),
            scan.llm.response_issue.as_ref().map(word).unwrap_or_else(||"none".into()),
            scan.llm
                .failure
                .as_ref()
                .map(word)
                .unwrap_or_else(|| "none".into()),
            scan.llm.elapsed_ms
        ),
    );
    h.field(
        "X-NoiseFence-Antivirus",
        format!(
            "main={}; signatures={}; main.elapsed-ms={}; signatures.elapsed-ms={};",
            word(&scan.antivirus.status),
            word(&scan.signatures.status),
            scan.antivirus.elapsed_ms,
            scan.signatures.elapsed_ms
        ),
    );
    let vision_errors = scan
        .vision
        .errors
        .iter()
        .take(16)
        .filter(|error| crate::vision::valid_error(error))
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    let vision_errors = if scan.vision.errors.is_empty() {
            "none".into()
        } else if vision_errors.is_empty() {
            "unrecognized".into()
        } else {
            vision_errors.into_iter().collect::<Vec<_>>().join(",")
        };
    h.field(
        "X-NoiseFence-Vision",
        format!(
            "status={}; parts={}; pages={}; qr-codes={}; other-codes={}; errors={}; elapsed-ms={};",
            word(&scan.vision.status),
            scan.vision.parts,
            scan.vision.pages,
            scan.vision.qr_codes,
            scan.vision.other_codes,
            vision_errors,
            scan.vision.elapsed_ms
        ),
    );
    h.field(
        "X-NoiseFence-Reputation",
        scan.protection
            .as_ref()
            .map(|p| {
                format!(
                    "{} {}",
                    provider("crdf", &p.crdf),
                    provider("virustotal", &p.virustotal)
                )
            })
            .unwrap_or_else(|| {
                if config.protection.is_some() {
                    "not_run"
                } else {
                    "disabled"
                }
                .into()
            }),
    );
    // Admission observations reach the renderer separately; the classifier
    // never receives them as additional evidence or counts their score twice.
    h.field("X-NoiseFence-RBL", early_rbl.or(scan.early_rbl.as_ref()).map(|r| {
        use crate::rbl::Status;
        let count = |status| r.checks.iter().filter(|c| c.status == status).count();
        format!("checks={}; listed-providers={}; not-listed={}; listed={}; policy={}; unavailable={}; skipped={}; action={};",
            r.checks.len(), r.listed_providers, count(Status::NotListed), count(Status::Listed),
            count(Status::Policy), count(Status::Unavailable), count(Status::Skipped), word(&r.effective_action))
    }).unwrap_or_else(|| "not_recorded".into()));
    let native = scan.native_filter
            .as_ref()
            .map(|n| {
                format!(
                    "status={}; mode={}; affects-delivery={}; calibrated={}; elapsed-ms={};",
                    word(&n.report.status),
                    word(&n.report.mode),
                    yes(n.report.affects_delivery),
                    yes(n.report.calibrated),
                    n.report.elapsed_ms
                )
            })
            .unwrap_or_else(|| {
                if config.native_filter.is_some() {
                    "not_run"
                } else {
                    "disabled"
                }
                .into()
            });
    let native_rules = scan.native_filter
            .as_ref()
            .and_then(|n| n.report.score.as_ref())
            .map(|s| {
                rules(
                    s.symbols
                        .iter()
                        .filter(|r| r.absorbed_by.is_empty())
                        .map(|r| (r.id.as_str(), r.weight)),
                    s.symbols
                        .iter()
                        .filter(|r| r.absorbed_by.is_empty())
                        .count(),
                    "pre-cap-points",
                    "native-rule",
                )
            })
            .unwrap_or_else(|| "unavailable".into());
    h.field(
        "X-NoiseFence-Native",
        format!("{native} {native_rules}"),
    );
    let mut wire = received;
    for name in FIELDS {
        wire.push_str(h.0.get(name).expect("registered header must be rendered"));
    }
    wire
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        engine::Signal,
        fusion::runtime::{Decision, DecisionSource, Outcome},
    };

    fn config() -> Config {
        Config::load(std::path::Path::new("config/development.toml")).unwrap()
    }
    fn scan() -> Scan {
        Scan {
            score: 99.86,
            complete: true,
            model: "test-model".into(),
            decision: Some(Decision {
                source: DecisionSource::Legacy,
                outcome: Outcome::Legitimate,
                score: Some(99.86),
                model: "test-model".into(),
            }),
            ..Default::default()
        }
    }

    fn parameter<'a>(field: &'a str, name: &str) -> &'a str {
        field
            .split(';')
            .find_map(|atom| {
                let (key, value) = atom.trim().split_once('=')?;
                (key == name).then_some(value)
            })
            .expect("wire parameter must be present")
    }

    #[test]
    fn version_eleven_has_one_verdict_and_a_stable_signed_inventory() {
        let wire = render(
            &config(),
            "192.0.2.1".parse().unwrap(),
            "fixture",
            &scan(),
            None,
        );
        let actual: Vec<_> = wire
            .lines()
            .filter(|l| l.starts_with("X-NoiseFence-"))
            .map(|l| l.split_once(':').unwrap().0)
            .collect();
        assert_eq!(actual, FIELDS);
        assert_eq!(FIELDS.len(), 25);
        assert!(
            FIELDS
                .iter()
                .all(|name| signed_fields().any(|signed| signed == *name))
        );
        for removed in [
            "Category",
            "Decision",
            "Status",
            "Engine",
            "Action-Coverage",
            "Subject-Tag",
            "Content-Threshold",
            "Action-Effective",
            "Raw-Score",
            "Model",
        ] {
            assert!(!wire.contains(&format!("X-NoiseFence-{removed}:")));
        }
        assert!(wire.contains("X-NoiseFence-Header-Version: 11\r\n"));
    }

    #[test]
    fn authentication_headers_use_eligible_facts_and_preserve_scan_bytes() {
        use crate::evidence::{Artifacts, AuthResult as A, Evidence, Source, State};
        let c = config();
        let mut s = scan();
        let mut e = Evidence::new(&c, Artifacts::new(&c, None, None, false), false);
        e.source = Source::SmtpSession;
        e.authentication.state = State::Unavailable;
        e.authentication.spf_state = State::Complete;
        e.authentication.spf = Some(A::Fail);
        e.authentication.arc_state = State::Complete;
        e.authentication.arc = Some(A::Pass);
        e.authentication.arc_can_seal = Some(false);
        s.evidence = Some(e);
        let before = serde_json::to_value(&s).unwrap();
        let h = headers(&s);
        assert!(
            h["x-noisefence-authentication"]
                .contains("eligibility=transport-evidence-1; spf=fail;")
        );
        assert!(h["x-noisefence-authentication"].contains("arc=pass;"));
        assert_eq!(serde_json::to_value(&s).unwrap(), before);
        s.evidence.as_mut().unwrap().authentication.state = State::Disabled;
        let h = headers(&s);
        assert!(h["x-noisefence-authentication"].contains("spf=not_recorded;"));
        assert!(h["x-noisefence-authentication"].contains("arc=pass;"));
        s.evidence.as_mut().unwrap().schema = "unsupported".into();
        let h = headers(&s);
        assert!(!h["x-noisefence-authentication"].contains("=pass"));
        assert!(!h["x-noisefence-authentication"].contains("=fail"));
    }

    #[test]
    fn recorded_rule_weights_and_dependencies_are_signed_and_never_rebuilt_from_signals() {
        use crate::{
            evidence::{AuthResult as A, Source, State},
            scoring,
        };
        let c = config();
        let mut s = scan();
        let mut e = crate::evidence::Evidence::new(
            &c,
            crate::evidence::Artifacts::new(&c, None, None, false),
            false,
        );
        e.source = Source::SmtpSession;
        e.authentication.state = State::Complete;
        e.authentication.spf_state = State::Complete;
        e.authentication.spf = Some(A::Fail);
        e.authentication.dmarc_state = State::Complete;
        e.authentication.dmarc_spf = Some(A::Fail);
        e.authentication.dmarc_dkim = Some(A::Fail);
        s.evidence = Some(e);
        s.reasons = [
            ("spf_fail", 1.),
            ("dmarc_fail", 2.),
            ("urgency", 0.5),
            ("urgency", 0.5),
        ]
        .into_iter()
        .map(|(id, weight)| Signal {
            id: id.into(),
            weight,
            detail: "private body".into(),
        })
        .collect();
        s.scoring = Some(scoring::combine(&s, None, false));
        s.score = s.scoring.as_ref().unwrap().score.unwrap();
        s.decision = None;
        crate::decision_record::record_analysis(&mut s, &c);
        // An observer or retry changing mutable fields must not change wire accounting.
        s.scoring = None;
        s.reasons = vec![Signal {
            id: "urgency".into(),
            weight: 99.,
            detail: "private body".into(),
        }];
        let h = headers(&s);
        assert_eq!(h["x-noisefence-header-version"], "11");
        assert_eq!(h["x-noisefence-score"], number(Some(s.score)));
        assert!(h["x-noisefence-rules"].contains("rules-retained=2.5; total-logit=-2.5;"));
        assert!(h["x-noisefence-rules"].contains("rule.spf_fail=+0.0000;"));
        assert!(h["x-noisefence-rules"].contains("rule.urgency=+0.5000;"));
        assert!(
            h["x-noisefence-rules"].contains("adjustment.spf_fail:subsumed_evidence:dmarc_fail;")
        );
        assert!(h["x-noisefence-rules"].contains("adjustment.urgency:duplicate;"));
        assert!(
            !h.values()
                .any(|v| v.contains("private body") || v.contains("99.0000"))
        );
        assert!(signed_fields().any(|f| f == "X-NoiseFence-Rules"));
        let legacy = headers(&scan());
        assert!(legacy["x-noisefence-rules"].contains("combination-policy=not_recorded"));
        assert!(legacy["x-noisefence-rules"].contains("adjustment-total=not_recorded"));
    }
    fn headers(scan: &Scan) -> std::collections::BTreeMap<String, String> {
        let wire = render(
            &config(),
            "192.0.2.1".parse().unwrap(),
            "test-id",
            scan,
            None,
        );
        let wire = format!("{wire}From: sender@example.test\r\n\r\nBody\r\n");
        crate::message::validate(wire.as_bytes()).unwrap();
        assert!(wire.len() < 12 * 1024);
        assert!(wire.split("\r\n").all(|line| line.len() <= 998));
        let (fields, _) = crate::message::fields(wire.as_bytes()).unwrap();
        let result: std::collections::BTreeMap<_, _> = fields
            .iter()
            .map(|field| {
                let value = std::str::from_utf8(field)
                    .unwrap()
                    .split_once(':')
                    .unwrap()
                    .1
                    .split_ascii_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ");
                (crate::message::name(field), value)
            })
            .collect();
        assert_eq!(result.len(), fields.len());
        assert!(
            FIELDS
                .iter()
                .all(|name| result.contains_key(&name.to_ascii_lowercase()))
        );
        assert_eq!(fields.len(), FIELDS.len() + 2);
        result
    }

    #[test]
    fn activation_header_uses_canonical_receipt_and_is_in_signing_fields() {
        let mut scan = scan();
        scan.activation_epoch = Some(crate::cluster::activation::Epoch {
            sequence: 7,
            revision: 12,
            digest: "a".repeat(64),
        });
        // A transport epoch alone is not recorded canonical identity.
        assert_eq!(parameter(&headers(&scan)["x-noisefence-policy"], "activation-sequence"), "not_recorded");
        crate::decision_record::record_recipient(&mut scan, &config(), None, 1234);
        assert_eq!(
            parameter(&headers(&scan)["x-noisefence-policy"], "activation-sequence"),
            "7"
        );
        assert_eq!(parameter(&headers(&scan)["x-noisefence-policy"], "activation-revision"), "12");
        assert_eq!(parameter(&headers(&scan)["x-noisefence-policy"], "activation-sha256"), "a".repeat(64));
        assert_eq!(
            parameter(&headers(&scan)["x-noisefence-policy"], "record-version"),
            "2"
        );
        assert!(signed_fields().any(|field| field == "X-NoiseFence-Policy"));
        scan.activation_epoch.as_mut().unwrap().sequence += 1;
        assert_eq!(parameter(&headers(&scan)["x-noisefence-policy"], "activation-sequence"), "not_recorded");
    }

    #[test]
    fn incomplete_keeps_recorded_numeric_score_and_specific_cause() {
        let mut s = scan();
        s.complete = false;
        s.decision.as_mut().unwrap().score = None;
        s.decision.as_mut().unwrap().outcome = Outcome::Undetermined;
        s.vision.status = crate::vision::Status::Limited;
        s.vision.errors = vec!["pixel_limit".into(), "private-worker-response".into()];
        s.elapsed_ms = 1245;
        s.reasons.push(Signal {
            id: "vision_incomplete".into(),
            detail: "Private visual text".into(),
            weight: 0.,
        });
        let h = headers(&s);
        assert_eq!(h["x-noisefence-score"], "99.9");
        assert_eq!(h["x-noisefence-score-type"], "partial");
        assert_eq!(parameter(&h["x-noisefence-score-details"], "source"), "raw");
        assert_eq!(
            parameter(&h["x-noisefence-score-details"], "decision"),
            "unavailable"
        );
        assert!(h["x-noisefence-analysis"].contains("complete=no;"));
        assert_eq!(
            parameter(&h["x-noisefence-policy"], "decision-outcome"),
            "undetermined"
        );
        assert!(h["x-noisefence-analysis"].contains("incomplete=vision_incomplete;"));
        assert!(h["x-noisefence-analysis"].contains("elapsed-ms=1245"));
        assert!(h["x-noisefence-vision"].contains("status=limited"));
        assert!(h["x-noisefence-vision"].contains("errors=pixel_limit;"));
        assert!(!h.values().any(|v| v.contains("Private")));
    }

    #[test]
    fn score_boundary_headers_preserve_native_units_and_missing_history() {
        for value in [f64::MAX, f64::MIN_POSITIVE, 1e-300, 95.00000000001] {
            assert!(precise(value).len() < 32);
            assert_eq!(precise(value).parse::<f64>().unwrap(), value);
        }
        let mut s = scan();
        s.decision = Some(crate::fusion::runtime::Decision {
            source: DecisionSource::Fusion,
            outcome: Outcome::Legitimate,
            score: Some(50.),
            model: "fusion-boundary-fixture".into(),
        });
        let hash = crate::message::digest(b"synthetic boundary model");
        s.fusion.model_sha256 = Some(hash.clone());
        s.fusion_boundary = Some(crate::score_boundary::Boundary {
            version: 1,
            source: crate::score_boundary::Source::Fusion,
            value: 0.,
            cutoff: 1.,
            index_cutoff: 50.,
            above: false,
            model: "fusion-boundary-fixture".into(),
            model_sha256: Some(hash.clone()),
            calibration: Some(crate::score_boundary::Calibration {
                slope: 0.,
                intercept: 0.,
            }),
        });
        crate::decision_record::record_recipient(&mut s, &config(), None, 42);
        let h = headers(&s);
        let field = &h["x-noisefence-score-boundary"];
        assert!(
            field.contains("unit=fusion_logit; value=0; cutoff=1; index-cutoff=50; above=false;")
        );
        assert!(field.contains(&hash));
        assert_eq!(h["x-noisefence-score"], "50.0");
        // Render the frozen boundary even if the mutable runtime metadata changes.
        s.fusion_boundary = None;
        assert_eq!(&headers(&s)["x-noisefence-score-boundary"], field);
        s.recipient_decision
            .as_mut()
            .unwrap()
            .assessment
            .score_boundary = None;
        assert_eq!(headers(&s)["x-noisefence-score-boundary"], "not_recorded");
    }

    #[test]
    fn review_fusion_malware_and_recipient_categories_do_not_rewrite_scores() {
        let mut s = scan();
        s.decision.as_mut().unwrap().score = None;
        s.decision.as_mut().unwrap().outcome = Outcome::Undetermined;
        let baseline = s.decision.as_ref().unwrap().clone();
        s.arbitration = Some(crate::decision::Arbitration {
            version: crate::decision::VERSION.into(),
            baseline: baseline.clone(),
            opinion: Outcome::Legitimate,
            resolution: crate::decision::Resolution::Disagreement,
            decision: baseline,
        });
        s.delivery_classification = Some(crate::mailing::Category::Legitimate);
        let h = headers(&s);
        assert_eq!(h["x-noisefence-score-type"], "advisory");
        assert_eq!(h["x-noisefence-verdict"], "ham");
        assert_eq!(
            parameter(&h["x-noisefence-policy"], "decision-outcome"),
            "undetermined"
        );
        assert!(h["x-noisefence-arbitration"].contains("resolution=disagreement"));
        s.delivery_classification = None;
        s.decision = Some(Decision {
            source: DecisionSource::Fusion,
            outcome: Outcome::Unwanted,
            score: Some(12.5),
            model: "test-fusion".into(),
        });
        let h = headers(&s);
        assert_eq!(h["x-noisefence-score"], "12.5");
        assert_eq!(
            parameter(&h["x-noisefence-score-details"], "content"),
            "99.9"
        );
        assert_eq!(
            parameter(&h["x-noisefence-score-details"], "model"),
            "test-fusion"
        );
        assert_eq!(h["x-noisefence-score-type"], "decision");
        s.score = 1.2;
        s.antivirus.status = crate::antivirus::AntivirusStatus::Malware;
        crate::decision::apply(&mut s, true);
        let h = headers(&s);
        assert_eq!(h["x-noisefence-score"], "1.2");
        assert_eq!(h["x-noisefence-score-type"], "advisory");
        assert_eq!(h["x-noisefence-verdict"], "spam");
        assert_eq!(parameter(&h["x-noisefence-policy"], "decision-source"), "antivirus");
        assert!(h["x-noisefence-antivirus"].contains("main=malware"));
    }

    #[test]
    fn headers_match_shared_assessment_including_historical_decisions() {
        let cases: Vec<serde_json::Value> =
            serde_json::from_str(include_str!("../tests/fixtures/assessment.json")).unwrap();
        for case in cases {
            let mut data = serde_json::to_value(Scan::default()).unwrap();
            for (key, value) in case["scan"].as_object().unwrap() {
                data[key] = value.clone();
            }
            let scan: Scan = serde_json::from_value(data).unwrap();
            let report = assessment::assess(&scan, config().filter.threshold);
            let h = headers(&scan);
            assert_eq!(h["x-noisefence-score"], number(report.score.value));
            assert_eq!(h["x-noisefence-verdict"], report.verdict());
            assert_eq!(h["x-noisefence-verdict"], report.verdict());
            assert_eq!(
                parameter(&h["x-noisefence-policy"], "decision-outcome"),
                word(&report.decision.outcome)
            );
            assert_eq!(
                parameter(&h["x-noisefence-policy"], "decision-recorded"),
                yes(report.decision_recorded)
            );
            assert_eq!(
                parameter(&h["x-noisefence-score-details"], "decision"),
                number(report.score.decision)
            );
        }
    }

    #[test]
    fn invalid_numbers_never_turn_into_zero_and_real_zero_stays_visible() {
        for value in [f64::NAN, f64::INFINITY, -1., 101.] {
            let mut s = scan();
            s.score = value;
            s.decision.as_mut().unwrap().score = Some(value);
            let h = headers(&s);
            assert_eq!(h["x-noisefence-score"], "unavailable");
            assert_eq!(h["x-noisefence-score-type"], "unavailable");
        }
        for value in [0., 100.] {
            let mut s = scan();
            s.score = value;
            s.decision = None;
            assert_eq!(headers(&s)["x-noisefence-score"], format!("{value:.1}"));
        }
    }

    #[test]
    fn diagnostics_are_bounded_ascii_and_do_not_expose_private_fields() {
        let mut s = scan();
        s.model = "injected\r\nBcc: secret@example.test".into();
        s.decision = None;
        s.subject = "private subject".into();
        s.sender = "secret@example.test".into();
        s.reasons = (0..1000)
            .map(|_| Signal {
                id: "x".repeat(64),
                detail: "private text".into(),
                weight: f64::MAX,
            })
            .collect();
        s.reasons[0].id = "forged\r\nX-Forged: yes".into();
        s.reasons[1].weight = f64::NAN;
        s.llm.verdict = Some(crate::llm::Verdict {
            category: crate::llm::Category::Phishing,
            spam_probability: 0.99,
            confidence: 0.95,
            explanation: "private text secret@example.test".into(),
        });
        let h = headers(&s);
        assert!(h["x-noisefence-rules"].contains("rule-shown=22; rule-omitted=978"));
        assert_eq!(
            parameter(&h["x-noisefence-score-details"], "model"),
            "unavailable"
        );
        assert!(!h.values().any(|v| v.contains("private")
            || v.contains("secret")
            || v.contains("forged")
            || v.contains("NaN")));
    }

    #[test]
    fn missing_checks_are_not_invented_as_clean_and_provider_errors_are_explicit() {
        let mut s = scan();
        let c = config();
        s.evidence = Some(crate::evidence::Evidence::new(
            &c,
            crate::evidence::Artifacts::new(&c, None, None, false),
            false,
        ));
        let e = s.evidence.as_mut().unwrap();
        e.authentication.spf_state = crate::evidence::State::NotRun;
        let mut p = crate::protection::Report::default();
        p.crdf.status = crate::protection::Status::Unavailable;
        p.crdf.failure = Some(crate::protection::ProviderFailure::Timeout);
        s.protection = Some(p);
        s.llm.status = crate::llm::LlmStatus::Unavailable;
        s.llm.failure = Some(crate::llm::Failure::Timeout);
        s.complete = false;
        s.antivirus.status = crate::antivirus::AntivirusStatus::Unscannable;
        let h = headers(&s);
        assert!(h["x-noisefence-checks"].contains("spf=not_run"));
        assert!(h["x-noisefence-authentication"].contains("spf=not_recorded"));
        assert!(h["x-noisefence-reputation"].contains("crdf.failure=timeout"));
        assert!(h["x-noisefence-llm"].contains("failure=timeout"));
        assert!(h["x-noisefence-analysis"].contains("incomplete=antivirus_unscannable;"));
    }
}

#[cfg(test)]
mod contract_tests {
    use super::*;
    #[test]
    fn wire_and_console_share_scores_and_separate_tagging_from_classification() {
        let c = Config::load(std::path::Path::new("config/development.toml")).unwrap();
        let cases: Vec<serde_json::Value> =
            serde_json::from_str(include_str!("../tests/fixtures/assessment.json")).unwrap();
        for case in cases {
            let mut data = serde_json::to_value(Scan::default()).unwrap();
            for (k, v) in case["scan"].as_object().unwrap() {
                data[k] = v.clone();
            }
            let s: Scan = serde_json::from_value(data).unwrap();
            let report = assessment::assess(&s, c.filter.threshold);
            let wire =
                render(&c, "192.0.2.1".parse().unwrap(), "test", &s, None).replace("\r\n\t", " ");
            for (name, value) in [
                ("X-NoiseFence-Score", number(report.score.value)),
                ("X-NoiseFence-Score-Type", word(&report.score.kind)),
                ("X-NoiseFence-Verdict", report.verdict().into()),
                ("X-NoiseFence-Header-Version", "11".into()),
            ] {
                assert!(
                    wire.contains(&format!("{name}: {value}\r\n")),
                    "{} / {name}",
                    case["name"]
                );
            }
            assert!(wire.contains("subject-tag=none;"), "{}", case["name"]);
            assert!(
                wire.contains(&format!(
                    "X-NoiseFence-Analysis: complete={}; elapsed-ms={};",
                    yes(report.complete),
                    s.elapsed_ms
                )),
                "{}",
                case["name"]
            );
        }
    }
}
