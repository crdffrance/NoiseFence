//! Versioned, bounded SMTP diagnostics. No free-form detector/provider text,
//! message identities, URLs, features or recipient policies belong on the wire.
use crate::{config::Config, engine::Scan, fusion::runtime::DecisionSource};
use serde::Serialize;
use std::net::IpAddr;

pub(crate) const FIELDS: &[&str] = &[
    "X-NoiseFence-Id",
    "X-NoiseFence-Header-Version",
    "X-NoiseFence-Version",
    "X-NoiseFence-Mode",
    "X-NoiseFence-Score",
    "X-NoiseFence-Score-Type",
    "X-NoiseFence-Score-Source",
    "X-NoiseFence-Score-Scale",
    "X-NoiseFence-Model",
    "X-NoiseFence-Raw-Score",
    "X-NoiseFence-Decision-Score",
    "X-NoiseFence-Status",
    "X-NoiseFence-Decision",
    "X-NoiseFence-Decision-Source",
    "X-NoiseFence-Category",
    "X-NoiseFence-Analysis",
    "X-NoiseFence-Checks",
    "X-NoiseFence-Authentication",
    "X-NoiseFence-Incomplete-Reasons",
    "X-NoiseFence-Arbitration",
    "X-NoiseFence-Rules",
    "X-NoiseFence-LLM",
    "X-NoiseFence-Antivirus",
    "X-NoiseFence-Vision",
    "X-NoiseFence-Vision-Errors",
    "X-NoiseFence-Reputation",
    "X-NoiseFence-RBL",
    "X-NoiseFence-Native",
    "X-NoiseFence-Native-Rules",
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
const INCOMPLETE_REASONS: &[&str] = &[
    "analysis_budget",
    "signature_budget",
    "checks_unavailable",
    "llm_unavailable",
    "semantic_unavailable",
    "smtp_policy_unavailable",
    "vision_incomplete",
    "complementary_signature_unavailable",
];

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
    value.filter(|v| v.is_finite() && (0.0..=100.0).contains(v))
}
fn number(value: Option<f64>) -> String {
    score(value)
        .map(|v| format!("{v:.1}"))
        .unwrap_or_else(|| "unavailable".into())
}

struct Writer(String);
impl Writer {
    fn field(&mut self, name: &str, value: impl AsRef<str>) {
        debug_assert!(FIELDS.contains(&name));
        self.0.push_str(name);
        self.0.push(':');
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
                self.0.push_str("\r\n\t");
                column = 1;
            } else {
                self.0.push(' ');
                column += 1;
            }
            self.0.push_str(atom);
            column += atom.len();
        }
        self.0.push_str("\r\n");
    }
}

fn rules<'a>(items: impl Iterator<Item = (&'a str, f64)>, total: usize, unit: &str) -> String {
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
            values.push_str(&format!(" {id}={weight};"));
            shown += 1;
        }
    }
    format!(
        "unit={unit}; total={total}; shown={shown}; omitted={};{values}",
        total.saturating_sub(shown)
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

pub(crate) fn render(config: &Config, ip: IpAddr, id: &str, scan: &Scan) -> String {
    let id = token(id).unwrap_or("invalid");
    let mut h = Writer(format!(
        "Received: from [{}] by {} with ESMTP id {};\r\n\t{}\r\n",
        ip,
        config.hostname,
        id,
        mail_parser::DateTime::from_timestamp(crate::now()).to_rfc822()
    ));
    let decision = scan.decision.as_ref();
    let selected_decision = decision
        .filter(|d| d.source != DecisionSource::Antivirus)
        .and_then(|d| score(d.score));
    let selected = selected_decision.or_else(|| score(Some(scan.score)));
    let source = if selected.is_none() {
        "unavailable"
    } else if selected_decision.is_some() {
        "decision"
    } else {
        "raw"
    };
    let model = if selected_decision.is_some() {
        decision.map(|d| d.model.as_str())
    } else {
        Some(scan.model.as_str())
    };
    // Same qualification as the console; neither score nor this label is used
    // to decide classification, recipient actions, tagging or quarantine.
    let kind = if selected.is_none() {
        "unavailable"
    } else if !scan.complete {
        "partial"
    } else if scan.model == "dsn" {
        "internal"
    } else if decision.is_some_and(|d| {
        d.source == DecisionSource::Antivirus
            || d.outcome == crate::fusion::runtime::Outcome::Undetermined
    }) {
        "advisory"
    } else if selected_decision.is_some()
        && decision.is_some_and(|d| d.source == DecisionSource::Fusion)
    {
        "decision"
    } else {
        "content"
    };

    h.field("X-NoiseFence-Id", id);
    h.field("X-NoiseFence-Header-Version", "2");
    h.field("X-NoiseFence-Version", env!("CARGO_PKG_VERSION"));
    h.field("X-NoiseFence-Mode", word(&config.filter.mode));
    h.field("X-NoiseFence-Score", number(selected));
    h.field("X-NoiseFence-Score-Type", kind);
    h.field("X-NoiseFence-Score-Source", source);
    h.field("X-NoiseFence-Score-Scale", "0-100");
    h.field(
        "X-NoiseFence-Model",
        model.and_then(token).unwrap_or("unavailable"),
    );
    h.field("X-NoiseFence-Raw-Score", number(Some(scan.score)));
    h.field(
        "X-NoiseFence-Decision-Score",
        number(decision.and_then(|d| d.score)),
    );
    h.field(
        "X-NoiseFence-Status",
        if !scan.complete {
            "incomplete"
        } else if scan.tagged {
            "spam"
        } else if scan.pub_tagged {
            "pub"
        } else {
            "observed"
        },
    );
    h.field(
        "X-NoiseFence-Decision",
        decision
            .map(|d| word(&d.outcome))
            .unwrap_or_else(|| "undetermined".into()),
    );
    h.field(
        "X-NoiseFence-Decision-Source",
        decision
            .map(|d| word(&d.source))
            .unwrap_or_else(|| "legacy".into()),
    );
    h.field(
        "X-NoiseFence-Category",
        crate::mailing::category(scan, config.filter.threshold).as_str(),
    );
    h.field(
        "X-NoiseFence-Analysis",
        format!(
            "complete={}; elapsed-ms={};",
            yes(scan.complete),
            scan.elapsed_ms
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
            let result = |v: Option<crate::evidence::AuthResult>| {
                v.map(|v| word(&v)).unwrap_or_else(|| "not_recorded".into())
            };
            let dkim = e
                .authentication
                .dkim
                .as_ref()
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
                "spf={}; dkim={dkim}; dmarc-spf={}; dmarc-dkim={}; arc={};",
                result(e.authentication.spf),
                result(e.authentication.dmarc_spf),
                result(e.authentication.dmarc_dkim),
                result(e.authentication.arc)
            )
        })
        .unwrap_or_else(|| "not_recorded".into()),
    );
    let mut missing: Vec<_> = INCOMPLETE_REASONS
        .iter()
        .copied()
        .filter(|id| scan.reasons.iter().any(|r| &r.id == id))
        .collect();
    match scan.antivirus.status {
        crate::antivirus::AntivirusStatus::Unavailable => missing.push("antivirus_unavailable"),
        crate::antivirus::AntivirusStatus::Unscannable => missing.push("antivirus_unscannable"),
        _ => {}
    }
    h.field(
        "X-NoiseFence-Incomplete-Reasons",
        if scan.complete {
            "none".into()
        } else if missing.is_empty() {
            "unspecified".into()
        } else {
            missing.join("; ")
        },
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
    h.field(
        "X-NoiseFence-Rules",
        rules(
            scan.reasons.iter().map(|r| (r.id.as_str(), r.weight)),
            scan.reasons.len(),
            "logit",
        ),
    );
    h.field(
        "X-NoiseFence-LLM",
        format!(
            "status={}; verdict={}; failure={}; elapsed-ms={}; advisory=yes;",
            word(&scan.llm.status),
            scan.llm
                .verdict
                .as_ref()
                .map(|v| word(&v.category))
                .unwrap_or_else(|| "none".into()),
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
    h.field(
        "X-NoiseFence-Vision",
        format!(
            "status={}; parts={}; pages={}; qr-codes={}; other-codes={}; errors={}; elapsed-ms={};",
            word(&scan.vision.status),
            scan.vision.parts,
            scan.vision.pages,
            scan.vision.qr_codes,
            scan.vision.other_codes,
            scan.vision.errors.len(),
            scan.vision.elapsed_ms
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
    h.field(
        "X-NoiseFence-Vision-Errors",
        if scan.vision.errors.is_empty() {
            "none".into()
        } else if vision_errors.is_empty() {
            "unrecognized".into()
        } else {
            vision_errors.into_iter().collect::<Vec<_>>().join("; ")
        },
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
    h.field("X-NoiseFence-RBL", scan.early_rbl.as_ref().map(|r| {
        use crate::rbl::Status;
        let count = |status| r.checks.iter().filter(|c| c.status == status).count();
        format!("checks={}; listed-providers={}; not-listed={}; listed={}; policy={}; unavailable={}; skipped={}; action={};",
            r.checks.len(), r.listed_providers, count(Status::NotListed), count(Status::Listed),
            count(Status::Policy), count(Status::Unavailable), count(Status::Skipped), word(&r.effective_action))
    }).unwrap_or_else(|| "not_recorded".into()));
    h.field(
        "X-NoiseFence-Native",
        scan.native_filter
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
            }),
    );
    h.field(
        "X-NoiseFence-Native-Rules",
        scan.native_filter
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
                )
            })
            .unwrap_or_else(|| "unavailable".into()),
    );
    h.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        engine::Signal,
        fusion::runtime::{Decision, Outcome},
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
    fn headers(scan: &Scan) -> std::collections::BTreeMap<String, String> {
        let wire = render(&config(), "192.0.2.1".parse().unwrap(), "test-id", scan);
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
        assert_eq!(h["x-noisefence-score-source"], "raw");
        assert_eq!(h["x-noisefence-decision-score"], "unavailable");
        assert_eq!(h["x-noisefence-status"], "incomplete");
        assert_eq!(h["x-noisefence-decision"], "undetermined");
        assert_eq!(h["x-noisefence-incomplete-reasons"], "vision_incomplete");
        assert!(h["x-noisefence-analysis"].contains("elapsed-ms=1245"));
        assert!(h["x-noisefence-vision"].contains("status=limited"));
        assert_eq!(h["x-noisefence-vision-errors"], "pixel_limit");
        assert!(!h.values().any(|v| v.contains("Private")));
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
        assert_eq!(h["x-noisefence-category"], "legitimate");
        assert_eq!(h["x-noisefence-decision"], "undetermined");
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
        assert_eq!(h["x-noisefence-raw-score"], "99.9");
        assert_eq!(h["x-noisefence-model"], "test-fusion");
        assert_eq!(h["x-noisefence-score-type"], "decision");
        s.score = 1.2;
        s.antivirus.status = crate::antivirus::AntivirusStatus::Malware;
        crate::decision::apply(&mut s, true);
        let h = headers(&s);
        assert_eq!(h["x-noisefence-score"], "1.2");
        assert_eq!(h["x-noisefence-score-type"], "advisory");
        assert_eq!(h["x-noisefence-category"], "spam");
        assert_eq!(h["x-noisefence-decision-source"], "antivirus");
        assert!(h["x-noisefence-antivirus"].contains("main=malware"));
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
        assert!(h["x-noisefence-rules"].contains("shown=22; omitted=978"));
        assert_eq!(h["x-noisefence-model"], "unavailable");
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
        assert_eq!(
            h["x-noisefence-incomplete-reasons"],
            "antivirus_unscannable"
        );
    }
}
