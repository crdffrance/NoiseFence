//! Versioned, bounded SMTP diagnostics. No free-form detector/provider text,
//! message identities, URLs, features or recipient policies belong on the wire.
use crate::{assessment, config::Config, engine::Scan};
use serde::Serialize;
use std::net::IpAddr;

pub(crate) const FIELDS: &[&str] = &[
    "X-NoiseFence-Id",
    "X-NoiseFence-Header-Version",
    "X-NoiseFence-Activation",
    "X-NoiseFence-Record-Version",
    "X-NoiseFence-Classification",
    "X-NoiseFence-Coverage",
    "X-NoiseFence-Policy-SHA256",
    "X-NoiseFence-Action-Requested",
    "X-NoiseFence-Action-Effective",
    "X-NoiseFence-Action-Coverage",
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
    "X-NoiseFence-Assessment-Version",
    "X-NoiseFence-Classification-Source",
    "X-NoiseFence-Content-Threshold",
    "X-NoiseFence-Score-Boundary",
    "X-NoiseFence-Policy-Version",
    "X-NoiseFence-Delivery-Policy",
    "X-NoiseFence-Subject-Tag",
    "X-NoiseFence-Decision",
    "X-NoiseFence-Decision-Source",
    "X-NoiseFence-Decision-Recorded",
    "X-NoiseFence-Category",
    "X-NoiseFence-Analysis",
    "X-NoiseFence-Checks",
    "X-NoiseFence-Authentication",
    "X-NoiseFence-Incomplete-Reasons",
    "X-NoiseFence-Supplementary-Gaps",
    "X-NoiseFence-Arbitration",
    "X-NoiseFence-Score-Resolution",
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

struct Writer(String);
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

pub(crate) fn render(
    config: &Config,
    ip: IpAddr,
    id: &str,
    scan: &Scan,
    early_rbl: Option<&crate::rbl::Report>,
) -> String {
    let id = token(id).unwrap_or("invalid");
    let mut h = Writer(format!(
        "Received: from [{}] by {} with ESMTP id {};\r\n\t{}\r\n",
        ip,
        config.hostname,
        id,
        mail_parser::DateTime::from_timestamp(crate::now()).to_rfc822()
    ));
    let report = assessment::assess(scan, config.filter.threshold);
    if let Some(record) = &scan.recipient_decision {
        h.field("X-NoiseFence-Record-Version", record.version.to_string());
        h.field("X-NoiseFence-Classification", word(&record.classification));
        h.field("X-NoiseFence-Coverage", word(&record.coverage));
        h.field("X-NoiseFence-Policy-SHA256", &record.policy_sha256);
        if let Some(action) = &report.action {
            h.field("X-NoiseFence-Action-Requested", word(&action.requested));
            h.field("X-NoiseFence-Action-Effective", word(&action.effective));
        } else {
            h.field("X-NoiseFence-Action-Requested", "not_recorded");
            h.field("X-NoiseFence-Action-Effective", "not_recorded");
        }
    } else {
        for name in [
            "X-NoiseFence-Record-Version",
            "X-NoiseFence-Classification",
            "X-NoiseFence-Coverage",
            "X-NoiseFence-Policy-SHA256",
            "X-NoiseFence-Action-Requested",
            "X-NoiseFence-Action-Effective",
        ] {
            h.field(name, "not_recorded");
        }
    }
    if let Some(coverage) = report.action.as_ref().and_then(|a| a.coverage.as_ref()) {
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
        h.field(
            "X-NoiseFence-Action-Coverage",
            format!(
                "version={}; partial-policy={}; basis={}; eligible={}; required={}; missing={};",
                token(&coverage.version).unwrap_or("unknown"),
                yes(coverage.partial_actions),
                word(&coverage.basis),
                yes(coverage.eligible()),
                list(&coverage.required),
                list(&coverage.missing)
            ),
        );
    } else {
        h.field("X-NoiseFence-Action-Coverage", "not_recorded");
    }
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
    h.field(
        "X-NoiseFence-Supplementary-Gaps",
        if report.supplementary_gaps.is_empty() {
            "none".into()
        } else {
            report.supplementary_gaps.join("; ")
        },
    );

    h.field("X-NoiseFence-Id", id);
    h.field("X-NoiseFence-Header-Version", "6");
    h.field(
        "X-NoiseFence-Activation",
        crate::decision_record::recorded_activation(scan).map_or_else(
            || "not_recorded".into(),
            |epoch| {
                format!(
                    "sequence={}; revision={}; bundle-sha256={};",
                    epoch.sequence, epoch.revision, epoch.digest
                )
            },
        ),
    );
    h.field("X-NoiseFence-Version", env!("CARGO_PKG_VERSION"));
    h.field(
        "X-NoiseFence-Mode",
        word(&report.mode.unwrap_or(config.filter.mode)),
    );
    h.field("X-NoiseFence-Score", number(report.score.value));
    h.field("X-NoiseFence-Score-Type", word(&report.score.kind));
    h.field("X-NoiseFence-Score-Source", word(&report.score.source));
    h.field("X-NoiseFence-Score-Scale", "0-100");
    h.field(
        "X-NoiseFence-Model",
        token(&report.score.model).unwrap_or("unavailable"),
    );
    h.field("X-NoiseFence-Raw-Score", number(report.score.raw));
    h.field("X-NoiseFence-Decision-Score", number(report.score.decision));
    h.field(
        "X-NoiseFence-Status",
        if report.complete {
            "complete"
        } else {
            "incomplete"
        },
    );
    h.field(
        "X-NoiseFence-Assessment-Version",
        report.version.to_string(),
    );
    h.field(
        "X-NoiseFence-Classification-Source",
        word(&report.classification_source),
    );
    h.field(
        "X-NoiseFence-Content-Threshold",
        number(report.content_threshold),
    );
    h.field("X-NoiseFence-Score-Boundary", report.score_boundary.as_ref().map_or_else(
        || if report.score.value.is_some() { "not_recorded" } else { "unavailable" }.into(),
        |b| format!("version={}; unit={}; value={}; cutoff={}; index-cutoff={}; above={}; model-sha256={};",
            b.version, match b.source { crate::score_boundary::Source::Content => "content_index", crate::score_boundary::Source::Fusion => "fusion_logit" },
            precise(b.value), precise(b.cutoff), precise(b.index_cutoff), b.above,
            b.model_sha256.as_deref().filter(|h| crate::compatibility::valid_hash(h)).unwrap_or("not_recorded"))));
    h.field(
        "X-NoiseFence-Policy-Version",
        report
            .policy_version
            .as_deref()
            .and_then(token)
            .unwrap_or("not_recorded"),
    );
    h.field(
        "X-NoiseFence-Delivery-Policy",
        report
            .action
            .as_ref()
            .map(|a| {
                format!(
                    "requested={}; effective={}; reason={};",
                    word(&a.requested),
                    word(&a.effective),
                    token(&a.reason).unwrap_or("unknown")
                )
            })
            .unwrap_or_else(|| "not_recorded".into()),
    );
    h.field("X-NoiseFence-Subject-Tag", word(&report.subject_tag));
    h.field("X-NoiseFence-Decision", word(&report.decision.outcome));
    h.field(
        "X-NoiseFence-Decision-Source",
        word(&report.decision.source),
    );
    h.field(
        "X-NoiseFence-Decision-Recorded",
        yes(report.decision_recorded),
    );
    h.field("X-NoiseFence-Category", report.category.as_str());
    h.field(
        "X-NoiseFence-Analysis",
        format!(
            "complete={}; elapsed-ms={};",
            yes(report.complete),
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
    h.field(
        "X-NoiseFence-Incomplete-Reasons",
        if report.incomplete_reasons.is_empty() {
            "none".into()
        } else {
            report.incomplete_reasons.join("; ")
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
    // Admission observations reach the renderer separately; the classifier
    // never receives them as additional evidence or counts their score twice.
    h.field("X-NoiseFence-RBL", early_rbl.or(scan.early_rbl.as_ref()).map(|r| {
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
        assert_eq!(headers(&scan)["x-noisefence-activation"], "not_recorded");
        crate::decision_record::record_recipient(&mut scan, &config(), None, 1234);
        assert_eq!(
            headers(&scan)["x-noisefence-activation"],
            format!("sequence=7; revision=12; bundle-sha256={};", "a".repeat(64))
        );
        assert_eq!(headers(&scan)["x-noisefence-record-version"], "2");
        assert!(signed_fields().any(|field| field == "X-NoiseFence-Activation"));
        scan.activation_epoch.as_mut().unwrap().sequence += 1;
        assert_eq!(headers(&scan)["x-noisefence-activation"], "not_recorded");
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
            assert_eq!(h["x-noisefence-category"], report.category.as_str());
            assert_eq!(h["x-noisefence-decision"], word(&report.decision.outcome));
            assert_eq!(
                h["x-noisefence-decision-recorded"],
                yes(report.decision_recorded)
            );
            assert_eq!(
                h["x-noisefence-decision-score"],
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
                ("X-NoiseFence-Category", report.category.as_str().into()),
                ("X-NoiseFence-Subject-Tag", "none".into()),
                ("X-NoiseFence-Header-Version", "6".into()),
                (
                    "X-NoiseFence-Status",
                    if s.complete { "complete" } else { "incomplete" }.into(),
                ),
            ] {
                assert!(
                    wire.contains(&format!("{name}: {value}\r\n")),
                    "{} / {name}",
                    case["name"]
                );
            }
        }
    }
}
