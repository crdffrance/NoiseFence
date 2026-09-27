//! Validate citations against the bounded request, not against model confidence.
//! No brand allowlist, external fetch or automatic legitimate verdict is added.
use super::{Category, Verdict};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Claim {
    CurrentRequest,
    ReportedIndicator,
    ConditionalNotification,
    DifferentDomain,
    AuthenticationFailure,
    OwnershipMismatch,
    AttachmentThreat,
    Extortion,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Citation {
    pub source: String,
    pub claim: Claim,
    pub quote: String,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Issue {
    MissingEvidence,
    InvalidCitation,
    QuoteNotFound,
    AuthenticationNotObserved,
    DomainDifferenceNotObserved,
    OwnershipNotObserved,
    AttachmentThreatNotObserved,
    ExtortionNotObserved,
    ReportWithoutCurrentRequest,
    ConditionalNoticeWithoutThreat,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Report {
    pub version: String,
    pub supported: bool,
    pub mail_kind: crate::quality::Kind,
    pub accepted_citations: usize,
    pub issues: Vec<Issue>,
}
fn normalized(s: &str) -> String {
    crate::content_view::compact(s).to_lowercase()
}
/// Exact bounded citations establish that a fact was supplied, not that the
/// email is malicious. Authentication alone cannot prove benign intent either.
pub fn validate(
    verdict: &Verdict,
    kind: crate::quality::Kind,
    citations: &[Citation],
    data: &Value,
    facts: &Value,
) -> Report {
    let mut issues = Vec::new();
    let mut accepted = 0;
    let mut current_request = false;
    if citations.is_empty() || citations.len() > 6 {
        issues.push(Issue::MissingEvidence);
    }
    let auth = &facts["gateway_observations"]["authentication"];
    for citation in citations.iter().take(6) {
        let quote = normalized(&citation.quote);
        let source = citation.source.as_str();
        let source_valid = matches!(
            source,
            "subject" | "text" | "html_text" | "quoted_text" | "link_context" | "authentication"
        );
        let mut issue = None;
        if !source_valid
            || citation.quote.len() > 240
            || quote.len() < 8
            || citation.quote.chars().any(char::is_control)
        {
            issue = Some(Issue::InvalidCitation);
        } else if source != "authentication"
            && !data[source]
                .as_str()
                .is_some_and(|text| normalized(text).contains(&quote))
        {
            issue = Some(Issue::QuoteNotFound);
        } else {
            match citation.claim {
                Claim::AuthenticationFailure => {
                    if source != "authentication"
                        || !["spf", "dmarc_spf_alignment", "dmarc_dkim_alignment"]
                            .iter()
                            .any(|k| {
                                auth[k].as_str() == Some("fail") && quote == format!("{k}=fail")
                            })
                    {
                        issue = Some(Issue::AuthenticationNotObserved);
                    }
                }
                Claim::DifferentDomain => {
                    if source != "link_context"
                        || !data["link_domain_relationships"]
                            .as_array()
                            .is_some_and(|links| {
                                links.iter().any(|l| {
                                    l["relationship"] == "different_registrable_domain"
                                        && l["host"].as_str().is_some_and(|h| {
                                            crate::content_urls::extract(&citation.quote).any(|u| {
                                                reqwest::Url::parse(&u)
                                                    .ok()
                                                    .is_some_and(|u| u.host_str() == Some(h))
                                            })
                                        })
                                })
                            })
                    {
                        issue = Some(Issue::DomainDifferenceNotObserved);
                    }
                }
                // No ownership registry or attachment behaviour is supplied to
                // this text-only classifier. Provider assertions cannot add one.
                Claim::OwnershipMismatch => issue = Some(Issue::OwnershipNotObserved),
                Claim::AttachmentThreat => issue = Some(Issue::AttachmentThreatNotObserved),
                Claim::Extortion => {
                    if !matches!(source, "text" | "html_text")
                        || data["content_context_hints"]["direct_extortion"] != true
                    {
                        issue = Some(Issue::ExtortionNotObserved);
                    } else {
                        current_request = true;
                    }
                }
                Claim::CurrentRequest => {
                    if matches!(source, "text" | "html_text") {
                        current_request = true;
                    } else {
                        issue = Some(Issue::ReportWithoutCurrentRequest);
                    }
                }
                Claim::ConditionalNotification | Claim::ReportedIndicator => {
                    if source == "authentication" {
                        issue = Some(Issue::InvalidCitation);
                    }
                }
            }
        }
        if let Some(issue) = issue {
            if !issues.contains(&issue) {
                issues.push(issue);
            }
        } else {
            accepted += 1;
        }
    }
    if matches!(verdict.category, Category::Spam | Category::Phishing) {
        if !current_request {
            issues.push(Issue::ReportWithoutCurrentRequest);
        }
        let hints = &data["content_context_hints"];
        let aligned = ["dmarc_spf_alignment", "dmarc_dkim_alignment"]
            .iter()
            .any(|k| auth[k] == "pass");
        if aligned
            && hints["conditional_security_notice"] == true
            && hints["action_demand"] != true
            && hints["direct_extortion"] != true
            && hints["injected_reward_lure"] != true
        {
            issues.push(Issue::ConditionalNoticeWithoutThreat);
        }
    }
    Report {
        version: "llm-grounding-2".into(),
        supported: issues.is_empty() && accepted > 0,
        mail_kind: kind,
        accepted_citations: accepted,
        issues,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn verdict() -> Verdict {
        Verdict {
            category: Category::Phishing,
            spam_probability: 0.9,
            confidence: 0.99,
            explanation: "Fixture".into(),
        }
    }
    fn data() -> Value {
        json!({"text":"Please enter your password to recover the account.","link_context":"Verify -> https://other.example.org","link_domain_relationships":[{"host":"other.example.org","relationship":"different_registrable_domain"}],"content_context_hints":{"action_demand":true}})
    }
    fn citation(source: &str, claim: Claim, quote: &str) -> Citation {
        Citation {
            source: source.into(),
            claim,
            quote: quote.into(),
        }
    }
    #[test]
    fn citations_need_observed_facts_and_current_request() {
        let d = data();
        let facts = json!({"gateway_observations":{"authentication":{"spf":"pass","dmarc_dkim_alignment":"pass"}}});
        let c = citation("text", Claim::CurrentRequest, "enter your password");
        assert!(validate(&verdict(), crate::quality::Kind::Other, &[c], &d, &facts).supported);
        for c in [
            citation("text", Claim::CurrentRequest, "Invented evidence"),
            citation("authentication", Claim::AuthenticationFailure, "SPF failed"),
            citation("text", Claim::OwnershipMismatch, "enter your password"),
            citation("text", Claim::AttachmentThreat, "enter your password"),
        ] {
            assert!(!validate(&verdict(), crate::quality::Kind::Other, &[c], &d, &facts).supported);
        }
        let c = citation(
            "link_context",
            Claim::DifferentDomain,
            "https://other.example.org",
        );
        assert!(!validate(&verdict(), crate::quality::Kind::Other, &[c], &d, &facts).supported);
    }
    #[test]
    fn quoted_reports_never_supply_the_current_request() {
        let mut d = data();
        d["quoted_text"] = d["text"].clone();
        assert!(
            !validate(
                &verdict(),
                crate::quality::Kind::Other,
                &[citation(
                    "quoted_text",
                    Claim::CurrentRequest,
                    "enter your password"
                )],
                &d,
                &Value::Null
            )
            .supported
        );
    }
    #[test]
    fn conditional_security_notices_need_additional_evidence_and_do_not_whitelist_attackers() {
        let mut d = data();
        d["content_context_hints"] =
            json!({"conditional_security_notice":true,"action_demand":false});
        let facts =
            json!({"gateway_observations":{"authentication":{"dmarc_dkim_alignment":"pass"}}});
        assert!(
            !validate(
                &verdict(),
                crate::quality::Kind::Notification,
                &[citation(
                    "text",
                    Claim::CurrentRequest,
                    "enter your password"
                )],
                &d,
                &facts
            )
            .supported
        );
        d["content_context_hints"]["action_demand"] = json!(true);
        assert!(
            validate(
                &verdict(),
                crate::quality::Kind::Other,
                &[citation(
                    "text",
                    Claim::CurrentRequest,
                    "enter your password"
                )],
                &d,
                &facts
            )
            .supported
        );
    }
    #[test]
    fn authentication_citations_must_name_the_exact_observed_failed_check() {
        let mut verdict = verdict();
        verdict.category = Category::Ambiguous;
        let facts = json!({"gateway_observations":{"authentication":{"spf":"fail","dmarc_dkim_alignment":"pass"}}});
        for (quote, supported) in [
            ("spf=fail", true),
            ("dmarc_dkim_alignment=fail", false),
            ("DKIM failed", false),
        ] {
            let report = validate(
                &verdict,
                crate::quality::Kind::Other,
                &[citation(
                    "authentication",
                    Claim::AuthenticationFailure,
                    quote,
                )],
                &data(),
                &facts,
            );
            assert_eq!(report.supported, supported, "{quote}");
        }
    }
}

/// Replace each bounded source string by exact, locally assigned text records.
/// Metadata adds identifiers, not a second copy of the email text. Joining a
/// field's records reproduces the original field byte for byte.
pub fn indexed_input(mut data: Value) -> Value {
    for source in [
        "subject",
        "text",
        "html_text",
        "quoted_text",
        "link_context",
    ] {
        let text = data[source].as_str().unwrap_or("").to_owned();
        let mut records = Vec::new();
        let mut remaining = text.as_str();
        while !remaining.is_empty() {
            let mut end = remaining.len().min(240);
            while !remaining.is_char_boundary(end) {
                end -= 1;
            }
            if end < remaining.len()
                && let Some(boundary) = remaining[..end]
                    .rfind(char::is_whitespace)
                    .filter(|i| *i >= 120)
            {
                end = boundary;
            }
            records.push(serde_json::json!({"id":format!("{source}:{}",records.len()),"text":&remaining[..end]}));
            remaining = &remaining[end..];
        }
        data[source] = serde_json::json!(records);
    }
    data
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Reference {
    pub reference: String,
    pub claim: Claim,
}
pub(super) fn resolve(
    references: Vec<Reference>,
    data: &Value,
    facts: &Value,
) -> (Vec<Citation>, Value) {
    let mut plain = data.clone();
    let mut records = std::collections::BTreeMap::new();
    for source in [
        "subject",
        "text",
        "html_text",
        "quoted_text",
        "link_context",
    ] {
        let mut text = String::new();
        for record in data[source].as_array().into_iter().flatten() {
            if let (Some(id), Some(value)) = (record["id"].as_str(), record["text"].as_str()) {
                records.insert(id.to_owned(), (source, value.to_owned()));
                text.push_str(value);
            }
        }
        plain[source] = serde_json::json!(text);
    }
    for key in ["spf", "dmarc_spf_alignment", "dmarc_dkim_alignment"] {
        if facts["gateway_observations"]["authentication"][key] == "fail" {
            records.insert(
                format!("authentication:{key}"),
                ("authentication", format!("{key}=fail")),
            );
        }
    }
    let citations = references
        .into_iter()
        .map(|r| {
            let (source, quote) = records
                .get(&r.reference)
                .cloned()
                .unwrap_or(("invalid_reference", String::new()));
            Citation {
                source: source.into(),
                claim: r.claim,
                quote: crate::content_view::compact(&quote),
            }
        })
        .collect();
    (citations, plain)
}

#[cfg(test)]
mod reference_tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn indexing_preserves_the_shared_text_budget_and_rejects_forged_ids() {
        let d = json!({"subject":"Synthetic fixture","text":"étéλ ".repeat(1500),"html_text":"short","quoted_text":"quoted history","link_context":"Open -> https://other.example.org"});
        let indexed = indexed_input(d.clone());
        let (citations, plain) = resolve(
            vec![
                Reference {
                    reference: "text:0".into(),
                    claim: Claim::CurrentRequest,
                },
                Reference {
                    reference: "text:999999".into(),
                    claim: Claim::CurrentRequest,
                },
            ],
            &indexed,
            &Value::Null,
        );
        assert_eq!(plain, d);
        assert_eq!(citations[0].source, "text");
        assert_eq!(citations[1].source, "invalid_reference");
        assert!(citations[0].quote.len() <= 240);
    }
}
