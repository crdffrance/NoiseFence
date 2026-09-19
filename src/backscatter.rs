//! Do not turn strongly corroborated hostile mail into a bounce to a forged sender.
//! This policy runs only AFTER a permanent upstream content rejection. It cannot
//! reject incoming SMTP, classify mail, or change observation/tagging policies.
use crate::{
    antivirus::AntivirusStatus,
    delivery_log::Attempt,
    engine::Scan,
    evidence::{AuthResult, Source, State},
    fusion::runtime::Outcome,
    llm::{Category, LlmStatus},
};

pub const VERSION: &str = "backscatter-1";
pub const STATUS: &str = "dsn_suppressed";

/// A remote reply, a high score, failed SPF or an LLM opinion alone never suffice.
/// Missing, conflicting or authenticated evidence preserves the normal DSN.
pub fn suppression_reason(scan: &Scan, attempt: &Attempt) -> Option<&'static str> {
    let final_reply = attempt.events.last()?;
    if attempt.outcome != "permanent"
        || attempt.truncated
        || !attempt.events.iter().any(|e| {
            e.phase == "tls"
                && e.detail
                    .as_deref()
                    .is_some_and(|d| d.starts_with("Verified TLS;"))
        })
        || final_reply.phase != "data_result"
        || !matches!(final_reply.code, Some(550 | 554))
        || final_reply.enhanced_code.as_deref() != Some("5.7.1")
        || !final_reply
            .response
            .as_deref()?
            .eq_ignore_ascii_case(&format!(
                "{} 5.7.1 rejected by rspamd filter",
                final_reply.code?
            ))
        || !scan.complete
        || scan.decision.as_ref()?.outcome != Outcome::Unwanted
        || scan
            .delivery_classification
            .is_some_and(|c| c != crate::mailing::Category::Spam)
    {
        return None;
    }
    let evidence = scan.evidence.as_ref()?;
    let auth = &evidence.authentication;
    if evidence.source != Source::SmtpSession
        || auth.state != State::Complete
        || auth.spf_state != State::Complete
        || !matches!(auth.spf, Some(AuthResult::Fail | AuthResult::SoftFail))
        || auth.dkim_state != State::Complete
        || auth
            .dkim
            .as_ref()?
            .iter()
            .any(|r| !matches!(r, AuthResult::None | AuthResult::Fail))
        || auth.dmarc_state != State::Complete
        || !matches!(auth.dmarc_spf, Some(AuthResult::None | AuthResult::Fail))
        || !matches!(auth.dmarc_dkim, Some(AuthResult::None | AuthResult::Fail))
        || auth.arc_state != State::Complete
        || !matches!(auth.arc, Some(AuthResult::None | AuthResult::Fail))
    {
        return None;
    }
    if scan.antivirus.status == AntivirusStatus::Malware {
        return Some("malware_and_upstream_rejection");
    }
    let verdict = scan.llm.verdict.as_ref()?;
    if (99.0..=100.0).contains(&scan.score)
        && scan.signatures.status == AntivirusStatus::Suspicious
        && scan
            .signatures
            .signature
            .as_deref()?
            .starts_with("Sanesecurity.Phishing.")
        && matches!(scan.llm.status, LlmStatus::Complete)
        && scan.llm.opinion() == Some(crate::fusion::runtime::Outcome::Unwanted)
        && matches!(verdict.category, Category::Phishing)
        && (0.9..=1.0).contains(&verdict.confidence)
        && (0.9..=1.0).contains(&verdict.spam_probability)
    {
        Some("phishing_signature_llm_and_upstream_rejection")
    } else {
        None
    }
}

/// Use only a valid permanent enhanced code, and an ASCII single-line bounded
/// diagnostic. Remote replies are untrusted and must not inject DSN fields.
pub fn failure_diagnostic(error: &str, attempt: Option<&Attempt>) -> (String, String) {
    fn permanent(code: &str) -> bool {
        let parts: Vec<_> = code.split('.').collect();
        parts.len() == 3
            && parts[0] == "5"
            && parts[1..]
                .iter()
                .all(|p| !p.is_empty() && p.len() <= 3 && p.bytes().all(|b| b.is_ascii_digit()))
    }
    if error.starts_with("5.4.7 ") {
        return ("5.4.7".into(), "Delivery retry period expired".into());
    }
    let event = attempt.and_then(|a| {
        a.events
            .iter()
            .rev()
            .find(|e| matches!(e.code, Some(500..=599)))
    });
    let status = event
        .and_then(|e| e.enhanced_code.as_deref())
        .filter(|c| permanent(c))
        .or_else(|| error.split_whitespace().next().filter(|c| permanent(c)))
        .unwrap_or("5.0.0")
        .to_owned();
    let text = event.and_then(|e| e.response.as_deref()).unwrap_or(error);
    let diagnostic = crate::delivery_log::sanitize_text(text)
        .chars()
        .map(|c| {
            if c.is_ascii() && !c.is_control() {
                c
            } else {
                '?'
            }
        })
        .take(400)
        .collect();
    (status, diagnostic)
}
