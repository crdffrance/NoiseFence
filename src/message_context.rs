//! Bounded context for interpretation, never an allowlist or a learned score.
use crate::engine::Scan;
use mail_parser::MimeHeaders;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Context {
    pub encrypted: bool,
    pub threat_report: bool,
    pub transaction_notice: bool,
}

pub fn inspect(raw: &[u8]) -> Context {
    let mut result = Context::default();
    let Some(message) = mail_parser::MessageParser::default().parse(raw) else {
        return result;
    };
    // Signed text remains readable. Encrypted MIME and opaque S/MIME do not.
    result.encrypted = message.parts.first().is_some_and(|part| {
        part.content_type().is_some_and(|ct| {
            let sub = ct.c_subtype.as_deref().unwrap_or("");
            (ct.c_type.eq_ignore_ascii_case("multipart") && sub.eq_ignore_ascii_case("encrypted"))
                || (ct.c_type.eq_ignore_ascii_case("application")
                    && (sub.eq_ignore_ascii_case("pkcs7-mime")
                        || sub.eq_ignore_ascii_case("x-pkcs7-mime")))
        })
    });
    let Some((subject, body)) = crate::features::text(raw) else {
        return result;
    };
    let subject = subject.to_lowercase();
    let body = body.to_lowercase();
    static REPORT: OnceLock<Regex> = OnceLock::new();
    let report_subject = REPORT.get_or_init(|| Regex::new(r"(?i)\b(?:phishing (?:url|report)|malicious url report|url feed|signalement (?:de |d'une? )?(?:phishing|hameconnage))\b").unwrap()).is_match(&subject);
    let report_body = body.contains("url report for blocklist")
        || body.contains("phishing/malicious url database")
        || body.contains("phishing / malicious url database")
        || body.matches("hxxp").take(3).count() >= 3;
    result.threat_report = report_subject && report_body;
    static TRANSACTION: OnceLock<Regex> = OnceLock::new();
    result.transaction_notice = TRANSACTION.get_or_init(|| Regex::new(r"(?i)\b(?:colis|commande|order|package|shipment)\b.*\b(?:re[cç]u|retir[eé]|exp[eé]di[eé]|en route|received|delivered|shipped)\b").unwrap()).is_match(&subject)
        && (body.contains("commande") || body.contains("order") || body.contains("colis") || body.contains("package"));
    result
}

pub fn attach(scan: &mut Scan, raw: &[u8], max_bytes: usize) {
    if raw.len() > max_bytes {
        return;
    }
    let context = inspect(raw);
    if context.encrypted {
        scan.complete = false;
        scan.reasons.push(crate::engine::Signal {
            id: "encrypted_content".into(),
            detail: "Encrypted or opaque content is not readable by this gateway; only accessible evidence was analysed.".into(),
            weight: 0.0,
        });
    }
    scan.message_context = Some(context);
}

/// A contextual contradiction can require review, never mark a message safe.
/// Only gateway-observed aligned authentication is eligible; header claims,
/// content-only scans and missing authentication do not qualify.
pub fn needs_review(scan: &Scan) -> bool {
    use crate::evidence::{AuthResult, Source, State};
    let Some(context) = &scan.message_context else {
        return false;
    };
    if !(context.threat_report || context.transaction_notice)
        || crate::confirmation::corroborated(scan)
    {
        return false;
    }
    let Some(evidence) = &scan.evidence else {
        return false;
    };
    evidence.source != Source::ContentOnly
        && evidence.authentication.dmarc_state == State::Complete
        && (evidence.authentication.dmarc_spf == Some(AuthResult::Pass)
            || evidence.authentication.dmarc_dkim == Some(AuthResult::Pass))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reports_need_a_reporting_context_and_do_not_become_trusted_mail() {
        let report = inspect(b"Subject: Example URL feed\r\n\r\nhxxps://bad.example/a\nhxxps://bad.example/b\nhxxps://bad.example/c\r\n");
        assert!(report.threat_report);
        let attack = inspect(b"Subject: Phishing URL\r\n\r\nSign in and enter your password at https://bad.example\r\n");
        assert!(!attack.threat_report);
        assert!(!needs_review(&Scan {
            message_context: Some(report),
            ..Default::default()
        }));
    }
    #[test]
    fn encrypted_body_is_distinct_from_signed_readable_mail() {
        assert!(inspect(b"Content-Type: multipart/encrypted; boundary=a\r\n\r\n--a\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n--a--\r\n").encrypted);
        assert!(!inspect(b"Content-Type: multipart/signed; boundary=a\r\n\r\n--a\r\nContent-Type: text/plain\r\n\r\nHello\r\n--a--\r\n").encrypted);
    }
}
