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
    /// An explicit demand conflicts with the apparent reporting/receipt context.
    #[serde(default)]
    pub action_demand: bool,
    /// Explicit first-person compromise, disclosure threat and cryptocurrency demand.
    /// This contextual evidence never supplies a verdict by itself.
    #[serde(default)]
    pub direct_extortion: bool,
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
    result.merge_text(&subject, &body);
    // Quoted HTML attacks are evidence in a report, not a direct sender demand.
    if (0..message.html_body_count().min(20)).any(|i| {
        message
            .body_html(i)
            .is_some_and(|html| html.to_ascii_lowercase().contains("<blockquote"))
    }) {
        result.direct_extortion = false;
    }
    result
}

impl Context {
    /// Also used on the already bounded LLM excerpt. These hints are never
    /// trusted sender identity or permission to bypass security checks.
    pub(crate) fn merge_text(&mut self, subject: &str, body: &str) {
        let subject = subject.to_lowercase();
        let body = body.to_lowercase();
        static REPORT: OnceLock<Regex> = OnceLock::new();
        let report_subject = REPORT.get_or_init(|| Regex::new(r"(?i)\b(?:phishing (?:url|report|/ trademark)|malicious url report|url feed|threat intelligence|abuse report|pre-weaponized|signalement (?:de |d'une? )?(?:phishing|hameconnage))\b").unwrap()).is_match(&subject);
        let report_body = body.contains("url report for blocklist")
            || body.contains("phishing/malicious url database")
            || body.contains("phishing / malicious url database")
            || (body.contains("reporter:")
                && (body.contains("keep the url in your feed")
                    || body.contains("retain the url in your feed")))
            || body.matches("hxxp").take(3).count() >= 3;
        self.threat_report = report_subject && report_body;
        static TRANSACTION: OnceLock<Regex> = OnceLock::new();
        let shipment = TRANSACTION.get_or_init(|| Regex::new(r"(?i)\b(?:colis|commande|order|package|shipment)\b.*\b(?:re[cç]u|retir[eé]|exp[eé]di[eé]|en route|received|delivered|shipped)\b").unwrap()).is_match(&subject)
        && (body.contains("commande") || body.contains("order") || body.contains("colis") || body.contains("package"));
        static RECEIPT: OnceLock<Regex> = OnceLock::new();
        let payment_subject = RECEIPT.get_or_init(|| Regex::new(r"(?i)\b(?:re[cç]u (?:pour|de)|payment (?:receipt|confirmation|notification)|notification de paiement|paiement (?:effectu[eé]|re[cç]u)|automatic payment)\b").unwrap()).is_match(&subject);
        let payment_body = [
            "vous avez payé",
            "you paid",
            "payment was successful",
            "payment has been processed",
            "traitée avec succès",
            "paiement effectué",
            "payment received",
        ]
        .iter()
        .any(|s| body.contains(s));
        self.transaction_notice = shipment || (payment_subject && payment_body);
        static DEMAND: OnceLock<Regex> = OnceLock::new();
        self.direct_extortion =
            direct_extortion(&subject, &body) && !self.threat_report && !self.transaction_notice;
        self.action_demand = DEMAND.get_or_init(|| Regex::new(r"(?i)\b(?:enter (?:your |the )?(?:password|credentials|card)|verify your (?:account|identity|payment)|send (?:money|bitcoin)|transfer .{0,35}(?:wallet|bitcoin)|pay .{0,20}(?:bitcoin|btc)|install .{0,25}(?:software|application)|saisissez (?:votre |vos )?(?:mot de passe|identifiants)|v[eé]rifiez votre (?:compte|identit[eé])|g[eé]rer mon abonnement|annuler votre commande)\b").unwrap()).is_match(&body);
    }
}

/// Intentionally narrow: quoted incidents and ordinary crypto receipts abstain.
fn direct_extortion(subject: &str, body: &str) -> bool {
    static QUOTED: OnceLock<Regex> = OnceLock::new();
    static ACCESS: OnceLock<Regex> = OnceLock::new();
    static DISCLOSURE: OnceLock<Regex> = OnceLock::new();
    static PAYMENT: OnceLock<Regex> = OnceLock::new();
    static WALLET: OnceLock<Regex> = OnceLock::new();
    if QUOTED.get_or_init(|| Regex::new(r"(?i)^(?:re|fw|fwd|tr):|\b(?:sextortion report|abuse report|reported incident|scam analysis)\b").unwrap()).is_match(subject)
        || body.lines().any(|line| line.trim_start().starts_with('>'))
        || ["forwarded message", "original message", "received this", "received the following", "the following email", "example of", "sample of", "scammer", "quoted message"]
            .iter().any(|phrase| body.contains(phrase))
    { return false; }
    let body = body.split_whitespace().collect::<Vec<_>>().join(" ");
    ACCESS.get_or_init(|| Regex::new(r"\b(?:i (?:have |had )?(?:gained access to|recorded you|hacked your)|my (?:private )?trojan.{0,100}(?:your (?:files|camera|device)|access))\b").unwrap()).is_match(&body)
        && DISCLOSURE.get_or_init(|| Regex::new(r"\b(?:i (?:will|can)|clicks to).{0,45}(?:share|publish|send).{0,130}(?:friends|relatives|colleagues|contacts|online)\b").unwrap()).is_match(&body)
        && PAYMENT.get_or_init(|| Regex::new(r"\b(?:send|transfer(?:red)?|pay|demanding|all you need)\b.{0,90}(?:bitcoin|btc|cryptocurrency|wallet)\b").unwrap()).is_match(&body)
        && WALLET.get_or_init(|| Regex::new(r"\b(?:bc1[a-z0-9]{25,87}|[13][a-z0-9]{25,34})\b").unwrap()).is_match(&body)
}

pub fn attach(scan: &mut Scan, raw: &[u8], max_bytes: usize) {
    if raw.len() > max_bytes || scan.features_complete == Some(false) {
        return;
    }
    let context = inspect(raw);
    if context.encrypted {
        scan.complete = false;
        scan.features_complete = Some(false);
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
        || context.action_demand
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
