//! Bounded context for interpretation, never an allowlist or a learned score.
use crate::engine::Scan;
use mail_parser::MimeHeaders;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
mod notices;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Context {
    pub encrypted: bool,
    pub threat_report: bool,
    pub transaction_notice: bool,
    #[serde(default)]
    pub conditional_security_notice: bool,
    /// A bounded operational event or automatic software-update notice.
    /// Still requires observed alignment, clean scanners and no sensitive demand.
    #[serde(default)]
    pub passive_service_notice: bool,
    /// An explicit demand conflicts with the apparent reporting/receipt context.
    #[serde(default)]
    pub action_demand: bool,
    /// Explicit first-person compromise, disclosure threat and cryptocurrency demand.
    /// This contextual evidence never supplies a verdict by itself.
    #[serde(default)]
    pub direct_extortion: bool,
    /// A cryptocurrency reward instruction echoed in a subscription profile field.
    #[serde(default)]
    pub injected_reward_lure: bool,
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
    // Evaluate demands within each bounded alternative. Joining a plain part
    // and its HTML rendering can put unrelated end/start words next to each
    // other, especially when whitespace prevents feature-text deduplication.
    result.action_demand = (0..message.text_body_count().min(20)).any(|i| {
        message.body_text(i).is_some_and(|text| {
            action_demand(&text.chars().take(32_000).collect::<String>().to_lowercase())
        })
    }) || (0..message.html_body_count().min(20)).any(|i| {
        message.body_html(i).is_some_and(|html| {
            action_demand(
                &crate::features::visible(&html)
                    .chars()
                    .take(32_000)
                    .collect::<String>()
                    .to_lowercase(),
            )
        })
    });
    let sender = message
        .from()
        .and_then(|a| a.first())
        .and_then(|a| a.address.as_deref())
        .and_then(|a| a.rsplit_once('@').map(|(_, d)| d.to_ascii_lowercase()));
    result.injected_reward_lure = sender
        .as_deref()
        .is_some_and(|s| injected_reward_lure(&subject, &body, s));
    // Quoted HTML attacks are evidence in a report, not a direct sender demand.
    if (0..message.html_body_count().min(20)).any(|i| {
        message
            .body_html(i)
            .is_some_and(|html| html.to_ascii_lowercase().contains("<blockquote"))
    }) {
        result.direct_extortion = false;
        result.injected_reward_lure = false;
    }
    result
}

fn injected_reward_lure(subject: &str, body: &str, sender: &str) -> bool {
    let subject = subject.to_lowercase();
    let body = body.to_lowercase();
    if ["re:", "fw:", "fwd:", "tr:"]
        .iter()
        .any(|p| subject.starts_with(p))
        || body.lines().any(|line| line.trim_start().starts_with('>'))
        || [
            "forwarded message",
            "received the following",
            "scam analysis",
            "abuse report",
            "reported incident",
            "quoted message",
            "example of",
            "sample of",
        ]
        .iter()
        .any(|p| body.contains(p))
        || !body.contains("subscription")
        || !body.contains("confirmed")
        || !body.contains("information you submitted")
    {
        return false;
    }
    let Some(sender_site) = psl::domain_str(sender) else {
        return false;
    };
    static FIELD: OnceLock<Regex> = OnceLock::new();
    static REWARD: OnceLock<Regex> = OnceLock::new();
    static CLAIM: OnceLock<Regex> = OnceLock::new();
    FIELD.get_or_init(|| Regex::new(r"\bfirst name\s*:\s*([^\r\n]{1,400})").unwrap())
        .captures_iter(&body).take(4).any(|field| {
            let value = &field[1];
            REWARD.get_or_init(|| Regex::new(r"\b[0-9][0-9,.]{1,18}\s*(?:usdt|btc|bitcoin|eth)\b.{0,35}\b(?:reward|prize|bonus)\b").unwrap()).is_match(value)
                && CLAIM.get_or_init(|| Regex::new(r"\b(?:collect|claim|redeem)\s+(?:it\s+)?now\b").unwrap()).is_match(value)
                && crate::content_urls::extract(value).any(|url| {
                    reqwest::Url::parse(&url).ok().and_then(|u| u.host_str().map(str::to_owned))
                        .is_some_and(|host| psl::domain_str(&host).is_some_and(|site| site != sender_site))
                })
        })
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
        // Classification disputes quote reported malicious URLs as evidence.
        // Require the reporting purpose and structured report fields together;
        // a subject saying "dispute" or an isolated hostile URL is insufficient.
        static DISPUTE_TITLE: OnceLock<Regex> = OnceLock::new();
        static DISPUTE_PURPOSE: OnceLock<Regex> = OnceLock::new();
        static DISPUTE_FIELDS: OnceLock<Regex> = OnceLock::new();
        let dispute = DISPUTE_TITLE.get_or_init(|| Regex::new(
            r"\b(?:new dispute|classification dispute|false positive review|contestation de classification)\b"
        ).unwrap()).is_match(&subject)
            && DISPUTE_PURPOSE.get_or_init(|| Regex::new(
                r"\b(?:contestation de classification|classification dispute|false positive review)\b"
            ).unwrap()).is_match(&body)
            && DISPUTE_FIELDS.get_or_init(|| Regex::new(
                r"\b(?:nombre d['’]urls signal[eé]es|reported url count)\s*:\s*[1-9][0-9]{0,3}\b"
            ).unwrap()).is_match(&body)
            && (body.contains("urls signalées") || body.contains("reported urls"))
            && (body.contains("référence :") || body.contains("reference:"));
        self.threat_report = (report_subject && report_body) || dispute;
        static TRANSACTION: OnceLock<Regex> = OnceLock::new();
        let shipment = TRANSACTION.get_or_init(|| Regex::new(r"(?i)\b(?:colis|commande|order|package|shipment)\b.*\b(?:re[cç]u|retir[eé]|exp[eé]di[eé]|en route|received|delivered|shipped)\b").unwrap()).is_match(&subject)
        && (body.contains("commande") || body.contains("order") || body.contains("colis") || body.contains("package"));
        // Many transactional templates put the shipment status first and omit
        // "order" from the subject. Require a completed event in the body and
        // an order reference; a delivery-themed title alone is not evidence.
        let shipment = shipment || status_first_shipment(&subject, &body);
        static RECEIPT: OnceLock<Regex> = OnceLock::new();
        let payment_subject = RECEIPT.get_or_init(|| Regex::new(r"(?i)\b(?:re[cç]u (?:pour|de|du)|r[eé]c[eé]piss[eé]|payment (?:receipt|confirmation|notification)|notification de paiement|paiement (?:effectu[eé]|re[cç]u)|automatic payment)\b").unwrap()).is_match(&subject);
        let payment_body = [
            "vous avez payé",
            "you paid",
            "payment was successful",
            "payment has been processed",
            "traitée avec succès",
            "paiement effectué",
            "payment received",
            "amount paid",
            "montant payé",
            "paiement a bien été pris en compte",
        ]
        .iter()
        .any(|s| body.contains(s));
        // Completed-transfer and ride-receipt context is independent of any
        // brand or sender allowlist. A current sensitive demand still conflicts.
        static TRANSFER: OnceLock<Regex> = OnceLock::new();
        let transfer = TRANSFER.get_or_init(|| Regex::new(r"(?i)\b(?:virement|bank transfer|payout)\b.{0,40}\b(?:en route|on (?:its|the) way|processed|sent)\b").unwrap()).is_match(&subject)
            && ["montant du virement", "transfer amount", "payout amount"].iter().any(|p| body.contains(p))
            && ["compte bancaire", "bank account"].iter().any(|p| body.contains(p));
        static TRIP: OnceLock<Regex> = OnceLock::new();
        let trip_receipt = TRIP
            .get_or_init(|| Regex::new(r"(?i)\byour\b.{0,40}\b(?:trip|ride)\b").unwrap())
            .is_match(&subject)
            && body.contains("thanks for riding")
            && body.contains("trip fare")
            && body.contains("payments");
        static COMPLETED_PAYMENT: OnceLock<Regex> = OnceLock::new();
        let completed_payment = COMPLETED_PAYMENT.get_or_init(|| Regex::new(
            r"\b(?:votre paiement|le paiement|your payment|payment for)\b.{0,140}\b(?:a [eé]t[eé] (?:effectu[eé]|r[eé]alis[eé]) avec succ[eè]s|has been successfully completed)\b"
        ).unwrap()).is_match(&body.split_whitespace().collect::<Vec<_>>().join(" "));
        self.transaction_notice = shipment
            || (payment_subject && (payment_body || completed_payment))
            || transfer
            || trip_receipt
            || notices::transaction(&subject, &body);
        self.passive_service_notice =
            passive_service_notice(&subject, &body) || notices::service(&subject, &body);
        static SECURITY_EVENT: OnceLock<Regex> = OnceLock::new();
        static OPTIONAL_ACTION: OnceLock<Regex> = OnceLock::new();
        self.conditional_security_notice = SECURITY_EVENT.get_or_init(|| Regex::new(
            r"(?i)\b(?:password (?:was |has been )?(?:changed|reset)|(?:modification|changement) du mot de passe|security (?:information|info) (?:was |has been )?added|informations de s[eé]curit[eé].{0,45}ajout[eé]es)\b"
        ).unwrap()).is_match(&subject) && OPTIONAL_ACTION.get_or_init(|| Regex::new(
            r"\b(?:if (?:this|it) was you[ ,:;\t-]*(?:then )?(?:(?:(?:you (?:can|may)|please) )?ignore|no action is required)|si c['’][eé]tait vous[ ,:;\t-]*(?:vous pouvez ignorer|aucune action n['’]est (?:requise|n[eé]cessaire)))\b"
        ).unwrap()).is_match(&body);
        self.direct_extortion =
            direct_extortion(&subject, &body) && !self.threat_report && !self.transaction_notice;
        self.action_demand = action_demand(&body);
    }
}

fn status_first_shipment(subject: &str, body: &str) -> bool {
    static TITLE: OnceLock<Regex> = OnceLock::new();
    static EVENT: OnceLock<Regex> = OnceLock::new();
    static REFERENCE: OnceLock<Regex> = OnceLock::new();
    let body = body.split_whitespace().collect::<Vec<_>>().join(" ");
    TITLE.get_or_init(|| Regex::new(
        r"^\s*(?:exp[eé]di[eé]|livr[eé]|en cours de livraison|shipped|dispatched|delivered|out for delivery)\s*:"
    ).unwrap()).is_match(subject)
        && EVENT.get_or_init(|| Regex::new(
            r"\b(?:(?:votre|le) (?:colis|commande) (?:a [eé]t[eé]|est) (?:exp[eé]di[eé]e?|livr[eé]e?|en cours de livraison)|(?:your|the) (?:order|package|shipment) (?:has been|was|is) (?:shipped|dispatched|delivered|out for delivery))\b"
        ).unwrap()).is_match(&body)
        && REFERENCE.get_or_init(|| Regex::new(
            r"\b(?:n[°o]\s*de commande|commande\s*(?:n[°o]|#)|order\s*(?:number|id|#))\s*[:#]?\s*[a-z0-9][a-z0-9-]{2,40}\b"
        ).unwrap()).is_match(&body)
}

fn action_demand(body: &str) -> bool {
    static DEMAND: OnceLock<Regex> = OnceLock::new();
    DEMAND.get_or_init(|| Regex::new(r"(?i)\b(?:enter (?:your |the )?(?:password|credentials|card)|verify your (?:account|identity|payment)|send (?:money|bitcoin)|transfer .{0,35}(?:wallet|bitcoin)|pay .{0,20}(?:bitcoin|btc)|install .{0,25}(?:software|application)|saisissez (?:votre |vos )?(?:mot de passe|identifiants)|v[eé]rifiez votre (?:compte|identit[eé])|g[eé]rer mon abonnement|annuler votre commande)\b").unwrap()).is_match(body)
        || sensitive_service_demand(body)
}

fn passive_service_notice(subject: &str, body: &str) -> bool {
    static OPERATION: OnceLock<Regex> = OnceLock::new();
    static EVENT: OnceLock<Regex> = OnceLock::new();
    static UPDATE: OnceLock<Regex> = OnceLock::new();
    let operation = OPERATION.get_or_init(|| Regex::new(
        r"\b(?:t[aâ]che de sauvegarde|backup (?:task|job)|v[eé]rification de l['’]int[eé]grit[eé]|integrity check)\b"
    ).unwrap());
    let event = EVENT.get_or_init(|| Regex::new(
        r"\b(?:[eé]chec|[eé]chou[eé]|suspendu[eé]?|interrompu[eé]?|failed|failure|suspended|interrupted|resumed|completed)\b"
    ).unwrap());
    let operational = operation.is_match(subject)
        && event.is_match(subject)
        && operation.is_match(body)
        && event.is_match(body);
    let automatic_update = UPDATE
        .get_or_init(|| {
            Regex::new(
                r"\b(?:mise [aà] jour du (?:logiciel|firmware)|(?:software|firmware) update)\b",
            )
            .unwrap()
        })
        .is_match(subject)
        && [
            "reçoivent automatiquement des mises à jour",
            "sera installé automatiquement",
            "will be installed automatically",
            "automatically receives software updates",
        ]
        .iter()
        .any(|p| body.contains(p));
    operational || automatic_update
}

/// A service/receipt title cannot neutralize a current credential, restriction
/// or urgent callback demand. No bank names, sender allowlists or link visits.
fn sensitive_service_demand(body: &str) -> bool {
    static CALL: OnceLock<Regex> = OnceLock::new();
    static CARD: OnceLock<Regex> = OnceLock::new();
    static ACTIVATE: OnceLock<Regex> = OnceLock::new();
    static CREDENTIAL: OnceLock<Regex> = OnceLock::new();
    static MANUAL_UPDATE: OnceLock<Regex> = OnceLock::new();
    static URL: OnceLock<Regex> = OnceLock::new();
    // Indicator feeds quote hostile URLs. Their hostname/path tokens are data,
    // not prose asking this recipient to activate, call or disclose credentials.
    let prose = URL
        .get_or_init(|| {
            Regex::new(
        r"(?i)\b(?:https?|hxxps?)://[^\s<>]+|\b(?:[a-z0-9-]+(?:\.|\[\.\]))+[a-z]{2,63}(?:/[^\s<>]*)?"
    ).unwrap()
        })
        .replace_all(body, " ");
    let text = prose.split_whitespace().collect::<Vec<_>>().join(" ");
    let callback = CALL.get_or_init(|| Regex::new(
        r"\b(?:appelez|contactez|call|contact)\b.{0,60}\b(?:imm[eé]diatement|urgence|urgent|immediately|opposition|fraud)\b"
    ).unwrap()).is_match(&text) && CARD.get_or_init(|| Regex::new(
        r"\b(?:carte|card|paiement|payment|d[eé]bit|debit)\b"
    ).unwrap()).is_match(&text);
    let activation = ACTIVATE.get_or_init(|| {
        let action = r"\b(?:activez|activer|activate|activation|mise [aà] jour obligatoire|mandatory update)\b";
        let restriction = r"\b(?:bloqu[eé](?:e?s)?|blocage|suspendu(?:e?s)?|suspension|restreint(?:e?s)?|restricted|blocked|suspended)\b";
        Regex::new(&format!(r"(?:{action}.{{0,180}}{restriction}|{restriction}.{{0,180}}{action})")).unwrap()
    }).is_match(&text);
    let manual_update = MANUAL_UPDATE.get_or_init(|| Regex::new(
        r"\b(?:(?:you must|you need to|please) (?:complete|perform|install) (?:a |the |this )?(?:manual|security|firmware) update|(?:vous devez|veuillez) (?:effectuer|installer) (?:une |la |cette )?mise [aà] jour (?:manuelle|de s[eé]curit[eé]))\b"
    ).unwrap()).is_match(&text);
    callback || activation || manual_update || CREDENTIAL.get_or_init(|| Regex::new(
        r"\b(?:saisir|saisissez|renseignez|communiquez|confirmez|enter|provide|confirm)\b.{0,35}\b(?:identifiants|mot de passe|code de s[eé]curit[eé]|password|credentials|security code)\b"
    ).unwrap()).is_match(&text)
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
    if context.injected_reward_lure && !context.encrypted {
        scan.reasons.push(crate::engine::Signal {
            id: "injected_reward_lure".into(),
            detail: "A subscription profile field contains a cryptocurrency reward, an immediate claim instruction and an off-site URL. Authentication of the sending service does not authenticate this submitted content.".into(),
            weight: 1.5,
        });
    }
    scan.message_context = Some(context);
}

/// A contextual contradiction can require review, never mark a message safe.
/// Only gateway-observed aligned authentication is eligible; header claims,
/// content-only scans and missing authentication do not qualify.
pub fn needs_review(scan: &Scan) -> bool {
    let Some(context) = &scan.message_context else {
        return false;
    };
    if !(context.threat_report
        || context.transaction_notice
        || context.conditional_security_notice
        || context.passive_service_notice)
        || context.action_demand
        || context.direct_extortion
        || context.injected_reward_lure
        || crate::confirmation::corroborated(scan)
    {
        return false;
    }
    let Some(evidence) = &scan.evidence else {
        return false;
    };
    crate::evidence::eligibility::dmarc_pass(evidence)
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
