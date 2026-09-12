//! Local, bounded categorization of bulk mail. Never changes a security decision.
use crate::{
    engine::Scan,
    fusion::runtime::{Decision, Outcome},
    message,
};
use anyhow::Result;
use mail_parser::MimeHeaders;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::PathBuf, sync::OnceLock, time::Instant};

pub const VERSION: &str = "mailing-1";
pub(crate) const SIGNAL_SQL: &str = "COALESCE(json_extract(m.scan,'$.mailing.status')='complete' AND json_extract(m.scan,'$.mailing.verdict') IN ('promotion','newsletter'),0)";
pub(crate) const PUBLICITY_SQL: &str = "COALESCE(json_extract(m.scan,'$.delivery_classification')='publicity',(json_extract(m.scan,'$.complete')=1 AND COALESCE(json_extract(m.scan,'$.mailing.status')='complete' AND json_extract(m.scan,'$.mailing.verdict') IN ('promotion','newsletter'),0)))";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    pub include_newsletters: bool,
    pub tag_subject: bool,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            include_newsletters: true,
            tag_subject: true,
        }
    }
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub policy: Policy,
    /// Separate evidence for the exact [PUB] prefix; an old [SPAM] report is insufficient.
    pub proton_report: Option<PathBuf>,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Spam,
    Publicity,
    Legitimate,
    Undetermined,
}
impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Spam => "spam",
            Self::Publicity => "publicity",
            Self::Legitimate => "legitimate",
            Self::Undetermined => "undetermined",
        }
    }
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FeedbackCategory {
    Spam,
    Publicity,
    Legitimate,
}
impl FeedbackCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Spam => "spam",
            Self::Publicity => "publicity",
            Self::Legitimate => "legitimate",
        }
    }
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "spam" => Ok(Self::Spam),
            "publicity" => Ok(Self::Publicity),
            "legitimate" => Ok(Self::Legitimate),
            _ => anyhow::bail!("invalid feedback category"),
        }
    }
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Complete,
    Limited,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    None,
    Promotion,
    Newsletter,
    Transactional,
    Conversation,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Reason {
    pub id: String,
    pub detail: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Report {
    pub version: String,
    pub status: Status,
    pub verdict: Verdict,
    pub include_newsletters: bool,
    pub reasons: Vec<Reason>,
    /// Content-free observations for later evaluation with explicit human labels.
    pub features: BTreeMap<String, bool>,
    pub elapsed_us: u64,
}
impl Report {
    pub fn is_publicity(&self) -> bool {
        self.status == Status::Complete
            && matches!(self.verdict, Verdict::Promotion | Verdict::Newsletter)
    }
}
pub fn category(scan: &Scan, threshold: f64) -> Category {
    if let Some(category) = scan.delivery_classification {
        return category;
    }
    let decision = scan
        .decision
        .clone()
        .unwrap_or_else(|| Decision::legacy(scan, threshold));
    match decision.outcome {
        Outcome::Unwanted => Category::Spam,
        Outcome::Undetermined => Category::Undetermined,
        Outcome::Legitimate
            if scan.complete && scan.mailing.as_ref().is_some_and(Report::is_publicity) =>
        {
            Category::Publicity
        }
        Outcome::Legitimate => Category::Legitimate,
    }
}

fn normalize(value: &str) -> String {
    value
        .to_lowercase()
        .chars()
        .map(|c| match c {
            'é' | 'è' | 'ê' | 'ë' => 'e',
            'à' | 'â' | 'ä' => 'a',
            'î' | 'ï' => 'i',
            'ô' | 'ö' => 'o',
            'ù' | 'û' | 'ü' => 'u',
            'ç' => 'c',
            '’' => '\'',
            c => c,
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}
fn matches(pattern: &'static str, slot: &'static OnceLock<Regex>, text: &str) -> bool {
    slot.get_or_init(|| Regex::new(pattern).unwrap())
        .is_match(text)
}
fn reason(report: &mut Report, id: &str, detail: &str) {
    report.reasons.push(Reason {
        id: id.into(),
        detail: detail.into(),
    });
}
fn feature(report: &mut Report, id: &str, value: bool) -> bool {
    report.features.insert(id.into(), value);
    value
}

pub fn inspect(raw: &[u8], policy: &Policy, max_bytes: usize) -> Report {
    let started = Instant::now();
    let mut report = Report {
        version: VERSION.into(),
        status: Status::Complete,
        verdict: Verdict::None,
        include_newsletters: policy.include_newsletters,
        reasons: vec![],
        features: BTreeMap::new(),
        elapsed_us: 0,
    };
    if raw.len() > max_bytes.min(2 * 1024 * 1024) {
        report.status = Status::Limited;
        reason(
            &mut report,
            "input_limit",
            "Message trop volumineux pour la catégorisation PUB.",
        );
    } else if analyze(raw, policy, &mut report).is_err() {
        report.status = Status::Limited;
        report.verdict = Verdict::None;
        reason(
            &mut report,
            "parse_limit",
            "Analyse du contenu ou des en-têtes limitée : aucun classement PUB.",
        );
    }
    report.elapsed_us = started.elapsed().as_micros() as u64;
    report
}

fn analyze(raw: &[u8], policy: &Policy, report: &mut Report) -> Result<()> {
    let (headers, _) = message::fields(raw)?;
    let parsed = mail_parser::MessageParser::default()
        .parse(raw)
        .ok_or_else(|| anyhow::anyhow!("MIME"))?;
    anyhow::ensure!(
        parsed.parts.len() <= 200
            && parsed.text_body_count() <= 20
            && parsed.html_body_count() <= 20,
        "MIME limit"
    );
    let mut values = BTreeMap::new();
    for header in headers {
        let name = message::name(header);
        if [
            "list-unsubscribe",
            "list-unsubscribe-post",
            "list-id",
            "list-post",
            "precedence",
            "auto-submitted",
            "in-reply-to",
            "references",
            "content-type",
        ]
        .contains(&name.as_str())
        {
            anyhow::ensure!(
                header.len() <= 4096 && !values.contains_key(&name),
                "ambiguous mailing header"
            );
            let colon = header.iter().position(|b| *b == b':').unwrap();
            values.insert(
                name,
                String::from_utf8_lossy(&header[colon + 1..])
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" "),
            );
        }
    }
    let header = |name: &str| values.get(name).map(String::as_str).unwrap_or("");
    let (subject, body) =
        crate::features::text(raw).ok_or_else(|| anyhow::anyhow!("text extraction"))?;
    anyhow::ensure!(
        subject.chars().count() < 500 && body.chars().count() < 32_000,
        "text limit"
    );
    let normalized_subject = normalize(&subject);
    let subject = normalized_subject.trim_start_matches("[pub]").trim();
    let body = normalize(&body);
    let lead: String = body.chars().take(4000).collect();
    let content = format!("{subject} {body}");
    static URI: OnceLock<Regex> = OnceLock::new();
    let unsubscribe = URI
        .get_or_init(|| Regex::new(r"(?i)<((?:https?://|mailto:)[^<>\s]+)>").unwrap())
        .captures_iter(header("list-unsubscribe"))
        .any(|c| reqwest::Url::parse(&c[1]).is_ok());
    static LIST: OnceLock<Regex> = OnceLock::new();
    let list_id = matches(
        r"<[^<>\s@]{1,200}\.[a-zA-Z0-9-]+>",
        &LIST,
        header("list-id"),
    );
    let bulk = matches!(
        header("precedence").to_ascii_lowercase().as_str(),
        "bulk" | "list"
    );
    feature(report, "list_unsubscribe", unsubscribe);
    feature(report, "list_id", list_id);
    feature(report, "precedence_bulk", bulk);
    let one_click = feature(
        report,
        "one_click_syntax",
        unsubscribe
            && header("list-unsubscribe-post").eq_ignore_ascii_case("List-Unsubscribe=One-Click"),
    );
    if unsubscribe {
        reason(
            report,
            "unsubscribe",
            "Un mécanisme de désinscription est annoncé.",
        );
    }
    if list_id || bulk {
        reason(
            report,
            "distribution",
            "En-têtes caractéristiques d'une diffusion en liste.",
        );
    }
    if one_click {
        reason(
            report,
            "one_click",
            "Syntaxe de désinscription en un clic présente, sans désinscription automatique.",
        );
    }
    static OPT_OUT: OnceLock<Regex> = OnceLock::new();
    let opt_out = feature(
        report,
        "body_opt_out",
        matches(
            r"\b(?:se desabonner|me desabonner|vous desabonner|desinscription|unsubscribe|manage (?:your )?(?:email )?preferences|abmelden|darse de baja)\b",
            &OPT_OUT,
            &body,
        ),
    );
    static OFFER: OnceLock<Regex> = OnceLock::new();
    let offer = feature(
        report,
        "commercial_offer",
        matches(
            r"\b(?:promotions?|promos?|soldes|reductions?|remises?|discounts?|offres? (?:exclusives?|speciales?|du jour)|vente privee|black friday|flash sale|special offer|limited.time offer|rabatt|ofertas?|descuentos?|sconti)\b",
            &OFFER,
            &content,
        ),
    );
    static ACTION: OnceLock<Regex> = OnceLock::new();
    let action = feature(
        report,
        "commercial_action",
        matches(
            r"\b(?:achetez|acheter maintenant|commandez|profitez.en|j'en profite|decouvrez (?:nos|notre)|shop now|buy now|save now|get (?:your|the) deal|jetzt kaufen|compra ahora)\b",
            &ACTION,
            &content,
        ),
    );
    static DISCOUNT: OnceLock<Regex> = OnceLock::new();
    let discount = feature(
        report,
        "discount",
        matches(
            r"(?:\b[1-9][0-9]?\s*%\s*(?:off|de (?:remise|reduction)|discount|de descuento)|\b(?:code promo|promo code|coupon code|livraison offerte|free shipping)\b)",
            &DISCOUNT,
            &content,
        ),
    );
    static NEWS: OnceLock<Regex> = OnceLock::new();
    let newsletter = feature(
        report,
        "newsletter_content",
        matches(
            r"\b(?:newsletters?|lettre (?:d'information|hebdomadaire|mensuelle)|revue de presse|weekly (?:digest|roundup|newsletter)|daily digest|this week's (?:news|edition)|actualites de la semaine|bulletin (?:hebdomadaire|mensuel)|boletin|rundbrief)\b",
            &NEWS,
            &format!("{subject} {lead}"),
        ),
    );
    static TRANSACTION: OnceLock<Regex> = OnceLock::new();
    let transaction_subject = feature(
        report,
        "transaction_subject",
        matches(
            r"^(?:(?:votre|vos|your|ma|mon|notre|the|a|une|un)\s+)?(?:facture\b|invoice\b|recu\b|receipt\b|confirmation (?:de |d')?(?:commande|paiement|reservation|rendez.vous)|commande\s*(?:n[°o]|#|numero)|order (?:confirmation|receipt|#)|payment (?:confirmation|receipt)|shipping confirmation|votre colis|suivi (?:de )?(?:commande|colis)|mot de passe|password reset|code (?:de |d')?(?:connexion|verification|securite|authentification)|verification code|security (?:code|alert)|alerte (?:de )?securite|nouvelle connexion|new sign.in|reservation confirm|appointment|rendez.vous|ticket\s*#|incident\s*#|notification (?:de |d')?incident)",
            &TRANSACTION,
            subject,
        ),
    );
    static TX_BODY: OnceLock<Regex> = OnceLock::new();
    let transaction_body = feature(
        report,
        "transaction_body",
        matches(
            r"\b(?:votre code (?:de |d')?(?:verification|connexion|securite)|your (?:verification|security|one.time) code|numero de (?:commande|facture)|order number|invoice number|paiement (?:a ete |est )?(?:recu|confirme)|payment (?:has been )?received)\b",
            &TX_BODY,
            &lead,
        ),
    );
    static NOTIFICATION: OnceLock<Regex> = OnceLock::new();
    feature(
        report,
        "notification_subject",
        matches(
            r"\b(?:code (?:de |d')?(?:connexion|verification|securite)|verification code|security alert|alerte|notification|password reset|mot de passe|incident)\b",
            &NOTIFICATION,
            subject,
        ),
    );
    static INVOICE: OnceLock<Regex> = OnceLock::new();
    feature(
        report,
        "invoice_subject",
        matches(r"\b(?:facture|invoice|recu|receipt)\b", &INVOICE, subject),
    );
    static ORDER: OnceLock<Regex> = OnceLock::new();
    feature(
        report,
        "order_subject",
        matches(
            r"\b(?:commande|order|reservation|shipping|colis)\b",
            &ORDER,
            subject,
        ),
    );
    let automatic_response = feature(
        report,
        "automatic_response",
        header("auto-submitted")
            .split(';')
            .next()
            .unwrap_or("")
            .eq_ignore_ascii_case("auto-replied"),
    );
    let report_or_calendar = feature(
        report,
        "service_message",
        parsed.parts.iter().any(|p| {
            p.content_type().is_some_and(|ct| {
                ct.c_type.eq_ignore_ascii_case("text")
                    && ct
                        .c_subtype
                        .as_deref()
                        .is_some_and(|s| s.eq_ignore_ascii_case("calendar"))
            })
        }) || header("content-type")
            .to_ascii_lowercase()
            .contains("multipart/report"),
    );
    static REPLY: OnceLock<Regex> = OnceLock::new();
    let reply = feature(
        report,
        "conversation",
        !header("in-reply-to").is_empty()
            || !header("references").is_empty()
            || matches(r"^(?:re|fw|fwd|tr)\s*:", &REPLY, subject),
    );
    let discussion = feature(
        report,
        "discussion_list",
        !header("list-post").is_empty() && !header("list-post").eq_ignore_ascii_case("NO"),
    );
    if transaction_subject || transaction_body || automatic_response || report_or_calendar {
        report.verdict = Verdict::Transactional;
        reason(
            report,
            "transactional",
            "Indices de facture, reçu, authentification, alerte ou message de service : catégorie PUB écartée.",
        );
    } else if reply || discussion {
        report.verdict = Verdict::Conversation;
        reason(
            report,
            "conversation",
            "Réponse, transfert ou liste de discussion : catégorie PUB écartée.",
        );
    } else {
        // Correlated list headers form one distribution signal, never several votes.
        let distribution = unsubscribe || list_id || bulk || opt_out;
        let commercial = [offer, action, discount].into_iter().filter(|v| *v).count() >= 2;
        if distribution && commercial {
            report.verdict = Verdict::Promotion;
            reason(
                report,
                "promotion",
                "Diffusion collective et plusieurs indices commerciaux concordants.",
            );
        } else if policy.include_newsletters && distribution && newsletter {
            report.verdict = Verdict::Newsletter;
            reason(
                report,
                "newsletter",
                "Contenu de newsletter associé à un indice de diffusion collective.",
            );
        }
    }
    Ok(())
}
