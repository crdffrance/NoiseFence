//! Versioned, bounded content features shared by training and Rust inference.
//! No DNS, link fetches, attachment execution, or historical filter headers.
use crate::{engine::Scan, message};
use regex::Regex;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::OnceLock,
};

pub const VERSION: u32 = 3;
pub const DIMENSION: usize = 262_144;
const TEXT_LIMIT: usize = 32_000;
static WORDS: OnceLock<Regex> = OnceLock::new();
static ACTIVE: OnceLock<Regex> = OnceLock::new();
static PREFIX: OnceLock<Regex> = OnceLock::new();
static URL: OnceLock<Regex> = OnceLock::new();
static NUMBERS: OnceLock<Regex> = OnceLock::new();

fn hash(namespace: &str, token: &str) -> usize {
    let mut hash = 14695981039346656037u64;
    for byte in namespace.bytes().chain(token.bytes()) {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(1099511628211);
    }
    (hash % DIMENSION as u64) as usize
}

fn visible(html: &str) -> String {
    // Explicitly remove non-visible blocks before the MIME library conversion.
    // Do not let stylesheets become training features or dominate LLM excerpts.
    let hidden = ACTIVE.get_or_init(|| {
        Regex::new(r"(?is)<!--.*?-->|<\s*(?:style|script|template|head)\b[^>]*>.*?</\s*(?:style|script|template|head)\s*>").unwrap()
    });
    mail_parser::decoders::html::html_to_text(&hidden.replace_all(html, " "))
}

pub fn text(raw: &[u8]) -> Option<(String, String)> {
    let parsed = mail_parser::MessageParser::default().parse(raw)?;
    if parsed.parts.len() > 200 {
        return None;
    }
    let subject = unlabelled_subject(parsed.subject().unwrap_or(""));
    let mut pieces = Vec::new();
    for i in 0..parsed.text_body_count().min(20) {
        if let Some(body) = parsed.body_text(i) {
            pieces.push(body.chars().take(TEXT_LIMIT).collect::<String>());
        }
    }
    for i in 0..parsed.html_body_count().min(20) {
        if let Some(body) = parsed.body_html(i) {
            let body = visible(&body).chars().take(TEXT_LIMIT).collect::<String>();
            if !pieces.contains(&body) {
                pieces.push(body);
            }
        }
    }
    Some((
        subject.chars().take(500).collect(),
        pieces.join(" ").chars().take(TEXT_LIMIT).collect(),
    ))
}

/// An upstream filter's subject tag is not evidence of abuse. Share the exact
/// normalization with the second opinion without changing schema-3 features.
pub(crate) fn unlabelled_subject(subject: &str) -> std::borrow::Cow<'_, str> {
    PREFIX
        .get_or_init(|| {
            Regex::new(r"(?i)^(?:\s*\[(?:spam|junk|phishing|bulk)(?:[^\]]{0,20})\]\s*)+").unwrap()
        })
        .replace_all(subject, "")
}

pub fn campaign_text(raw: &[u8]) -> Option<String> {
    let (subject, body) = text(raw)?;
    let text = format!("{subject} {body}").to_lowercase();
    let text = URL
        .get_or_init(|| {
            Regex::new(r"(?i)https?://[^\s<>]+|[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}").unwrap()
        })
        .replace_all(&text, " LINK ");
    let text = NUMBERS
        .get_or_init(|| Regex::new(r"\d+").unwrap())
        .replace_all(&text, "#");
    Some(text.split_whitespace().collect::<Vec<_>>().join(" "))
}

/// Campaign grouping hint, retained with features after the raw message expires.
pub fn simhash(text: &str) -> String {
    let mut votes = [0i32; 64];
    let words: BTreeSet<&str> = text.split_whitespace().take(20_000).collect();
    for word in words {
        let digest = message::digest(word.as_bytes());
        let hash = u64::from_str_radix(&digest[..16], 16).unwrap();
        for (bit, vote) in votes.iter_mut().enumerate() {
            *vote += if hash & (1 << bit) != 0 { 1 } else { -1 };
        }
    }
    let mut hash = 0u64;
    for (bit, vote) in votes.into_iter().enumerate() {
        if vote > 0 {
            hash |= 1 << bit;
        }
    }
    format!("{hash:016x}")
}

pub fn extract(raw: &[u8], max_bytes: usize) -> Scan {
    let mut scan = crate::engine::extract(raw, max_bytes);
    scan.feature_version = VERSION;
    scan.features_complete = Some(false);
    if !scan.complete {
        scan.features.clear();
        return scan;
    }
    let Some((subject, body)) = text(raw) else {
        scan.complete = false;
        scan.features.clear();
        return scan;
    };
    let lower = format!("{subject} {body}").to_lowercase();
    scan.reasons.retain(|r| {
        !matches!(
            r.id.as_str(),
            "urgency" | "credential_request" | "financial_lure"
        )
    });
    for (id, detail, weight, tokens) in [
        (
            "urgency",
            "Vocabulaire d’urgence",
            0.5,
            &["urgent", "immediately", "immédiatement"][..],
        ),
        (
            "credential_request",
            "Demande liée aux identifiants",
            1.5,
            &[
                "verify your account",
                "confirmez votre compte",
                "password expires",
                "mot de passe expire",
            ][..],
        ),
        (
            "financial_lure",
            "Promesse financière suspecte",
            1.5,
            &[
                "lottery",
                "loterie",
                "million dollars",
                "guaranteed profit",
                "profit garanti",
            ][..],
        ),
    ] {
        if tokens.iter().any(|token| lower.contains(token)) {
            scan.reasons.push(crate::engine::Signal {
                id: id.into(),
                detail: detail.into(),
                weight,
            });
        }
    }
    let word = WORDS.get_or_init(|| Regex::new(r"[\p{L}\p{N}]{2,40}").unwrap());
    let words: Vec<_> = word
        .find_iter(&lower)
        .take(8_000)
        .map(|m| m.as_str())
        .collect();
    let mut counts: BTreeMap<usize, f64> = BTreeMap::new();
    let mut add = |namespace, token: &str, value| {
        *counts.entry(hash(namespace, token)).or_default() += value;
    };
    for token in &words {
        add("w:", token, 1.0);
    }
    for tokens in words.windows(2) {
        add("b:", &format!("{} {}", tokens[0], tokens[1]), 1.0);
    }
    for token in word.find_iter(&subject.to_lowercase()).take(100) {
        add("s:", token.as_str(), 1.0);
    }
    // Word-boundary character grams generalize spelling, morphology and obfuscation.
    let mut remaining = 24_000;
    for token in &words {
        let chars: Vec<char> = format!(" {token} ").chars().collect();
        if chars.len() > remaining {
            break;
        }
        remaining -= chars.len();
        for width in 3..=5 {
            for gram in chars.windows(width) {
                add("c:", &gram.iter().collect::<String>(), 0.5);
            }
        }
    }
    let parsed = mail_parser::MessageParser::default().parse(raw).unwrap();
    let html = parsed.body_html(0).unwrap_or_default();
    let links = crate::engine::domains_in_text(&format!("{body} {html}"));
    let sender_domain = scan
        .sender
        .rsplit_once('@')
        .map(|(_, d)| d.to_lowercase())
        .unwrap_or_default();
    let aligned = links
        .iter()
        .filter(|domain| {
            !sender_domain.is_empty()
                && (**domain == sender_domain
                    || domain.ends_with(&format!(".{sender_domain}"))
                    || sender_domain.ends_with(&format!(".{domain}")))
        })
        .count();
    for value in [
        format!("html:{}", !html.is_empty()),
        format!("parts:{}", parsed.parts.len().min(8)),
        format!("attachments:{}", parsed.attachments.len().min(5)),
        format!("link_domains:{}", links.len().min(6)),
        format!("external_link_domains:{}", (links.len() - aligned).min(6)),
        format!("aligned_link:{}", aligned > 0),
        format!(
            "body_length_bin:{}",
            (body.chars().count().max(1).ilog2()).min(16)
        ),
        format!("form:{}", html.to_ascii_lowercase().contains("<form")),
    ] {
        add("structure:", &value, 1.0);
    }
    for reason in &scan.reasons {
        add("rule:", &reason.id, 1.0);
    }
    // These observations are already learned features. Adding hand-written
    // weights again would invalidate the model's independently fitted cutoff.
    for reason in &mut scan.reasons {
        reason.weight = 0.0;
    }
    for value in counts.values_mut() {
        *value = value.ln_1p();
    }
    let norm = counts
        .values()
        .map(|v| v * v)
        .sum::<f64>()
        .sqrt()
        .max(1e-12);
    scan.features = counts.into_iter().map(|(i, v)| (i, v / norm)).collect();
    let campaign = campaign_text(raw).unwrap_or_default();
    scan.fingerprint = message::digest(campaign.as_bytes());
    scan.campaign_simhash = Some(simhash(&campaign));
    scan.features_complete = Some(true);
    scan
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_visible_html_and_filter_headers_do_not_train_the_model() {
        let a = b"From: Billing <service@example.org>\r\nSubject: Receipt\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>Your receipt &amp; invoice.</p>";
        let b = b"X-Spam-Status: Yes, score=100\r\nAuthentication-Results: forged; dmarc=fail\r\nFrom: Billing <service@example.org>\r\nSubject: [SPAM] Receipt\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<style>.urgent{password:expire}</style><script>lottery()</script><!-- guaranteed profit --><p>Your receipt &amp; invoice.</p>";
        assert_eq!(text(a), text(b));
        assert_eq!(campaign_text(a), campaign_text(b));
        // Legacy reason extraction can observe hidden HTML; v3 must ignore it.
        let left = extract(a, 10000);
        let right = extract(b, 10000);
        assert_eq!(left.features, right.features);
        let mbox = [
            b"From archive@example.org Thu Aug 29 11:00:00 2002\r\n".as_slice(),
            a,
        ]
        .concat();
        assert_eq!(left.features, extract(&mbox, 10000).features);
    }

    #[test]
    fn unicode_features_are_bounded_and_campaign_tokens_ignore_unique_links() {
        let a = "From: test@example.org\r\nSubject: Facture été\r\n\r\nBonjour, facture 123 https://a.example/123";
        let b = "From: test@example.org\r\nSubject: Facture été\r\n\r\nBonjour, facture 456 https://b.example/456";
        assert_eq!(campaign_text(a.as_bytes()), campaign_text(b.as_bytes()));
        let scan = extract(a.as_bytes(), 10000);
        assert_eq!(scan.feature_version, VERSION);
        assert!(scan.complete && !scan.features.is_empty());
        assert!(
            scan.features
                .iter()
                .all(|(i, x)| *i < DIMENSION && x.is_finite())
        );
        assert!(extract(a.as_bytes(), 5).features.is_empty());
    }
}
