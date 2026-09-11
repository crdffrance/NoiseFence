//! Ephemeral link/brand context. Only digests and bounded findings are retained.
use super::{Policy, Report, Targets, redirects};
use scraper::{Html, Selector};
use std::sync::OnceLock;

pub struct Hint {
    pub source_sha256: String,
    pub displayed_site: Option<String>,
    pub brand_site: Option<String>,
    pub qr: bool,
    pub reply_conflict: bool,
}
fn site(url: &str) -> Option<String> {
    let u = reqwest::Url::parse(url).ok()?;
    psl::domain_str(u.host_str()?).map(str::to_owned)
}
fn mentions(text: &str, name: &str) -> bool {
    let text = text.to_lowercase();
    let name = name.trim().to_lowercase();
    if name.chars().count() < 3 {
        return false;
    }
    text.match_indices(&name).any(|(i, _)| {
        text[..i]
            .chars()
            .next_back()
            .is_none_or(|c| !c.is_alphanumeric())
            && text[i + name.len()..]
                .chars()
                .next()
                .is_none_or(|c| !c.is_alphanumeric())
    })
}
pub fn collect(raw: &[u8], visual: &str, targets: &mut Targets, policy: &Policy, report: &Report) {
    if !policy.links || raw.len() > 2 * 1024 * 1024 {
        return;
    }
    let Some(mail) = mail_parser::MessageParser::default().parse(raw) else {
        return;
    };
    let reply_conflict = report
        .findings
        .iter()
        .any(|f| f.id == "reply_domain_mismatch");
    let from_name = mail
        .from()
        .and_then(|a| a.first())
        .and_then(|a| a.name())
        .unwrap_or("");
    for url in &targets.urls {
        if visual.contains(url) {
            for brand in &policy.protected_names {
                if mentions(visual, &brand.name) || from_name.eq_ignore_ascii_case(&brand.name) {
                    targets.context.push(Hint {
                        source_sha256: crate::message::digest(url.as_bytes()),
                        displayed_site: None,
                        brand_site: psl::domain_str(&brand.domain).map(str::to_owned),
                        qr: true,
                        reply_conflict,
                    });
                }
                if targets.context.len() >= 32 {
                    return;
                }
            }
        }
    }
    static LINKS: OnceLock<Selector> = OnceLock::new();
    let selector = LINKS.get_or_init(|| Selector::parse("a[href]").unwrap());
    for part in mail.html_bodies().take(16) {
        let Some(html) = part.text_contents().filter(|s| s.len() <= 256 * 1024) else {
            continue;
        };
        let doc = Html::parse_document(html);
        for anchor in doc.select(selector).take(128) {
            let Some(url) = anchor.value().attr("href").and_then(super::canonical_url) else {
                continue;
            };
            if !targets.urls.contains(&url) {
                continue;
            }
            let text: String = anchor.text().flat_map(str::chars).take(4096).collect();
            let shown = site(text.trim()).or_else(|| {
                if text.trim().len() <= 253 && !text.contains(char::is_whitespace) {
                    site(&format!("https://{}", text.trim()))
                } else {
                    None
                }
            });
            let brand = policy
                .protected_names
                .iter()
                .find(|b| mentions(&text, &b.name))
                .and_then(|b| psl::domain_str(&b.domain))
                .map(str::to_owned);
            if shown.is_some() || brand.is_some() {
                targets.context.push(Hint {
                    source_sha256: crate::message::digest(url.as_bytes()),
                    displayed_site: shown,
                    brand_site: brand,
                    qr: false,
                    reply_conflict,
                });
            }
            if targets.context.len() >= 32 {
                return;
            }
        }
    }
}
pub fn apply(hints: &[Hint], resolution: &redirects::Report, policy: &Policy, report: &mut Report) {
    for hint in hints {
        let Some(chain) = resolution
            .chains
            .iter()
            .find(|c| c.source_sha256 == hint.source_sha256 && c.complete)
        else {
            continue;
        };
        let Some(last) = chain.hops.last() else {
            continue;
        };
        // An exception must describe the actual final site, never only the tracker.
        if policy.link_exceptions.iter().any(|s| s == &last.site) {
            continue;
        }
        let display_mismatch = hint
            .displayed_site
            .as_ref()
            .is_some_and(|s| s != &last.site);
        let brand_mismatch = hint.brand_site.as_ref().is_some_and(|s| s != &last.site);
        for (active, id, detail) in [
            (
                display_mismatch,
                "display_destination_mismatch",
                "Le domaine affiché diffère de la destination finale vérifiée",
            ),
            (
                brand_mismatch,
                "brand_destination_mismatch",
                "La marque annoncée et la destination finale ne correspondent pas",
            ),
            (
                brand_mismatch && hint.qr,
                "qr_brand_mismatch",
                "Le lien OCR/QR mène hors du domaine de la marque annoncée",
            ),
            (
                (brand_mismatch || display_mismatch) && hint.reply_conflict,
                "identity_context_mismatch",
                "Incohérences concordantes du lien final et du domaine de réponse",
            ),
        ] {
            if active {
                report.add(
                    id,
                    "identity_context",
                    &last.url_sha256,
                    "final_destination",
                    detail,
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::digest;
    fn resolution(site: &str, complete: bool) -> redirects::Report {
        redirects::Report {
            version: "fixture".into(),
            settings_sha256: digest(b"fixture"),
            chains: vec![redirects::Chain {
                source_sha256: digest(b"https://tracker.example/c"),
                hops: vec![redirects::Hop {
                    url_sha256: digest(b"final URL"),
                    site: site.into(),
                    code: 200,
                }],
                complete,
                detail: None,
            }],
            omitted: 0,
            elapsed_ms: 1,
            local_inventory_available: Some(true),
        }
    }
    #[test]
    fn known_tracker_does_not_hide_final_mismatch_and_matching_destination_is_not_flagged() {
        let hint = Hint {
            source_sha256: digest(b"https://tracker.example/c"),
            displayed_site: Some("bank.com".into()),
            brand_site: Some("bank.com".into()),
            qr: true,
            reply_conflict: true,
        };
        let mut policy = Policy::default();
        policy.link_exceptions.push("tracker.example".into());
        let mut safe = Report::default();
        apply(
            std::slice::from_ref(&hint),
            &resolution("bank.com", true),
            &policy,
            &mut safe,
        );
        assert!(safe.findings.is_empty());
        let mut unknown = Report::default();
        apply(
            std::slice::from_ref(&hint),
            &resolution("example.net", false),
            &policy,
            &mut unknown,
        );
        assert!(unknown.findings.is_empty());
        let mut unsafe_report = Report::default();
        apply(
            std::slice::from_ref(&hint),
            &resolution("example.net", true),
            &policy,
            &mut unsafe_report,
        );
        assert_eq!(unsafe_report.findings.len(), 4);
        assert!(
            unsafe_report
                .findings
                .iter()
                .any(|f| f.id == "qr_brand_mismatch")
        );
        let once = unsafe_report.findings.len();
        apply(
            std::slice::from_ref(&hint),
            &resolution("example.net", true),
            &policy,
            &mut unsafe_report,
        );
        assert_eq!(unsafe_report.findings.len(), once);
        policy.link_exceptions.push("example.net".into());
        let mut excepted = Report::default();
        apply(
            &[hint],
            &resolution("example.net", true),
            &policy,
            &mut excepted,
        );
        assert!(excepted.findings.is_empty());
    }
    #[test]
    fn brand_context_uses_bounded_words_and_preserves_shown_link_through_redirects() {
        let raw=b"From: Example Bank <updates@bank.com>\r\nContent-Type: text/html\r\n\r\n<a href=\"https://tracker.example/c\">https://bank.com</a>";
        let mut targets = Targets {
            urls: vec!["https://tracker.example/c".into()],
            ..Default::default()
        };
        collect(
            raw,
            "",
            &mut targets,
            &Policy::default(),
            &Report::default(),
        );
        assert_eq!(targets.context.len(), 1);
        assert_eq!(
            targets.context[0].displayed_site.as_deref(),
            Some("bank.com")
        );
        assert!(mentions("Your Example Bank notice", "example bank"));
        assert!(!mentions("Example Bankrupt", "Example Bank"));
    }
}
