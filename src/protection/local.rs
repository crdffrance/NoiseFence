use super::{Policy, Report, Status, Targets, VERSION};
use crate::{config::Config, message};
use regex::Regex;
use scraper::{Html, Selector};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, HashSet},
    io::Read,
    path::Path,
    sync::OnceLock,
    time::Instant,
};

#[derive(Default)]
pub struct Feed {
    urls: HashSet<String>,
    updated: i64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FeedFile {
    version: u32,
    updated: i64,
    urls: Vec<String>,
}
impl Feed {
    pub fn load(root: &Path) -> Self {
        let parsed = (|| -> anyhow::Result<FeedFile> {
            let file = std::fs::File::open(root.join("protection/url-feed.json"))?;
            let mut bytes = Vec::new();
            file.take(8 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
            anyhow::ensure!(bytes.len() <= 8 * 1024 * 1024, "feed too large");
            Ok(serde_json::from_slice(&bytes)?)
        })();
        let Ok(feed) = parsed else {
            return Self::default();
        };
        if feed.version != 1 || feed.urls.len() > 50_000 || feed.updated > crate::now() + 60 {
            return Self::default();
        }
        Self {
            urls: feed
                .urls
                .into_iter()
                .filter_map(|u| canonical_url(&u))
                .map(|u| message::digest(u.as_bytes()))
                .collect(),
            updated: feed.updated,
        }
    }
    fn status(&self) -> Status {
        if self.updated == 0 {
            Status::NotConfigured
        } else if self.updated < crate::now() - 72 * 3600 {
            Status::Stale
        } else {
            Status::Complete
        }
    }
    pub(super) fn contains(&self, url: &str) -> bool {
        self.status() == Status::Complete && self.urls.contains(&message::digest(url.as_bytes()))
    }
}
/// Canonicalize only semantics-preserving URL components. Paths and queries remain exact.
/// Returned values are ephemeral and are never sent to the reputation providers.
pub fn canonical_url(value: &str) -> Option<String> {
    if value.len() > 4096 || value.chars().any(char::is_control) {
        return None;
    }
    let mut url = reqwest::Url::parse(value.trim()).ok()?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return None;
    }
    url.set_fragment(None);
    Some(url.to_string())
}
fn domain(value: &str) -> Option<String> {
    let host = idna::domain_to_ascii_strict(value.trim_end_matches('.'))
        .ok()?
        .to_ascii_lowercase();
    (crate::config::valid_domain(&host)
        && psl::domain_str(&host).is_some()
        && host.parse::<std::net::IpAddr>().is_err())
    .then_some(host)
}
pub(super) fn public_domain(host: &str) -> bool {
    domain(host).is_some() && psl::suffix(host.as_bytes()).is_some_and(|s| s.typ().is_some())
}
fn registered(host: &str) -> &str {
    psl::domain_str(host).unwrap_or(host)
}
fn urls(text: &str) -> impl Iterator<Item = String> + '_ {
    static URLS: OnceLock<Regex> = OnceLock::new();
    URLS.get_or_init(|| Regex::new(r#"(?i)https?://[^\s<>"']{1,4096}"#).unwrap())
        .find_iter(text)
        .take(257)
        .filter_map(|m| canonical_url(m.as_str()))
}
fn mailbox_domain(address: Option<&str>) -> Option<String> {
    address?.rsplit_once('@').and_then(|(_, d)| domain(d))
}
fn similar(a: &str, b: &str) -> bool {
    if a == b || a.len().min(b.len()) < 4 || a.len().abs_diff(b.len()) > 1 {
        return false;
    }
    let mut previous: Vec<usize> = (0..=b.len()).collect();
    for (i, x) in a.bytes().enumerate() {
        let mut next = vec![i + 1];
        for (j, y) in b.bytes().enumerate() {
            next.push(
                (previous[j + 1] + 1)
                    .min(next[j] + 1)
                    .min(previous[j] + usize::from(x != y)),
            );
        }
        previous = next;
    }
    previous[b.len()] == 1
}
fn skeleton(value: &str) -> String {
    idna::domain_to_unicode(value)
        .0
        .to_lowercase()
        .chars()
        .map(|c| match c {
            'а' | 'α' => 'a',
            'е' | 'ε' => 'e',
            'о' | 'ο' => 'o',
            'р' | 'ρ' => 'p',
            'с' => 'c',
            'х' | 'χ' => 'x',
            'у' => 'y',
            'і' | 'ι' => 'i',
            'ј' => 'j',
            _ => c,
        })
        .collect()
}

pub fn local_checks(
    raw: &[u8],
    visual: &str,
    config: &Config,
    policy: &Policy,
    feed: &Feed,
) -> (Report, Targets) {
    let started = Instant::now();
    let mut report = Report {
        version: VERSION.into(),
        observation_only: true,
        local_status: Status::Complete,
        feed_status: if policy.links {
            feed.status()
        } else {
            Status::Disabled
        },
        campaign_status: if policy.campaigns {
            Status::NotRun
        } else {
            Status::Disabled
        },
        crdf: super::ProviderReport {
            status: if policy.crdf {
                Status::NotRun
            } else {
                Status::Disabled
            },
            ..Default::default()
        },
        virustotal: super::ProviderReport {
            status: if policy.virustotal {
                Status::NotRun
            } else {
                Status::Disabled
            },
            ..Default::default()
        },
        ..Default::default()
    };
    let mut targets = Targets::default();
    if raw.len() > config.filter.max_analysis_bytes.min(2 * 1024 * 1024) {
        report.local_status = Status::Limited;
        return (report, targets);
    }
    let Some(parsed) = mail_parser::MessageParser::default().parse(raw) else {
        report.local_status = Status::Unavailable;
        return (report, targets);
    };
    let from = parsed.from().and_then(|a| a.first());
    let from_domain = mailbox_domain(from.and_then(|a| a.address()));
    let reply_domain = mailbox_domain(
        parsed
            .reply_to()
            .and_then(|a| a.first())
            .and_then(|a| a.address()),
    );
    if let Some(host) = &from_domain {
        targets.domains.insert(host.clone());
    }
    if policy.identity {
        if let (Some(from), Some(reply)) = (&from_domain, &reply_domain)
            && registered(from) != registered(reply)
            && !policy.reply_exceptions.contains(reply)
        {
            report.add(
                "reply_domain_mismatch",
                "identity",
                reply,
                "headers",
                "Le domaine de réponse diffère de celui de l’expéditeur",
            );
        }
        if let Some(host) = &from_domain {
            for protected in &config.domains {
                let expected = registered(&protected.name);
                let actual = registered(host);
                if actual != expected
                    && (similar(actual, expected) || skeleton(actual) == skeleton(expected))
                {
                    report.add(
                        "lookalike_sender",
                        "identity",
                        host,
                        "headers",
                        "Le domaine expéditeur ressemble à un domaine protégé",
                    );
                }
            }
            let name = from
                .and_then(|a| a.name())
                .unwrap_or_default()
                .trim()
                .to_lowercase();
            for identity in &policy.protected_names {
                if name == identity.name.trim().to_lowercase()
                    && registered(host) != registered(&identity.domain)
                {
                    report.add(
                        "protected_display_name",
                        "identity",
                        host,
                        "headers",
                        "Un nom protégé est utilisé depuis un autre domaine",
                    );
                }
            }
        }
    }
    if parsed.text_bodies().count() > 16
        || parsed.html_bodies().count() > 16
        || parsed.attachments().count() > 8
    {
        report.local_status = Status::Limited;
    }
    let mut found: BTreeMap<String, HashSet<&str>> = BTreeMap::new();
    let mut add_urls = |text: &str, source: &'static str| {
        for (index, url) in urls(text).enumerate() {
            if index >= 256 {
                report.local_status = Status::Limited;
                break;
            }
            if found.contains_key(&url) || found.len() < 512 {
                found.entry(url).or_default().insert(source);
            } else {
                report.local_status = Status::Limited;
            }
        }
    };
    for part in parsed.text_bodies().take(16) {
        if !matches!(part.body, mail_parser::PartType::Text(_)) {
            continue;
        }
        if let Some(text) = part.text_contents() {
            add_urls(text, "text");
        }
    }
    add_urls(visual, "ocr_qr");
    for part in parsed.html_bodies().take(16) {
        if !matches!(part.body, mail_parser::PartType::Html(_)) {
            continue;
        }
        let Some(html) = part.text_contents() else {
            continue;
        };
        if html.len() > 256 * 1024 {
            report.local_status = Status::Limited;
            continue;
        }
        let document = Html::parse_document(html);
        static LINKS: OnceLock<Selector> = OnceLock::new();
        for (index, anchor) in document
            .select(
                LINKS.get_or_init(|| Selector::parse("a[href], area[href], form[action]").unwrap()),
            )
            .take(513)
            .enumerate()
        {
            if index >= 512 {
                report.local_status = Status::Limited;
                break;
            }
            let Some(destination) = anchor
                .value()
                .attr("href")
                .or_else(|| anchor.value().attr("action"))
                .and_then(canonical_url)
            else {
                continue;
            };
            if found.len() >= 512 {
                report.local_status = Status::Limited;
                break;
            }
            found.entry(destination.clone()).or_default().insert(
                if anchor.value().name() == "form" {
                    "form"
                } else {
                    "html"
                },
            );
            if !policy.links {
                continue;
            }
            let destination_url = reqwest::Url::parse(&destination).unwrap();
            let host = destination_url.host_str().unwrap();
            if policy.link_exceptions.iter().any(|d| d == host) {
                continue;
            }
            let display: String = anchor.text().flat_map(str::chars).take(4096).collect();
            let displayed = urls(&display).next().or_else(|| {
                let text = display.trim();
                if text.contains(' ') || text.len() > 253 {
                    None
                } else {
                    domain(text).and_then(|d| canonical_url(&format!("https://{d}")))
                }
            });
            if let Some(displayed) = displayed {
                let shown = reqwest::Url::parse(&displayed).unwrap();
                if registered(shown.host_str().unwrap()) != registered(host) {
                    report.add(
                        "misleading_link",
                        "link_structure",
                        host,
                        "html",
                        "Le lien affiché et sa destination appartiennent à des domaines différents",
                    );
                }
            }
            if !destination_url.username().is_empty() {
                report.add(
                    "url_userinfo",
                    "link_structure",
                    host,
                    "html",
                    "Le lien utilise une partie utilisateur pouvant masquer sa destination",
                );
            }
        }
    }
    let mut found: Vec<_> = found.into_iter().collect();
    found.sort_by_key(|(url, sources)| (!feed.contains(url), !sources.contains("ocr_qr")));
    for (url, sources) in found {
        // Forms and remote images are never submitted/fetched by this feature.
        if policy.follow_urls && sources.iter().any(|source| *source != "form") {
            if targets.urls.len() < 8 {
                targets.urls.push(url.clone());
            } else {
                targets.urls_truncated = true;
            }
        }
        let parsed = reqwest::Url::parse(&url).unwrap();
        let host = parsed.host_str().unwrap();
        if let Some(host) = domain(host) {
            if targets.domains.contains(&host) || targets.domains.len() < 8 {
                targets.domains.insert(host);
            } else {
                report.local_status = Status::Limited;
            }
        }
        if policy.links && feed.contains(&url) {
            for source in sources {
                report.add(
                    "known_phishing_url",
                    "link_reputation",
                    host,
                    source,
                    "Lien présent dans la base locale de phishing",
                );
            }
        }
    }
    for attachment in parsed.attachments().take(8) {
        targets
            .hashes
            .insert(message::digest(attachment.contents()));
    }
    report.elapsed_ms = started.elapsed().as_millis() as u64;
    (report, targets)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> Config {
        let mut c: Config = toml::from_str(include_str!("../../config/development.toml")).unwrap();
        c.domains[0].name = "crdf.fr".into();
        c
    }
    fn mail(body: &str) -> Vec<u8> {
        format!("From: Comptabilite <service@crdf.fr>\r\nSubject: Facture\r\nContent-Type: text/html; charset=utf-8\r\n\r\n{body}").into_bytes()
    }
    #[test]
    fn html_entities_psl_and_tracking_exceptions() {
        let cfg = config();
        let policy = Policy::default();
        let (report, _) = local_checks(
            &mail(
                "<a href='https://evil.co.uk/?a=1&amp;b=2'>https://bank.co.uk</a><a href='https://a.github.io'>https://b.github.io</a><a href='https://sub.bank.co.uk'>https://bank.co.uk</a>",
            ),
            "",
            &cfg,
            &policy,
            &Feed::default(),
        );
        assert_eq!(
            report
                .findings
                .iter()
                .filter(|f| f.id == "misleading_link")
                .count(),
            2
        );
        let policy = Policy {
            link_exceptions: vec!["evil.co.uk".into()],
            ..policy
        };
        let (report, _) = local_checks(
            &mail(
                "<a href='https://evil.co.uk'>https://bank.co.uk</a><a href='https://sub.evil.co.uk'>https://bank.co.uk</a>",
            ),
            "",
            &cfg,
            &policy,
            &Feed::default(),
        );
        assert_eq!(report.findings.len(), 1, "exceptions are exact hosts");
    }
    #[test]
    fn lookalikes_names_and_reply_domains_are_separate_observations() {
        let cfg = config();
        let policy = Policy {
            protected_names: vec![super::super::Identity {
                name: "Direction CRDF".into(),
                domain: "crdf.fr".into(),
            }],
            ..Default::default()
        };
        let raw=b"From: Direction CRDF <billing@crdff.fr>\r\nReply-To: help@elsewhere.fr\r\nSubject: facture\r\n\r\nBonjour";
        let (report, _) = local_checks(raw, "", &cfg, &policy, &Feed::default());
        assert_eq!(report.findings.len(), 3);
        assert_eq!(report.families, vec!["identity"]);
        assert!(report.observation_only);
    }
    #[test]
    fn feed_matches_exact_url_deduplicates_qr_and_expires() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("protection")).unwrap();
        std::fs::write(dir.path().join("protection/url-feed.json"),serde_json::json!({"version":1,"updated":crate::now(),"urls":["https://evil.com/login?a=1&b=2"]}).to_string()).unwrap();
        let mut feed = Feed::load(dir.path());
        let raw = mail(
            "<a href='https://evil.com/login?a=1&amp;b=2'>Connexion</a><a href='https://evil.com/other'>Autre</a>",
        );
        let (r, t) = local_checks(
            &raw,
            "https://evil.com/login?a=1&b=2",
            &config(),
            &Policy::default(),
            &feed,
        );
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].sources.len(), 2);
        assert_eq!(t.domains.len(), 2);
        assert!(!serde_json::to_string(&r).unwrap().contains("login?a=1"));
        feed.updated -= 80 * 3600;
        let (r, _) = local_checks(&raw, "", &config(), &Policy::default(), &feed);
        assert_eq!(r.feed_status, Status::Stale);
        assert!(r.findings.is_empty());
    }
    #[test]
    fn bounded_input_and_url_normalization() {
        assert_eq!(
            canonical_url("HTTPS://EVIL.COM:443/a?x=1#secret"),
            Some("https://evil.com/a?x=1".into())
        );
        assert!(canonical_url("file:///etc/passwd").is_none());
        assert!(canonical_url("https://evil.com/\nsecret").is_none());
        let (r, _) = local_checks(
            &vec![b'x'; 2 * 1024 * 1024 + 1],
            "",
            &config(),
            &Policy::default(),
            &Feed::default(),
        );
        assert_eq!(r.local_status, Status::Limited);
        let raw = mail("<a href='http://127.0.0.1'>local</a><a href='http://localhost'>local</a>");
        let (_, targets) = local_checks(&raw, "", &config(), &Policy::default(), &Feed::default());
        assert!(
            targets
                .domains
                .iter()
                .all(|d| d != "127.0.0.1" && d != "localhost")
        );
    }
    #[test]
    fn encoded_attachment_is_hashed_without_keeping_its_content() {
        let raw=b"From: a@example.com\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nContent-Type: text/plain\r\n\r\nHi\r\n--x\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=a.bin\r\nContent-Transfer-Encoding: base64\r\n\r\naGVsbG8=\r\n--x--\r\n";
        let (_, targets) = local_checks(raw, "", &config(), &Policy::default(), &Feed::default());
        assert!(targets.hashes.contains(&message::digest(b"hello")));
    }
}
