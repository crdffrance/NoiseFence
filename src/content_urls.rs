//! Bounded URL inventory. Bare www hosts are candidates, never trusted destinations.
use regex::Regex;
use std::sync::OnceLock;

/// Syntactically declared destinations in a small allowlist of redirect formats.
/// This does not establish a redirect, ownership, reputation, or permission to fetch.
/// Every active request still goes through the resolver's DNS/IP checks.
pub(crate) fn embedded_destinations(value: &str) -> Vec<String> {
    fn single(url: &reqwest::Url, keys: &[&str]) -> Option<String> {
        let values: Vec<_> = url
            .query_pairs()
            .filter(|(k, _)| keys.contains(&k.trim_start_matches("amp;")))
            .collect();
        (values.len() == 1).then(|| values[0].1.to_string())
    }
    fn candidate(value: &str, bare: bool) -> Option<String> {
        if value.len() > 4096 || value.contains('\\') || value.chars().any(char::is_control) {
            return None;
        }
        let value = if value.starts_with("//") {
            format!("https:{value}")
        } else if bare && !value.contains("://") {
            format!("https://{value}")
        } else {
            value.to_owned()
        };
        let canonical = crate::protection::canonical_url(&value)?;
        let url = reqwest::Url::parse(&canonical).ok()?;
        let host = url.host_str()?.trim_end_matches('.');
        if !url.username().is_empty()
            || url.password().is_some()
            || !crate::config::valid_domain(host)
            || psl::domain_str(host).is_none()
            || host.parse::<std::net::IpAddr>().is_ok()
        {
            return None;
        }
        Some(canonical)
    }
    let Some(mut current) = candidate(value, false) else {
        return vec![];
    };
    let mut seen = std::collections::BTreeSet::from([current.clone()]);
    let mut output = Vec::new();
    for _ in 0..3 {
        let Ok(url) = reqwest::Url::parse(&current) else {
            break;
        };
        let host = url.host_str().unwrap_or("").trim_end_matches('.');
        let mut extra = None;
        let next = match (host, url.path()) {
            ("www.google.com" | "google.com" | "www.google.fr" | "google.fr", "/url") => {
                single(&url, &["q", "url"]).and_then(|s| candidate(&s, false))
            }
            (h, _) if h.ends_with(".safelinks.protection.outlook.com") => {
                single(&url, &["url"]).and_then(|s| candidate(&s, false))
            }
            ("adclick.g.doubleclick.net", p) if p.trim_start_matches('/') == "pcs/click" => {
                single(&url, &["adurl"]).and_then(|s| candidate(&s, false))
            }
            ("www.tiktok.com" | "tiktok.com", p) if p.trim_start_matches('/') == "link/v2" => {
                let next = single(&url, &["target"]).and_then(|s| candidate(&s, true));
                // An unescaped nested query can leave adurl on the outer wrapper.
                if next
                    .as_ref()
                    .and_then(|s| reqwest::Url::parse(s).ok())
                    .is_some_and(|u| {
                        u.host_str()
                            .is_some_and(|h| h.trim_end_matches('.') == "adclick.g.doubleclick.net")
                            && u.path().trim_start_matches('/') == "pcs/click"
                            && single(&u, &["adurl"]).is_none()
                    })
                {
                    extra = single(&url, &["adurl"]).and_then(|s| candidate(&s, false));
                }
                next
            }
            _ => None,
        };
        let Some(next) = next.filter(|s| seen.insert(s.clone())) else {
            break;
        };
        current = next.clone();
        output.push(next);
        if let Some(extra) = extra.filter(|s| seen.insert(s.clone())) {
            current = extra.clone();
            output.push(extra);
        }
        if output.len() >= 3 {
            break;
        }
    }
    output.truncate(3);
    output
}

pub(crate) fn extract(text: &str) -> impl Iterator<Item = String> + '_ {
    static URLS: OnceLock<Regex> = OnceLock::new();
    URLS.get_or_init(|| Regex::new(r#"(?i)https?://[^\s<>"']+|\bwww\.[^\s<>"']+"#).unwrap())
        .find_iter(text)
        .take(257)
        .filter_map(|m| {
            let value = m.as_str();
            if value.len() > 4092 {
                return None;
            }
            if !value[..4].eq_ignore_ascii_case("www.") {
                return crate::protection::canonical_url(value);
            }
            // Do not activate an email address, defanged URL, or another URI scheme.
            if text[..m.start()]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_alphanumeric() || "@/.:_-".contains(c))
            {
                return None;
            }
            let value = value.trim_end_matches(['.', ',', ';', ':', '!', '?', ')', ']', '}']);
            let url = reqwest::Url::parse(&format!("https://{value}")).ok()?;
            let host = url.host_str()?;
            if !url.username().is_empty()
                || url.password().is_some()
                || !crate::config::valid_domain(host)
                || psl::domain_str(host).is_none()
                || !psl::suffix(host.as_bytes()).is_some_and(|s| s.typ().is_some())
                || host.parse::<std::net::IpAddr>().is_ok()
            {
                return None;
            }
            crate::protection::canonical_url(url.as_str())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unwraps_only_bounded_declared_destinations_not_arbitrary_query_values() {
        assert_eq!(
            embedded_destinations(
                "https://www.google.com/url?q=https%3A%2F%2Fexample.org%2Flogin%3Ftoken%3Da%252Fb&sa=D"
            ),
            ["https://example.org/login?token=a%2Fb"]
        );
        assert_eq!(
            embedded_destinations(
                "https://www.tiktok.com//link/v2?target=adclick.g.doubleclick.net./////////pcs/click?x=1&adurl=//example.org/portal"
            ),
            [
                "https://adclick.g.doubleclick.net./////////pcs/click?x=1",
                "https://example.org/portal"
            ]
        );
        assert_eq!(
            embedded_destinations(
                "https://www.tiktok.com//link/v2?target=adclick.g.doubleclick.net/pcs/click?x=1&adurl=//example.org/portal"
            ),
            [
                "https://adclick.g.doubleclick.net/pcs/click?x=1",
                "https://example.org/portal"
            ]
        );
        for url in [
            "https://google.com.attacker.org/url?q=https://example.org/",
            "https://www.google.com/search?q=https://example.org/",
            "https://www.google.com/url?q=https://example.org/&q=https://other.org/",
            "https://www.google.com/url?q=https://example.org/&url=https://other.org/",
            "https://www.google.com/url?q=javascript:alert(1)",
            "https://www.google.com/url?q=http://127.0.0.1/",
            "https://www.google.com/url?q=https://user:pass@example.org/",
            "https://www.google.com/url?q=%2Frelative",
        ] {
            assert!(embedded_destinations(url).is_empty(), "{url}");
        }
    }
    #[test]
    fn nested_entity_separators_remain_unverified_inventory_candidates() {
        assert_eq!(
            embedded_destinations(
                "https://www.tiktok.com//link/v2?target=adclick.g.doubleclick.net.///////%2f%2fpcs/click?x%26amp%3B%26amp%3Badurl=//example.org/login"
            ),
            [
                "https://adclick.g.doubleclick.net./////////pcs/click?x&amp;&amp;adurl=//example.org/login",
                "https://example.org/login"
            ]
        );
        assert!(
            embedded_destinations(
                "https://www.google.com/url?q=https://example.org/&amp;q=https://other.org/"
            )
            .is_empty()
        );
    }
    #[test]
    fn bare_urls_require_a_public_host_and_preserve_paths() {
        assert_eq!(
            extract("Claim at (WWW.Example.org/claim?a=1&b=2).").collect::<Vec<_>>(),
            ["https://www.example.org/claim?a=1&b=2"]
        );
        for text in [
            "person@www.example.org",
            "hxxps://www.example.org",
            "hxxps[:]//www.example.org",
            "ftp://www.example.org",
            "www.host.invalid",
            "www.local",
            "www.example.org@evil.com",
        ] {
            assert!(extract(text).next().is_none(), "{text}");
        }
        assert_eq!(
            extract("https://www.example.org/path?q=a%2Fb").collect::<Vec<_>>(),
            ["https://www.example.org/path?q=a%2Fb"]
        );
        assert_eq!(extract(&"www.example.org ".repeat(1000)).count(), 257);
    }
}
