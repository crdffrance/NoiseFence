//! Bounded URL inventory. Bare www hosts are candidates, never trusted destinations.
use regex::Regex;
use std::sync::OnceLock;

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
