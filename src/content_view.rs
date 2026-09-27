//! Bounded presentation hints, never authentication or evidence of consent.
use scraper::{ElementRef, Html, Selector};

pub(crate) fn truncate(text: &str, maximum: usize) -> &str {
    let mut end = text.len().min(maximum);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

pub(crate) fn compact(text: &str) -> String {
    let chars: Vec<_> = text.chars().collect();
    chars
        .iter()
        .enumerate()
        .filter_map(|(i, &c)| {
            if matches!(
                c,
                '\u{00ad}' | '\u{034f}' | '\u{200b}' | '\u{2060}' | '\u{feff}'
            ) {
                return None;
            }
            // Remove Latin word obfuscation while preserving joiners used in other scripts.
            if matches!(c, '\u{200c}' | '\u{200d}')
                && [i.checked_sub(1), i.checked_add(1)].into_iter().all(|p| {
                    p.and_then(|p| chars.get(p))
                        .is_none_or(|c| c.is_ascii_alphanumeric() || c.is_whitespace())
                })
            {
                return None;
            }
            Some(c)
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

#[derive(Default)]
pub(crate) struct View {
    pub current: String,
    pub quoted: String,
    pub links: Vec<Link>,
}

pub(crate) struct Link {
    pub url: String,
    pub label: String,
    pub quoted: bool,
}
impl Link {
    pub fn priority(&self) -> u8 {
        let label = self.label.to_lowercase();
        if self.quoted {
            return 4;
        }
        if [
            "unsubscribe",
            "privacy",
            "désabonner",
            "confidentialité",
            "view in browser",
        ]
        .iter()
        .any(|s| label.contains(s))
        {
            return 3;
        }
        if !crate::content_urls::embedded_destinations(&self.url).is_empty()
            || [
                "open",
                "listen",
                "verify",
                "review",
                "sign in",
                "login",
                "download",
                "pay",
                "cancel",
                "ouvrir",
                "écouter",
                "vérifier",
                "consulter",
                "payer",
                "télécharger",
            ]
            .iter()
            .any(|s| label.contains(s))
        {
            return 0;
        }
        1
    }
}

fn quoted(el: ElementRef<'_>) -> bool {
    el.value().name() == "blockquote"
        || el.value().classes().any(|c| {
            matches!(
                c,
                "gmail_quote" | "gmail_attr" | "yahoo_quoted" | "moz-cite-prefix"
            )
        })
}
fn hidden(el: ElementRef<'_>) -> bool {
    matches!(el.value().name(), "head" | "script" | "style" | "template")
        || el.value().attr("hidden").is_some()
}
fn context(el: ElementRef<'_>) -> (bool, bool) {
    let mut quote = quoted(el);
    let mut hide = hidden(el);
    for ancestor in el.ancestors().take(64).filter_map(ElementRef::wrap) {
        quote |= quoted(ancestor);
        hide |= hidden(ancestor);
    }
    (quote, hide)
}

pub(crate) fn html(text: &str) -> View {
    let doc = Html::parse_fragment(truncate(text, 256_000));
    let mut view = View::default();
    // Bounding both nodes and ancestry avoids quadratic work on pathological HTML.
    for node in doc.tree.root().descendants().take(32_000) {
        let Some(text) = node.value().as_text() else {
            continue;
        };
        let Some(parent) = node.parent().and_then(ElementRef::wrap) else {
            continue;
        };
        let (quote, hide) = context(parent);
        if hide {
            continue;
        }
        let output = if quote {
            &mut view.quoted
        } else {
            &mut view.current
        };
        if output.len() < 256_000 {
            output.push_str(truncate(text, 256_000 - output.len()));
            if output.len() < 256_000 {
                output.push(' ');
            }
        }
    }
    view.current = compact(&view.current);
    view.quoted = compact(&view.quoted);
    let selector = Selector::parse("a[href],area[href]").unwrap();
    for anchor in doc.select(&selector).take(512) {
        let (quoted, hide) = context(anchor);
        if hide {
            continue;
        }
        if let Some(url) = anchor
            .value()
            .attr("href")
            .and_then(crate::protection::canonical_url)
        {
            let label: String = anchor.text().flat_map(str::chars).take(512).collect();
            view.links.push(Link {
                url,
                label: compact(&label),
                quoted,
            });
        }
    }
    view
}

pub(crate) fn plain(text: &str) -> View {
    let mut view = View::default();
    let mut thread = false;
    for line in truncate(text, 256_000).lines() {
        let trimmed = line.trim();
        let lower = trimmed.to_lowercase();
        thread |= (lower.starts_with("on ") && lower.ends_with(" wrote:"))
            || (lower.starts_with("le ")
                && (lower.ends_with(" écrit :") || lower.ends_with(" écrit:")))
            || lower.contains("-----original message-----")
            || lower.contains("---------- forwarded message ---------");
        let quote = thread || trimmed.starts_with('>');
        let output = if quote {
            &mut view.quoted
        } else {
            &mut view.current
        };
        output.push_str(line);
        output.push('\n');
        for url in crate::content_urls::extract(line).take(32) {
            if view.links.len() < 512
                && !crate::content_urls::embedded_destinations(&url).is_empty()
            {
                view.links.push(Link {
                    url,
                    label: "Text link".into(),
                    quoted: quote,
                });
            }
        }
    }
    view.current = compact(&view.current);
    view.quoted = compact(&view.quoted);
    view
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn separates_requests_from_history_without_discarding_quotes() {
        let view = html(
            "<style>hidden</style>Review document <a href='https://example.org/open'>Open</a><div class='gmail_quote'>On Tuesday Alice wrote:<blockquote>Old payment approved <a href='https://old.example.org'>Invoice</a></blockquote></div>",
        );
        assert_eq!(view.current, "Review document Open");
        assert!(view.quoted.contains("Old payment approved"));
        assert!(!view.current.contains("hidden"));
        assert_eq!(view.links[0].priority(), 0);
        assert_eq!(view.links[1].priority(), 4);
        let view =
            plain("Please check this incident.\n> Enter your password now.\nThis is a report.");
        assert!(view.current.contains("This is a report."));
        assert!(!view.current.contains("password"));
        assert!(view.quoted.contains("password"));
    }
    #[test]
    fn normalizes_latin_obfuscation_without_removing_script_joiners() {
        assert_eq!(compact("P\u{200c}a\u{200d}y\u{200b} now"), "Pay now");
        assert_eq!(compact("می\u{200c}روم"), "می\u{200c}روم");
    }
}
