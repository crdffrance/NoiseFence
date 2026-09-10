//! Bounded, display-safe outbound SMTP diagnostics. Message data and outgoing
//! command arguments are deliberately absent from this schema.
//!
//! Remote replies are untrusted text. Redact mailbox-shaped identities (including
//! SMTPUTF8, quoted/escaped local parts, domain literals and common display
//! encodings) before output truncation, both on write and when reading old rows.
//! This is NOT a general content/DLP guarantee: names, private phrases, opaque
//! encodings and already-truncated address fragments may not be recognizable.
//! Never deliberately log DATA or treat a sanitized reply as safe message content.

use serde::{Deserialize, Serialize};
use std::{ops::Range, sync::OnceLock};

pub const MAX_EVENTS: usize = 32;
pub const MAX_TEXT_BYTES: usize = 2048;
// A complete upstream response is at most 100 * 512 bytes. Larger imported
// diagnostics are omitted wholesale: cutting input first could expose a local
// part while discarding its later '@'. This also bounds normalization/regex work.
const MAX_INPUT_BYTES: usize = 64 * 1024;
const OMITTED: &str = "[diagnostic text omitted: inspection limit]";

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Attempt {
    pub route: String,
    pub peer: Option<String>,
    pub started: i64,
    pub elapsed_ms: u64,
    pub outcome: String,
    pub events: Vec<Event>,
    pub truncated: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Event {
    pub phase: String,
    /// Milliseconds since the beginning of this route attempt.
    pub elapsed_ms: u64,
    pub code: Option<u16>,
    pub enhanced_code: Option<String>,
    pub response: Option<String>,
    pub detail: Option<String>,
}

impl Attempt {
    /// Reapply bounds at the persistence boundary, including to externally
    /// constructed/deserialized records. Keep the last event for failure context.
    pub fn sanitize(&mut self) {
        fn clean(value: &mut String, truncated: &mut bool) {
            let (safe, cut) = sanitize(value, MAX_TEXT_BYTES);
            *value = safe;
            *truncated |= cut;
        }
        clean(&mut self.route, &mut self.truncated);
        if let Some(peer) = &mut self.peer {
            clean(peer, &mut self.truncated);
        }
        clean(&mut self.outcome, &mut self.truncated);
        if self.events.len() > MAX_EVENTS {
            let last = self.events.pop().unwrap();
            self.events.truncate(MAX_EVENTS - 1);
            self.events.push(last);
            self.truncated = true;
        }
        for event in &mut self.events {
            clean(&mut event.phase, &mut self.truncated);
            for value in [
                &mut event.enhanced_code,
                &mut event.response,
                &mut event.detail,
            ]
            .into_iter()
            .flatten()
            {
                clean(value, &mut self.truncated);
            }
        }
    }
}

/// Redact identities, sanitize formatting and byte-bound saved diagnostic text.
pub fn sanitize_text(value: &str) -> String {
    sanitize(value, MAX_TEXT_BYTES).0
}

/// Shared privacy boundary for new and historical diagnostics. No prefix is
/// emitted until the whole bounded input has been inspected for identities.
pub(crate) fn sanitize(value: &str, limit: usize) -> (String, bool) {
    sanitize_with(value, limit, None)
}

/// Keep exact known-envelope matching in addition to generic mailbox redaction.
/// The relay supplies its escaped, case-insensitive sender/destination regex.
pub(crate) fn sanitize_with(
    value: &str,
    limit: usize,
    known: Option<&regex::Regex>,
) -> (String, bool) {
    let limit = limit.min(MAX_TEXT_BYTES);
    if value.len() > MAX_INPUT_BYTES {
        return (bound(OMITTED, limit).0, true);
    }
    let mut clean = String::with_capacity(value.len());
    strip_controls(value, &mut |c, _| clean.push(c));
    let mut ranges = identity_ranges(&clean, known);
    let mut normalized = MappedText {
        text: clean.clone(),
        origins: (0..clean.len()).map(|i| i..i + 1).collect(),
    };
    // Bounded repeated decoding handles e.g. JSON unicode escapes inside an
    // HTML/percent-encoded representation. Quotes/backslashes themselves stay
    // intact so raw SMTP quoted-pairs and JSON-escaped quotes both remain covered.
    for _ in 0..4 {
        let decoded = normalized
            .transform(decode_display_escapes)
            .transform(strip_controls);
        // Collect every representation, without replacing substrings first:
        // decoding a literal local part like name%20tag@example.test must not
        // leave "name" behind, and exact matching must not split other IDs.
        ranges.extend(
            identity_ranges(&decoded.text, known)
                .into_iter()
                .map(|r| decoded.origins[r.start].start..decoded.origins[r.end - 1].end),
        );
        if decoded.text == normalized.text {
            ranges.sort_unstable_by_key(|r| r.start);
            let mut redacted = String::with_capacity(clean.len());
            let mut end = 0;
            for range in ranges {
                if range.start >= end {
                    redacted.push_str(&clean[end..range.start]);
                    redacted.push_str("[redacted]");
                }
                end = end.max(range.end);
            }
            redacted.push_str(&clean[end..]);
            return bound(&redacted, limit);
        }
        normalized = decoded;
    }
    // Deeply nested encodings cannot cause unlimited work or leak a partial ID.
    (bound(OMITTED, limit).0, true)
}

fn identity_ranges(value: &str, known: Option<&regex::Regex>) -> Vec<Range<usize>> {
    mailboxes()
        .find_iter(value)
        .chain(known.into_iter().flat_map(|r| r.find_iter(value)))
        .filter(|m| m.start() < m.end())
        .map(|m| m.range())
        .collect()
}

// Preserve source spans through decoding/control removal so matches in every
// representation redact their complete original bytes. Input and pass counts
// are bounded; mappings are monotonic and never refer to a UTF-8 fragment.
struct MappedText {
    text: String,
    origins: Vec<Range<usize>>,
}

type Emit<'a> = &'a mut dyn FnMut(char, Range<usize>);

impl MappedText {
    fn transform(&self, transform: fn(&str, Emit<'_>)) -> Self {
        let mut text = String::with_capacity(self.text.len());
        let mut origins = Vec::with_capacity(self.text.len());
        transform(&self.text, &mut |c, source| {
            let original = self.origins[source.start].start..self.origins[source.end - 1].end;
            text.push(c);
            origins.resize(text.len(), original);
        });
        Self { text, origins }
    }
}

fn mailboxes() -> &'static regex::Regex {
    static MAILBOXES: OnceLock<regex::Regex> = OnceLock::new();
    MAILBOXES.get_or_init(|| {
        // Privacy recognition, not address validation: deliberately accept
        // malformed/overlong atoms and single-label domains too. Permissive
        // quoted spans cover both RFC quoted-pairs and JSON-escaped quotes;
        // they may redact extra quoted prose rather than expose part of an ID.
        // All Unicode non-whitespace atoms are included, not only ASCII letters.
        regex::Regex::new(
            r#"(?x)
            (?: \\*" [^\r\n]*? \\*" | [^\s<>()\[\],;:"@]+ )
            (?: \s* \([^@\r\n]*?\) )* \s* @ \s*
            (?: \([^@\r\n]*?\) \s* )*
            (?: \[[^\]\r\n]*(?:\]|$) | [^\s<>()\[\],;:"@]+ )
        "#,
        )
        .expect("constant mailbox privacy pattern")
    })
}

fn bound(value: &str, limit: usize) -> (String, bool) {
    let mut end = value.len().min(limit);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    (value[..end].to_owned(), end < value.len())
}

fn decode_display_escapes(value: &str, emit: Emit<'_>) {
    fn scalar(hex: &str, radix: u32) -> Option<char> {
        u32::from_str_radix(hex, radix)
            .ok()
            .and_then(char::from_u32)
    }
    let mut rest = value;
    while !rest.is_empty() {
        let start = value.len() - rest.len();
        let decoded = if rest.starts_with("\\u{") {
            rest.as_bytes()
                .iter()
                .take(10)
                .position(|b| *b == b'}')
                .and_then(|end| Some((scalar(rest.get(3..end)?, 16)?, end + 1)))
        } else if rest.starts_with("\\u") || rest.starts_with("\\U") || rest.starts_with("\\x") {
            let end = match rest.as_bytes()[1] {
                b'u' => 6,
                b'U' => 10,
                _ => 4,
            };
            rest.get(2..end)
                .and_then(|s| scalar(s, 16))
                .map(|c| (c, end))
        } else if rest.starts_with('%') {
            // Decode ASCII syntax; percent-encoded non-ASCII bytes remain in
            // the atom and are redacted with it, without lossy UTF-8 conversion.
            rest.get(1..3)
                .and_then(|s| scalar(s, 16))
                .filter(char::is_ascii)
                .map(|c| (c, 3))
        } else if rest.starts_with('&') {
            rest.as_bytes()
                .iter()
                .take(16)
                .position(|b| *b == b';')
                .and_then(|end| {
                    let entity = &rest[1..end];
                    let c = if let Some(hex) = entity
                        .strip_prefix("#x")
                        .or_else(|| entity.strip_prefix("#X"))
                    {
                        scalar(hex, 16)
                    } else if let Some(decimal) = entity.strip_prefix('#') {
                        scalar(decimal, 10)
                    } else {
                        match entity {
                            "commat" => Some('@'),
                            "quot" => Some('"'),
                            "apos" => Some('\''),
                            "amp" => Some('&'),
                            "lt" => Some('<'),
                            "gt" => Some('>'),
                            "period" => Some('.'),
                            "bsol" => Some('\\'),
                            _ => None,
                        }
                    }?;
                    Some((c, end + 1))
                })
        } else {
            None
        };
        if let Some((c, bytes)) = decoded {
            emit(c, start..start + bytes);
            rest = &rest[bytes..];
        } else {
            let c = rest.chars().next().unwrap();
            let folded = match c {
                '\u{ff20}' | '\u{fe6b}' => '@',
                '\u{201c}' | '\u{201d}' | '\u{ff02}' => '"',
                '\u{3002}' | '\u{ff0e}' | '\u{ff61}' => '.',
                _ => c,
            };
            emit(folded, start..start + c.len_utf8());
            rest = &rest[c.len_utf8()..];
        }
    }
}

/// Strip terminal escapes, controls and invisible direction/formatting marks.
/// Newlines become spaces. Only called with input bounded by sanitize_with.
fn strip_controls(value: &str, emit: Emit<'_>) {
    let mut chars = value.char_indices().peekable();
    while let Some((start, c)) = chars.next() {
        let source = start..start + c.len_utf8();
        let escape = if c == '\u{1b}' {
            chars.next().map(|(_, c)| c)
        } else {
            None
        };
        if matches!(escape, Some('[')) || c == '\u{9b}' {
            // ANSI CSI, including colors and cursor/screen manipulation.
            for (_, c) in chars.by_ref() {
                if ('@'..='~').contains(&c) {
                    break;
                }
            }
            continue;
        }
        if matches!(escape, Some(']' | 'P' | 'X' | '^' | '_'))
            || matches!(c, '\u{90}' | '\u{98}' | '\u{9d}' | '\u{9e}' | '\u{9f}')
        {
            // OSC (including hyperlinks), DCS, SOS, PM and APC payloads.
            while let Some((_, c)) = chars.next() {
                if matches!(c, '\u{7}' | '\u{9c}') {
                    break;
                }
                if c == '\u{1b}' && chars.peek().is_some_and(|(_, c)| *c == '\\') {
                    chars.next();
                    break;
                }
            }
            continue;
        }
        if c == '\u{1b}' {
            // Other ESC sequences can have intermediate bytes before a final.
            if escape.is_some_and(|c| (' '..='/').contains(&c)) {
                for (_, c) in chars.by_ref() {
                    if ('0'..='~').contains(&c) {
                        break;
                    }
                }
            }
            continue;
        }
        let c = if c.is_whitespace() {
            ' '
        } else if c.is_control()
            || matches!(c, '\u{61c}' | '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{206f}' | '\u{feff}')
        {
            continue;
        } else {
            c
        };
        emit(c, source);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_unlisted_mailboxes_quoted_pairs_unicode_and_display_encodings() {
        for address in [
            "unlisted-bcc@example.test",
            "private+alias@sub.example.test",
            "a.!#$%&'*+-/=?^_`{|}~@example.test",
            "δοκιμή@παράδειγμα.δοκιμή",
            "用户@例子.公司",
            "hidden@[IPv6:2001:db8::1]",
            "hidden@[192.0.2.1]",
            "hidden@localhost",
            r#""hidden \"quoted\" name"@example.test"#,
            r#""hidden @ inside"@example.test"#,
            r#"\"hidden \\\"quoted\\\" name\"@example.test"#,
            "“hidden quoted name”＠例子。公司",
            "＂hidden name＂﹫example.test",
            "hidden (comment) @ (route) example.test",
            "hidden\u{200b}@ex\u{202e}ample.test",
            "hid\u{1b}[31mden\u{1b}[0m@example.test",
            r"hidden\u0040example.test",
            r"hidden\u{40}example.test",
            r"hidden\U00000040example.test",
            r"hidden\x40example.test",
            r"hidden\uFF20example.test",
            "hidden%40example.test",
            "%22hidden%20name%22%40example.test",
            "hidden%2540example.test",
            "hidden&#64;example.test",
            "hidden&#x40;example.test",
            "hidden&commat;example.test",
            "&quot;hidden name&quot;&commat;example.test",
            "hidden&amp;#64;example.test",
            // Literal RFC atext can resemble display escapes. Match both the
            // original mailbox and decoded views, without leaking a prefix.
            "hidden%20alias@example.test",
            "hidden%40alias@example.test",
            r#""hidden&#32;alias"@example.test"#,
            "&quot;hidden name&quot;@example.test",
            r"\u0022hidden name\u0022@example.test",
            "hidden\\u0020alias@example.test",
        ] {
            let raw = format!("550 5.7.1 Recipient <{address}> rejected");
            let (safe, cut) = sanitize(&raw, MAX_TEXT_BYTES);
            assert_eq!(
                safe, "550 5.7.1 Recipient <[redacted]> rejected",
                "input: {address:?}"
            );
            assert!(!cut);
            assert_eq!(
                sanitize_text(&safe),
                safe,
                "privacy sanitization must be idempotent"
            );
        }
    }

    #[test]
    fn redaction_precedes_output_limits_and_unbounded_input_is_omitted() {
        let private = format!("secret-{}@example.test", "x".repeat(MAX_TEXT_BYTES * 2));
        let raw = format!("451 4.7.1 <{private}> retry later");
        assert_eq!(sanitize_text(&raw), "451 4.7.1 <[redacted]> retry later");
        let raw = format!(
            "{} hidden-address@example.test",
            "x".repeat(MAX_TEXT_BYTES - 8)
        );
        let (safe, cut) = sanitize(&raw, MAX_TEXT_BYTES);
        assert!(cut);
        assert!(
            !safe.contains("hidden"),
            "the prefix of an address crossing the output limit leaked"
        );
        let raw = format!("{}@example.test", "private".repeat(MAX_INPUT_BYTES));
        assert_eq!(sanitize(&raw, MAX_TEXT_BYTES), (OMITTED.into(), true));
        assert_eq!(
            sanitize("hidden%252525252540example.test", MAX_TEXT_BYTES),
            (OMITTED.into(), true)
        );
    }

    #[test]
    fn exact_known_identities_still_supplement_generic_redaction() {
        // A known non-mailbox routing identity must retain exact matching too.
        let known = regex::RegexBuilder::new(&regex::escape("legacy opaque recipient"))
            .case_insensitive(true)
            .build()
            .unwrap();
        let (safe, cut) = sanitize_with(
            "451 4.7.1 LEGACY OPAQUE RECIPIENT; other@example.test; retry",
            MAX_TEXT_BYTES,
            Some(&known),
        );
        assert_eq!(safe, "451 4.7.1 [redacted]; [redacted]; retry");
        assert!(!cut);
        let known = regex::Regex::new(&regex::escape("known@example.test")).unwrap();
        assert_eq!(
            sanitize_with(
                "550 other-known@example.test rejected",
                MAX_TEXT_BYTES,
                Some(&known)
            )
            .0,
            "550 [redacted] rejected",
            "exact matching inside a different mailbox must not leak its prefix"
        );
    }

    #[test]
    fn sanitizes_every_historical_field_without_altering_structured_codes() {
        let secret = "hidden-bcc@example.test";
        let mut attempt = Attempt {
            route: secret.into(),
            peer: Some(secret.into()),
            started: 123,
            elapsed_ms: 200,
            outcome: secret.into(),
            truncated: false,
            events: vec![Event {
                phase: secret.into(),
                elapsed_ms: 100,
                code: Some(550),
                enhanced_code: Some("5.7.1".into()),
                response: Some(format!("550 5.7.1 <{secret}> refused")),
                detail: Some(r#"Alias "hidden \"other\" user"@例子.公司"#.into()),
            }],
        };
        attempt.sanitize();
        let json = serde_json::to_string(&attempt).unwrap();
        assert!(!json.contains("hidden") && !json.contains('@') && !json.contains("例子"));
        assert_eq!(attempt.events[0].code, Some(550));
        assert_eq!(attempt.events[0].enhanced_code.as_deref(), Some("5.7.1"));
        assert_eq!(
            attempt.events[0].response.as_deref(),
            Some("550 5.7.1 <[redacted]> refused")
        );
        assert_eq!(attempt.started, 123);
        assert_eq!(attempt.events[0].elapsed_ms, 100);
        attempt.sanitize();
        assert_eq!(serde_json::to_string(&attempt).unwrap(), json);
    }

    #[test]
    fn preserves_useful_smtp_details_without_claiming_to_scrub_arbitrary_content() {
        let text =
            "451 4.7.1 policy denied; queue=remote-123; mx.example.test:25; TLSv1_3; retry later";
        assert_eq!(sanitize_text(text), text);
        // Explicit limitation: mailbox recognition cannot identify private prose.
        assert_eq!(
            sanitize_text("550 5.7.1 a private phrase"),
            "550 5.7.1 a private phrase"
        );
    }

    #[test]
    fn removes_controls_bidi_and_terminal_escape_payloads() {
        let (text, truncated) = sanitize(
            "a\r\n\t\0\u{7}\u{7f}\u{202e}\u{2066}\u{61c}\u{200f}\u{2028}\u{1b}[31mred\u{1b}[0m\u{1b}]8;;secret\u{1b}\\link\u{1b}]8;;\u{7}\u{9b}2J\u{90}hidden\u{9c}z",
            MAX_TEXT_BYTES,
        );
        assert_eq!(text, "a    redlinkz");
        assert!(!truncated);
    }

    #[test]
    fn bounds_utf8_bytes_without_breaking_characters() {
        let (text, truncated) = sanitize(&"€".repeat(1000), MAX_TEXT_BYTES);
        assert_eq!(text.len(), 2046);
        assert!(truncated);
        assert_eq!(sanitize(&"x".repeat(2048), 2048), ("x".repeat(2048), false));
    }

    #[test]
    fn persistence_sanitizer_bounds_every_string_and_keeps_last_event() {
        let untrusted = format!("\u{1b}[31m\r\n\u{202e}{}", "€".repeat(1000));
        let event = Event {
            phase: untrusted.clone(),
            elapsed_ms: 1,
            code: Some(250),
            enhanced_code: Some(untrusted.clone()),
            response: Some(untrusted.clone()),
            detail: Some(untrusted.clone()),
        };
        let mut attempt = Attempt {
            route: untrusted.clone(),
            peer: Some(untrusted.clone()),
            started: 123,
            elapsed_ms: 2,
            outcome: untrusted,
            events: vec![event; 40],
            truncated: false,
        };
        attempt.events.last_mut().unwrap().phase = "data_result".into();
        attempt.sanitize();
        assert_eq!(attempt.started, 123);
        assert!(attempt.truncated);
        assert_eq!(attempt.events.len(), MAX_EVENTS);
        assert_eq!(attempt.events.last().unwrap().phase, "data_result");
        for text in [
            &attempt.route,
            attempt.peer.as_ref().unwrap(),
            &attempt.outcome,
        ]
        .into_iter()
        .chain(attempt.events.iter().flat_map(|e| {
            [
                &e.phase,
                e.enhanced_code.as_ref().unwrap(),
                e.response.as_ref().unwrap(),
                e.detail.as_ref().unwrap(),
            ]
        })) {
            assert!(text.len() <= MAX_TEXT_BYTES);
            assert!(!text.chars().any(char::is_control));
            assert!(!text.contains('\u{202e}'));
        }
        let before = serde_json::to_value(&attempt).unwrap();
        attempt.sanitize();
        assert_eq!(before, serde_json::to_value(attempt).unwrap());
        assert_eq!(
            sanitize_text("451\r\n4.7.1 \u{1b}[31mbusy\u{1b}[0m"),
            "451  4.7.1 busy"
        );
    }
}
