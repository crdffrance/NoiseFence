//! Bounded, display-safe outbound SMTP diagnostics. Message data and outgoing
//! command arguments are deliberately absent from this schema.

use serde::{Deserialize, Serialize};

pub const MAX_EVENTS: usize = 32;
pub const MAX_TEXT_BYTES: usize = 2048;

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

/// Sanitize and byte-bound a saved delivery error or other diagnostic text.
pub fn sanitize_text(value: &str) -> String {
    sanitize(value, MAX_TEXT_BYTES).0
}

/// Strip terminal escapes, controls and invisible direction/formatting marks,
/// then limit UTF-8 bytes without splitting a character. Newlines become spaces.
pub(crate) fn sanitize(value: &str, limit: usize) -> (String, bool) {
    let mut out = String::with_capacity(value.len().min(limit));
    let mut chars = value.chars().peekable();
    while let Some(c) = chars.next() {
        let escape = if c == '\u{1b}' { chars.next() } else { None };
        if matches!(escape, Some('[')) || c == '\u{9b}' {
            // ANSI CSI, including colors and cursor/screen manipulation.
            for c in chars.by_ref() {
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
            while let Some(c) = chars.next() {
                if matches!(c, '\u{7}' | '\u{9c}') {
                    break;
                }
                if c == '\u{1b}' && chars.peek() == Some(&'\\') {
                    chars.next();
                    break;
                }
            }
            continue;
        }
        if c == '\u{1b}' {
            // Other ESC sequences can have intermediate bytes before a final.
            if escape.is_some_and(|c| (' '..='/').contains(&c)) {
                for c in chars.by_ref() {
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
        if out.len() + c.len_utf8() > limit {
            return (out, true);
        }
        out.push(c);
    }
    (out, false)
}

#[cfg(test)]
mod tests {
    use super::*;

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
