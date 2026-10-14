//! Recognize an entire literal navigation statement, without running JavaScript.
//! Expressions, callbacks, comments and additional statements remain unresolved.

const MAX_STATEMENT: usize = 4352;
const MAX_DESTINATION: usize = 4096;

// ECMAScript whitespace and line terminators. Rust's whitespace also accepts
// NEL (U+0085), which is not a JavaScript token separator, and omits BOM.
fn space(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200a}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202f}'
                | '\u{205f}'
                | '\u{3000}'
                | '\u{feff}'
    )
}

fn token<'a>(input: &'a str, expected: &str) -> Option<&'a str> {
    input.trim_start_matches(space).strip_prefix(expected)
}

fn hex(chars: &mut std::str::CharIndices<'_>, digits: usize) -> Option<u32> {
    (0..digits).try_fold(0, |value, _| {
        Some(value * 16 + chars.next()?.1.to_digit(16)?)
    })
}

fn escape(chars: &mut std::str::CharIndices<'_>) -> Option<char> {
    match chars.next()?.1 {
        c @ ('\'' | '"' | '/' | '\\') => Some(c),
        'x' => char::from_u32(hex(chars, 2)?),
        'u' if chars.as_str().starts_with('{') => {
            chars.next()?;
            let mut value = 0;
            let mut digits = 0;
            loop {
                let c = chars.next()?.1;
                if c == '}' {
                    return (digits > 0).then(|| char::from_u32(value)).flatten();
                }
                digits += 1;
                if digits > 6 {
                    return None;
                }
                value = value * 16 + c.to_digit(16)?;
            }
        }
        'u' => {
            let first = hex(chars, 4)?;
            let scalar = if (0xd800..=0xdbff).contains(&first) {
                if chars.next()?.1 != '\\' || chars.next()?.1 != 'u' {
                    return None;
                }
                let second = hex(chars, 4)?;
                if !(0xdc00..=0xdfff).contains(&second) {
                    return None;
                }
                0x10000 + ((first - 0xd800) << 10) + second - 0xdc00
            } else {
                first
            };
            char::from_u32(scalar)
        }
        // Octal, identity escapes and line continuations remain unsupported.
        // Control escapes could not form an accepted URL either.
        _ => None,
    }
}

fn string(input: &str) -> Option<(String, &str)> {
    let mut chars = input.char_indices();
    let quote = chars.next()?.1;
    if !matches!(quote, '\'' | '"') {
        return None;
    }
    let mut target = String::new();
    while let Some((index, c)) = chars.next() {
        if c == quote {
            return (!target.is_empty()).then_some((target, &input[index + 1..]));
        }
        let c = if c == '\\' { escape(&mut chars)? } else { c };
        // Escapes cannot introduce a control character or URL backslash.
        if c.is_control() || matches!(c, '\\' | '\u{2028}' | '\u{2029}') {
            return None;
        }
        if target.len() + c.len_utf8() > MAX_DESTINATION {
            return None;
        }
        target.push(c);
    }
    None
}

pub(super) fn literal_destination(script: &str) -> Option<String> {
    if script.len() > MAX_STATEMENT {
        return None;
    }
    let mut rest = script.trim_start_matches(space);
    if let Some(after) = rest
        .strip_prefix("window")
        .or_else(|| rest.strip_prefix("document"))
    {
        rest = token(after, ".")?;
    }
    rest = token(rest, "location")?.trim_start_matches(space);
    let call;
    if let Some(after) = rest.strip_prefix('.') {
        if let Some(after) = token(after, "href") {
            call = false;
            rest = token(after, "=")?;
        } else {
            let after = token(after, "assign").or_else(|| token(after, "replace"))?;
            call = true;
            rest = token(after, "(")?;
        }
    } else {
        call = false;
        rest = token(rest, "=")?;
    }
    let (target, mut suffix) = string(rest.trim_start_matches(space))?;
    if call {
        suffix = token(suffix, ")")?;
    }
    if !matches!(suffix.trim_matches(space), "" | ";") {
        return None;
    }
    Some(target)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recognizes_only_complete_literal_navigation() {
        for js in [
            "location='/next';",
            " window . location . href = \"/next\"; ",
            "document.location.replace('/next');",
            "location.assign( '/next' )",
            "\u{feff}location\u{a0}=\u{2009}'/next'\u{2029};",
        ] {
            assert_eq!(literal_destination(js).as_deref(), Some("/next"), "{js}");
        }
        for js in [
            "if (false) location='/next'",
            "// location='/next'",
            "location=`/next`",
            "location='/a'+userInput",
            "location='https://a/'; steal()",
            "location.assign = '/next'",
            "location.href('/next')",
            "location('https://a/')",
            "location.replace('/a', x)",
            "location='/a\nnext'",
            "var location='/next'",
            "location='/a' /* comment */",
            "setTimeout(()=>location='/next', 0)",
            "locationExtra='/next'",
            "location.hrefExtra='/next'",
            "windowExtra.location='/next'",
            "location\u{85}='/next'",
            "location='/next'\u{85}",
        ] {
            assert_eq!(literal_destination(js), None, "{js}");
        }
    }

    #[test]
    fn decodes_quoted_hex_and_unicode_destinations_exactly_once() {
        for (js, expected) in [
            (
                r"location='https:\/\/example.com\x2fnext';",
                "https://example.com/next",
            ),
            (
                r"window.location.replace('\u002fnext\u{3f}token=CANARY');",
                "/next?token=CANARY",
            ),
            (r#"location="/a\"b\'c""#, "/a\"b'c"),
            (r"location='/\u00e9/\uD83D\uDE00';", "/é/😀"),
            (r"location='/\u{1f600}';", "/😀"),
            (r"location='/a\xA0';", "/a\u{a0}"),
            (r"location='/%255cprivate';", "/%255cprivate"),
        ] {
            assert_eq!(literal_destination(js).as_deref(), Some(expected), "{js}");
        }
    }

    #[test]
    fn malformed_ambiguous_and_control_escapes_remain_unresolved() {
        for js in [
            r"location='/\x0';",
            r"location='/\xGG';",
            r"location='/\u000';",
            r"location='/\u{}';",
            r"location='/\u{110000}';",
            r"location='/\u{00000001}';",
            r"location='/\uD83D';",
            r"location='/\uDE00';",
            r"location='/\uD83D\u0001';",
            r"location='/\u{D800}';",
            r"location='/\x00';",
            r"location='/\x0a';",
            r"location='/\u2028';",
            r"location='/\u2029';",
            r"location='/\x5c';",
            r"location='/\\private';",
            r"location='/\0';",
            r"location='/\141';",
            r"location='/\q';",
            "location='/a\\\nb';",
            r"location='/a\';",
            r"location='\x2fa'+userInput",
            r"location='\x2fa';location='/b'",
        ] {
            assert_eq!(literal_destination(js), None, "{js}");
        }
    }

    #[test]
    fn input_and_decoded_destination_have_independent_bounds() {
        let url = format!("/{}", "x".repeat(MAX_DESTINATION - 1));
        assert_eq!(literal_destination(&format!("location='{url}'")), Some(url));
        assert!(
            literal_destination(&format!("location='/{}'", "x".repeat(MAX_DESTINATION))).is_none()
        );
        assert!(
            literal_destination(&format!("{}location='/a'", " ".repeat(MAX_STATEMENT))).is_none()
        );
    }
}
