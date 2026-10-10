//! Recognize an entire literal navigation statement, without running JavaScript.
//! Expressions, escapes, callbacks and additional statements remain unresolved.
use std::sync::LazyLock;

pub(super) fn literal_destination(script: &str) -> Option<&str> {
    static NAVIGATION: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(
            r#"(?s)\A(?:(?:window|document)\s*\.\s*)?location\s*(?:\.\s*(href|assign|replace)\s*)?(=|\()\s*(['"])(.*)\z"#,
        )
        .unwrap()
    });
    let statement = script.trim();
    if statement.len() > 4352 {
        return None;
    }
    let captures = NAVIGATION.captures(statement)?;
    let member = captures.get(1).map(|m| m.as_str());
    let call = captures.get(2)?.as_str() == "(";
    if call != matches!(member, Some("assign" | "replace")) {
        return None;
    }
    let quote = captures.get(3)?.as_str();
    let rest = captures.get(4)?.as_str();
    let end = rest.find(quote)?;
    let target = &rest[..end];
    if target.is_empty()
        || target.len() > 4096
        || target.contains('\\')
        || target
            .chars()
            .any(|c| c.is_control() || matches!(c, '\u{2028}' | '\u{2029}'))
    {
        return None;
    }
    let mut suffix = rest[end + 1..].trim();
    if call {
        suffix = suffix.strip_prefix(')')?.trim();
    }
    if !matches!(suffix, "" | ";") {
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
        ] {
            assert_eq!(literal_destination(js), Some("/next"), "{js}");
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
            "location='\\x2fnext'",
            "location='/a\nnext'",
            "var location='/next'",
            "location='/a' /* comment */",
            "setTimeout(()=>location='/next', 0)",
        ] {
            assert_eq!(literal_destination(js), None, "{js}");
        }
    }
}
