use anyhow::{Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};

pub const MAX_HEADER_BYTES: usize = 256 * 1024;

/// Return whole folded fields without normalizing the signed wire representation.
pub fn fields(raw: &[u8]) -> Result<(Vec<&[u8]>, &[u8])> {
    let end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("missing header separator"))?;
    ensure!(end <= MAX_HEADER_BYTES, "too many header bytes");
    let header = &raw[..end + 2];
    let mut fields = Vec::new();
    let mut start = 0;
    let mut pos = 0;
    while pos < header.len() {
        let n = header[pos..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| anyhow::anyhow!("invalid header line"))?;
        let line = &header[pos..pos + n];
        ensure!(
            !line.contains(&b'\n') && !line.contains(&b'\r') && !line.contains(&0),
            "invalid header control"
        );
        if line.first().is_some_and(|b| *b != b' ' && *b != b'\t') {
            if pos > start {
                fields.push(&header[start..pos]);
            }
            start = pos;
            let colon = line
                .iter()
                .position(|c| *c == b':')
                .ok_or_else(|| anyhow::anyhow!("invalid header field"))?;
            ensure!(
                colon > 0
                    && line[..colon]
                        .iter()
                        .all(|c| (33..=126).contains(c) && *c != b':'),
                "invalid field name"
            );
        } else {
            ensure!(pos > 0, "orphan folded header");
        }
        pos += n + 2;
        ensure!(fields.len() <= 1000, "too many headers");
    }
    if start < header.len() {
        fields.push(&header[start..]);
    }
    Ok((fields, &raw[end + 4..]))
}
pub fn name(field: &[u8]) -> String {
    let n = field.iter().position(|c| *c == b':').unwrap_or(0);
    String::from_utf8_lossy(&field[..n]).to_ascii_lowercase()
}
pub fn validate(raw: &[u8]) -> Result<()> {
    let (headers, _) = fields(raw)?;
    ensure!(
        headers.iter().all(|h| h
            .iter()
            .all(|b| b.is_ascii() && (!b.is_ascii_control() || b"\t\r\n".contains(b)))),
        "SMTPUTF8 headers or invalid header controls are not supported"
    );
    for unique in ["from", "subject", "date", "message-id"] {
        ensure!(
            headers.iter().filter(|h| name(h) == unique).count() <= 1,
            "duplicate {unique}"
        );
    }
    ensure!(
        headers.iter().filter(|h| name(h) == "received").count() < 100,
        "mail loop detected"
    );
    // A strict CRLF wire grammar removes disagreement between SMTP implementations.
    for (i, b) in raw.iter().enumerate() {
        if *b == 0
            || (*b == b'\n' && (i == 0 || raw[i - 1] != b'\r'))
            || (*b == b'\r' && raw.get(i + 1) != Some(&b'\n'))
        {
            bail!("invalid SMTP wire newline or NUL");
        }
    }
    ensure!(raw.ends_with(b"\r\n"), "message must end with CRLF");
    Ok(())
}
pub fn rewrite(raw: &[u8], tag: bool, extra: &str) -> Result<Vec<u8>> {
    let (headers, body) = fields(raw)?;
    let decoded = mail_parser::MessageParser::default().parse_headers(raw);
    let subject = decoded.as_ref().and_then(|m| m.subject()).unwrap_or("");
    let mut out = Vec::with_capacity(raw.len() + extra.len() + 100);
    out.extend_from_slice(extra.as_bytes());
    let mut has_subject = false;
    for header in headers {
        let n = name(header);
        // Namespaced results are never accepted from the untrusted upstream peer.
        if n.starts_with("x-noisefence-")
            || n.starts_with("x-antispam-")
            || n == "authentication-results"
        {
            continue;
        }
        if n == "subject" {
            has_subject = true;
            if tag && !subject.trim_start().starts_with("[SPAM]") {
                if header
                    .split(|b| *b == b'\n')
                    .next()
                    .unwrap_or_default()
                    .len()
                    + 7
                    > 999
                {
                    out.extend_from_slice(b"Subject: [SPAM]\r\n\t");
                } else {
                    out.extend_from_slice(b"Subject: [SPAM] ");
                }
                let colon = header.iter().position(|b| *b == b':').unwrap();
                let value = &header[colon + 1..];
                let first = value
                    .iter()
                    .position(|b| *b != b' ' && *b != b'\t')
                    .unwrap_or(0);
                // Keep existing RFC 2047 encoded words and folding intact.
                out.extend_from_slice(&value[first..]);
                continue;
            }
        }
        out.extend_from_slice(header);
    }
    if tag && !has_subject {
        out.extend_from_slice(b"Subject: [SPAM]\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    Ok(out)
}
pub fn safe_value(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(250).collect()
}
pub fn encoded_subject(s: &str) -> String {
    format!("=?UTF-8?B?{}?=", STANDARD.encode(s.as_bytes()))
}
pub fn digest(raw: &[u8]) -> String {
    hex::encode(Sha256::digest(raw))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn subject_and_signed_body() {
        let raw = b"From: a@example.org\r\nSubject: =?UTF-8?B?UsOpc3Vtw6k=?=\r\nX-NoiseFence-Score: 0\r\n\r\nbody\r\n";
        let result = rewrite(raw, true, "X-NoiseFence-Score: 99\r\n").unwrap();
        assert!(String::from_utf8_lossy(&result).contains("Subject: [SPAM] =?UTF-8?B?"));
        assert_eq!(fields(&result).unwrap().1, fields(raw).unwrap().1);
        assert_eq!(
            String::from_utf8_lossy(&result)
                .matches("X-NoiseFence-Score:")
                .count(),
            1
        );
        let again = rewrite(&result, true, "").unwrap();
        assert_eq!(String::from_utf8_lossy(&again).matches("[SPAM]").count(), 1);
    }
    #[test]
    fn invalid_messages() {
        for raw in [
            b"Subject: a\r\nSubject: b\r\n\r\nx\r\n".as_slice(),
            b"Subject: a\r\n\r\na\n.\r\n",
            b" folded\r\n\r\nx\r\n",
        ] {
            assert!(validate(raw).is_err());
        }
    }
    #[test]
    fn forged_authentication_results_never_survive_the_trust_boundary() {
        let raw = b"From: a@example.org\r\nAuthentication-Results: gateway.example.test; dkim=pass\r\nX-NoiseFence-Score: 0\r\nSubject: Hello\r\n\r\nbody\r\n";
        let out = rewrite(
            raw,
            false,
            "Authentication-Results: gateway.example.test; dkim=fail\r\n",
        )
        .unwrap();
        let text = String::from_utf8_lossy(&out);
        assert!(!text.contains("dkim=pass"));
        assert_eq!(text.matches("Authentication-Results:").count(), 1);
        assert_eq!(fields(raw).unwrap().1, fields(&out).unwrap().1);
    }
}
