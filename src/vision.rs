//! Local OCR/QR extraction. Untrusted decoders run in a separate, confined service.
//! Raw recovered text and barcode payloads are transient, never stored in Scan.
use anyhow::{Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use mail_parser::{MessageParser, MimeHeaders};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, path::PathBuf, time::Instant};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};

pub const PROTOCOL: &str = "noisefence-vision-1";
const MAX_REQUEST: usize = 12 * 1024 * 1024;
const MAX_RESPONSE: usize = 256 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub socket: PathBuf,
    pub timeout_ms: u64,
    pub max_parallel: usize,
    pub max_parts: usize,
    pub max_part_bytes: usize,
    pub max_total_bytes: usize,
    pub max_pixels: usize,
    pub max_pages: usize,
    pub max_text_chars: usize,
    pub max_codes: usize,
    /// Small joint heuristic only; the OCR lexical score is always advisory.
    pub contribute_to_score: bool,
    pub backend_sha256: Option<String>,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            socket: "/run/noisefence-vision/worker.sock".into(),
            timeout_ms: 3000,
            max_parallel: 1,
            max_parts: 6,
            max_part_bytes: 4 * 1024 * 1024,
            max_total_bytes: 8 * 1024 * 1024,
            max_pixels: 8_000_000,
            max_pages: 4,
            max_text_chars: 16_000,
            max_codes: 16,
            contribute_to_score: false,
            backend_sha256: None,
        }
    }
}
impl Settings {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.socket.is_absolute() && self.socket.as_os_str().len() < 100,
            "vision.socket must be a short absolute Unix socket path"
        );
        ensure!(
            (200..=5000).contains(&self.timeout_ms),
            "vision.timeout_ms must be 200..5000"
        );
        ensure!(
            (1..=4).contains(&self.max_parallel),
            "vision.max_parallel must be 1..4"
        );
        ensure!(
            (1..=8).contains(&self.max_parts),
            "vision.max_parts must be 1..8"
        );
        ensure!(
            (1..=4 * 1024 * 1024).contains(&self.max_part_bytes)
                && self.max_total_bytes >= self.max_part_bytes
                && self.max_total_bytes <= 8 * 1024 * 1024,
            "invalid vision byte limits"
        );
        ensure!(
            (10_000..=16_000_000).contains(&self.max_pixels)
                && (1..=8).contains(&self.max_pages)
                && (100..=32_000).contains(&self.max_text_chars)
                && (1..=32).contains(&self.max_codes),
            "invalid vision output limits"
        );
        ensure!(
            self.backend_sha256.as_ref().is_none_or(|h| valid_hash(h)),
            "vision.backend_sha256 must be a lowercase SHA-256"
        );
        Ok(())
    }
}
fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn worker_sha256() -> String {
    crate::message::digest(include_bytes!("../deploy/vision-worker.py"))
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    #[default]
    Disabled,
    Complete,
    Limited,
    Unavailable,
    Busy,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Summary {
    pub status: Status,
    pub version: String,
    pub backend_sha256: Option<String>,
    pub parts: usize,
    pub pages: usize,
    pub text_chars: usize,
    pub qr_codes: usize,
    pub other_codes: usize,
    pub link_domains: usize,
    pub credential_request: bool,
    pub urgency: bool,
    /// A separate, uncalibrated observation. Never a replacement for mail features.
    pub lexical_logit: Option<f64>,
    pub errors: Vec<String>,
    pub elapsed_ms: u64,
}
impl Summary {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.version.is_empty() || self.version == PROTOCOL,
            "unknown vision protocol"
        );
        ensure!(
            self.backend_sha256.as_ref().is_none_or(|h| valid_hash(h)),
            "invalid vision backend digest"
        );
        ensure!(
            self.parts <= 8
                && self.pages <= 8
                && self.text_chars <= 32_000
                && self.qr_codes + self.other_codes <= 32
                && self.link_domains <= 12
                && self.lexical_logit.is_none_or(f64::is_finite),
            "invalid vision observation"
        );
        ensure!(
            self.errors.len() <= 16 && self.errors.iter().all(|s| valid_error(s)),
            "invalid vision errors"
        );
        Ok(())
    }
}
pub(crate) fn valid_error(value: &str) -> bool {
    matches!(
        value,
        "invalid_request"
            | "invalid_limits"
            | "invalid_parts"
            | "invalid_part"
            | "invalid_encoding"
            | "input_limit"
            | "timeout"
            | "decoder_failed"
            | "output_limit"
            | "page_limit"
            | "pixel_limit"
            | "invalid_codes"
            | "code_limit"
            | "text_limit"
            | "invalid_pdf"
            | "unsupported_image"
            | "invalid_document"
            | "worker_limit"
            | "mime_limit"
            | "part_limit"
            | "backend_mismatch"
            | "worker_unavailable"
    )
}

#[derive(Debug, Serialize)]
struct Part {
    kind: &'static str,
    data: String,
}
#[derive(Debug, Serialize)]
struct Limits {
    timeout_ms: u64,
    max_pixels: usize,
    max_pages: usize,
    max_text_chars: usize,
    max_codes: usize,
}
#[derive(Debug, Serialize)]
struct Request {
    protocol: &'static str,
    limits: Limits,
    parts: Vec<Part>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Code {
    pub kind: String,
    pub data: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Page {
    pub part: usize,
    pub page: usize,
    pub text: String,
    pub codes: Vec<Code>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    protocol: String,
    status: Status,
    backend_sha256: Option<String>,
    pages: Vec<Page>,
    errors: Vec<String>,
}
/// Available only to explicit local inspection; never part of the persisted Scan.
#[derive(Debug, Serialize)]
pub struct Inspection {
    pub summary: Summary,
    pub pages: Vec<Page>,
}
impl Inspection {
    pub fn text(&self) -> String {
        let mut text = String::new();
        for page in &self.pages {
            text.push_str(&page.text);
            text.push('\n');
            for code in &page.codes {
                text.push_str(&code.data);
                text.push('\n');
            }
        }
        text
    }
    pub fn domains(&self) -> Vec<String> {
        static URLS: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
        let pattern =
            URLS.get_or_init(|| regex::Regex::new(r#"(?i)https?://[^\s<>"']{1,4096}"#).unwrap());
        let text = self.text();
        let mut domains: Vec<_> = pattern
            .find_iter(&text)
            .take(100)
            .filter_map(|m| reqwest::Url::parse(m.as_str()).ok())
            .filter_map(|url| {
                url.host_str()
                    .map(|d| d.trim_end_matches('.').to_ascii_lowercase())
            })
            .filter(|d| crate::config::valid_domain(d))
            .collect();
        domains.sort();
        domains.dedup();
        domains.truncate(12);
        domains
    }
    pub fn apply(&self, scan: &mut crate::engine::Scan, contribute: bool) {
        use crate::engine::Signal;
        scan.vision = self.summary.clone();
        match self.summary.status {
            Status::Disabled => return,
            Status::Limited | Status::Unavailable | Status::Busy => {
                scan.complete = false;
                scan.reasons.push(Signal {
                    id: "vision_incomplete".into(),
                    detail: "Lecture OCR / codes limitée ou indisponible".into(),
                    weight: 0.0,
                });
            }
            Status::Complete => {}
        }
        if self.summary.pages > 0 {
            scan.reasons.push(Signal {
                id: "vision_read".into(),
                detail: format!(
                    "OCR local : {} caractères, {} QR et {} autres codes sur {} pages",
                    self.summary.text_chars,
                    self.summary.qr_codes,
                    self.summary.other_codes,
                    self.summary.pages
                ),
                weight: 0.0,
            });
        }
        // A QR or login link alone is ordinary mail content, not a spam rule.
        if self.summary.credential_request && self.summary.urgency && self.summary.link_domains > 0
        {
            scan.reasons.push(Signal {
                id: "vision_credential_lure".into(),
                detail: "Texte visuel combinant urgence, demande d’identifiants et lien".into(),
                weight: if contribute && self.summary.status == Status::Complete {
                    0.75
                } else {
                    0.0
                },
            });
        }
    }
}

fn select(raw: &[u8], settings: &Settings) -> (Vec<Part>, Vec<String>) {
    let mut parts = Vec::new();
    let mut errors = Vec::new();
    let mut total = 0;
    let mut seen = BTreeSet::new();
    let Some(message) = MessageParser::default().parse(raw) else {
        return (parts, vec!["mime_limit".into()]);
    };
    if message.parts.len() > 200 {
        return (parts, vec!["mime_limit".into()]);
    }
    let mut add = |kind, bytes: &[u8]| {
        if bytes.is_empty() || bytes.len() > settings.max_part_bytes {
            errors.push("input_limit".into());
        } else if seen.insert(crate::message::digest(bytes)) {
            if parts.len() >= settings.max_parts {
                errors.push("part_limit".into());
            } else if total + bytes.len() > settings.max_total_bytes {
                errors.push("input_limit".into());
            } else {
                total += bytes.len();
                parts.push(Part {
                    kind,
                    data: STANDARD.encode(bytes),
                });
            }
        }
    };
    for part in &message.parts {
        let content_type = part.content_type();
        let bytes = part.contents();
        // MIME plus magic catches common files mislabeled as octet-stream.
        if bytes.starts_with(b"%PDF-")
            || content_type.is_some_and(|t| {
                t.c_type.eq_ignore_ascii_case("application")
                    && t.c_subtype
                        .as_deref()
                        .is_some_and(|v| v.eq_ignore_ascii_case("pdf"))
            })
        {
            add("pdf", bytes);
        } else if content_type.is_some_and(|t| t.c_type.eq_ignore_ascii_case("image"))
            || bytes.starts_with(b"\x89PNG\r\n\x1a\n")
            || bytes.starts_with(b"\xff\xd8\xff")
            || bytes.starts_with(b"GIF8")
            || bytes.starts_with(b"II*\0")
            || bytes.starts_with(b"MM\0*")
            || bytes.starts_with(b"BM")
            || (bytes.starts_with(b"RIFF") && bytes.get(8..12) == Some(b"WEBP"))
        {
            add("image", bytes);
        }
    }
    // data: images are local bytes too. Never fetch http(s) src or a CID remotely.
    static DATA_IMAGES: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let pattern = DATA_IMAGES.get_or_init(|| {
        regex::Regex::new(r"(?i)data:image/[a-z0-9.+-]+;base64,([a-z0-9+/=\r\n]+)").unwrap()
    });
    let mut embedded_count = 0;
    let mut invalid_embedded = false;
    for body in (0..message.html_body_count().min(20)).filter_map(|i| message.body_html(i)) {
        for captures in pattern.captures_iter(&body).take(settings.max_parts + 1) {
            embedded_count += 1;
            if captures[1].len() > settings.max_part_bytes.div_ceil(3) * 4 + 4096 {
                invalid_embedded = true;
                continue;
            }
            let encoded: String = captures[1]
                .chars()
                .filter(|c| !c.is_ascii_whitespace())
                .collect();
            match STANDARD.decode(encoded) {
                Ok(bytes) => add("image", &bytes),
                Err(_) => invalid_embedded = true,
            }
        }
    }
    if embedded_count > settings.max_parts || invalid_embedded {
        errors.push("input_limit".into());
    }
    errors.sort();
    errors.dedup();
    (parts, errors)
}

pub struct Client {
    settings: Settings,
    slots: std::sync::Arc<crate::capacity::Capacity>,
}
impl Client {
    pub fn new(settings: Settings) -> Result<Self> {
        settings.validate()?;
        Ok(Self {
            slots: crate::capacity::Capacity::new(settings.max_parallel),
            settings,
        })
    }
    pub(crate) fn reconfigure(&self, settings: Settings) -> Result<Self> {
        let mut next = Self::new(settings)?;
        next.slots = self.slots.clone();
        Ok(next)
    }
    pub(crate) fn activate(&self) {
        self.slots.set_limit(self.settings.max_parallel);
    }
    pub async fn inspect(&self, raw: &[u8]) -> Inspection {
        let started = Instant::now();
        let (parts, errors) = select(raw, &self.settings);
        let mut inspection = Inspection {
            summary: Summary {
                status: if errors.is_empty() {
                    Status::Complete
                } else {
                    Status::Limited
                },
                version: PROTOCOL.into(),
                parts: parts.len(),
                errors,
                ..Default::default()
            },
            pages: Vec::new(),
        };
        if !parts.is_empty() {
            if let Ok(_permit) = self.slots.try_acquire() {
                match tokio::time::timeout(
                    std::time::Duration::from_millis(self.settings.timeout_ms),
                    self.exchange(parts),
                )
                .await
                {
                    Ok(Ok(response)) => {
                        if inspection.summary.status != Status::Limited
                            || response.status != Status::Complete
                        {
                            inspection.summary.status = response.status;
                        }
                        inspection.summary.backend_sha256 = response.backend_sha256;
                        inspection.summary.errors.extend(response.errors);
                        inspection.pages = response.pages;
                    }
                    Ok(Err(_)) => {
                        inspection.summary.status = Status::Unavailable;
                        inspection.summary.errors.push("worker_unavailable".into());
                    }
                    Err(_) => {
                        inspection.summary.status = Status::Unavailable;
                        inspection.summary.errors.push("timeout".into());
                    }
                }
            } else {
                inspection.summary.status = Status::Busy;
            }
        }
        inspection.summary.pages = inspection.pages.len();
        inspection.summary.text_chars = inspection
            .pages
            .iter()
            .map(|p| p.text.chars().count())
            .sum();
        for code in inspection.pages.iter().flat_map(|p| &p.codes) {
            if code.kind == "QR-Code" {
                inspection.summary.qr_codes += 1;
            } else {
                inspection.summary.other_codes += 1;
            }
        }
        let text = inspection.text().to_lowercase();
        inspection.summary.credential_request = [
            "password",
            "mot de passe",
            "seed phrase",
            "recovery phrase",
            "identifiants",
            "verify your account",
            "vérifiez votre compte",
        ]
        .iter()
        .any(|s| text.contains(s));
        inspection.summary.urgency = [
            "urgent",
            "immediately",
            "suspend",
            "expire",
            "immédiat",
            "within 24",
            "sous 24",
            "action required",
        ]
        .iter()
        .any(|s| text.contains(s));
        inspection.summary.link_domains = inspection.domains().len();
        inspection.summary.elapsed_ms = started.elapsed().as_millis() as u64;
        inspection.summary.errors.sort();
        inspection.summary.errors.dedup();
        inspection
    }
    async fn exchange(&self, parts: Vec<Part>) -> Result<Response> {
        let count = parts.len();
        let request = serde_json::to_vec(&Request {
            protocol: PROTOCOL,
            limits: Limits {
                timeout_ms: self
                    .settings
                    .timeout_ms
                    .saturating_sub(150)
                    .clamp(100, 4000),
                max_pixels: self.settings.max_pixels,
                max_pages: self.settings.max_pages,
                max_text_chars: self.settings.max_text_chars,
                max_codes: self.settings.max_codes,
            },
            parts,
        })?;
        ensure!(request.len() <= MAX_REQUEST, "vision request too large");
        let mut socket = UnixStream::connect(&self.settings.socket).await?;
        socket.write_u32(request.len() as u32).await?;
        socket.write_all(&request).await?;
        let length = socket.read_u32().await? as usize;
        ensure!(
            length > 0 && length <= MAX_RESPONSE,
            "vision response too large"
        );
        let mut response = vec![0; length];
        socket.read_exact(&mut response).await?;
        let response: Response = serde_json::from_slice(&response)?;
        ensure!(
            response.protocol == PROTOCOL
                && matches!(
                    response.status,
                    Status::Complete | Status::Limited | Status::Unavailable | Status::Busy
                ),
            "invalid vision status"
        );
        ensure!(
            response
                .backend_sha256
                .as_ref()
                .is_some_and(|h| valid_hash(h)),
            "missing vision backend"
        );
        ensure!(
            self.settings
                .backend_sha256
                .as_ref()
                .is_none_or(|h| Some(h) == response.backend_sha256.as_ref()),
            "vision backend mismatch"
        );
        ensure!(
            response.errors.len() <= 16
                && response.errors.iter().all(|e| valid_error(e))
                && (response.status != Status::Complete || response.errors.is_empty()),
            "invalid vision errors"
        );
        ensure!(
            response.pages.len() <= self.settings.max_pages
                && (response.status != Status::Complete || !response.pages.is_empty()),
            "invalid vision pages"
        );
        let mut chars = 0;
        let mut codes = 0;
        let mut seen = BTreeSet::new();
        for page in &response.pages {
            ensure!(
                page.part < count
                    && page.page < self.settings.max_pages
                    && seen.insert((page.part, page.page)),
                "invalid vision page"
            );
            chars += page.text.chars().count();
            codes += page.codes.len();
            for code in &page.codes {
                ensure!(
                    code.kind.len() <= 32
                        && code
                            .kind
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"-_/ ".contains(&b))
                        && code.data.chars().count() <= 4096,
                    "invalid barcode"
                );
            }
        }
        ensure!(
            chars <= self.settings.max_text_chars && codes <= self.settings.max_codes,
            "vision output limit"
        );
        if response.status == Status::Complete {
            ensure!(
                (0..count).all(|part| response.pages.iter().any(|p| p.part == part)),
                "unscanned vision part"
            );
        }
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const IMAGE: &[u8] = b"MIME-Version: 1.0\r\nContent-Type: image/png\r\nContent-Transfer-Encoding: base64\r\n\r\niVBORw0KGgo=";
    #[test]
    fn select_inline_and_limits() {
        let (parts, errors) = select(IMAGE, &Settings::default());
        assert_eq!(parts.len(), 1);
        assert!(errors.is_empty());
        assert_eq!(
            STANDARD.decode(&parts[0].data).unwrap(),
            b"\x89PNG\r\n\x1a\n"
        );
        let (_, errors) = select(
            IMAGE,
            &Settings {
                max_part_bytes: 2,
                ..Default::default()
            },
        );
        assert_eq!(errors, ["input_limit"]);
        let raw = b"Content-Type: text/html\r\n\r\n<img src=\"https://private.invalid/image.png\"><img src=\"data:image/png;base64,iVBORw0KGgo=\">";
        assert_eq!(select(raw, &Settings::default()).0.len(), 1);
    }
    #[tokio::test]
    async fn no_images_does_not_connect_and_failure_is_not_clean() {
        let client = Client::new(Settings {
            socket: "/nonexistent/vision.sock".into(),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(
            client
                .inspect(b"Subject: text\r\n\r\nhello")
                .await
                .summary
                .status,
            Status::Complete
        );
        let inspection = client.inspect(IMAGE).await;
        assert_eq!(inspection.summary.status, Status::Unavailable);
        let mut scan = crate::engine::Scan {
            complete: true,
            ..Default::default()
        };
        inspection.apply(&mut scan, true);
        assert!(!scan.complete);
        assert!(scan.reasons.iter().all(|r| r.weight == 0.0));
    }
    #[test]
    fn qr_is_not_spam_and_summary_never_contains_payload() {
        let inspection = Inspection {
            summary: Summary {
                status: Status::Complete,
                pages: 1,
                qr_codes: 1,
                link_domains: 1,
                ..Default::default()
            },
            pages: vec![Page {
                part: 0,
                page: 0,
                text: "Welcome".into(),
                codes: vec![Code {
                    kind: "QR-Code".into(),
                    data: "https://example.org/login?token=SECRET".into(),
                }],
            }],
        };
        let mut scan = crate::engine::Scan::default();
        inspection.apply(&mut scan, true);
        assert!(scan.reasons.iter().all(|r| r.weight == 0.0));
        assert!(!serde_json::to_string(&scan).unwrap().contains("SECRET"));
        assert_eq!(inspection.domains(), ["example.org"]);
    }
}
