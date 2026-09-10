//! Bounded, advisory static inspection. No attachment execution, network or file IO.
//! See docs/content-inspection.md for the deliberately limited coverage contract.
use anyhow::{Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use mail_parser::{MessageParser, MimeHeaders};
use serde::{Deserialize, Serialize};
use std::{
    borrow::Cow,
    collections::BTreeSet,
    io::{Cursor, Read, Seek, SeekFrom},
};

pub const REPORT_VERSION: &str = "noisefence-content-inspection-3";
const MIB: usize = 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub max_raw_bytes: usize,
    pub max_parts: usize,
    pub max_mime_depth: usize,
    pub max_header_bytes: usize,
    pub max_part_bytes: usize,
    pub max_total_decoded_bytes: usize,
    pub max_html_bytes: usize,
    pub max_archive_entries: usize,
    pub max_unpacked_bytes: usize,
    pub max_total_unpacked_bytes: usize,
    pub max_compression_ratio: usize,
    pub max_structure_nodes: usize,
    pub max_nesting: usize,
    pub max_findings: usize,
    pub max_image_pixels: u64,
    /// Advisory threshold, not a permission to skip subsequent images.
    pub max_images: usize,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            max_raw_bytes: 8 * MIB,
            max_parts: 64,
            max_mime_depth: 8,
            max_header_bytes: 32 * 1024,
            max_part_bytes: 4 * MIB,
            max_total_decoded_bytes: 8 * MIB,
            max_html_bytes: 256 * 1024,
            max_archive_entries: 256,
            max_unpacked_bytes: 4 * MIB,
            max_total_unpacked_bytes: 8 * MIB,
            max_compression_ratio: 100,
            max_structure_nodes: 50_000,
            max_nesting: 32,
            max_findings: 128,
            max_image_pixels: 16_000_000,
            max_images: 20,
        }
    }
}
impl Settings {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (1..=16 * MIB).contains(&self.max_raw_bytes),
            "invalid content_inspection.max_raw_bytes"
        );
        ensure!(
            (1..=256).contains(&self.max_parts) && (1..=16).contains(&self.max_mime_depth),
            "invalid content_inspection MIME limits"
        );
        ensure!(
            (1..=64 * 1024).contains(&self.max_header_bytes),
            "invalid content_inspection.max_header_bytes"
        );
        ensure!(
            (1..=8 * MIB).contains(&self.max_part_bytes)
                && self.max_part_bytes <= self.max_total_decoded_bytes
                && self.max_total_decoded_bytes <= 16 * MIB,
            "invalid content_inspection decoded byte limits"
        );
        ensure!(
            (1..=512 * 1024).contains(&self.max_html_bytes),
            "invalid content_inspection.max_html_bytes"
        );
        ensure!(
            (1..=1024).contains(&self.max_archive_entries),
            "invalid content_inspection.max_archive_entries"
        );
        ensure!(
            (1..=8 * MIB).contains(&self.max_unpacked_bytes)
                && self.max_unpacked_bytes <= self.max_total_unpacked_bytes
                && self.max_total_unpacked_bytes <= 32 * MIB,
            "invalid content_inspection unpacked byte limits"
        );
        ensure!(
            (1..=200).contains(&self.max_compression_ratio),
            "invalid content_inspection.max_compression_ratio"
        );
        ensure!(
            (1..=100_000).contains(&self.max_structure_nodes)
                && (1..=64).contains(&self.max_nesting),
            "invalid content_inspection structure limits"
        );
        ensure!(
            (1..=512).contains(&self.max_findings)
                && (1..=256).contains(&self.max_images)
                && (1..=100_000_000).contains(&self.max_image_pixels),
            "invalid content_inspection output limits"
        );
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Complete,
    Incomplete,
    InvalidSettings,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ContentKind {
    Html,
    Png,
    Jpeg,
    Gif,
    Pdf,
    OfficeZip,
    CompoundFile,
    Other,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingId {
    RawLimit,
    PartLimit,
    MimeDepthLimit,
    HeaderLimit,
    DecodedLimit,
    MalformedMime,
    UnsupportedEncoding,
    HtmlLimit,
    StructureLimit,
    HtmlActiveElement,
    HtmlEventHandler,
    HtmlActiveUrl,
    HtmlRefresh,
    HtmlEmbeddedContent,
    TypeMismatch,
    UnsupportedFormat,
    ImageDimensions,
    ImageCount,
    ImageStructureInvalid,
    TrailingData,
    PdfActiveName,
    PdfMalformed,
    PdfEncrypted,
    PdfUnsupportedFilter,
    PdfUnsupportedStructure,
    PdfEmbeddedFile,
    PdfExternalReference,
    ArchiveMalformed,
    ArchiveEntryLimit,
    ArchiveEncrypted,
    ArchiveUnsupported,
    ArchiveAmbiguous,
    DecompressionLimit,
    OfficeVbaProject,
    OfficeMacroEnabled,
    OfficeXlmMacros,
    OfficeExternalRelationship,
    OfficeEmbeddedObject,
    OfficeMalformedXml,
    OfficeUnsupportedXml,
    OfficeEncrypted,
    CompoundMalformed,
    CompoundIoLimit,
    OfficeLegacyCoverage,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Finding {
    pub id: FindingId,
    pub part: Option<usize>,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Stats {
    pub parts: usize,
    pub decoded_bytes: usize,
    pub unpacked_bytes: usize,
    pub structure_nodes: usize,
    pub images: usize,
    pub pdfs: usize,
    pub office_documents: usize,
    pub html_parts: usize,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PartReport {
    pub index: usize,
    pub kind: ContentKind,
    pub bytes: usize,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub frames: Option<u32>,
    pub complete: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Report {
    pub version: String,
    pub status: Status,
    pub advisory: bool,
    /// Work or findings omitted because a resource budget was exhausted.
    pub truncated: bool,
    pub limits: Settings,
    pub stats: Stats,
    pub parts: Vec<PartReport>,
    pub findings: Vec<Finding>,
}
struct Inspection<'a> {
    s: &'a Settings,
    r: Report,
    incomplete_parts: BTreeSet<usize>,
}
impl Inspection<'_> {
    fn finding(&mut self, id: FindingId, part: Option<usize>) {
        let f = Finding { id, part };
        if self.r.findings.contains(&f) {
            return;
        }
        if self.r.findings.len() == self.s.max_findings {
            self.r.truncated = true;
            if let Some(index) = part {
                self.incomplete_parts.insert(index);
            }
            self.r.status = Status::Incomplete;
            if let Some(p) = part.and_then(|p| self.r.parts.iter_mut().find(|x| x.index == p)) {
                p.complete = false;
            }
        } else {
            self.r.findings.push(f);
        }
    }
    fn incomplete(&mut self, id: FindingId, part: Option<usize>, limit: bool) {
        self.r.status = Status::Incomplete;
        if let Some(index) = part {
            self.incomplete_parts.insert(index);
        }
        self.r.truncated |= limit;
        if let Some(p) = part.and_then(|p| self.r.parts.iter_mut().find(|x| x.index == p)) {
            p.complete = false;
        }
        self.finding(id, part);
    }
    fn node(&mut self) -> ParseResult<()> {
        if self.r.stats.structure_nodes >= self.s.max_structure_nodes {
            return Err(Fault::Limit);
        }
        self.r.stats.structure_nodes += 1;
        Ok(())
    }
    fn absolute_unpack_cap(&self) -> usize {
        self.s.max_unpacked_bytes.min(
            self.s
                .max_total_unpacked_bytes
                .saturating_sub(self.r.stats.unpacked_bytes),
        )
    }
    fn unpack_cap(&self, compressed: usize) -> usize {
        self.absolute_unpack_cap()
            .min(compressed.saturating_mul(self.s.max_compression_ratio))
    }
    fn inflate(&mut self, bytes: &[u8], zlib: bool) -> ParseResult<Vec<u8>> {
        let cap = self.unpack_cap(bytes.len());
        let mut decoder = flate2::Decompress::new(zlib);
        let mut output = Vec::new();
        loop {
            let mut chunk = [0; 8192];
            let before_in = decoder.total_in();
            let before_out = decoder.total_out();
            let n = chunk.len().min(cap.saturating_sub(output.len()) + 1);
            let result = decoder
                .decompress(
                    &bytes[before_in as usize..],
                    &mut chunk[..n],
                    flate2::FlushDecompress::None,
                )
                .map_err(|_| Fault::Malformed)?;
            let written = (decoder.total_out() - before_out) as usize;
            self.r.stats.unpacked_bytes += written.min(cap.saturating_sub(output.len()));
            if output.len() + written > cap {
                return Err(Fault::Limit);
            }
            output.extend_from_slice(&chunk[..written]);
            if result == flate2::Status::StreamEnd {
                if decoder.total_in() as usize != bytes.len() {
                    return Err(Fault::Malformed);
                }
                return Ok(output);
            }
            if decoder.total_in() == before_in && written == 0 {
                return Err(Fault::Malformed);
            }
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fault {
    Malformed,
    Limit,
    Unsupported,
}
type ParseResult<T> = std::result::Result<T, Fault>;

/// Inspect an RFC 5322/MIME message. A complete report is not a clean verdict.
/// Parsing is synchronous and has deterministic resource bounds, not a deadline.
pub fn analyze(raw: &[u8], settings: &Settings) -> Report {
    let mut c = Inspection {
        s: settings,
        r: Report {
            version: REPORT_VERSION.into(),
            status: Status::Complete,
            advisory: true,
            truncated: false,
            limits: settings.clone(),
            stats: Stats::default(),
            parts: Vec::new(),
            findings: Vec::new(),
        },
        incomplete_parts: BTreeSet::new(),
    };
    if settings.validate().is_err() {
        c.r.status = Status::InvalidSettings;
        return c.r;
    }
    if raw.len() > settings.max_raw_bytes {
        c.incomplete(FindingId::RawLimit, None, true);
        return c.r;
    }
    c.mime(raw, 0);
    if c.r.stats.images > settings.max_images {
        c.finding(FindingId::ImageCount, None);
    }
    c.r
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
fn decode_body<'a>(body: &'a [u8], enc: &str, cap: usize) -> ParseResult<Cow<'a, [u8]>> {
    match enc {
        "7bit" | "8bit" | "binary" | "" => {
            if body.len() > cap {
                Err(Fault::Limit)
            } else {
                Ok(Cow::Borrowed(body))
            }
        }
        "base64" => {
            let len = body.iter().filter(|b| !b.is_ascii_whitespace()).count();
            if len / 4 * 3 > cap.saturating_add(2) {
                return Err(Fault::Limit);
            }
            let compact: Vec<u8> = body
                .iter()
                .copied()
                .filter(|b| !b.is_ascii_whitespace())
                .collect();
            let bytes = STANDARD.decode(compact).map_err(|_| Fault::Malformed)?;
            if bytes.len() > cap {
                Err(Fault::Limit)
            } else {
                Ok(Cow::Owned(bytes))
            }
        }
        "quoted-printable" => {
            let mut out = Vec::new();
            let mut i = 0;
            while i < body.len() {
                let b = body[i];
                i += 1;
                if b == b'=' {
                    if body.get(i..i + 2) == Some(b"\r\n") {
                        i += 2;
                        continue;
                    }
                    if body.get(i) == Some(&b'\n') {
                        i += 1;
                        continue;
                    }
                    let h = body
                        .get(i)
                        .and_then(|b| hex_digit(*b))
                        .ok_or(Fault::Malformed)?;
                    let l = body
                        .get(i + 1)
                        .and_then(|b| hex_digit(*b))
                        .ok_or(Fault::Malformed)?;
                    if out.len() == cap {
                        return Err(Fault::Limit);
                    }
                    out.push(h * 16 + l);
                    i += 2;
                } else {
                    if out.len() == cap {
                        return Err(Fault::Limit);
                    }
                    out.push(b);
                }
            }
            Ok(Cow::Owned(out))
        }
        _ => Err(Fault::Unsupported),
    }
}
impl Inspection<'_> {
    fn mime(&mut self, raw: &[u8], depth: usize) {
        if depth > self.s.max_mime_depth {
            self.incomplete(FindingId::MimeDepthLimit, None, true);
            return;
        }
        if self.r.stats.parts >= self.s.max_parts {
            self.incomplete(FindingId::PartLimit, None, true);
            return;
        }
        let index = self.r.stats.parts;
        self.r.stats.parts += 1;
        let window = &raw[..raw.len().min(self.s.max_header_bytes.saturating_add(4))];
        let end = window
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|i| i + 4)
            .or_else(|| window.windows(2).position(|w| w == b"\n\n").map(|i| i + 2));
        let Some(end) = end else {
            self.incomplete(
                if raw.len() > self.s.max_header_bytes {
                    FindingId::HeaderLimit
                } else {
                    FindingId::MalformedMime
                },
                Some(index),
                raw.len() > self.s.max_header_bytes,
            );
            return;
        };
        if end > self.s.max_header_bytes {
            self.incomplete(FindingId::HeaderLimit, Some(index), true);
            return;
        }
        let mut previous_header = false;
        for line in raw[..end].split(|b| *b == b'\n') {
            let line = line.strip_suffix(b"\r").unwrap_or(line);
            if line.is_empty() {
                continue;
            }
            let controls = line.iter().any(|b| *b < 32 && *b != b'\t' || *b == 127);
            let valid_field = if matches!(line[0], b' ' | b'\t') {
                previous_header
            } else {
                line.iter()
                    .position(|b| *b == b':')
                    .is_some_and(|n| n > 0 && line[..n].iter().all(|b| (33..=126).contains(b)))
            };
            if controls || !valid_field {
                self.incomplete(FindingId::MalformedMime, Some(index), false);
                return;
            }
            previous_header = true;
        }
        let Some(message) = MessageParser::default().parse_headers(&raw[..end]) else {
            self.incomplete(FindingId::MalformedMime, Some(index), false);
            return;
        };
        for name in [
            "content-type",
            "content-transfer-encoding",
            "content-disposition",
        ] {
            if message
                .headers()
                .iter()
                .filter(|h| h.name().eq_ignore_ascii_case(name))
                .count()
                > 1
            {
                self.incomplete(FindingId::MalformedMime, Some(index), false);
            }
        }
        let root = message.root_part();
        let ct = root.content_type();
        let ty = ct.map(|c| c.ctype()).unwrap_or("text").to_ascii_lowercase();
        let sub = ct
            .and_then(|c| c.subtype())
            .unwrap_or("plain")
            .to_ascii_lowercase();
        let enc = root
            .content_transfer_encoding()
            .unwrap_or("")
            .to_ascii_lowercase();
        let body = &raw[end..];
        if ty == "multipart" {
            if !matches!(enc.as_str(), "" | "7bit" | "8bit" | "binary") {
                self.incomplete(FindingId::UnsupportedEncoding, Some(index), false);
                return;
            }
            let Some(boundary) = ct.and_then(|c| c.attribute("boundary")) else {
                self.incomplete(FindingId::MalformedMime, Some(index), false);
                return;
            };
            if boundary.is_empty()
                || boundary.len() > 70
                || !boundary.bytes().all(|b| (32..127).contains(&b))
            {
                self.incomplete(FindingId::MalformedMime, Some(index), false);
                return;
            }
            let marker = format!("--{boundary}");
            let mut offset = 0;
            let mut start = None;
            let mut closed = false;
            for line in body.split_inclusive(|b| *b == b'\n') {
                let line_start = offset;
                offset += line.len();
                let bare = line.strip_suffix(b"\n").unwrap_or(line);
                let bare = bare.strip_suffix(b"\r").unwrap_or(bare);
                let bare = &bare[..bare
                    .iter()
                    .rposition(|b| !matches!(b, b' ' | b'\t'))
                    .map_or(0, |p| p + 1)];
                if let Some(suffix) = bare.strip_prefix(marker.as_bytes())
                    && (suffix.is_empty() || suffix == b"--")
                {
                    if let Some(start) = start {
                        let mut stop = line_start;
                        if stop >= 2 && body.get(stop - 2..stop) == Some(b"\r\n") {
                            stop -= 2;
                        } else if stop >= 1 && body[stop - 1] == b'\n' {
                            stop -= 1;
                        }
                        self.mime(&body[start..stop.max(start)], depth + 1);
                    }
                    if suffix == b"--" {
                        closed = true;
                        break;
                    }
                    if self.r.stats.parts >= self.s.max_parts {
                        self.incomplete(FindingId::PartLimit, Some(index), true);
                        return;
                    }
                    start = Some(offset);
                }
            }
            if closed && start.is_none() {
                self.incomplete(FindingId::MalformedMime, Some(index), false);
            }
            if !closed {
                if let Some(start) = start {
                    self.mime(&body[start..], depth + 1);
                }
                self.incomplete(FindingId::MalformedMime, Some(index), false);
            }
            return;
        }
        let cap = self.s.max_part_bytes.min(
            self.s
                .max_total_decoded_bytes
                .saturating_sub(self.r.stats.decoded_bytes),
        );
        let decoded = match decode_body(body, &enc, cap) {
            Ok(v) => v,
            Err(e) => {
                self.incomplete(
                    match e {
                        Fault::Limit => FindingId::DecodedLimit,
                        Fault::Malformed => FindingId::MalformedMime,
                        Fault::Unsupported => FindingId::UnsupportedEncoding,
                    },
                    Some(index),
                    e == Fault::Limit,
                );
                return;
            }
        };
        self.r.stats.decoded_bytes += decoded.len();
        if ty == "message" && matches!(sub.as_str(), "rfc822" | "global") {
            self.mime(&decoded, depth + 1);
            return;
        }
        if ty == "text"
            && sub == "html"
            && ct.and_then(|c| c.attribute("charset")).is_some_and(|s| {
                !s.eq_ignore_ascii_case("utf-8") && !s.eq_ignore_ascii_case("us-ascii")
            })
        {
            self.incomplete(FindingId::UnsupportedEncoding, Some(index), false);
        }
        let declared = format!("{ty}/{sub}");
        self.part(&decoded, &declared, root.attachment_name(), index);
    }
    fn part(&mut self, bytes: &[u8], declared: &str, filename: Option<&str>, index: usize) {
        let detected = sniff(bytes);
        let expected = expected_kind(declared, filename);
        let kind = detected.or(expected).unwrap_or(ContentKind::Other);
        self.r.parts.push(PartReport {
            index,
            kind,
            bytes: bytes.len(),
            width: None,
            height: None,
            frames: None,
            complete: !self.incomplete_parts.contains(&index),
        });
        let filename_kind = expected_kind("", filename);
        if detected.is_some_and(|d| {
            expected.is_some_and(|e| d != e) || filename_kind.is_some_and(|e| d != e)
        }) || detected.is_some()
            && expected.is_none()
            && !matches!(declared, "application/octet-stream" | "application/zip")
        {
            self.finding(FindingId::TypeMismatch, Some(index));
        }
        match kind {
            ContentKind::Html => self.html(bytes, index),
            ContentKind::Png | ContentKind::Jpeg | ContentKind::Gif => {
                self.image(bytes, kind, index)
            }
            ContentKind::Pdf => self.pdf(bytes, index),
            ContentKind::OfficeZip => self.office_zip(bytes, index),
            ContentKind::CompoundFile => {
                self.r.stats.office_documents += 1;
                self.compound(bytes, index);
            }
            ContentKind::Other => {
                if declared != "text/plain" || filename.is_some() {
                    self.incomplete(FindingId::UnsupportedFormat, Some(index), false);
                }
            }
        }
        // A declared HTML document can also be an image/PDF polyglot.
        if expected == Some(ContentKind::Html) && kind != ContentKind::Html {
            self.html(bytes, index);
        }
    }
    fn html(&mut self, bytes: &[u8], index: usize) {
        self.r.stats.html_parts += 1;
        if bytes.len() > self.s.max_html_bytes {
            self.incomplete(FindingId::HtmlLimit, Some(index), true);
            return;
        }
        let Ok(text) = std::str::from_utf8(bytes) else {
            self.incomplete(FindingId::UnsupportedEncoding, Some(index), false);
            return;
        };
        if text.contains('\0') {
            self.incomplete(FindingId::UnsupportedEncoding, Some(index), false);
            return;
        }
        let document = scraper::Html::parse_document(text);
        // HTML5 tree construction handles comments, raw-text elements, entities,
        // foreign content and browser error recovery. Input cap precedes the DOM.
        for node in document.tree.nodes() {
            if self.node().is_err() {
                self.incomplete(FindingId::StructureLimit, Some(index), true);
                break;
            }
            let Some(e) = node.value().as_element() else {
                continue;
            };
            if matches!(
                e.name(),
                "script" | "iframe" | "object" | "embed" | "applet"
            ) {
                self.finding(FindingId::HtmlActiveElement, Some(index));
            }
            if e.name() == "meta"
                && (e.attr("charset").is_some_and(|s| {
                    !s.eq_ignore_ascii_case("utf-8") && !s.eq_ignore_ascii_case("us-ascii")
                }) || e
                    .attr("http-equiv")
                    .is_some_and(|s| s.eq_ignore_ascii_case("content-type")))
            {
                self.incomplete(FindingId::UnsupportedEncoding, Some(index), false);
            }
            if e.name() == "meta"
                && e.attr("http-equiv")
                    .is_some_and(|v| v.eq_ignore_ascii_case("refresh"))
            {
                self.finding(FindingId::HtmlRefresh, Some(index));
            }
            for (name, value) in e.attrs() {
                if name.starts_with("on") && name.len() > 2 {
                    self.finding(FindingId::HtmlEventHandler, Some(index));
                }
                if name == "srcdoc" {
                    self.finding(FindingId::HtmlEmbeddedContent, Some(index));
                }
                if matches!(
                    name,
                    "href" | "src" | "action" | "formaction" | "data" | "background"
                ) {
                    let normalized: String = value
                        .trim_matches(|c: char| c <= '\u{20}')
                        .chars()
                        .filter(|c| !matches!(c, '\t' | '\n' | '\r'))
                        .take(128)
                        .collect();
                    let lower = normalized.to_ascii_lowercase();
                    if lower.starts_with("javascript:") || lower.starts_with("vbscript:") {
                        self.finding(FindingId::HtmlActiveUrl, Some(index));
                    }
                    if lower.starts_with("data:") {
                        self.finding(FindingId::HtmlEmbeddedContent, Some(index));
                    }
                }
            }
        }
    }
}
fn expected_kind(mime: &str, filename: Option<&str>) -> Option<ContentKind> {
    let ext = filename
        .and_then(|n| n.rsplit('.').next())
        .unwrap_or("")
        .to_ascii_lowercase();
    match mime {
        "text/html" | "application/xhtml+xml" => return Some(ContentKind::Html),
        "image/png" => return Some(ContentKind::Png),
        "image/jpeg" => return Some(ContentKind::Jpeg),
        "image/gif" => return Some(ContentKind::Gif),
        "application/pdf" => return Some(ContentKind::Pdf),
        "application/msword" | "application/vnd.ms-excel" | "application/vnd.ms-powerpoint" => {
            return Some(ContentKind::CompoundFile);
        }
        _ if mime.starts_with("application/vnd.openxmlformats-officedocument.")
            || mime.starts_with("application/vnd.ms-word.")
            || mime.starts_with("application/vnd.ms-excel.")
            || mime.starts_with("application/vnd.ms-powerpoint.") =>
        {
            return Some(ContentKind::OfficeZip);
        }
        _ => (),
    }
    match ext.as_str() {
        "htm" | "html" | "xhtml" => Some(ContentKind::Html),
        "png" => Some(ContentKind::Png),
        "jpg" | "jpeg" => Some(ContentKind::Jpeg),
        "gif" => Some(ContentKind::Gif),
        "pdf" => Some(ContentKind::Pdf),
        "doc" | "xls" | "ppt" => Some(ContentKind::CompoundFile),
        "docx" | "docm" | "dotm" | "xlsx" | "xlsm" | "xlam" | "xlsb" | "pptx" | "pptm" | "potm"
        | "ppam" | "zip" => Some(ContentKind::OfficeZip),
        _ => None,
    }
}
fn sniff(b: &[u8]) -> Option<ContentKind> {
    if b.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some(ContentKind::Png)
    } else if b.starts_with(b"\xff\xd8") {
        Some(ContentKind::Jpeg)
    } else if b.starts_with(b"GIF87a") || b.starts_with(b"GIF89a") {
        Some(ContentKind::Gif)
    } else if b.starts_with(b"%PDF-") {
        Some(ContentKind::Pdf)
    } else if b.starts_with(b"PK\x03\x04") || b.starts_with(b"PK\x05\x06") {
        Some(ContentKind::OfficeZip)
    } else if b.starts_with(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") {
        Some(ContentKind::CompoundFile)
    } else {
        None
    }
}

fn slice(b: &[u8], start: usize, len: usize) -> ParseResult<&[u8]> {
    b.get(start..start.checked_add(len).ok_or(Fault::Malformed)?)
        .ok_or(Fault::Malformed)
}
fn le16(b: &[u8], p: usize) -> ParseResult<u16> {
    Ok(u16::from_le_bytes(slice(b, p, 2)?.try_into().unwrap()))
}
fn le32(b: &[u8], p: usize) -> ParseResult<u32> {
    Ok(u32::from_le_bytes(slice(b, p, 4)?.try_into().unwrap()))
}
fn be16(b: &[u8], p: usize) -> ParseResult<u16> {
    Ok(u16::from_be_bytes(slice(b, p, 2)?.try_into().unwrap()))
}
fn be32(b: &[u8], p: usize) -> ParseResult<u32> {
    Ok(u32::from_be_bytes(slice(b, p, 4)?.try_into().unwrap()))
}
impl Inspection<'_> {
    fn dimensions(&mut self, w: u32, h: u32, index: usize) -> ParseResult<()> {
        if w == 0 || h == 0 {
            return Err(Fault::Malformed);
        }
        if let Some(p) = self.r.parts.iter_mut().find(|p| p.index == index) {
            p.width = Some(w);
            p.height = Some(h);
        }
        if u64::from(w) * u64::from(h) > self.s.max_image_pixels {
            self.finding(FindingId::ImageDimensions, Some(index));
        }
        Ok(())
    }
    fn image(&mut self, b: &[u8], kind: ContentKind, index: usize) {
        self.r.stats.images += 1;
        let result = match kind {
            ContentKind::Png => self.png(b, index),
            ContentKind::Jpeg => self.jpeg(b, index),
            ContentKind::Gif => self.gif(b, index),
            _ => unreachable!(),
        };
        match result {
            Ok((end, frames)) => {
                if let Some(p) = self.r.parts.iter_mut().find(|p| p.index == index) {
                    p.frames = Some(frames);
                }
                if end != b.len() {
                    self.incomplete(FindingId::TrailingData, Some(index), false);
                }
            }
            Err(e) => self.incomplete(
                match e {
                    Fault::Malformed => FindingId::ImageStructureInvalid,
                    Fault::Limit => FindingId::DecompressionLimit,
                    Fault::Unsupported => FindingId::UnsupportedFormat,
                },
                Some(index),
                e == Fault::Limit,
            ),
        }
    }
    fn png(&mut self, b: &[u8], index: usize) -> ParseResult<(usize, u32)> {
        if !b.starts_with(b"\x89PNG\r\n\x1a\n") {
            return Err(Fault::Malformed);
        }
        let mut pos = 8;
        let mut ihdr = None;
        let mut idat = Vec::new();
        let mut palette = false;
        let mut ended_data = false;
        let mut saw_data = false;
        loop {
            self.node()?;
            let len = be32(b, pos)? as usize;
            let tag = slice(b, pos + 4, 4)?;
            let data = slice(b, pos + 8, len)?;
            let crc = be32(b, pos + 8 + len)?;
            if crc32fast::hash(slice(b, pos + 4, len + 4)?) != crc {
                return Err(Fault::Malformed);
            }
            pos += len + 12;
            if ihdr.is_none() && tag != b"IHDR" {
                return Err(Fault::Malformed);
            }
            if tag != b"IDAT" && saw_data {
                ended_data = true;
            }
            match tag {
                b"IHDR" => {
                    if ihdr.is_some() || len != 13 {
                        return Err(Fault::Malformed);
                    }
                    let w = be32(data, 0)?;
                    let h = be32(data, 4)?;
                    self.dimensions(w, h, index)?;
                    let depth = data[8];
                    let color = data[9];
                    let valid = match color {
                        0 => [1, 2, 4, 8, 16].contains(&depth),
                        2 | 4 | 6 => [8, 16].contains(&depth),
                        3 => [1, 2, 4, 8].contains(&depth),
                        _ => false,
                    };
                    if !valid || data[10] != 0 || data[11] != 0 || data[12] > 1 {
                        return Err(Fault::Malformed);
                    }
                    if data[12] != 0 {
                        return Err(Fault::Unsupported);
                    }
                    ihdr = Some((w, h, depth, color));
                }
                b"PLTE" => {
                    if palette || saw_data || len == 0 || len > 768 || !len.is_multiple_of(3) {
                        return Err(Fault::Malformed);
                    }
                    palette = true;
                }
                b"IDAT" => {
                    if ended_data {
                        return Err(Fault::Malformed);
                    }
                    saw_data = true;
                    idat.extend_from_slice(data);
                }
                b"IEND" => {
                    if len != 0 || !saw_data {
                        return Err(Fault::Malformed);
                    }
                    let (w, h, depth, color) = ihdr.ok_or(Fault::Malformed)?;
                    if color == 3 && !palette {
                        return Err(Fault::Malformed);
                    }
                    let channels = match color {
                        2 => 3,
                        4 => 2,
                        6 => 4,
                        _ => 1,
                    };
                    let row = (u64::from(w) * channels * u64::from(depth)).div_ceil(8) + 1;
                    let expected = row.checked_mul(u64::from(h)).ok_or(Fault::Limit)?;
                    if expected > self.absolute_unpack_cap() as u64 {
                        return Err(Fault::Limit);
                    }
                    self.png_rows(&idat, row as usize, expected as usize)?;
                    return Ok((pos, 1));
                }
                b"acTL" | b"fcTL" | b"fdAT" => return Err(Fault::Unsupported),
                _ => {
                    if !tag.iter().all(u8::is_ascii_alphabetic) || tag[0].is_ascii_uppercase() {
                        return Err(Fault::Unsupported);
                    }
                }
            }
        }
    }
    /// IHDR fixes the exact output length. Enforce that length and both absolute
    /// byte budgets, without rejecting ordinary, highly compressible banners or
    /// allocating a pixel buffer. PDF/Office retain the generic ratio guard.
    fn png_rows(&mut self, bytes: &[u8], row: usize, expected: usize) -> ParseResult<()> {
        let mut decoder = flate2::Decompress::new(true);
        let mut chunk = [0; 8192];
        loop {
            let before_in = decoder.total_in();
            let produced = decoder.total_out() as usize;
            let remaining = expected - produced;
            // A single discarded sentinel detects forged IHDR dimensions.
            let n = chunk.len().min(remaining + 1);
            let result = decoder.decompress(
                &bytes[before_in as usize..],
                &mut chunk[..n],
                flate2::FlushDecompress::None,
            );
            let written = decoder.total_out() as usize - produced;
            self.r.stats.unpacked_bytes += written.min(remaining);
            let result = result.map_err(|_| Fault::Malformed)?;
            if written > remaining {
                return Err(Fault::Malformed);
            }
            let first_filter = (row - produced % row) % row;
            if (first_filter..written).step_by(row).any(|i| chunk[i] > 4) {
                return Err(Fault::Malformed);
            }
            if result == flate2::Status::StreamEnd {
                return if produced + written == expected
                    && decoder.total_in() as usize == bytes.len()
                {
                    Ok(())
                } else {
                    Err(Fault::Malformed)
                };
            }
            if decoder.total_in() == before_in && written == 0 {
                return Err(Fault::Malformed);
            }
        }
    }
    fn jpeg(&mut self, b: &[u8], index: usize) -> ParseResult<(usize, u32)> {
        self.jpeg_inner(b, index, None)
    }
    fn jpeg_inner(
        &mut self,
        b: &[u8],
        index: usize,
        declared: Option<[usize; 4]>,
    ) -> ParseResult<(usize, u32)> {
        if !b.starts_with(b"\xff\xd8") {
            return Err(Fault::Malformed);
        }
        let mut p = 2;
        let mut frame = false;
        let mut scan = false;
        loop {
            self.node()?;
            if slice(b, p, 1)? != b"\xff" {
                return Err(Fault::Malformed);
            }
            while b.get(p) == Some(&255) {
                p += 1;
            }
            let marker = *b.get(p).ok_or(Fault::Malformed)?;
            p += 1;
            if marker == 0xd9 {
                return if frame && scan {
                    Ok((p, 1))
                } else {
                    Err(Fault::Malformed)
                };
            }
            if marker == 0 || marker == 0xd8 || (0xd0..=0xd7).contains(&marker) {
                return Err(Fault::Malformed);
            }
            if marker == 1 {
                continue;
            }
            let len = be16(b, p)? as usize;
            if len < 2 {
                return Err(Fault::Malformed);
            }
            let data = slice(b, p + 2, len - 2)?;
            p += len;
            if (0xc0..=0xcf).contains(&marker) && ![0xc4, 0xc8, 0xcc].contains(&marker) {
                if frame || data.len() < 6 {
                    return Err(Fault::Malformed);
                }
                if !matches!(marker, 0xc0..=0xc2) {
                    return Err(Fault::Unsupported);
                }
                let n = data[5] as usize;
                if n == 0 || n > 4 || data.len() != 6 + 3 * n || ![8, 12].contains(&data[0]) {
                    return Err(Fault::Malformed);
                }
                let w = u32::from(be16(data, 3)?);
                let h = u32::from(be16(data, 1)?);
                if let Some(expected) = declared {
                    if w == 0 || h == 0 || expected != [w as usize, h as usize, data[0] as usize, n]
                    {
                        return Err(Fault::Malformed);
                    }
                    // PDF image dimensions are observations of embedded images,
                    // not dimensions of the containing PDF MIME part.
                    if u64::from(w) * u64::from(h) > self.s.max_image_pixels {
                        self.finding(FindingId::ImageDimensions, Some(index));
                    }
                } else {
                    self.dimensions(w, h, index)?;
                }
                frame = true;
            }
            if marker == 0xda {
                if !frame
                    || data.is_empty()
                    || data[0] == 0
                    || data[0] > 4
                    || data.len() != 4 + 2 * data[0] as usize
                {
                    return Err(Fault::Malformed);
                }
                scan = true;
                loop {
                    let byte = *b.get(p).ok_or(Fault::Malformed)?;
                    if byte != 255 {
                        p += 1;
                        continue;
                    }
                    let start = p;
                    p += 1;
                    while b.get(p) == Some(&255) {
                        p += 1;
                    }
                    let next = *b.get(p).ok_or(Fault::Malformed)?;
                    if next == 0 || (0xd0..=0xd7).contains(&next) {
                        p += 1;
                    } else {
                        p = start;
                        break;
                    }
                }
            }
        }
    }
    fn gif_blocks(&mut self, b: &[u8], p: &mut usize) -> ParseResult<usize> {
        let mut total = 0;
        loop {
            self.node()?;
            let n = *b.get(*p).ok_or(Fault::Malformed)? as usize;
            *p += 1;
            if n == 0 {
                return Ok(total);
            }
            slice(b, *p, n)?;
            *p += n;
            total += n;
        }
    }
    fn gif(&mut self, b: &[u8], index: usize) -> ParseResult<(usize, u32)> {
        if !b.starts_with(b"GIF87a") && !b.starts_with(b"GIF89a") {
            return Err(Fault::Malformed);
        }
        let w = le16(b, 6)? as u32;
        let h = le16(b, 8)? as u32;
        self.dimensions(w, h, index)?;
        let header = slice(b, 0, 13)?;
        let mut p = 13;
        let mut frames = 0;
        let global = header[10] & 0x80 != 0;
        if global {
            let n = 3usize << ((header[10] & 7) + 1);
            slice(b, p, n)?;
            p += n;
        }
        loop {
            self.node()?;
            let tag = *b.get(p).ok_or(Fault::Malformed)?;
            p += 1;
            match tag {
                0x3b => {
                    return if frames > 0 {
                        Ok((p, frames))
                    } else {
                        Err(Fault::Malformed)
                    };
                }
                0x21 => {
                    slice(b, p, 1)?;
                    p += 1;
                    self.gif_blocks(b, &mut p)?;
                }
                0x2c => {
                    let d = slice(b, p, 9)?;
                    p += 9;
                    let x = le16(d, 0)? as u32;
                    let y = le16(d, 2)? as u32;
                    let fw = le16(d, 4)? as u32;
                    let fh = le16(d, 6)? as u32;
                    if fw == 0 || fh == 0 || x + fw > w || y + fh > h {
                        return Err(Fault::Malformed);
                    }
                    if d[8] & 0x80 != 0 {
                        let n = 3usize << ((d[8] & 7) + 1);
                        slice(b, p, n)?;
                        p += n;
                    } else if !global {
                        return Err(Fault::Malformed);
                    }
                    let code = *b.get(p).ok_or(Fault::Malformed)?;
                    p += 1;
                    if !(2..=8).contains(&code) || self.gif_blocks(b, &mut p)? == 0 {
                        return Err(Fault::Malformed);
                    }
                    frames += 1;
                }
                _ => return Err(Fault::Malformed),
            }
        }
    }
}

// PDF lexical/object grammar. Strings/comments/stream payloads never become name tokens.
#[derive(Debug)]
enum PdfValue {
    Name(Vec<u8>),
    Int(i64),
    Bool(bool),
    Null,
    Scalar,
    Reference,
    Array(Vec<PdfValue>),
    Dict(Vec<(Vec<u8>, PdfValue)>),
}
impl PdfValue {
    fn get(&self, key: &[u8]) -> Option<&Self> {
        if let Self::Dict(items) = self {
            items.iter().find(|(k, _)| k == key).map(|(_, v)| v)
        } else {
            None
        }
    }
    fn number(&self) -> Option<usize> {
        if let Self::Int(v) = self {
            usize::try_from(*v).ok()
        } else {
            None
        }
    }
    fn name_is(&self, s: &[u8]) -> bool {
        matches!(self, Self::Name(n) if n == s)
    }
    fn filter_is(&self, s: &[u8]) -> bool {
        self.name_is(s) || matches!(self, Self::Array(a) if a.len() == 1 && a[0].name_is(s))
    }
}
struct PdfParser<'a> {
    b: &'a [u8],
    p: usize,
}
fn pdf_space(b: u8) -> bool {
    matches!(b, 0 | 9 | 10 | 12 | 13 | 32)
}
fn pdf_delim(b: u8) -> bool {
    pdf_space(b) || b"()<>[]{}/%".contains(&b)
}
impl<'a> PdfParser<'a> {
    fn ws(&mut self) {
        loop {
            while self.b.get(self.p).is_some_and(|b| pdf_space(*b)) {
                self.p += 1;
            }
            if self.b.get(self.p) != Some(&b'%') {
                return;
            }
            while self
                .b
                .get(self.p)
                .is_some_and(|b| !matches!(b, b'\r' | b'\n'))
            {
                self.p += 1;
            }
        }
    }
    fn word(&mut self) -> ParseResult<&'a [u8]> {
        self.ws();
        let start = self.p;
        while self.b.get(self.p).is_some_and(|b| !pdf_delim(*b)) {
            self.p += 1;
        }
        if start == self.p {
            Err(Fault::Malformed)
        } else {
            Ok(&self.b[start..self.p])
        }
    }
    fn expect(&mut self, word: &[u8]) -> ParseResult<()> {
        if self.word()? == word {
            Ok(())
        } else {
            Err(Fault::Malformed)
        }
    }
    fn uint(&mut self) -> ParseResult<usize> {
        let w = self.word()?;
        if w.is_empty() || !w.iter().all(u8::is_ascii_digit) {
            return Err(Fault::Malformed);
        }
        std::str::from_utf8(w)
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or(Fault::Malformed)
    }
    fn name(&mut self) -> ParseResult<Vec<u8>> {
        if self.b.get(self.p) != Some(&b'/') {
            return Err(Fault::Malformed);
        }
        self.p += 1;
        let mut name = Vec::new();
        while let Some(&b) = self.b.get(self.p) {
            if pdf_delim(b) {
                break;
            }
            self.p += 1;
            if name.len() == 256 {
                return Err(Fault::Limit);
            }
            if b == b'#' {
                let h = self
                    .b
                    .get(self.p)
                    .and_then(|b| hex_digit(*b))
                    .ok_or(Fault::Malformed)?;
                let l = self
                    .b
                    .get(self.p + 1)
                    .and_then(|b| hex_digit(*b))
                    .ok_or(Fault::Malformed)?;
                if h == 0 && l == 0 {
                    return Err(Fault::Malformed);
                }
                name.push(h * 16 + l);
                self.p += 2;
            } else {
                name.push(b);
            }
        }
        Ok(name)
    }
    fn value(&mut self, c: &mut Inspection<'_>, depth: usize) -> ParseResult<PdfValue> {
        c.node()?;
        if depth > c.s.max_nesting {
            return Err(Fault::Limit);
        }
        self.ws();
        match self.b.get(self.p).copied().ok_or(Fault::Malformed)? {
            b'/' => Ok(PdfValue::Name(self.name()?)),
            b'(' => {
                self.p += 1;
                let mut nesting = 1;
                while nesting != 0 {
                    let b = *self.b.get(self.p).ok_or(Fault::Malformed)?;
                    self.p += 1;
                    match b {
                        b'\\' => {
                            self.b.get(self.p).ok_or(Fault::Malformed)?;
                            self.p += 1;
                        }
                        b'(' => {
                            nesting += 1;
                            if nesting > c.s.max_nesting {
                                return Err(Fault::Limit);
                            }
                        }
                        b')' => nesting -= 1,
                        _ => (),
                    }
                }
                Ok(PdfValue::Scalar)
            }
            b'<' if self.b.get(self.p + 1) == Some(&b'<') => {
                self.p += 2;
                let mut items = Vec::new();
                let mut keys = BTreeSet::new();
                loop {
                    self.ws();
                    if self.b.get(self.p..self.p + 2) == Some(b">>") {
                        self.p += 2;
                        return Ok(PdfValue::Dict(items));
                    }
                    let key = self.name()?;
                    if !keys.insert(key.clone()) {
                        return Err(Fault::Malformed);
                    }
                    let v = self.value(c, depth + 1)?;
                    items.push((key, v));
                }
            }
            b'<' => {
                self.p += 1;
                loop {
                    let b = *self.b.get(self.p).ok_or(Fault::Malformed)?;
                    self.p += 1;
                    if b == b'>' {
                        break;
                    }
                    if !pdf_space(b) && hex_digit(b).is_none() {
                        return Err(Fault::Malformed);
                    }
                }
                Ok(PdfValue::Scalar)
            }
            b'[' => {
                self.p += 1;
                let mut items = Vec::new();
                loop {
                    self.ws();
                    if self.b.get(self.p) == Some(&b']') {
                        self.p += 1;
                        return Ok(PdfValue::Array(items));
                    }
                    items.push(self.value(c, depth + 1)?);
                }
            }
            _ => {
                let token = self.word()?;
                match token {
                    b"true" => return Ok(PdfValue::Bool(true)),
                    b"false" => return Ok(PdfValue::Bool(false)),
                    b"null" => return Ok(PdfValue::Null),
                    _ => (),
                }
                let s = std::str::from_utf8(token).map_err(|_| Fault::Malformed)?;
                let digits = s.strip_prefix(['+', '-']).unwrap_or(s);
                if digits.is_empty()
                    || !digits.bytes().all(|b| b.is_ascii_digit() || b == b'.')
                    || digits.bytes().filter(|b| *b == b'.').count() > 1
                    || !digits.bytes().any(|b| b.is_ascii_digit())
                {
                    return Err(Fault::Malformed);
                }
                if digits.contains('.') {
                    return Ok(PdfValue::Scalar);
                }
                let n: i64 = s.parse().map_err(|_| Fault::Malformed)?;
                let save = self.p;
                if n >= 0 && self.uint().is_ok() && self.word().is_ok_and(|v| v == b"R") {
                    return Ok(PdfValue::Reference);
                }
                self.p = save;
                Ok(PdfValue::Int(n))
            }
        }
    }
}
impl Inspection<'_> {
    fn pdf(&mut self, bytes: &[u8], index: usize) {
        self.r.stats.pdfs += 1;
        if let Err(e) = self.pdf_inner(bytes, index) {
            self.incomplete(
                match e {
                    Fault::Malformed => FindingId::PdfMalformed,
                    Fault::Limit => FindingId::StructureLimit,
                    Fault::Unsupported => FindingId::PdfUnsupportedStructure,
                },
                Some(index),
                e == Fault::Limit,
            );
        }
    }
    fn pdf_names(&mut self, v: &PdfValue, index: usize) {
        match v {
            PdfValue::Name(n) => self.pdf_name(n, index),
            PdfValue::Array(a) => {
                for v in a {
                    self.pdf_names(v, index);
                }
            }
            PdfValue::Dict(d) => {
                for (k, v) in d {
                    self.pdf_name(k, index);
                    self.pdf_names(v, index);
                }
            }
            _ => (),
        }
    }
    fn pdf_name(&mut self, n: &[u8], index: usize) {
        if matches!(
            n,
            b"JavaScript"
                | b"JS"
                | b"AA"
                | b"OpenAction"
                | b"Launch"
                | b"RichMedia"
                | b"XFA"
                | b"SubmitForm"
                | b"ImportData"
                | b"Rendition"
                | b"Movie"
                | b"Sound"
        ) {
            self.finding(FindingId::PdfActiveName, Some(index));
        }
        if matches!(n, b"EmbeddedFile" | b"EmbeddedFiles" | b"EF") {
            self.incomplete(FindingId::PdfEmbeddedFile, Some(index), false);
        }
        if matches!(n, b"URI" | b"GoToR" | b"GoToE") {
            self.finding(FindingId::PdfExternalReference, Some(index));
        }
        if n == b"Encrypt" {
            self.incomplete(FindingId::PdfEncrypted, Some(index), false);
        }
    }
    fn pdf_inner(&mut self, b: &[u8], index: usize) -> ParseResult<()> {
        if !matches!(b.get(8), Some(b'\n' | b'\r'))
            || !b.starts_with(b"%PDF-")
            || !matches!(
                slice(b, 5, 3)?,
                b"1.0" | b"1.1" | b"1.2" | b"1.3" | b"1.4" | b"1.5" | b"1.6" | b"1.7" | b"2.0"
            )
        {
            return Err(Fault::Malformed);
        }
        if !b.trim_ascii_end().ends_with(b"%%EOF") {
            self.incomplete(FindingId::PdfMalformed, Some(index), false);
        }
        let mut p = PdfParser { b, p: 0 };
        let mut objects = 0;
        let mut trailer = false;
        let mut startxref = false;
        loop {
            p.ws();
            if p.p == b.len() {
                break;
            }
            self.node()?;
            let save = p.p;
            let word = p.word()?;
            match word {
                b"xref" => {
                    loop {
                        p.ws();
                        let save = p.p;
                        if p.word()? == b"trailer" {
                            break;
                        }
                        p.p = save;
                        let _first = p.uint()?;
                        let count = p.uint()?;
                        if count
                            > self
                                .s
                                .max_structure_nodes
                                .saturating_sub(self.r.stats.structure_nodes)
                        {
                            return Err(Fault::Limit);
                        }
                        for _ in 0..count {
                            self.node()?;
                            let offset = p.uint()?;
                            let generation = p.uint()?;
                            let state = p.word()?;
                            if generation > 65535
                                || !matches!(state, b"n" | b"f")
                                || state == b"n" && offset >= b.len()
                            {
                                return Err(Fault::Malformed);
                            }
                        }
                    }
                    let v = p.value(self, 0)?;
                    if !matches!(v, PdfValue::Dict(_)) {
                        return Err(Fault::Malformed);
                    }
                    self.pdf_names(&v, index);
                    trailer = true;
                }
                b"trailer" => {
                    let v = p.value(self, 0)?;
                    if !matches!(v, PdfValue::Dict(_)) {
                        return Err(Fault::Malformed);
                    }
                    self.pdf_names(&v, index);
                    trailer = true;
                }
                b"startxref" => {
                    if p.uint()? >= b.len() {
                        return Err(Fault::Malformed);
                    }
                    startxref = true;
                }
                _ => {
                    p.p = save;
                    let id = p.uint()?;
                    let generation = p.uint()?;
                    p.expect(b"obj")?;
                    if id == 0 || generation > 65535 {
                        return Err(Fault::Malformed);
                    }
                    objects += 1;
                    let v = p.value(self, 0)?;
                    self.pdf_names(&v, index);
                    if v.get(b"Type").is_some_and(|v| v.name_is(b"XRef")) {
                        trailer = true;
                    }
                    p.ws();
                    let after = p.word()?;
                    if after == b"stream" {
                        if !matches!(v, PdfValue::Dict(_)) {
                            return Err(Fault::Malformed);
                        }
                        // Delimit by declared direct length; never search binary data for endstream.
                        let len = v
                            .get(b"Length")
                            .and_then(PdfValue::number)
                            .ok_or(Fault::Unsupported)?;
                        if b.get(p.p..p.p + 2) == Some(b"\r\n") {
                            p.p += 2;
                        } else if b.get(p.p) == Some(&b'\n') {
                            p.p += 1;
                        } else {
                            return Err(Fault::Malformed);
                        }
                        let stream = slice(b, p.p, len)?;
                        p.p += len;
                        p.expect(b"endstream")?;
                        let object_stream = v.get(b"Type").is_some_and(|v| v.name_is(b"ObjStm"));
                        if v.get(b"F").is_some() {
                            self.incomplete(FindingId::PdfExternalReference, Some(index), false);
                        }
                        let filter = v.get(b"Filter");
                        let flate = filter
                            .is_some_and(|v| v.filter_is(b"FlateDecode") || v.filter_is(b"Fl"));
                        let dct = filter
                            .is_some_and(|v| v.filter_is(b"DCTDecode") || v.filter_is(b"DCT"));
                        if dct {
                            match self.pdf_jpeg(stream, &v, index) {
                                Ok(()) => (),
                                Err(Fault::Unsupported) => self.incomplete(
                                    FindingId::PdfUnsupportedFilter,
                                    Some(index),
                                    false,
                                ),
                                Err(e) => return Err(e),
                            }
                        } else if filter.is_some_and(|v| !matches!(v, PdfValue::Null)) && !flate {
                            self.incomplete(FindingId::PdfUnsupportedFilter, Some(index), false);
                        } else if object_stream {
                            if v.get(b"DecodeParms").is_some() {
                                self.incomplete(
                                    FindingId::PdfUnsupportedFilter,
                                    Some(index),
                                    false,
                                );
                            } else {
                                let decoded = if flate {
                                    match self.inflate(stream, true) {
                                        Ok(d) => Cow::Owned(d),
                                        Err(Fault::Limit) => {
                                            self.incomplete(
                                                FindingId::DecompressionLimit,
                                                Some(index),
                                                true,
                                            );
                                            p.expect(b"endobj")?;
                                            continue;
                                        }
                                        Err(e) => return Err(e),
                                    }
                                } else {
                                    Cow::Borrowed(stream)
                                };
                                self.pdf_object_stream(&decoded, &v, index)?;
                            }
                        }
                        p.expect(b"endobj")?;
                    } else if after != b"endobj" {
                        return Err(Fault::Malformed);
                    }
                }
            }
        }
        if objects == 0 || !trailer || !startxref {
            return Err(Fault::Malformed);
        }
        Ok(())
    }
    /// Inspect JPEG framing in a declared image XObject. This never treats a
    /// compressed object/content stream as an image or decodes image pixels.
    fn pdf_jpeg(&mut self, data: &[u8], dict: &PdfValue, index: usize) -> ParseResult<()> {
        if !dict.get(b"Subtype").is_some_and(|v| v.name_is(b"Image"))
            || dict.get(b"Type").is_some_and(|v| !v.name_is(b"XObject"))
            || dict
                .get(b"ImageMask")
                .is_some_and(|v| !matches!(v, PdfValue::Bool(false)))
        {
            return Err(Fault::Unsupported);
        }
        let components = match dict.get(b"ColorSpace") {
            Some(v) if v.name_is(b"DeviceGray") => 1,
            Some(v) if v.name_is(b"DeviceRGB") => 3,
            Some(v) if v.name_is(b"DeviceCMYK") => 4,
            _ => return Err(Fault::Unsupported),
        };
        if let Some(params) = dict.get(b"DecodeParms") {
            let params = match params {
                PdfValue::Array(a) if a.len() == 1 => &a[0],
                v => v,
            };
            match params {
                PdfValue::Null => (),
                PdfValue::Dict(items)
                    if items.iter().all(|(key, value)| {
                        key == b"ColorTransform" && matches!(value, PdfValue::Int(0 | 1))
                    }) => {}
                _ => return Err(Fault::Unsupported),
            }
        }
        let declared = [
            dict.get(b"Width")
                .and_then(PdfValue::number)
                .ok_or(Fault::Unsupported)?,
            dict.get(b"Height")
                .and_then(PdfValue::number)
                .ok_or(Fault::Unsupported)?,
            dict.get(b"BitsPerComponent")
                .and_then(PdfValue::number)
                .ok_or(Fault::Unsupported)?,
            components,
        ];
        let (end, _) = self.jpeg_inner(data, index, Some(declared))?;
        if end != data.len() {
            return Err(Fault::Malformed);
        }
        Ok(())
    }
    fn pdf_object_stream(&mut self, data: &[u8], dict: &PdfValue, index: usize) -> ParseResult<()> {
        let first = dict
            .get(b"First")
            .and_then(PdfValue::number)
            .ok_or(Fault::Malformed)?;
        let n = dict
            .get(b"N")
            .and_then(PdfValue::number)
            .ok_or(Fault::Malformed)?;
        if n > self
            .s
            .max_structure_nodes
            .saturating_sub(self.r.stats.structure_nodes)
        {
            return Err(Fault::Limit);
        }
        let mut header = PdfParser {
            b: slice(data, 0, first)?,
            p: 0,
        };
        let mut offsets = Vec::new();
        let mut ids = BTreeSet::new();
        for _ in 0..n {
            self.node()?;
            let id = header.uint()?;
            let offset = header.uint()?;
            if id == 0 || !ids.insert(id) || offsets.last().is_some_and(|last| *last >= offset) {
                return Err(Fault::Malformed);
            }
            offsets.push(offset);
        }
        header.ws();
        if header.p != first {
            return Err(Fault::Malformed);
        }
        for (i, offset) in offsets.iter().enumerate() {
            let end = offsets
                .get(i + 1)
                .copied()
                .unwrap_or(data.len().checked_sub(first).ok_or(Fault::Malformed)?);
            let start = first.checked_add(*offset).ok_or(Fault::Malformed)?;
            let len = end.checked_sub(*offset).ok_or(Fault::Malformed)?;
            let mut p = PdfParser {
                b: slice(data, start, len)?,
                p: 0,
            };
            let v = p.value(self, 0)?;
            self.pdf_names(&v, index);
            p.ws();
            if p.p != p.b.len() {
                return Err(Fault::Malformed);
            }
        }
        Ok(())
    }
}

struct ZipMeta {
    name: String,
    compressed: usize,
    size: usize,
    data: usize,
    method: u16,
    crc: u32,
}
impl Inspection<'_> {
    fn zip_directory(&mut self, b: &[u8], index: usize) -> ParseResult<Vec<ZipMeta>> {
        let lower = b.len().saturating_sub(65535 + 22);
        let end = (lower..b.len().saturating_sub(21))
            .rev()
            .find(|&p| {
                b.get(p..p + 4) == Some(b"PK\x05\x06")
                    && le16(b, p + 20).is_ok_and(|n| p + 22 + n as usize == b.len())
            })
            .ok_or(Fault::Malformed)?;
        if le16(b, end + 4)? != 0
            || le16(b, end + 6)? != 0
            || le16(b, end + 8)? != le16(b, end + 10)?
        {
            return Err(Fault::Unsupported);
        }
        let count = le16(b, end + 10)? as usize;
        if count == 65535 {
            return Err(Fault::Unsupported);
        }
        if count > self.s.max_archive_entries {
            self.incomplete(FindingId::ArchiveEntryLimit, Some(index), true);
            return Err(Fault::Limit);
        }
        let size = le32(b, end + 12)? as usize;
        let start = le32(b, end + 16)? as usize;
        if start.checked_add(size) != Some(end) {
            return Err(Fault::Malformed);
        }
        let mut p = start;
        let mut result = Vec::new();
        let mut names = BTreeSet::new();
        let mut spans = Vec::new();
        for _ in 0..count {
            self.node()?;
            if slice(b, p, 4)? != b"PK\x01\x02" {
                return Err(Fault::Malformed);
            }
            let flags = le16(b, p + 8)?;
            let method = le16(b, p + 10)?;
            let crc = le32(b, p + 16)?;
            let compressed = le32(b, p + 20)? as usize;
            let size = le32(b, p + 24)? as usize;
            let namelen = le16(b, p + 28)? as usize;
            let extra = le16(b, p + 30)? as usize;
            let comment = le16(b, p + 32)? as usize;
            if namelen == 0 || namelen > 512 || extra > 4096 {
                return Err(Fault::Limit);
            }
            if le16(b, p + 34)? != 0 || compressed == u32::MAX as usize || size == u32::MAX as usize
            {
                return Err(Fault::Unsupported);
            }
            let local = le32(b, p + 42)? as usize;
            let name = slice(b, p + 46, namelen)?;
            let name_str = std::str::from_utf8(name).map_err(|_| Fault::Unsupported)?;
            let normalized = name_str.to_ascii_lowercase();
            if normalized.contains(['\\', '\0', '%'])
                || normalized.starts_with('/')
                || normalized.split('/').any(|s| s == "." || s == "..")
                || !names.insert(normalized)
            {
                self.incomplete(FindingId::ArchiveAmbiguous, Some(index), false);
                return Err(Fault::Unsupported);
            }
            let mut ep = p + 46 + namelen;
            let extra_end = ep + extra;
            while ep < extra_end {
                if ep + 4 > extra_end {
                    return Err(Fault::Malformed);
                }
                if le16(b, ep)? == 1 {
                    return Err(Fault::Unsupported);
                } // ZIP64
                ep += 4 + le16(b, ep + 2)? as usize;
                if ep > extra_end {
                    return Err(Fault::Malformed);
                }
            }
            p += 46 + namelen + extra + comment;
            if p > end {
                return Err(Fault::Malformed);
            }
            if flags & (1 | 64) != 0 {
                self.incomplete(FindingId::ArchiveEncrypted, Some(index), false);
                return Err(Fault::Unsupported);
            }
            if flags & !(0x800 | 8 | 6) != 0 || !matches!(method, 0 | 8) {
                return Err(Fault::Unsupported);
            }
            if slice(b, local, 4)? != b"PK\x03\x04"
                || le16(b, local + 6)? != flags
                || le16(b, local + 8)? != method
                || le16(b, local + 26)? as usize != namelen
            {
                return Err(Fault::Malformed);
            }
            if slice(b, local + 30, namelen)? != name {
                self.incomplete(FindingId::ArchiveAmbiguous, Some(index), false);
                return Err(Fault::Malformed);
            }
            if flags & 8 == 0
                && (le32(b, local + 14)? != crc
                    || le32(b, local + 18)? as usize != compressed
                    || le32(b, local + 22)? as usize != size)
            {
                return Err(Fault::Malformed);
            }
            let local_extra = le16(b, local + 28)? as usize;
            if local_extra > 4096 {
                return Err(Fault::Limit);
            }
            let data = local
                .checked_add(30 + namelen + local_extra)
                .ok_or(Fault::Malformed)?;
            let mut stop = data.checked_add(compressed).ok_or(Fault::Malformed)?;
            if flags & 8 != 0 {
                if slice(b, stop, 4)? == b"PK\x07\x08" {
                    stop += 4;
                }
                if le32(b, stop)? != crc
                    || le32(b, stop + 4)? as usize != compressed
                    || le32(b, stop + 8)? as usize != size
                {
                    return Err(Fault::Malformed);
                }
                stop += 12;
            }
            if stop > start {
                return Err(Fault::Malformed);
            }
            if method == 0 && compressed != size {
                return Err(Fault::Malformed);
            }
            spans.push((local, stop));
            result.push(ZipMeta {
                name: name_str.into(),
                compressed,
                size,
                data,
                method,
                crc,
            });
        }
        if p != end {
            return Err(Fault::Malformed);
        }
        spans.sort_unstable();
        let mut previous = 0;
        for (start, end) in spans {
            if start != previous {
                self.incomplete(FindingId::ArchiveAmbiguous, Some(index), false);
                return Err(Fault::Malformed);
            }
            previous = end;
        }
        if previous != start {
            return Err(Fault::Malformed);
        }
        Ok(result)
    }
    fn office_zip(&mut self, b: &[u8], index: usize) {
        let result = self.office_zip_inner(b, index);
        if let Err(e) = result {
            self.incomplete(
                match e {
                    Fault::Malformed => FindingId::ArchiveMalformed,
                    Fault::Limit => FindingId::DecompressionLimit,
                    Fault::Unsupported => FindingId::ArchiveUnsupported,
                },
                Some(index),
                e == Fault::Limit,
            );
        }
    }
    fn office_zip_inner(&mut self, b: &[u8], index: usize) -> ParseResult<()> {
        // Preflight actual central records and local extents BEFORE ZipArchive allocates.
        let entries = self.zip_directory(b, index)?;
        let office = entries
            .iter()
            .any(|e| e.name.eq_ignore_ascii_case("[Content_Types].xml"));
        if office {
            self.r.stats.office_documents += 1;
        } else {
            self.incomplete(FindingId::ArchiveUnsupported, Some(index), false);
        }
        let mut archive = zip::ZipArchive::new(Cursor::new(b)).map_err(|_| Fault::Malformed)?;
        if archive.len() != entries.len() {
            return Err(Fault::Malformed);
        }
        for (i, entry) in entries.iter().enumerate() {
            let f = archive.by_index_raw(i).map_err(|_| Fault::Malformed)?;
            if f.name_raw() != entry.name.as_bytes()
                || f.size() != entry.size as u64
                || f.compressed_size() != entry.compressed as u64
            {
                return Err(Fault::Malformed);
            }
            let cap = self.unpack_cap(entry.compressed);
            if entry.size > cap {
                self.incomplete(FindingId::DecompressionLimit, Some(index), true);
                continue;
            }
            let compressed = slice(b, entry.data, entry.compressed)?;
            let output = if entry.method == 8 {
                self.inflate(compressed, false)?
            } else {
                self.r.stats.unpacked_bytes += compressed.len();
                compressed.to_vec()
            };
            if output.len() != entry.size || crc32fast::hash(&output) != entry.crc {
                return Err(Fault::Malformed);
            }
            let lower = entry.name.to_ascii_lowercase();
            if lower.ends_with("vbaproject.bin") {
                self.finding(FindingId::OfficeVbaProject, Some(index));
                self.compound(&output, index);
            } else if lower == "[content_types].xml" || lower.ends_with(".rels") {
                self.office_xml(
                    &output,
                    index,
                    if lower == "[content_types].xml" {
                        "Types"
                    } else {
                        "Relationships"
                    },
                );
            } else if lower.starts_with("xl/macrosheets/")
                || lower.starts_with("xl/intlmacrosheets/")
            {
                self.finding(FindingId::OfficeXlmMacros, Some(index));
            } else if lower.contains("/embeddings/") {
                self.incomplete(FindingId::OfficeEmbeddedObject, Some(index), false);
            } else if lower.ends_with(".bin") {
                self.incomplete(FindingId::OfficeLegacyCoverage, Some(index), false);
            } else if sniff(&output) == Some(ContentKind::OfficeZip) {
                self.incomplete(FindingId::ArchiveUnsupported, Some(index), false);
            }
        }
        Ok(())
    }
    fn office_xml(&mut self, b: &[u8], index: usize, root: &str) {
        if let Err(e) = self.office_xml_inner(b, index, root) {
            self.incomplete(
                match e {
                    Fault::Malformed => FindingId::OfficeMalformedXml,
                    Fault::Limit => FindingId::StructureLimit,
                    Fault::Unsupported => FindingId::OfficeUnsupportedXml,
                },
                Some(index),
                e == Fault::Limit,
            );
        }
    }
    fn office_xml_inner(&mut self, b: &[u8], index: usize, root: &str) -> ParseResult<()> {
        use quick_xml::events::Event;
        let text = std::str::from_utf8(b).map_err(|_| Fault::Unsupported)?;
        let mut reader = quick_xml::NsReader::from_str(text);
        let expected_namespace = if root == "Types" {
            "http://schemas.openxmlformats.org/package/2006/content-types"
        } else {
            "http://schemas.openxmlformats.org/package/2006/relationships"
        };
        reader.config_mut().check_comments = true;
        let mut depth: usize = 0;
        let mut roots = 0;
        let mut xml_version = quick_xml::XmlVersion::Implicit1_0;
        let mut declaration = false;
        loop {
            self.node()?;
            let (namespace, event) = reader.read_resolved_event().map_err(|_| Fault::Malformed)?;
            match event {
                Event::Start(ref e) | Event::Empty(ref e) => {
                    let is_empty = matches!(event, Event::Empty(_));
                    if !matches!(namespace,quick_xml::name::ResolveResult::Bound(ns) if ns.as_ref() == expected_namespace)
                    {
                        self.incomplete(FindingId::OfficeUnsupportedXml, Some(index), false);
                    }
                    if depth == 0 {
                        roots += 1;
                        if roots > 1 || e.local_name().as_ref() != root {
                            return Err(Fault::Malformed);
                        }
                    }
                    if !is_empty {
                        depth += 1;
                        if depth > self.s.max_nesting {
                            return Err(Fault::Limit);
                        }
                    }
                    let name = e.local_name();
                    for a in e.attributes() {
                        let a = a.map_err(|_| Fault::Malformed)?;
                        let value = a
                            .normalized_value(xml_version)
                            .map_err(|_| Fault::Malformed)?;
                        let value = value.to_ascii_lowercase();
                        if a.key.as_ref().contains(':') {
                            continue;
                        }
                        let key = a.key.local_name();
                        if key.as_ref() == "ContentType"
                            && matches!(name.as_ref(), "Override" | "Default")
                        {
                            if value.contains("macroenabled") || value.ends_with(".vbaproject") {
                                self.finding(FindingId::OfficeMacroEnabled, Some(index));
                            }
                            if value.contains("macrosheet") {
                                self.finding(FindingId::OfficeXlmMacros, Some(index));
                            }
                        }
                        if name.as_ref() == "Relationship" {
                            if key.as_ref() == "TargetMode" && value == "external" {
                                self.finding(FindingId::OfficeExternalRelationship, Some(index));
                            }
                            if key.as_ref() == "Type" {
                                if value.ends_with("/vbaproject") {
                                    self.finding(FindingId::OfficeVbaProject, Some(index));
                                }
                                if value.ends_with("/oleobject") || value.ends_with("/package") {
                                    self.incomplete(
                                        FindingId::OfficeEmbeddedObject,
                                        Some(index),
                                        false,
                                    );
                                }
                            }
                        }
                    }
                }
                Event::End(_) => {
                    depth = depth.checked_sub(1).ok_or(Fault::Malformed)?;
                }
                Event::DocType(_) => return Err(Fault::Unsupported), // Never expand DTDs or external entities.
                Event::GeneralRef(_) => return Err(Fault::Unsupported),
                Event::Decl(d) => {
                    if declaration || roots != 0 {
                        return Err(Fault::Malformed);
                    }
                    declaration = true;
                    xml_version = quick_xml::XmlVersion::Explicit1_0;
                    if d.version().map_err(|_| Fault::Malformed)?.as_ref() != "1.0" {
                        return Err(Fault::Unsupported);
                    }
                    if let Some(enc) = d.encoding() {
                        let enc = enc.map_err(|_| Fault::Malformed)?;
                        if !enc.eq_ignore_ascii_case("utf-8")
                            && !enc.eq_ignore_ascii_case("us-ascii")
                        {
                            return Err(Fault::Unsupported);
                        }
                    }
                }
                Event::Text(t)
                    if depth == 0 && !t.as_ref().bytes().all(|b| b.is_ascii_whitespace()) =>
                {
                    return Err(Fault::Malformed);
                }
                Event::CData(_) if depth == 0 => return Err(Fault::Malformed),
                Event::Eof => {
                    return if depth == 0 && roots == 1 {
                        Ok(())
                    } else {
                        Err(Fault::Malformed)
                    };
                }
                _ => (),
            }
        }
    }
    fn compound(&mut self, b: &[u8], index: usize) {
        // Named storage entries are evidence of VBA presence, not proof of execution.
        self.incomplete(FindingId::OfficeLegacyCoverage, Some(index), false);
        if let Err(e) = self.compound_inner(b, index) {
            self.incomplete(
                match e {
                    Fault::Limit => FindingId::CompoundIoLimit,
                    _ => FindingId::CompoundMalformed,
                },
                Some(index),
                e == Fault::Limit,
            );
        }
    }
    fn compound_inner(&mut self, b: &[u8], index: usize) -> ParseResult<()> {
        if !b.starts_with(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") {
            return Err(Fault::Malformed);
        }
        let shift = le16(b, 30)?;
        if !matches!(shift, 9 | 12) {
            return Err(Fault::Malformed);
        }
        let sector = 1usize << shift;
        if b.len() < sector || !b.len().is_multiple_of(sector) {
            return Err(Fault::Malformed);
        }
        // Bound parser reads even if malicious DIFAT entries repeatedly name one sector.
        let exceeded = std::rc::Rc::new(std::cell::Cell::new(false));
        let reader = BoundedReader {
            inner: Cursor::new(b),
            remaining: b.len().saturating_mul(4),
            operations: b.len().saturating_mul(2),
            exceeded: exceeded.clone(),
        };
        let file = cfb::OpenOptions::new()
            .strict()
            .max_buffer_size(8192)
            .open_with(reader)
            .map_err(|_| {
                if exceeded.get() {
                    Fault::Limit
                } else {
                    Fault::Malformed
                }
            })?;
        for (n, entry) in file.walk().enumerate() {
            self.node()?;
            if n >= self.s.max_archive_entries {
                return Err(Fault::Limit);
            }
            if entry.path().components().count() > self.s.max_nesting {
                return Err(Fault::Limit);
            }
            let name = entry.name();
            if name.eq_ignore_ascii_case("VBA")
                || name.eq_ignore_ascii_case("_VBA_PROJECT")
                || name.eq_ignore_ascii_case("_VBA_PROJECT_CUR")
            {
                self.finding(FindingId::OfficeVbaProject, Some(index));
            }
            if name.eq_ignore_ascii_case("EncryptedPackage")
                || name.eq_ignore_ascii_case("EncryptionInfo")
            {
                self.incomplete(FindingId::OfficeEncrypted, Some(index), false);
            }
            if name.eq_ignore_ascii_case("ObjectPool")
                || name.eq_ignore_ascii_case("\u{1}Ole10Native")
            {
                self.incomplete(FindingId::OfficeEmbeddedObject, Some(index), false);
            }
            if entry.is_stream() && entry.len() > b.len() as u64 {
                return Err(Fault::Malformed);
            }
        }
        Ok(())
    }
}
struct BoundedReader<'a> {
    inner: Cursor<&'a [u8]>,
    remaining: usize,
    operations: usize,
    exceeded: std::rc::Rc<std::cell::Cell<bool>>,
}
impl BoundedReader<'_> {
    fn operation(&mut self) -> std::io::Result<()> {
        if self.operations == 0 {
            self.exceeded.set(true);
            return Err(std::io::Error::other("inspection IO budget"));
        }
        self.operations -= 1;
        Ok(())
    }
}
impl Read for BoundedReader<'_> {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        self.operation()?;
        if self.remaining == 0 && !b.is_empty() {
            self.exceeded.set(true);
            return Err(std::io::Error::other("inspection IO budget"));
        }
        let len = b.len().min(self.remaining);
        let n = self.inner.read(&mut b[..len])?;
        self.remaining -= n;
        Ok(n)
    }
}
impl Seek for BoundedReader<'_> {
    fn seek(&mut self, p: SeekFrom) -> std::io::Result<u64> {
        self.operation()?;
        self.inner.seek(p)
    }
}

#[cfg(test)]
#[path = "../tests/content_inspection/cases.rs"]
mod tests;
