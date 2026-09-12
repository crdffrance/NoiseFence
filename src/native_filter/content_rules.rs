//! Local Rust rules inspired by Rspamd's HTML, MIME and header checks.
//! Independent implementation: see docs/rspamd-rules.md for provenance and limits.
use super::rules::{Family, Symbol};
use anyhow::{Result, ensure};
use mail_parser::MimeHeaders;
use scraper::{ElementRef, Html};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};

pub const VERSION: &str = "noisefence-content-rules-1";
pub const UPSTREAM: &str = "e2de26d28ce857d5c48ac82703cf26b681bd1d89";
const HTML_BYTES: usize = 128 * 1024;
const NODES: usize = 8192;
const DEPTH: usize = 64;

#[derive(Clone, Debug, Serialize)]
pub struct Rule {
    pub id: &'static str,
    pub label: &'static str,
    pub weight: f64,
    pub inspiration: &'static str,
}
pub const RULES: &[Rule] = &[
    Rule {
        id: "NF_HTML_PASSWORD_FORM",
        label: "Champ de mot de passe dans un formulaire HTML",
        weight: 0.3,
        inspiration: "rules/html.lua",
    },
    Rule {
        id: "NF_HTML_REMOTE_PASSWORD_FORM",
        label: "Formulaire de mot de passe vers un autre domaine",
        weight: 0.9,
        inspiration: "src/plugins/lua/phishing.lua",
    },
    Rule {
        id: "NF_HTML_INSECURE_PASSWORD_FORM",
        label: "Formulaire de mot de passe transmis en HTTP",
        weight: 0.5,
        inspiration: "rules/html.lua",
    },
    Rule {
        id: "NF_HTML_HIDDEN_TEXT",
        label: "Quantité importante de texte masqué par le HTML ou le style intégré",
        weight: 0.15,
        inspiration: "rules/html.lua:HIDDEN_TEXT",
    },
    Rule {
        id: "NF_HTML_LINK_SCHEME",
        label: "Lien affiché en HTTPS mais dirigé vers HTTP",
        weight: 0.3,
        inspiration: "rules/html.lua:HTTP_TO_HTTPS",
    },
    Rule {
        id: "NF_HTML_DATA_LINK",
        label: "Lien vers du HTML ou un SVG incorporé dans une URL data",
        weight: 0.4,
        inspiration: "src/plugins/lua/phishing.lua",
    },
    Rule {
        id: "NF_HTML_META_REFRESH",
        label: "Redirection HTML automatique vers une URL distante",
        weight: 0.3,
        inspiration: "rules/html.lua",
    },
    Rule {
        id: "NF_MIME_EXECUTABLE_EXTENSION",
        label: "Pièce jointe portant une extension exécutable",
        weight: 0.2,
        inspiration: "src/plugins/lua/mime_types.lua:MIME_BAD_EXTENSION",
    },
    Rule {
        id: "NF_MIME_DOUBLE_EXTENSION",
        label: "Double extension document puis exécutable",
        weight: 0.8,
        inspiration: "src/plugins/lua/mime_types.lua:MIME_DOUBLE_BAD_EXTENSION",
    },
    Rule {
        id: "NF_MIME_EXECUTABLE_DISGUISED",
        label: "Binaire PE ou ELF présenté comme un document ou un média",
        weight: 1.0,
        inspiration: "src/plugins/lua/mime_types.lua",
    },
    Rule {
        id: "NF_MIME_FILENAME_BIDI",
        label: "Nom de pièce jointe contenant un contrôle d’ordre d’affichage",
        weight: 0.3,
        inspiration: "src/plugins/lua/mime_types.lua:MIME_BAD_UNICODE",
    },
    Rule {
        id: "NF_HEADER_DISPLAY_DOMAIN",
        label: "Adresse affichée dans le nom d’expéditeur d’un autre domaine",
        weight: 0.4,
        inspiration: "rules/headers_checks.lua:CHECK_FROM",
    },
];

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub enabled: bool,
    pub disabled: BTreeSet<String>,
    pub weights: BTreeMap<String, f64>,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            enabled: true,
            disabled: BTreeSet::new(),
            weights: BTreeMap::new(),
        }
    }
}
impl Settings {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.disabled
                .iter()
                .chain(self.weights.keys())
                .all(|id| RULES.iter().any(|r| r.id == id)),
            "unknown structured content rule"
        );
        ensure!(
            self.weights
                .values()
                .all(|w| w.is_finite() && (0.0..=2.0).contains(w)),
            "structured rule weights must be finite and within 0..2"
        );
        Ok(())
    }
    pub fn catalog(&self) -> serde_json::Value {
        serde_json::json!({"version":VERSION,"upstream_commit":UPSTREAM,"observation_only":true,
            "rules":RULES.iter().map(|r|serde_json::json!({"id":r.id,"label":r.label,"family":"content",
                "weight":self.weights.get(r.id).copied().unwrap_or(r.weight),
                "enabled":self.enabled && !self.disabled.contains(r.id),"inspiration":r.inspiration})).collect::<Vec<_>>()})
    }
    pub fn inspect(&self, raw: &[u8]) -> Result<Vec<Symbol>> {
        if !self.enabled {
            return Ok(vec![]);
        }
        ensure!(
            raw.len() <= 2 * 1024 * 1024,
            "structured message size limit"
        );
        let mail = mail_parser::MessageParser::default()
            .parse(raw)
            .ok_or_else(|| anyhow::anyhow!("structured MIME unavailable"))?;
        ensure!(mail.parts.len() <= 200, "structured MIME complexity limit");
        let mut found = BTreeSet::new();
        let sender = mail.from().and_then(|a| a.first());
        let sender_domain = sender.and_then(|a| a.address()).and_then(address_domain);
        if let Some(shown) = sender.and_then(|a| a.name()).and_then(address_domain)
            && sender_domain
                .as_ref()
                .is_some_and(|actual| !same_domain(actual, &shown))
        {
            found.insert("NF_HEADER_DISPLAY_DOMAIN");
        }
        let mut bytes = 0;
        for part in mail.html_bodies() {
            let Some(html) = part.text_contents() else {
                continue;
            };
            bytes += html.len();
            ensure!(bytes <= HTML_BYTES, "structured HTML size limit");
            inspect_html(html, sender_domain.as_deref(), &mut found)?;
        }
        for part in mail.attachments() {
            let filename = part.attachment_name().unwrap_or("");
            ensure!(filename.len() <= 4096, "structured filename size limit");
            if filename
                .chars()
                .any(|c| matches!(c, '\u{202d}' | '\u{202e}'))
            {
                found.insert("NF_MIME_FILENAME_BIDI");
            }
            // MIME decoding already handles RFC 2231/2047. Percent escapes are
            // literal filename bytes; do not invent an executable extension.
            let name = filename
                .rsplit(['/', '\\'])
                .next()
                .unwrap_or("")
                .trim_end_matches([' ', '.'])
                .to_ascii_lowercase();
            let mut suffixes = name.rsplit('.');
            let ext = suffixes.next().unwrap_or("");
            let previous = suffixes.next();
            if previous.is_some() && executable(ext) {
                found.insert("NF_MIME_EXECUTABLE_EXTENSION");
                if previous.is_some_and(document_extension) && suffixes.next().is_some() {
                    found.insert("NF_MIME_DOUBLE_EXTENSION");
                }
            }
            let declared_document = part.content_type().is_some_and(|ct| {
                matches!(ct.c_type.as_ref(), "image" | "audio" | "video")
                    || ct.c_type == "text" && ct.c_subtype.as_deref() == Some("plain")
                    || ct.c_type == "application" && ct.c_subtype.as_deref() == Some("pdf")
            });
            if (declared_document || previous.is_some() && document_extension(ext))
                && executable_magic(part.contents())
            {
                found.insert("NF_MIME_EXECUTABLE_DISGUISED");
            }
        }
        Ok(RULES
            .iter()
            .filter(|r| found.contains(r.id) && !self.disabled.contains(r.id))
            .map(|r| Symbol {
                id: r.id.into(),
                label: r.label.into(),
                family: Family::Content,
                weight: self.weights.get(r.id).copied().unwrap_or(r.weight),
                absorbed_by: vec![],
            })
            .collect())
    }
}

fn executable(ext: &str) -> bool {
    matches!(
        ext,
        "exe"
            | "com"
            | "scr"
            | "pif"
            | "bat"
            | "cmd"
            | "hta"
            | "js"
            | "jse"
            | "vbs"
            | "vbe"
            | "wsf"
            | "wsh"
            | "ps1"
            | "lnk"
            | "reg"
            | "msi"
            | "msp"
    )
}
fn document_extension(ext: &str) -> bool {
    matches!(
        ext,
        "pdf"
            | "doc"
            | "docx"
            | "xls"
            | "xlsx"
            | "ppt"
            | "pptx"
            | "txt"
            | "rtf"
            | "csv"
            | "jpg"
            | "jpeg"
            | "png"
            | "gif"
    )
}
fn executable_magic(bytes: &[u8]) -> bool {
    if bytes.len() >= 20
        && bytes.starts_with(b"\x7fELF")
        && matches!(bytes[4], 1 | 2)
        && matches!(bytes[5], 1 | 2)
        && bytes[6] == 1
    {
        let kind = if bytes[5] == 1 {
            u16::from_le_bytes([bytes[16], bytes[17]])
        } else {
            u16::from_be_bytes([bytes[16], bytes[17]])
        };
        if matches!(kind, 2 | 3) {
            return true;
        }
    }
    if bytes.len() < 64 || !bytes.starts_with(b"MZ") {
        return false;
    }
    let offset = u32::from_le_bytes(bytes[60..64].try_into().unwrap()) as usize;
    (64..=4096).contains(&offset) && bytes.get(offset..offset + 4) == Some(b"PE\0\0")
}
fn host(value: &str) -> Option<String> {
    let ascii = idna::domain_to_ascii_strict(value.trim_end_matches('.'))
        .ok()?
        .to_ascii_lowercase();
    crate::config::valid_domain(&ascii).then_some(ascii)
}
fn address_domain(value: &str) -> Option<String> {
    let value = value.trim();
    let (local, domain) = value.rsplit_once('@')?;
    if local.is_empty()
        || local.contains('@')
        || value
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '<' | '>'))
    {
        return None;
    }
    host(domain)
}
fn same_domain(a: &str, b: &str) -> bool {
    // Use registrable domains including PRIVATE PSL entries (e.g. github.io).
    let registered = |s: &str| {
        psl::domain(s.as_bytes())
            .filter(|d| d.suffix().is_known())
            .map(|d| d.as_bytes().to_vec())
    };
    a == b || matches!((registered(a), registered(b)), (Some(a),Some(b)) if a == b)
}
fn url(value: &str) -> Option<reqwest::Url> {
    if value.len() > 4096 {
        return None;
    }
    let url = reqwest::Url::parse(value.trim()).ok()?;
    (matches!(url.scheme(), "https" | "http") && url.host_str().is_some()).then_some(url)
}
fn inert(element: ElementRef<'_>) -> bool {
    element.ancestors().filter_map(ElementRef::wrap).any(|e| {
        matches!(
            e.value().name(),
            "script" | "style" | "template" | "noscript"
        )
    })
}
#[derive(Default)]
struct Visibility {
    subtree_hidden: bool,
    inherited_visibility: Option<bool>,
    inherited_zero_font: Option<bool>,
}
fn visibility(element: ElementRef<'_>) -> Visibility {
    let style = element
        .value()
        .attr("style")
        .unwrap_or("")
        .to_ascii_lowercase();
    let mut properties = BTreeMap::new();
    for (key, value) in style.split(';').filter_map(|s| s.split_once(':')) {
        let key = key.trim();
        if !matches!(key, "display" | "visibility" | "opacity" | "font-size") {
            continue;
        }
        let value = value.trim();
        let important = value.ends_with("!important");
        let value = value.strip_suffix("!important").unwrap_or(value).trim();
        if properties
            .get(key)
            .is_none_or(|(_, prior)| !prior || important)
        {
            properties.insert(key, (value, important));
        }
    }
    let property = |key| properties.get(key).map(|(value, _)| *value);
    Visibility {
        subtree_hidden: property("display")
            .map_or(element.value().attr("hidden").is_some(), |value| {
                value == "none"
            })
            || property("opacity").is_some_and(|value| matches!(value, "0" | "0.0")),
        inherited_visibility: match property("visibility") {
            Some("hidden" | "collapse") => Some(true),
            Some("visible") => Some(false),
            _ => None,
        },
        inherited_zero_font: match property("font-size") {
            Some("0" | "0px" | "0em" | "0pt" | "0%") => Some(true),
            Some("inherit" | "unset") | None => None,
            Some(_) => Some(false),
        },
    }
}
fn inspect_html(
    html: &str,
    sender: Option<&str>,
    found: &mut BTreeSet<&'static str>,
) -> Result<()> {
    let dom = Html::parse_document(html);
    ensure!(
        dom.tree.nodes().count() <= NODES,
        "structured DOM node limit"
    );
    // Check depth once before any ancestor searches or descendant iteration.
    for node in dom.tree.nodes() {
        ensure!(
            node.ancestors().take(DEPTH + 1).count() <= DEPTH,
            "structured DOM depth limit"
        );
    }
    let visibility: HashMap<_, _> = dom
        .tree
        .nodes()
        .filter_map(ElementRef::wrap)
        .map(|e| (e.id(), visibility(e)))
        .collect();
    let mut forms = BTreeMap::new();
    for form in dom
        .tree
        .nodes()
        .filter_map(ElementRef::wrap)
        .filter(|e| e.value().name() == "form" && !inert(*e))
    {
        if let Some(id) = form.value().id() {
            forms
                .entry(id)
                .and_modify(|value| *value = None)
                .or_insert(Some(form));
        }
    }
    let mut concealed = 0;
    let mut visible = 0;
    for node in dom.tree.nodes() {
        if let Some(text) = node.value().as_text() {
            let parents: Vec<_> = node.ancestors().filter_map(ElementRef::wrap).collect();
            if parents.iter().any(|e| {
                matches!(
                    e.value().name(),
                    "head" | "script" | "style" | "template" | "noscript"
                )
            }) {
                continue;
            }
            let count = text
                .chars()
                .filter(|c| {
                    !c.is_whitespace()
                        && !matches!(
                            c,
                            '\u{00ad}' | '\u{034f}' | '\u{200b}'
                                ..='\u{200d}' | '\u{2060}' | '\u{feff}'
                        )
                })
                .count();
            let styles: Vec<_> = parents
                .iter()
                .filter_map(|e| visibility.get(&e.id()))
                .collect();
            if styles.iter().any(|s| s.subtree_hidden)
                || styles
                    .iter()
                    .find_map(|s| s.inherited_visibility)
                    .unwrap_or(false)
                || styles
                    .iter()
                    .find_map(|s| s.inherited_zero_font)
                    .unwrap_or(false)
            {
                concealed += count;
            } else {
                visible += count;
            }
        }
        let Some(e) = ElementRef::wrap(node) else {
            continue;
        };
        if inert(e) {
            continue;
        }
        match e.value().name() {
            "input"
                if e.value().attr("disabled").is_none()
                    && e.value()
                        .attr("type")
                        .is_some_and(|t| t.eq_ignore_ascii_case("password")) =>
            {
                // An explicit form= association can target an element outside
                // the ancestors; resolve only a unique, active form id.
                let form = if let Some(id) = e.value().attr("form") {
                    forms.get(id).copied().flatten()
                } else {
                    e.ancestors()
                        .filter_map(ElementRef::wrap)
                        .find(|f| f.value().name() == "form")
                };
                if let Some(form) = form {
                    found.insert("NF_HTML_PASSWORD_FORM");
                    if let Some(action) = form.value().attr("action").and_then(url) {
                        if action.scheme() == "http" {
                            found.insert("NF_HTML_INSECURE_PASSWORD_FORM");
                        }
                        if let Some(sender) = sender
                            && action
                                .host_str()
                                .is_some_and(|target| !same_domain(sender, target))
                        {
                            found.insert("NF_HTML_REMOTE_PASSWORD_FORM");
                        }
                    }
                }
            }
            "a" | "area" => {
                let Some(href) = e.value().attr("href") else {
                    continue;
                };
                if let Some(target) = url(href)
                    && target.scheme() == "http"
                {
                    let shown: String = e.text().collect();
                    if let Some(shown) = url(shown.trim())
                        && shown.scheme() == "https"
                    {
                        found.insert("NF_HTML_LINK_SCHEME");
                    }
                }
                let lower = href.trim().to_ascii_lowercase();
                if let Some(data) = lower.strip_prefix("data:")
                    && let Some((kind, _)) = data.split_once(',')
                {
                    let kind = kind.split(';').next().unwrap_or("").trim();
                    if matches!(
                        kind,
                        "text/html" | "application/xhtml+xml" | "image/svg+xml"
                    ) {
                        found.insert("NF_HTML_DATA_LINK");
                    }
                }
            }
            "meta"
                if e.value()
                    .attr("http-equiv")
                    .is_some_and(|s| s.eq_ignore_ascii_case("refresh")) =>
            {
                if let Some(content) = e.value().attr("content")
                    && let Some((delay, target)) = content.split_once(';')
                    && delay.trim().parse::<u32>().is_ok()
                    && let Some((key, target)) = target.split_once('=')
                    && key.trim().eq_ignore_ascii_case("url")
                    && url(target.trim().trim_matches(['\'', '"'])).is_some()
                {
                    found.insert("NF_HTML_META_REFRESH");
                }
            }
            _ => {}
        }
    }
    // A normal short newsletter preheader or invisible padding is insufficient.
    if concealed >= 200 && concealed > visible {
        found.insert("NF_HTML_HIDDEN_TEXT");
    }
    Ok(())
}
