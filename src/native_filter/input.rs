//! Bounded, content-only views. No transport, old filter headers or attachments.
use anyhow::{Result, ensure};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, sync::OnceLock};

pub const PROTOCOL: &str = "noisefence-native-content-1";
pub const MAX_TOKENS: usize = 2048;
pub const MAX_FEATURES: usize = MAX_TOKENS * 4;
pub const DIMENSION: u32 = 65_536;
pub const SKETCH: usize = 32;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Features {
    pub protocol: String,
    pub fingerprint: String,
    pub osb: Vec<u32>,
    pub text: Vec<u64>,
    pub html: Vec<u64>,
    pub text_shingles: usize,
    pub html_shingles: usize,
}
impl Features {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.protocol == PROTOCOL,
            "native feature protocol mismatch"
        );
        ensure!(
            self.fingerprint.len() == 64 && self.fingerprint.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid native fingerprint"
        );
        ensure!(
            self.osb.len() <= MAX_FEATURES
                && self.osb.iter().all(|&v| v < DIMENSION)
                && self.osb.windows(2).all(|w| w[0] < w[1]),
            "invalid OSB features"
        );
        for sketch in [&self.text, &self.html] {
            ensure!(
                sketch.is_empty() || sketch.len() == SKETCH,
                "invalid native sketch"
            );
        }
        ensure!(
            self.text_shingles <= MAX_TOKENS && self.html_shingles <= MAX_TOKENS,
            "invalid shingle counts"
        );
        ensure!(
            self.text.is_empty() == (self.text_shingles == 0)
                && self.html.is_empty() == (self.html_shingles == 0),
            "inconsistent sketches"
        );
        Ok(())
    }
}

pub struct Input {
    pub subject: String,
    pub body: String,
    pub html: String,
    pub features: Features,
}

pub fn words(text: &str) -> Vec<String> {
    static WORDS: OnceLock<Regex> = OnceLock::new();
    WORDS
        .get_or_init(|| Regex::new(r"[\p{L}\p{N}]{2,40}").unwrap())
        .find_iter(text)
        .take(MAX_TOKENS)
        .map(|m| m.as_str().to_lowercase())
        .collect()
}

fn hash(bytes: &[u8]) -> u64 {
    let mut h = 0xcbf29ce484222325u64;
    for byte in bytes {
        h = (h ^ u64::from(*byte)).wrapping_mul(0x100000001b3);
    }
    mix(h)
}
fn mix(mut h: u64) -> u64 {
    h = (h ^ (h >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    h = (h ^ (h >> 27)).wrapping_mul(0x94d049bb133111eb);
    h ^ (h >> 31)
}

/// Presence of orthogonal sparse bigrams at distances 1..4. Repeated phrases
/// cannot multiply a feature, and subject/body never create a boundary bigram.
pub fn osb(subject: &str, body: &str) -> Vec<u32> {
    let mut out = BTreeSet::new();
    for (namespace, text) in [("subject", subject), ("body", body)] {
        let tokens = words(text);
        for (i, first) in tokens.iter().enumerate() {
            for distance in 1..=4 {
                if let Some(second) = tokens.get(i + distance) {
                    out.insert(
                        (hash(format!("{namespace}\0{distance}\0{first}\0{second}").as_bytes())
                            % u64::from(DIMENSION)) as u32,
                    );
                }
            }
        }
    }
    out.into_iter().take(MAX_FEATURES).collect()
}

fn sketch(tokens: &[String]) -> (Vec<u64>, usize) {
    let shingles: BTreeSet<_> = tokens
        .windows(3)
        .map(|w| hash(w.join("\0").as_bytes()))
        .collect();
    if shingles.is_empty() {
        return (vec![], 0);
    }
    let mut values = vec![u64::MAX; SKETCH];
    for h in &shingles {
        for (seed, minimum) in values.iter_mut().enumerate() {
            *minimum = (*minimum).min(mix(h ^ mix(seed as u64 + 1)));
        }
    }
    (values, shingles.len())
}

pub fn similarity(a: &[u64], b: &[u64]) -> Option<f64> {
    (a.len() == SKETCH && b.len() == SKETCH)
        .then(|| a.iter().zip(b).filter(|(a, b)| a == b).count() as f64 / SKETCH as f64)
}

pub fn extract(raw: &[u8], max_bytes: usize) -> Result<Input> {
    ensure!(raw.len() <= max_bytes, "native message size limit");
    let mail = mail_parser::MessageParser::default()
        .parse(raw)
        .ok_or_else(|| anyhow::anyhow!("native MIME unavailable"))?;
    ensure!(mail.parts.len() <= 200, "native MIME complexity limit");
    let (subject, body) =
        crate::features::text(raw).ok_or_else(|| anyhow::anyhow!("native text unavailable"))?;
    static TAGS: OnceLock<Regex> = OnceLock::new();
    let subject = TAGS
        .get_or_init(|| {
            Regex::new(r"(?i)^(?:\s*\[(?:spam|pub|junk|phishing|bulk)(?:[^\]]{0,20})\]\s*)+")
                .unwrap()
        })
        .replace_all(&subject, "")
        .into_owned();
    let mut html = String::new();
    for index in 0..mail.html_body_count().min(20) {
        if let Some(part) = mail.body_html(index) {
            html.extend(
                part.chars()
                    .take(32_000usize.saturating_sub(html.chars().count())),
            );
        }
    }
    // DOM tag order is structural evidence only. Attribute values, tracking ids
    // and URLs are never retained as part of this sketch.
    let dom = scraper::Html::parse_fragment(&html);
    let tags: Vec<_> = dom
        .tree
        .nodes()
        .filter_map(|n| n.value().as_element())
        .filter(|e| !matches!(e.name(), "html" | "head" | "style" | "script"))
        .take(MAX_TOKENS)
        .map(|e| e.name().to_owned())
        .collect();
    static VOLATILE: OnceLock<Regex> = OnceLock::new();
    let normalized = VOLATILE
        .get_or_init(|| Regex::new(r"(?i)https?://[^\s<>]+|[\w.+%-]+@[\w.-]+|\d+").unwrap())
        .replace_all(&body.to_lowercase(), " ")
        .into_owned();
    let tokens = words(&normalized);
    let (text, text_shingles) = sketch(&tokens);
    let (html_sketch, html_shingles) = sketch(&tags);
    let features = Features {
        protocol: PROTOCOL.into(),
        // Full normalized body: a sketch remains an approximate grouping hint.
        fingerprint: crate::message::digest(format!("{PROTOCOL}\0{}", tokens.join(" ")).as_bytes()),
        osb: osb(&subject, &body),
        text,
        html: html_sketch,
        text_shingles,
        html_shingles,
    };
    features.validate()?;
    Ok(Input {
        subject,
        body,
        html,
        features,
    })
}
