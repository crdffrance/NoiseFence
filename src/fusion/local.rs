//! Versioned, bounded observations for native fusion. No message text, manual
//! weights, timings or delivery decisions enter this projection.
use crate::{config::Config, content_inspection as content, engine::Scan, heuristics};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, sync::OnceLock};

pub const VERSION: &str = "noisefence-local-evidence-1";
pub const RULE_SLOTS: usize = 64;
pub const FEATURE_COUNT: usize = 109;
pub const COUNT_CAP: u16 = 256;
pub const DIMENSION_CAP: u32 = 16_384;
pub const PIXEL_CAP: u64 = 100_000_000;
pub const MEDIA_BYTES_CAP: u64 = 16 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HeuristicsBinding {
    pub version: String,
    pub pattern_version: String,
    pub settings_digest: String,
    pub enabled: bool,
    /// Slot order, not evaluation order. The digest also binds evaluation order.
    pub rule_ids: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StructureBinding {
    pub version: String,
    pub settings_digest: String,
    /// Allows exact report/configuration comparison without hashing per message.
    pub limits: content::Settings,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub version: String,
    pub heuristics: Option<HeuristicsBinding>,
    pub structure: Option<StructureBinding>,
}

fn token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
}

fn structure_digest(settings: &content::Settings) -> Result<String> {
    Ok(crate::message::digest(&serde_json::to_vec(&(
        content::REPORT_VERSION,
        settings,
    ))?))
}

impl Binding {
    /// Build once alongside the detector runtime, never in the per-mail path.
    /// Hashes bind configuration; they do not attest to quality or calibration.
    pub fn from_config(config: &Config) -> Result<Self> {
        let heuristics = config
            .heuristics
            .as_ref()
            .map(|s| -> Result<_> {
                s.validate()?;
                let mut rule_ids: Vec<_> = s.rules.iter().map(|r| r.id.clone()).collect();
                rule_ids.sort();
                Ok(HeuristicsBinding {
                    version: heuristics::VERSION.into(),
                    pattern_version: heuristics::PATTERN_VERSION.into(),
                    settings_digest: s.settings_digest()?,
                    enabled: s.mode != heuristics::Mode::Disabled,
                    rule_ids,
                })
            })
            .transpose()?;
        let structure = config
            .content_inspection
            .as_ref()
            .map(|s| -> Result<_> {
                s.validate()?;
                Ok(StructureBinding {
                    version: content::REPORT_VERSION.into(),
                    settings_digest: structure_digest(s)?,
                    limits: s.clone(),
                })
            })
            .transpose()?;
        let binding = Self {
            version: VERSION.into(),
            heuristics,
            structure,
        };
        binding.validate()?;
        Ok(binding)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(self.version == VERSION, "unsupported local binding version");
        if let Some(h) = &self.heuristics {
            ensure!(
                h.version == heuristics::VERSION
                    && h.pattern_version == heuristics::PATTERN_VERSION
                    && super::valid_hash(&h.settings_digest)
                    && h.rule_ids.len() <= RULE_SLOTS
                    && h.rule_ids.iter().all(|id| token(id))
                    && h.rule_ids.windows(2).all(|ids| ids[0] < ids[1]),
                "invalid local heuristic binding"
            );
        }
        if let Some(s) = &self.structure {
            s.limits.validate()?;
            ensure!(
                s.version == content::REPORT_VERSION
                    && super::valid_hash(&s.settings_digest)
                    && s.settings_digest == structure_digest(&s.limits)?,
                "invalid local structure binding"
            );
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Missing,
    Disabled,
    Complete,
    Busy,
    Partial,
    Invalid,
    Unavailable,
}

const STATES: [(State, &str); 7] = [
    (State::Missing, "missing"),
    (State::Disabled, "disabled"),
    (State::Complete, "complete"),
    (State::Busy, "busy"),
    (State::Partial, "partial"),
    (State::Invalid, "invalid"),
    (State::Unavailable, "unavailable"),
];

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HeuristicsEvidence {
    pub state: State,
    /// Exactly 64 slots; those beyond the pinned catalogue must be false.
    pub rule_hits: Vec<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StructureEvidence {
    pub state: State,
    /// Fixed order in STRUCTURAL_FINDINGS / specs().
    pub findings: [bool; 15],
    /// HTML parts, images, PDFs, Office documents; each clipped to 256.
    pub counts: [u16; 4],
    pub media: MediaEvidence,
}

/// Aggregates of decoded PartReport metadata, never a list of parts or names.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MediaEvidence {
    /// PNG, JPEG, GIF, PDF; each clipped to 256.
    pub format_counts: [u16; 4],
    pub image_max_width: u32,
    pub image_max_height: u32,
    /// Maximum per-image width * height, before clamping either dimension.
    pub image_max_pixels: u64,
    /// Sum of decoded part bytes, clipped independently for images and PDFs.
    pub image_bytes: u64,
    pub pdf_bytes: u64,
    pub tiny_images: u16,
    pub animated_images: u16,
    /// Either dimension is missing; a known dimension still informs its maximum.
    pub missing_dimensions: u16,
}

impl MediaEvidence {
    fn observe(&mut self, part: &content::PartReport) {
        use content::ContentKind::*;
        let slot = match part.kind {
            Png => 0,
            Jpeg => 1,
            Gif => 2,
            Pdf => 3,
            _ => return,
        };
        let increment = |n: &mut u16| *n = n.saturating_add(1).min(COUNT_CAP);
        increment(&mut self.format_counts[slot]);
        let bytes = part.bytes.min(MEDIA_BYTES_CAP as usize) as u64;
        if slot == 3 {
            self.pdf_bytes = self.pdf_bytes.saturating_add(bytes).min(MEDIA_BYTES_CAP);
            return;
        }
        self.image_bytes = self.image_bytes.saturating_add(bytes).min(MEDIA_BYTES_CAP);
        self.image_max_width = self
            .image_max_width
            .max(part.width.unwrap_or(0).min(DIMENSION_CAP));
        self.image_max_height = self
            .image_max_height
            .max(part.height.unwrap_or(0).min(DIMENSION_CAP));
        match (part.width, part.height) {
            (Some(width), Some(height)) => {
                let pixels = (width as u64).saturating_mul(height as u64);
                self.image_max_pixels = self.image_max_pixels.max(pixels.min(PIXEL_CAP));
                if width <= 2 && height <= 2 {
                    increment(&mut self.tiny_images);
                }
            }
            _ => increment(&mut self.missing_dimensions),
        }
        if part.frames.is_some_and(|frames| frames > 1) {
            increment(&mut self.animated_images);
        }
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.format_counts.iter().all(|n| *n <= COUNT_CAP)
                && self.image_max_width <= DIMENSION_CAP
                && self.image_max_height <= DIMENSION_CAP
                && self.image_max_pixels <= PIXEL_CAP
                && self.image_bytes <= MEDIA_BYTES_CAP
                && self.pdf_bytes <= MEDIA_BYTES_CAP
                && [
                    self.tiny_images,
                    self.animated_images,
                    self.missing_dimensions
                ]
                .iter()
                .all(|n| *n <= COUNT_CAP),
            "invalid local image/PDF payload bounds"
        );
        let images: u32 = self.format_counts[..3].iter().map(|n| *n as u32).sum();
        ensure!(
            [
                self.tiny_images,
                self.animated_images,
                self.missing_dimensions
            ]
            .iter()
            .all(|n| *n as u32 <= images)
                && self.tiny_images as u32 + self.missing_dimensions as u32 <= images
                && (images > 0
                    || (self.image_max_width == 0
                        && self.image_max_height == 0
                        && self.image_max_pixels == 0
                        && self.image_bytes == 0))
                && (self.format_counts[3] > 0 || self.pdf_bytes == 0),
            "inconsistent local image/PDF payload"
        );
        Ok(())
    }

    fn values(&self) -> [f64; 12] {
        // Preserve useful scale for small dimensions/volumes while mapping
        // zero to zero and the fixed cap to one. Counts remain linear.
        let log_normal = |value: f64, cap: f64| value.ln_1p() / cap.ln_1p();
        [
            self.format_counts[0] as f64 / COUNT_CAP as f64,
            self.format_counts[1] as f64 / COUNT_CAP as f64,
            self.format_counts[2] as f64 / COUNT_CAP as f64,
            self.format_counts[3] as f64 / COUNT_CAP as f64,
            log_normal(self.image_max_width as f64, DIMENSION_CAP as f64),
            log_normal(self.image_max_height as f64, DIMENSION_CAP as f64),
            log_normal(self.image_max_pixels as f64, PIXEL_CAP as f64),
            log_normal(self.image_bytes as f64, MEDIA_BYTES_CAP as f64),
            log_normal(self.pdf_bytes as f64, MEDIA_BYTES_CAP as f64),
            self.tiny_images as f64 / COUNT_CAP as f64,
            self.animated_images as f64 / COUNT_CAP as f64,
            self.missing_dimensions as f64 / COUNT_CAP as f64,
        ]
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LocalEvidence {
    pub version: String,
    pub binding: Binding,
    pub heuristics: HeuristicsEvidence,
    pub structure: StructureEvidence,
}

const STRUCTURAL_FINDINGS: [(content::FindingId, &str); 15] = [
    (content::FindingId::HtmlActiveElement, "html_active_element"),
    (content::FindingId::HtmlEventHandler, "html_event_handler"),
    (content::FindingId::HtmlActiveUrl, "html_active_url"),
    (content::FindingId::PdfActiveName, "pdf_active_name"),
    (content::FindingId::OfficeVbaProject, "office_vba_project"),
    (content::FindingId::OfficeXlmMacros, "office_xlm_macros"),
    (
        content::FindingId::OfficeExternalRelationship,
        "office_external_relationship",
    ),
    (
        content::FindingId::OfficeEmbeddedObject,
        "office_embedded_object",
    ),
    (content::FindingId::TypeMismatch, "type_mismatch"),
    (content::FindingId::ImageDimensions, "image_dimensions"),
    (content::FindingId::ImageCount, "image_count"),
    (content::FindingId::HtmlRefresh, "html_refresh"),
    (
        content::FindingId::HtmlEmbeddedContent,
        "html_embedded_content",
    ),
    (
        content::FindingId::PdfExternalReference,
        "pdf_external_reference",
    ),
    (
        content::FindingId::OfficeMacroEnabled,
        "office_macro_enabled",
    ),
];
const COUNTS: [&str; 4] = ["html_parts", "images", "pdfs", "office_documents"];
const MEDIA_FEATURES: [&str; 12] = [
    "png_parts_div256",
    "jpeg_parts_div256",
    "gif_parts_div256",
    "pdf_parts_div256",
    "image_max_width_log16384",
    "image_max_height_log16384",
    "image_max_pixels_log100000000",
    "image_bytes_log16777216",
    "pdf_bytes_log16777216",
    "tiny_images_div256",
    "animated_images_div256",
    "missing_dimensions_div256",
];

/// A shared worker failure supersedes a stale/partial individual report.
fn execution_state(scan: &Scan) -> Option<State> {
    use crate::research_engines::{Status, VERSION as EXECUTION_VERSION};
    match &scan.research_execution {
        None => Some(State::Missing),
        Some(e) if e.version != EXECUTION_VERSION => Some(State::Invalid),
        Some(e) => match e.status {
            Status::Complete => None,
            Status::Busy => Some(State::Busy),
            Status::Limited => Some(State::Partial),
            Status::Unavailable => Some(State::Unavailable),
        },
    }
}

impl LocalEvidence {
    /// `binding` is cached and validated when the engine is constructed. This
    /// operation neither reparses mail nor compiles regexes nor hashes patterns.
    pub fn capture(binding: &Binding, scan: &Scan) -> Self {
        let mut result = Self {
            version: VERSION.into(),
            binding: binding.clone(),
            heuristics: HeuristicsEvidence {
                state: State::Disabled,
                rule_hits: vec![false; RULE_SLOTS],
            },
            structure: StructureEvidence {
                state: State::Disabled,
                findings: [false; 15],
                counts: [0; 4],
                media: MediaEvidence::default(),
            },
        };
        result.refresh(scan);
        result
    }

    /// Replace observations, keeping the original runtime binding. A retry with
    /// no reports cannot retain an earlier successful result.
    pub fn refresh(&mut self, scan: &Scan) {
        self.heuristics.rule_hits = vec![false; RULE_SLOTS];
        self.structure.findings = [false; 15];
        self.structure.counts = [0; 4];
        self.structure.media = MediaEvidence::default();
        self.heuristics.state = self.capture_heuristics(scan).unwrap_or(State::Invalid);
        self.structure.state = self.capture_structure(scan).unwrap_or(State::Invalid);
        if self.heuristics.state != State::Complete {
            self.heuristics.rule_hits.fill(false);
        }
        if self.structure.state != State::Complete {
            self.structure.findings.fill(false);
            self.structure.counts.fill(0);
            self.structure.media = MediaEvidence::default();
        }
    }

    fn capture_heuristics(&mut self, scan: &Scan) -> Result<State> {
        let Some(binding) = self.binding.heuristics.as_ref().filter(|h| h.enabled) else {
            return Ok(State::Disabled);
        };
        if let Some(state) = execution_state(scan) {
            return Ok(state);
        }
        let Some(r) = &scan.heuristics else {
            return Ok(State::Missing);
        };
        ensure!(
            r.version == binding.version
                && r.pattern_version == binding.pattern_version
                && r.settings_digest == binding.settings_digest
                && r.mode != heuristics::Mode::Disabled,
            "heuristic report binding mismatch"
        );
        ensure!(
            r.findings.len() <= RULE_SLOTS
                && r.limits_hit.len() <= 15
                && r.candidate_weight.is_finite()
                && (0.0..=100.0).contains(&r.candidate_weight)
                && r.contribution.is_finite()
                && (0.0..=10.0).contains(&r.contribution),
            "invalid heuristic report bounds"
        );
        let mut seen = BTreeSet::new();
        let mut matches = 0usize;
        for f in &r.findings {
            ensure!(
                token(&f.id)
                    && seen.insert(&f.id)
                    && (1..=32).contains(&f.matches)
                    && !f.scopes.is_empty()
                    && f.scopes.len() <= 4
                    && f.scopes.iter().collect::<BTreeSet<_>>().len() == f.scopes.len()
                    && f.candidate_weight.is_finite()
                    && (0.0..=10.0).contains(&f.candidate_weight),
                "invalid heuristic finding"
            );
            let index = binding
                .rule_ids
                .binary_search(&f.id)
                .map_err(|_| anyhow::anyhow!("heuristic rule is outside bound catalogue"))?;
            ensure!(index < RULE_SLOTS, "heuristic slot exceeds bound");
            self.heuristics.rule_hits[index] = true;
            matches += f.matches;
        }
        ensure!(matches <= 512, "heuristic match budget exceeded");
        Ok(match r.status {
            heuristics::Status::Complete if r.limits_hit.is_empty() => State::Complete,
            heuristics::Status::Complete | heuristics::Status::Limited => State::Partial,
            heuristics::Status::InvalidMessage | heuristics::Status::Disabled => State::Invalid,
        })
    }

    fn capture_structure(&mut self, scan: &Scan) -> Result<State> {
        let Some(binding) = &self.binding.structure else {
            return Ok(State::Disabled);
        };
        if let Some(state) = execution_state(scan) {
            return Ok(state);
        }
        let Some(r) = &scan.content_inspection else {
            return Ok(State::Missing);
        };
        ensure!(
            r.version == binding.version && r.limits == binding.limits && r.advisory,
            "structure report binding mismatch"
        );
        let s = &binding.limits;
        ensure!(
            r.parts.len() <= s.max_parts.min(256) && r.findings.len() <= s.max_findings.min(512),
            "unbounded structure report"
        );
        let mut indices = BTreeSet::new();
        ensure!(
            r.parts
                .iter()
                .all(|p| p.index < 256 && indices.insert(p.index)),
            "invalid structure part indices"
        );
        let mut seen = BTreeSet::new();
        ensure!(
            r.findings
                .iter()
                .all(|f| f.part.is_none_or(|p| p < 256) && seen.insert((f.id as u8, f.part))),
            "invalid structure findings"
        );
        if r.status == content::Status::InvalidSettings {
            return Ok(State::Invalid);
        }
        if r.status == content::Status::Incomplete
            || r.truncated
            || r.parts.iter().any(|p| !p.complete)
        {
            return Ok(State::Partial);
        }
        // Coverage and resource-failure findings cannot masquerade as complete
        // observations even if an imported report claims Complete.
        if r.findings.iter().any(|f| !complete_finding(f.id)) {
            return Ok(State::Partial);
        }
        for (hit, (id, _)) in self.structure.findings.iter_mut().zip(STRUCTURAL_FINDINGS) {
            *hit = r.findings.iter().any(|f| f.id == id);
        }
        self.structure.counts = [
            r.stats.html_parts,
            r.stats.images,
            r.stats.pdfs,
            r.stats.office_documents,
        ]
        .map(|n| n.min(COUNT_CAP as usize) as u16);
        for part in &r.parts {
            self.structure.media.observe(part);
        }
        Ok(State::Complete)
    }

    pub fn validate(&self) -> Result<()> {
        self.binding.validate()?;
        self.structure.media.validate()?;
        ensure!(
            self.version == VERSION,
            "unsupported local evidence version"
        );
        let enabled = self.binding.heuristics.as_ref().is_some_and(|h| h.enabled);
        ensure!(
            enabled != (self.heuristics.state == State::Disabled)
                && self.binding.structure.is_some() != (self.structure.state == State::Disabled),
            "local availability contradicts binding"
        );
        let n = self
            .binding
            .heuristics
            .as_ref()
            .map_or(0, |h| h.rule_ids.len());
        ensure!(
            self.heuristics.rule_hits.len() == RULE_SLOTS
                && self.heuristics.rule_hits[n..].iter().all(|hit| !hit)
                && (self.heuristics.state == State::Complete
                    || self.heuristics.rule_hits.iter().all(|hit| !hit)),
            "invalid local heuristic payload"
        );
        ensure!(
            self.structure.counts.iter().all(|n| *n <= COUNT_CAP)
                && (self.structure.state == State::Complete
                    || (self.structure.findings.iter().all(|hit| !hit)
                        && self.structure.counts == [0; 4]
                        && self.structure.media == MediaEvidence::default())),
            "invalid local structure payload"
        );
        Ok(())
    }

    pub fn tag_eligible(&self) -> bool {
        self.validate().is_ok()
            && [self.heuristics.state, self.structure.state]
                .iter()
                .all(|s| matches!(s, State::Complete | State::Disabled))
    }

    pub fn profile(&self) -> String {
        let name = |s| STATES.iter().find(|(state, _)| *state == s).unwrap().1;
        format!(
            "{}/{}",
            name(self.heuristics.state),
            name(self.structure.state)
        )
    }

    pub fn values(&self) -> Result<Vec<f64>> {
        features(self)
    }
    pub fn eligible(&self) -> bool {
        self.tag_eligible()
    }
    pub fn availability_profile(&self) -> String {
        self.profile()
    }
}

fn complete_finding(id: content::FindingId) -> bool {
    use content::FindingId::*;
    matches!(
        id,
        HtmlActiveElement
            | HtmlEventHandler
            | HtmlActiveUrl
            | HtmlRefresh
            | HtmlEmbeddedContent
            | TypeMismatch
            | ImageDimensions
            | ImageCount
            | PdfActiveName
            | PdfExternalReference
            | OfficeVbaProject
            | OfficeMacroEnabled
            | OfficeXlmMacros
            | OfficeExternalRelationship
    )
}

/// Ordered append-only protocol fragment; every coordinate is in [0, 1].
pub fn specs() -> &'static [super::Feature] {
    static SPECS: OnceLock<Vec<super::Feature>> = OnceLock::new();
    SPECS.get_or_init(|| {
        let mut specs = Vec::with_capacity(FEATURE_COUNT);
        for family in ["heuristics", "structure"] {
            let mut push = |name: String| {
                specs.push(super::Feature {
                    name: format!("{family}.{name}"),
                    family: family.into(),
                    minimum: 0.0,
                    maximum: 1.0,
                })
            };
            for (_, state) in STATES {
                push(format!("state.{state}"));
            }
            if family == "heuristics" {
                for slot in 0..RULE_SLOTS {
                    push(format!("rule_{slot:02}.hit"));
                }
            } else {
                for (_, name) in &STRUCTURAL_FINDINGS[..9] {
                    push((*name).into());
                }
                for name in COUNTS {
                    push(format!("{name}_div256"));
                }
                // Preserve the initial 91 coordinates as a prefix of the
                // unpublished v2 contract; append metadata after those counts.
                for (_, name) in &STRUCTURAL_FINDINGS[9..] {
                    push((*name).into());
                }
                for name in MEDIA_FEATURES {
                    push(name.into());
                }
            }
        }
        specs
    })
}

pub fn features(e: &LocalEvidence) -> Result<Vec<f64>> {
    e.validate()?;
    let mut values = Vec::with_capacity(FEATURE_COUNT);
    values.extend(
        STATES
            .iter()
            .map(|(s, _)| u8::from(*s == e.heuristics.state) as f64),
    );
    values.extend(
        e.heuristics
            .rule_hits
            .iter()
            .map(|hit| u8::from(*hit) as f64),
    );
    values.extend(
        STATES
            .iter()
            .map(|(s, _)| u8::from(*s == e.structure.state) as f64),
    );
    values.extend(
        e.structure.findings[..9]
            .iter()
            .map(|hit| u8::from(*hit) as f64),
    );
    values.extend(
        e.structure
            .counts
            .iter()
            .map(|n| *n as f64 / COUNT_CAP as f64),
    );
    values.extend(
        e.structure.findings[9..]
            .iter()
            .map(|hit| u8::from(*hit) as f64),
    );
    values.extend(e.structure.media.values());
    Ok(values)
}
