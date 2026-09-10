#![no_main]

use libfuzzer_sys::{Corpus, fuzz_target};
use noisefence::{content_inspection, heuristics, research_engines};
use std::{collections::BTreeSet, sync::OnceLock};

const MAX_RAW_BYTES: usize = 64 * 1024;
const MAX_REPORT_BYTES: usize = 64 * 1024;

struct Harness {
    runtime: research_engines::Runtime,
    heuristics: heuristics::Settings,
    content: content_inspection::Settings,
}

impl Harness {
    fn new() -> Self {
        let heuristics = heuristics::Settings {
            mode: heuristics::Mode::Observation,
            limits: heuristics::Limits {
                max_raw_bytes: MAX_RAW_BYTES,
                max_header_bytes: 4 * 1024,
                max_headers: 32,
                max_parts: 16,
                max_part_bytes: 32 * 1024,
                max_input_bytes: 32 * 1024,
                max_segments: 16,
                max_html_nodes: 2048,
                max_matches_per_rule: 4,
                max_total_matches: 32,
                max_findings: 16,
                ..Default::default()
            },
            ..Default::default()
        };
        let content = content_inspection::Settings {
            max_raw_bytes: MAX_RAW_BYTES,
            max_parts: 16,
            max_mime_depth: 4,
            max_header_bytes: 4 * 1024,
            max_part_bytes: 32 * 1024,
            max_total_decoded_bytes: MAX_RAW_BYTES,
            max_html_bytes: 16 * 1024,
            max_archive_entries: 16,
            max_unpacked_bytes: 32 * 1024,
            max_total_unpacked_bytes: MAX_RAW_BYTES,
            max_compression_ratio: 20,
            max_structure_nodes: 2048,
            max_nesting: 12,
            max_findings: 32,
            max_image_pixels: 1_000_000,
            max_images: 8,
        };
        content
            .validate()
            .expect("valid fixed content fuzz budgets");
        let mut config: noisefence::config::Config =
            toml::from_str(include_str!("../../config/development.toml"))
                .expect("development config schema");
        config.filter.max_analysis_bytes = MAX_RAW_BYTES;
        config.heuristics = Some(heuristics.clone());
        config.content_inspection = Some(content.clone());
        config.sandbox_pipeline = None;
        // Runtime::new compiles the fixed rule set. offline() does not open the
        // configured database, sockets, sandbox, DNS, HTTP or SMTP connections.
        let runtime = research_engines::Runtime::new(&config)
            .expect("compile fixed detector rules once per fuzz process");
        Self {
            runtime,
            heuristics,
            content,
        }
    }

    fn inspect(&self, raw: &[u8]) {
        assert!(raw.len() <= MAX_RAW_BYTES);
        let inspected = self.runtime.offline(raw);
        assert_eq!(
            inspected.execution.status,
            research_engines::Status::Complete
        );
        // Execution completion and detector completeness are distinct. Malformed
        // inputs and exhausted budgets must not be treated as successful scans.
        let h = inspected.heuristics.expect("configured heuristic report");
        assert_eq!(h.mode, heuristics::Mode::Observation);
        assert_ne!(h.status, heuristics::Status::Disabled);
        assert_eq!(h.contribution, 0.0);
        assert!(h.candidate_weight.is_finite());
        assert!((0.0..=self.heuristics.max_candidate_weight).contains(&h.candidate_weight));
        let limits = &self.heuristics.limits;
        assert!(h.findings.len() <= limits.max_findings);
        assert!(h.findings.iter().map(|f| f.matches).sum::<usize>() <= limits.max_total_matches);
        let mut rule_ids = BTreeSet::new();
        for finding in &h.findings {
            assert!(rule_ids.insert(&finding.id));
            assert!((1..=limits.max_matches_per_rule).contains(&finding.matches));
            let rule = self
                .heuristics
                .rules
                .iter()
                .find(|r| r.id == finding.id)
                .expect("finding metadata comes from configured rules, never input");
            assert_eq!(finding.label, rule.label);
            assert_eq!(finding.family, rule.family);
            assert_eq!(finding.candidate_weight, rule.candidate_weight);
            assert!(finding.scopes.iter().all(|s| rule.scopes.contains(s)));
        }
        if !h.limits_hit.is_empty() {
            assert_ne!(h.status, heuristics::Status::Complete);
        }
        let encoded = serde_json::to_vec(&h).expect("serializable heuristic report");
        assert!(encoded.len() <= MAX_REPORT_BYTES);
        assert_eq!(
            serde_json::from_slice::<heuristics::Report>(&encoded).unwrap(),
            h
        );

        let c = inspected.content.expect("configured content report");
        assert!(c.advisory);
        assert_eq!(c.version, content_inspection::REPORT_VERSION);
        assert_eq!(c.limits, self.content);
        assert_ne!(c.status, content_inspection::Status::InvalidSettings);
        assert!(c.stats.parts <= self.content.max_parts);
        assert!(c.parts.len() <= c.stats.parts);
        assert!(c.stats.decoded_bytes <= self.content.max_total_decoded_bytes);
        assert!(c.stats.unpacked_bytes <= self.content.max_total_unpacked_bytes);
        assert!(c.stats.structure_nodes <= self.content.max_structure_nodes);
        assert!(c.findings.len() <= self.content.max_findings);
        if c.truncated {
            assert_eq!(c.status, content_inspection::Status::Incomplete);
        }
        let mut part_indices = BTreeSet::new();
        for part in &c.parts {
            assert!(part.index < c.stats.parts && part_indices.insert(part.index));
            assert!(part.bytes <= self.content.max_part_bytes);
            assert_eq!(part.width.is_some(), part.height.is_some());
            assert!(part.width.is_none_or(|w| w > 0));
            assert!(part.height.is_none_or(|h| h > 0));
            if !part.complete {
                assert_eq!(c.status, content_inspection::Status::Incomplete);
            }
        }
        for (i, finding) in c.findings.iter().enumerate() {
            assert!(finding.part.is_none_or(|p| p < c.stats.parts));
            assert!(!c.findings[..i].contains(finding));
        }
        let encoded = serde_json::to_vec(&c).expect("serializable content report");
        assert!(encoded.len() <= MAX_REPORT_BYTES);
        assert_eq!(
            serde_json::from_slice::<content_inspection::Report>(&encoded).unwrap(),
            c
        );
    }
}

// The original bytes ALWAYS exercise the RFC 5322/MIME path. A second pass uses
// byte 0 only to select a fixed MIME envelope, with bytes 1.. as its body. This
// gets mutations past headers without injecting parser keywords into a payload.
// Headers + payload, not merely the source input, must fit the 64 KiB limit.
const ENVELOPES: &[&[u8]] = &[
    b"Content-Type: text/plain\r\n\r\n",
    b"Content-Type: text/html\r\n\r\n",
    b"Content-Type: application/pdf\r\n\r\n",
    b"Content-Type: image/png\r\n\r\n",
    b"Content-Type: image/jpeg\r\n\r\n",
    b"Content-Type: image/gif\r\n\r\n",
    b"Content-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document\r\n\r\n",
    b"Content-Type: application/msword\r\n\r\n",
    b"Content-Type: multipart/mixed; boundary=fuzz\r\n\r\n",
    b"Content-Type: message/rfc822\r\n\r\n",
    b"Content-Type: text/html\r\nContent-Transfer-Encoding: base64\r\n\r\n",
    b"Content-Type: text/html\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n",
];

fuzz_target!(|data: &[u8]| -> Corpus {
    if data.len() > MAX_RAW_BYTES {
        return Corpus::Reject;
    }
    static HARNESS: OnceLock<Harness> = OnceLock::new();
    let harness = HARNESS.get_or_init(Harness::new);
    harness.inspect(data);
    if let Some((&selector, payload)) = data.split_first() {
        let header = ENVELOPES[usize::from(selector) % ENVELOPES.len()];
        let payload = &payload[..payload.len().min(MAX_RAW_BYTES - header.len())];
        let mut message = Vec::with_capacity(header.len() + payload.len());
        message.extend_from_slice(header);
        message.extend_from_slice(payload);
        harness.inspect(&message);
    }
    Corpus::Keep
});
