use noisefence::{
    config::Config,
    content_inspection as content,
    engine::Scan,
    fusion::local::{self, Binding, LocalEvidence, State},
    heuristics::{self, Rule, Scope},
    research_engines,
};

fn config() -> Config {
    let mut c: Config = toml::from_str(include_str!("../config/development.toml")).unwrap();
    c.heuristics = Some(heuristics::Settings {
        rules: vec![
            Rule {
                id: "z_subject".into(),
                label: "Libelle prive".into(),
                family: "private_family".into(),
                scopes: vec![Scope::Subject],
                pattern: "(?i)urgent".into(),
                candidate_weight: 3.0,
            },
            Rule {
                id: "a_body".into(),
                label: "Second libelle".into(),
                family: "private_family".into(),
                scopes: vec![Scope::Body],
                pattern: "(?i)payez".into(),
                candidate_weight: 2.0,
            },
        ],
        ..Default::default()
    });
    c.content_inspection = Some(content::Settings::default());
    c
}

fn inspect(c: &Config, raw: &[u8]) -> Scan {
    let mut scan = Scan::default();
    research_engines::Runtime::new(c)
        .unwrap()
        .offline(raw)
        .apply(&mut scan);
    scan
}

fn fixture() -> (Config, Scan, LocalEvidence) {
    let c = config();
    let scan = inspect(&c, b"From: Private <private@example.org>\r\nSubject: Urgent private canary\r\nContent-Type: text/html\r\n\r\n<p>Payez maintenant</p><script>hidden canary</script>");
    let e = LocalEvidence::capture(&Binding::from_config(&c).unwrap(), &scan);
    (c, scan, e)
}

fn value(e: &LocalEvidence, name: &str) -> f64 {
    e.values().unwrap()[local::specs().iter().position(|f| f.name == name).unwrap()]
}

#[test]
fn fixed_order_and_bounds_have_meaningful_unweighted_hits() {
    let (_, _, e) = fixture();
    e.validate().unwrap();
    assert!(e.tag_eligible());
    assert_eq!(e.profile(), "complete/complete");
    let specs = local::specs();
    assert_eq!(specs.len(), 109);
    assert_eq!(specs[0].name, "heuristics.state.missing");
    assert_eq!(specs[7].name, "heuristics.rule_00.hit");
    assert_eq!(specs[70].name, "heuristics.rule_63.hit");
    assert_eq!(specs[71].name, "structure.state.missing");
    assert_eq!(specs[78].name, "structure.html_active_element");
    assert_eq!(specs[86].name, "structure.type_mismatch");
    assert_eq!(specs[90].name, "structure.office_documents_div256");
    assert_eq!(specs[91].name, "structure.image_dimensions");
    assert_eq!(specs[96].name, "structure.office_macro_enabled");
    assert_eq!(specs[97].name, "structure.png_parts_div256");
    assert_eq!(specs[108].name, "structure.missing_dimensions_div256");
    let protocol = noisefence::fusion::specs_for(2).unwrap();
    assert_eq!(protocol.len(), 327);
    assert_eq!(
        serde_json::to_value(&protocol[218..]).unwrap(),
        serde_json::to_value(specs).unwrap()
    );
    assert_eq!(
        specs
            .iter()
            .map(|s| &s.name)
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        109
    );
    assert!(specs.iter().all(|s| s.minimum == 0.0 && s.maximum == 1.0));
    assert!(specs[..71].iter().all(|s| s.family == "heuristics"));
    assert!(specs[71..].iter().all(|s| s.family == "structure"));
    assert_eq!(value(&e, "heuristics.rule_00.hit"), 1.0);
    assert_eq!(value(&e, "heuristics.rule_01.hit"), 1.0);
    assert_eq!(value(&e, "structure.html_active_element"), 1.0);
    assert_eq!(value(&e, "structure.html_parts_div256"), 1.0 / 256.0);
    assert!(
        e.values()
            .unwrap()
            .iter()
            .all(|x| x.is_finite() && (0.0..=1.0).contains(x))
    );
}

#[test]
fn encoded_mime_uses_real_detectors_and_excludes_invisible_or_attachment_text() {
    let c = config();
    let binding = Binding::from_config(&c).unwrap();
    let raw = b"From: private@example.org\r\nSubject: =?UTF-8?B?VXJnZW50?=\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\nX-Spam-Report: payez\r\n\r\n--b\r\nContent-Type: text/html\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n<p>pa=79ez</p>\r\n--b\r\nContent-Type: text/plain; name=private.txt\r\nContent-Disposition: attachment; filename=private.txt\r\n\r\nprivate attachment\r\n--b--\r\n";
    let e = LocalEvidence::capture(&binding, &inspect(&c, raw));
    assert_eq!(e.heuristics.state, State::Complete);
    assert_eq!(&e.heuristics.rule_hits[..2], &[true, true]);
    let hidden = String::from_utf8(raw.to_vec())
        .unwrap()
        .replace(
            "<p>pa=79ez</p>",
            "<p>Bonjour</p><script>payez</script><p hidden>payez</p>",
        )
        .replace("private attachment", "payez");
    let hidden = LocalEvidence::capture(&binding, &inspect(&c, hidden.as_bytes()));
    assert_eq!(hidden.heuristics.state, State::Complete);
    assert_eq!(&hidden.heuristics.rule_hits[..2], &[false, true]);
}

#[test]
fn no_text_weights_or_timing_enter_evidence_and_valid_weight_changes_do_not_score() {
    let (c, mut scan, e) = fixture();
    let before = e.values().unwrap();
    let r = scan.heuristics.as_mut().unwrap();
    r.candidate_weight = 99.0;
    r.contribution = 9.0;
    for f in &mut r.findings {
        f.label = "RAW_PRIVATE_LABEL@example.org".into();
        f.family = "RAW_PRIVATE_FAMILY".into();
        f.candidate_weight = 0.0;
    }
    scan.score = 100.0;
    scan.research_execution.as_mut().unwrap().elapsed_ms = u64::MAX;
    let changed = LocalEvidence::capture(&Binding::from_config(&c).unwrap(), &scan);
    assert_eq!(changed.values().unwrap(), before);
    let serialized = serde_json::to_string(&changed).unwrap();
    for secret in [
        "private@example.org",
        "Urgent",
        "canary",
        "RAW_PRIVATE",
        "candidate_weight",
        "contribution",
        "elapsed_ms",
        "pattern\"",
        "Libelle",
    ] {
        assert!(
            !serialized.contains(secret),
            "unexpected private data: {secret}"
        );
    }
    assert_eq!(
        serde_json::from_str::<LocalEvidence>(&serialized).unwrap(),
        changed
    );
    assert!(serialized.len() < 4096);
}

#[test]
fn catalogue_and_digests_bind_exact_configuration_without_serializing_patterns() {
    let mut c = config();
    let original = Binding::from_config(&c).unwrap();
    assert_eq!(
        original.heuristics.as_ref().unwrap().rule_ids,
        ["a_body", "z_subject"]
    );
    let mut roundtrip = c.clone();
    roundtrip.heuristics =
        Some(toml::from_str(&toml::to_string(c.heuristics.as_ref().unwrap()).unwrap()).unwrap());
    roundtrip.content_inspection = Some(
        toml::from_str(&toml::to_string(c.content_inspection.as_ref().unwrap()).unwrap()).unwrap(),
    );
    assert_eq!(Binding::from_config(&roundtrip).unwrap(), original);
    c.heuristics.as_mut().unwrap().rules.reverse();
    let reordered = Binding::from_config(&c).unwrap();
    assert_eq!(
        original.heuristics.as_ref().unwrap().rule_ids,
        reordered.heuristics.as_ref().unwrap().rule_ids
    );
    assert_ne!(original, reordered);
    c = config();
    c.heuristics.as_mut().unwrap().rules[0]
        .pattern
        .push_str(" privé");
    assert_ne!(Binding::from_config(&c).unwrap(), original);
    c = config();
    c.content_inspection.as_mut().unwrap().max_findings = 127;
    assert_ne!(Binding::from_config(&c).unwrap(), original);
    let structural = original.structure.as_ref().unwrap();
    assert_eq!(
        structural.settings_digest,
        noisefence::message::digest(
            &serde_json::to_vec(&(content::REPORT_VERSION, content::Settings::default())).unwrap()
        )
    );
}

#[test]
fn previous_structure_revision_cannot_be_reused_with_current_fusion() {
    for version in [
        "noisefence-content-inspection-1",
        "noisefence-content-inspection-2",
    ] {
        let (c, mut scan, _) = fixture();
        let current = Binding::from_config(&c).unwrap();
        let mut old = current.clone();
        let structure = old.structure.as_mut().unwrap();
        structure.version = version.into();
        structure.settings_digest = noisefence::message::digest(
            &serde_json::to_vec(&(&structure.version, &structure.limits)).unwrap(),
        );
        scan.content_inspection.as_mut().unwrap().version = structure.version.clone();
        assert_ne!(old, current);
        assert!(old.validate().is_err());
        // Historical reports remain readable, but are not current detector output.
        let decoded: noisefence::engine::Scan =
            serde_json::from_slice(&serde_json::to_vec(&scan).unwrap()).unwrap();
        let captured = LocalEvidence::capture(&current, &decoded);
        assert_eq!(captured.structure.state, State::Invalid);
        assert!(!captured.tag_eligible());
    }
}

#[test]
fn missing_disabled_busy_partial_invalid_and_unavailable_are_distinct_and_safe() {
    let (mut c, scan, _) = fixture();
    let binding = Binding::from_config(&c).unwrap();
    let missing = LocalEvidence::capture(&binding, &Scan::default());
    assert_eq!(missing.profile(), "missing/missing");
    assert!(!missing.tag_eligible());
    for (status, expected) in [
        (research_engines::Status::Busy, State::Busy),
        (research_engines::Status::Limited, State::Partial),
        (research_engines::Status::Unavailable, State::Unavailable),
    ] {
        let mut scan = scan.clone();
        scan.research_execution.as_mut().unwrap().status = status;
        let e = LocalEvidence::capture(&binding, &scan);
        assert_eq!(e.heuristics.state, expected);
        assert_eq!(e.structure.state, expected);
        assert!(!e.tag_eligible());
        assert!(e.heuristics.rule_hits.iter().all(|hit| !hit));
        assert_eq!(e.structure.findings, [false; 15]);
        assert_eq!(e.structure.counts, [0; 4]);
        e.validate().unwrap();
    }
    let mut invalid = scan.clone();
    invalid.research_execution.as_mut().unwrap().version = "unsupported".into();
    assert_eq!(
        LocalEvidence::capture(&binding, &invalid).profile(),
        "invalid/invalid"
    );
    c.heuristics = None;
    c.content_inspection = None;
    let disabled = LocalEvidence::capture(&Binding::from_config(&c).unwrap(), &scan);
    assert_eq!(disabled.profile(), "disabled/disabled");
    assert!(disabled.tag_eligible());
    c.heuristics = Some(heuristics::Settings {
        mode: heuristics::Mode::Disabled,
        ..Default::default()
    });
    assert_eq!(
        LocalEvidence::capture(&Binding::from_config(&c).unwrap(), &Scan::default()).profile(),
        "disabled/disabled"
    );
}

#[test]
fn partial_or_mismatched_reports_never_keep_positive_payloads() {
    let (c, scan, _) = fixture();
    let binding = Binding::from_config(&c).unwrap();
    for change in 0..8 {
        let mut scan = scan.clone();
        match change {
            0 => scan.heuristics.as_mut().unwrap().status = heuristics::Status::Limited,
            1 => scan
                .heuristics
                .as_mut()
                .unwrap()
                .limits_hit
                .push(heuristics::LimitHit::Findings),
            2 => scan.heuristics.as_mut().unwrap().settings_digest = "f".repeat(64),
            3 => scan.heuristics.as_mut().unwrap().status = heuristics::Status::InvalidMessage,
            4 => scan.content_inspection.as_mut().unwrap().status = content::Status::Incomplete,
            5 => scan.content_inspection.as_mut().unwrap().truncated = true,
            6 => scan.content_inspection.as_mut().unwrap().limits.max_parts += 1,
            _ => scan
                .content_inspection
                .as_mut()
                .unwrap()
                .findings
                .push(content::Finding {
                    id: content::FindingId::RawLimit,
                    part: None,
                }),
        }
        let e = LocalEvidence::capture(&binding, &scan);
        assert!(!e.tag_eligible(), "change {change}");
        e.validate().unwrap();
        if change < 4 {
            assert!(e.heuristics.rule_hits.iter().all(|hit| !hit));
        } else {
            assert_eq!(e.structure.findings, [false; 15]);
            assert_eq!(e.structure.counts, [0; 4]);
        }
    }
}

#[test]
fn malformed_findings_overflows_and_nonfinite_manual_values_are_invalid() {
    let (c, scan, _) = fixture();
    let binding = Binding::from_config(&c).unwrap();
    for change in 0..8 {
        let mut scan = scan.clone();
        let r = scan.heuristics.as_mut().unwrap();
        match change {
            0 => r.findings[0].id = "unknown_rule".into(),
            1 => r.findings.push(r.findings[0].clone()),
            2 => r.findings[0].matches = usize::MAX,
            3 => r.findings[0].candidate_weight = f64::NAN,
            4 => r.candidate_weight = f64::INFINITY,
            5 => r.contribution = -1.0,
            6 => r.findings[0].scopes = vec![Scope::Body; 5],
            _ => r.findings = vec![r.findings[0].clone(); 65],
        }
        let e = LocalEvidence::capture(&binding, &scan);
        assert_eq!(e.heuristics.state, State::Invalid, "change {change}");
        assert!(!e.tag_eligible());
        assert!(e.heuristics.rule_hits.iter().all(|hit| !hit));
    }
}

#[test]
fn typed_payload_and_catalogue_validation_reject_imported_contract_violations() {
    let (_, _, e) = fixture();
    for change in 0..8 {
        let mut changed = e.clone();
        match change {
            0 => changed.binding.heuristics.as_mut().unwrap().rule_ids = vec!["a".into(); 65],
            1 => changed.binding.heuristics.as_mut().unwrap().rule_ids = vec!["a".into(); 2],
            2 => {
                changed.binding.heuristics.as_mut().unwrap().rule_ids[0] =
                    "address@private.org".into()
            }
            3 => changed.heuristics.rule_hits.push(true),
            4 => changed.heuristics.rule_hits[63] = true,
            5 => changed.heuristics.state = State::Busy,
            6 => changed.structure.counts[0] = 257,
            _ => changed.binding.structure.as_mut().unwrap().settings_digest = "0".repeat(64),
        }
        assert!(changed.validate().is_err(), "change {change}");
        assert!(changed.values().is_err());
        assert!(!changed.tag_eligible());
    }
    let mut json = serde_json::to_value(&e).unwrap();
    json["raw_subject"] = "private".into();
    assert!(serde_json::from_value::<LocalEvidence>(json).is_err());
    let mut json = serde_json::to_value(&e).unwrap();
    json["structure"]["findings"] = serde_json::to_value(vec![true; 10]).unwrap();
    assert!(serde_json::from_value::<LocalEvidence>(json).is_err());
}

#[test]
fn clipped_counts_cannot_overflow_and_failed_refresh_keeps_binding() {
    let (c, mut scan, mut e) = fixture();
    let original_binding = e.binding.clone();
    scan.content_inspection.as_mut().unwrap().stats.images = usize::MAX;
    e.refresh(&scan);
    assert_eq!(value(&e, "structure.images_div256"), 1.0);
    let mut other = c.clone();
    other.heuristics.as_mut().unwrap().rules[0].pattern = "different".into();
    let changed_scan = inspect(
        &other,
        b"From: a@example.org\r\nSubject: different\r\n\r\nbody",
    );
    e.refresh(&changed_scan);
    assert_eq!(e.binding, original_binding);
    assert_eq!(e.heuristics.state, State::Invalid);
    assert!(!e.tag_eligible());
    e.refresh(&Scan::default());
    assert_eq!(e.profile(), "missing/missing");
    assert_eq!(e.binding, original_binding);
}

#[test]
fn configuration_validation_enforces_catalogue_pattern_and_numeric_limits() {
    let mut c = config();
    let template = c.heuristics.as_ref().unwrap().rules[0].clone();
    c.heuristics.as_mut().unwrap().rules = (0..64)
        .map(|i| Rule {
            id: format!("rule_{i:02}"),
            ..template.clone()
        })
        .collect();
    assert_eq!(
        Binding::from_config(&c)
            .unwrap()
            .heuristics
            .unwrap()
            .rule_ids
            .len(),
        64
    );
    c.heuristics.as_mut().unwrap().rules.push(Rule {
        id: "rule_64".into(),
        ..template
    });
    assert!(Binding::from_config(&c).is_err());
    for change in 0..5 {
        let mut c = config();
        let h = c.heuristics.as_mut().unwrap();
        match change {
            0 => h.rules[0].pattern = "x".repeat(4097),
            1 => h.rules[0].pattern = "(?=unsupported)".into(),
            2 => h.rules[0].candidate_weight = f64::NAN,
            3 => h.limits.max_total_matches = usize::MAX,
            _ => c.content_inspection.as_mut().unwrap().max_parts = usize::MAX,
        }
        assert!(Binding::from_config(&c).is_err(), "change {change}");
    }
}

#[test]
fn wrong_structure_reports_are_bounded_and_never_create_positive_features() {
    let (c, scan, _) = fixture();
    let binding = Binding::from_config(&c).unwrap();
    for change in 0..7 {
        let mut scan = scan.clone();
        let r = scan.content_inspection.as_mut().unwrap();
        match change {
            0 => r.findings = vec![r.findings[0].clone(); 513],
            1 => r.findings.push(r.findings[0].clone()),
            2 => r.parts[0].index = usize::MAX,
            3 => r.findings[0].part = Some(usize::MAX),
            4 => r.version = "other-parser-version".into(),
            5 => r.advisory = false,
            _ => r.parts = vec![r.parts[0].clone(); 257],
        }
        let e = LocalEvidence::capture(&binding, &scan);
        assert_eq!(e.structure.state, State::Invalid, "change {change}");
        assert_eq!(e.structure.findings, [false; 15]);
        assert_eq!(e.structure.counts, [0; 4]);
        assert!(!e.tag_eligible());
        e.validate().unwrap();
    }
}

#[test]
fn actual_detector_budget_exhaustion_is_partial_even_when_shared_worker_completes() {
    let mut c = config();
    c.heuristics.as_mut().unwrap().limits.max_input_bytes = 1;
    c.content_inspection.as_mut().unwrap().max_html_bytes = 1;
    let scan = inspect(&c, b"From: a@example.org\r\nSubject: Urgent\r\nContent-Type: text/html\r\n\r\n<p>Payez</p><script>active</script>");
    assert_eq!(
        scan.research_execution.as_ref().unwrap().status,
        research_engines::Status::Complete
    );
    let e = LocalEvidence::capture(&Binding::from_config(&c).unwrap(), &scan);
    assert_eq!(e.profile(), "partial/partial");
    assert!(!e.tag_eligible());
    assert!(e.heuristics.rule_hits.iter().all(|hit| !hit));
    assert_eq!(e.structure.findings, [false; 15]);
    assert_eq!(e.structure.counts, [0; 4]);
    e.validate().unwrap();
}

fn part(
    index: usize,
    kind: content::ContentKind,
    bytes: usize,
    width: Option<u32>,
    height: Option<u32>,
    frames: Option<u32>,
) -> content::PartReport {
    content::PartReport {
        index,
        kind,
        bytes,
        width,
        height,
        frames,
        complete: true,
    }
}

fn media_scan(c: &Config, parts: Vec<content::PartReport>) -> (Scan, LocalEvidence) {
    let mut scan = inspect(
        c,
        b"From: private@example.org\r\nSubject: Bonjour\r\n\r\nbody",
    );
    let r = scan.content_inspection.as_mut().unwrap();
    r.parts = parts;
    r.stats.parts = r.parts.len();
    let e = LocalEvidence::capture(&Binding::from_config(c).unwrap(), &scan);
    (scan, e)
}

#[test]
fn decoded_metadata_is_aggregated_by_format_without_per_part_output() {
    use content::ContentKind::*;
    let (_, e) = media_scan(
        &config(),
        vec![
            part(0, Png, 100, Some(2), Some(1), Some(1)),
            part(1, Jpeg, 200, Some(100), Some(50), None),
            part(2, Gif, 300, Some(10), Some(20), Some(4)),
            part(3, Png, 400, None, Some(30), Some(1)),
            part(4, Gif, 500, Some(5), None, None),
            part(5, Pdf, 600, Some(u32::MAX), Some(u32::MAX), Some(u32::MAX)),
            part(6, Pdf, 700, None, None, None),
            // Other formats do not masquerade as image/PDF bytes or dimensions.
            part(
                7,
                Other,
                usize::MAX,
                Some(u32::MAX),
                Some(u32::MAX),
                Some(u32::MAX),
            ),
        ],
    );
    e.validate().unwrap();
    assert!(e.tag_eligible());
    let m = &e.structure.media;
    assert_eq!(m.format_counts, [2, 1, 2, 2]);
    assert_eq!(
        (m.image_max_width, m.image_max_height, m.image_max_pixels),
        (100, 50, 5000)
    );
    assert_eq!((m.image_bytes, m.pdf_bytes), (1500, 1300));
    assert_eq!(
        (m.tiny_images, m.animated_images, m.missing_dimensions),
        (1, 1, 2)
    );
    for (name, expected) in [
        ("png_parts_div256", 2.0 / 256.0),
        ("jpeg_parts_div256", 1.0 / 256.0),
        ("gif_parts_div256", 2.0 / 256.0),
        ("pdf_parts_div256", 2.0 / 256.0),
        (
            "image_max_width_log16384",
            100.0_f64.ln_1p() / 16384.0_f64.ln_1p(),
        ),
        (
            "image_max_height_log16384",
            50.0_f64.ln_1p() / 16384.0_f64.ln_1p(),
        ),
        (
            "image_max_pixels_log100000000",
            5000.0_f64.ln_1p() / 100_000_000.0_f64.ln_1p(),
        ),
        (
            "image_bytes_log16777216",
            1500.0_f64.ln_1p() / 16_777_216.0_f64.ln_1p(),
        ),
        (
            "pdf_bytes_log16777216",
            1300.0_f64.ln_1p() / 16_777_216.0_f64.ln_1p(),
        ),
        ("tiny_images_div256", 1.0 / 256.0),
        ("animated_images_div256", 1.0 / 256.0),
        ("missing_dimensions_div256", 2.0 / 256.0),
    ] {
        assert_eq!(value(&e, &format!("structure.{name}")), expected, "{name}");
    }
    let serialized = serde_json::to_value(&e).unwrap();
    assert_eq!(
        serde_json::from_value::<LocalEvidence>(serialized.clone()).unwrap(),
        e
    );
    assert!(serialized["structure"].get("parts").is_none());
    assert!(serialized["structure"]["media"].get("frames").is_none());
    assert!(serialized["structure"]["media"].get("index").is_none());
}

#[test]
fn metadata_caps_handle_extreme_values_and_per_image_pixel_products() {
    use content::ContentKind::*;
    let (_, e) = media_scan(
        &config(),
        vec![
            part(
                0,
                Png,
                usize::MAX,
                Some(u32::MAX),
                Some(u32::MAX),
                Some(u32::MAX),
            ),
            part(1, Jpeg, usize::MAX, Some(1), Some(1), Some(2)),
            part(2, Pdf, usize::MAX, None, None, None),
            part(3, Pdf, usize::MAX, None, None, None),
        ],
    );
    e.validate().unwrap();
    assert_eq!(e.structure.media.image_max_width, local::DIMENSION_CAP);
    assert_eq!(e.structure.media.image_max_height, local::DIMENSION_CAP);
    assert_eq!(e.structure.media.image_max_pixels, local::PIXEL_CAP);
    assert_eq!(e.structure.media.image_bytes, local::MEDIA_BYTES_CAP);
    assert_eq!(e.structure.media.pdf_bytes, local::MEDIA_BYTES_CAP);
    for name in [
        "image_max_width_log16384",
        "image_max_height_log16384",
        "image_max_pixels_log100000000",
        "image_bytes_log16777216",
        "pdf_bytes_log16777216",
    ] {
        assert_eq!(value(&e, &format!("structure.{name}")), 1.0, "{name}");
    }
    assert!(
        e.values()
            .unwrap()
            .iter()
            .all(|x| x.is_finite() && (0.0..=1.0).contains(x))
    );
    // Max width * max height would invent a large image from two skinny ones.
    let (_, e) = media_scan(
        &config(),
        vec![
            part(0, Png, 10, Some(20_000), Some(1), None),
            part(1, Png, 20, Some(1), Some(30_000), None),
        ],
    );
    assert_eq!(e.structure.media.image_max_pixels, 30_000);
    let mut c = config();
    c.content_inspection.as_mut().unwrap().max_parts = 256;
    let (_, e) = media_scan(
        &c,
        (0..256)
            .map(|i| part(i, Gif, usize::MAX, Some(2), Some(2), Some(2)))
            .collect(),
    );
    assert_eq!(e.structure.media.format_counts, [0, 0, 256, 0]);
    assert_eq!(e.structure.media.tiny_images, 256);
    assert_eq!(e.structure.media.animated_images, 256);
    assert_eq!(e.structure.media.image_bytes, local::MEDIA_BYTES_CAP);
    e.validate().unwrap();
}

#[test]
fn log_metadata_preserves_zero_and_small_values_without_rescaling_counts() {
    let (_, empty) = media_scan(&config(), vec![]);
    let (_, tiny) = media_scan(
        &config(),
        vec![
            part(0, content::ContentKind::Png, 1, Some(1), Some(1), Some(2)),
            part(1, content::ContentKind::Pdf, 1, None, None, None),
        ],
    );
    for (name, cap) in [
        ("image_max_width_log16384", 16384.0_f64),
        ("image_max_height_log16384", 16384.0),
        ("image_max_pixels_log100000000", 100_000_000.0),
        ("image_bytes_log16777216", 16_777_216.0),
        ("pdf_bytes_log16777216", 16_777_216.0),
    ] {
        let key = format!("structure.{name}");
        assert_eq!(value(&empty, &key), 0.0);
        let transformed = value(&tiny, &key);
        assert_eq!(transformed, 1.0_f64.ln_1p() / cap.ln_1p());
        assert!(transformed > 0.01 && transformed < 1.0);
    }
    for name in [
        "png_parts_div256",
        "pdf_parts_div256",
        "tiny_images_div256",
        "animated_images_div256",
    ] {
        assert_eq!(value(&tiny, &format!("structure.{name}")), 1.0 / 256.0);
    }
    assert_eq!(tiny.structure.media.image_max_width, 1);
    assert_eq!(tiny.structure.media.image_max_pixels, 1);
    assert_eq!(tiny.structure.media.image_bytes, 1);
    assert_eq!(tiny.structure.media.pdf_bytes, 1);
}

#[test]
fn additional_flags_are_observations_and_embedded_office_stays_partial() {
    use content::FindingId::*;
    let c = config();
    let (mut scan, _) = media_scan(&c, vec![]);
    scan.content_inspection.as_mut().unwrap().findings = [
        ImageDimensions,
        ImageCount,
        HtmlRefresh,
        HtmlEmbeddedContent,
        PdfExternalReference,
        OfficeMacroEnabled,
    ]
    .into_iter()
    .map(|id| content::Finding { id, part: None })
    .collect();
    let binding = Binding::from_config(&c).unwrap();
    let e = LocalEvidence::capture(&binding, &scan);
    assert!(e.tag_eligible());
    assert_eq!(&e.structure.findings[9..], &[true; 6]);
    assert_eq!(&e.values().unwrap()[91..97], &[1.0; 6]);
    scan.content_inspection
        .as_mut()
        .unwrap()
        .findings
        .push(content::Finding {
            id: OfficeEmbeddedObject,
            part: None,
        });
    let e = LocalEvidence::capture(&binding, &scan);
    assert_eq!(e.structure.state, State::Partial);
    assert!(!e.tag_eligible());
    assert_eq!(e.structure.findings, [false; 15]);
    assert_eq!(e.structure.media, local::MediaEvidence::default());
}

#[test]
fn metadata_is_zero_after_any_incomplete_report_or_worker_failure() {
    let c = config();
    let (scan, original) = media_scan(
        &c,
        vec![part(
            0,
            content::ContentKind::Png,
            100,
            Some(2),
            Some(2),
            Some(3),
        )],
    );
    assert!(original.structure.media.image_bytes > 0);
    for change in 0..6 {
        let mut changed = scan.clone();
        match change {
            0 => {
                changed.research_execution.as_mut().unwrap().status = research_engines::Status::Busy
            }
            1 => changed.content_inspection.as_mut().unwrap().truncated = true,
            2 => changed.content_inspection.as_mut().unwrap().parts[0].complete = false,
            3 => changed.content_inspection.as_mut().unwrap().status = content::Status::Incomplete,
            4 => changed.content_inspection = None,
            _ => changed.content_inspection.as_mut().unwrap().version = "invalid".into(),
        }
        let mut e = original.clone();
        e.refresh(&changed);
        assert!(!e.tag_eligible(), "change {change}");
        assert_eq!(e.structure.media, local::MediaEvidence::default());
        assert!(e.values().unwrap()[78..].iter().all(|v| *v == 0.0));
        e.structure.media = original.structure.media.clone();
        assert!(e.validate().is_err(), "partial media cannot survive import");
    }
}

#[test]
fn imported_metadata_rejects_bounds_wrong_types_and_inconsistent_counts() {
    let (_, original) = media_scan(
        &config(),
        vec![part(
            0,
            content::ContentKind::Png,
            10,
            Some(1),
            Some(1),
            Some(2),
        )],
    );
    for field in [
        "image_max_width",
        "image_max_height",
        "image_max_pixels",
        "image_bytes",
        "pdf_bytes",
        "tiny_images",
        "animated_images",
        "missing_dimensions",
    ] {
        let mut json = serde_json::to_value(&original).unwrap();
        json["structure"]["media"][field] = serde_json::json!(u64::MAX);
        assert!(
            !serde_json::from_value::<LocalEvidence>(json).is_ok_and(|e| e.validate().is_ok()),
            "{field}"
        );
    }
    let mut e = original.clone();
    e.structure.media.format_counts[0] = 257;
    assert!(e.validate().is_err());
    e = original.clone();
    e.structure.media.format_counts = [0; 4];
    assert!(e.validate().is_err());
    e = original.clone();
    e.structure.media.missing_dimensions = 1; // same image cannot also be tiny
    assert!(e.validate().is_err());
    let mut json = serde_json::to_value(&original).unwrap();
    json["structure"]["media"]["image_bytes"] = serde_json::json!(-1);
    assert!(serde_json::from_value::<LocalEvidence>(json).is_err());
    let mut json = serde_json::to_value(&original).unwrap();
    json["structure"]["media"]["raw_parts"] = serde_json::json!(["private.jpg"]);
    assert!(serde_json::from_value::<LocalEvidence>(json).is_err());
}

#[test]
fn native_mime_image_and_pdf_parsers_feed_metadata_features_without_raw_lists() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use std::io::Write;
    // Small structural fixtures, not assertions about rendering every format.
    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    let mut chunk = |tag: &[u8], bytes: &[u8]| {
        png.extend((bytes.len() as u32).to_be_bytes());
        let start = png.len();
        png.extend(tag);
        png.extend(bytes);
        png.extend(crc32fast::hash(&png[start..]).to_be_bytes());
    };
    let mut header = 2u32.to_be_bytes().to_vec();
    header.extend(2u32.to_be_bytes());
    header.extend([8, 0, 0, 0, 0]);
    chunk(b"IHDR", &header);
    let mut zip = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    zip.write_all(&[0, 1, 2, 0, 3, 4]).unwrap();
    chunk(b"IDAT", &zip.finish().unwrap());
    chunk(b"IEND", &[]);
    let jpeg = vec![
        0xff, 0xd8, 0xff, 0xc0, 0, 11, 8, 0, 1, 0, 2, 1, 1, 0x11, 0, 0xff, 0xda, 0, 8, 1, 1, 0, 0,
        63, 0, 0x42, 0xff, 0, 0xff, 0xd9,
    ];
    let mut gif = STANDARD
        .decode("R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==")
        .unwrap();
    let frame = gif[19..gif.len() - 1].to_vec();
    gif.pop();
    gif.extend(frame);
    gif.push(0x3b);
    let mut pdf = b"%PDF-1.7\n".to_vec();
    let offset = pdf.len();
    pdf.extend(b"1 0 obj\n<< /Type /Catalog >>\nendobj\n");
    let xref = pdf.len();
    pdf.extend(format!("xref\n0 2\n0000000000 65535 f \n{offset:010} 00000 n \ntrailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n").as_bytes());
    let image_bytes = png.len() + jpeg.len() + gif.len();
    let mut raw = "From: private@example.org\r\nSubject: metadata canary\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=m\r\n\r\n".to_string();
    for (mime, bytes) in [
        ("image/png", &png),
        ("image/jpeg", &jpeg),
        ("image/gif", &gif),
        ("application/pdf", &pdf),
    ] {
        raw.push_str(&format!("--m\r\nContent-Type: {mime}\r\nContent-Disposition: attachment; filename=private-canary.bin\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n", STANDARD.encode(bytes)));
    }
    raw.push_str("--m--\r\n");
    let c = config();
    let scan = inspect(&c, raw.as_bytes());
    assert_eq!(
        scan.content_inspection.as_ref().unwrap().status,
        content::Status::Complete
    );
    let e = LocalEvidence::capture(&Binding::from_config(&c).unwrap(), &scan);
    assert!(e.tag_eligible());
    let m = &e.structure.media;
    assert_eq!(m.format_counts, [1, 1, 1, 1]);
    assert_eq!(
        (m.image_max_width, m.image_max_height, m.image_max_pixels),
        (2, 2, 4)
    );
    assert_eq!(
        (m.image_bytes, m.pdf_bytes),
        (image_bytes as u64, pdf.len() as u64)
    );
    assert_eq!(
        (m.tiny_images, m.animated_images, m.missing_dimensions),
        (3, 1, 0)
    );
    let json = serde_json::to_string(&e).unwrap();
    assert!(!json.contains("canary") && !json.contains("private@example.org"));
    assert_eq!(value(&e, "structure.animated_images_div256"), 1.0 / 256.0);
    assert_eq!(value(&e, "structure.pdf_parts_div256"), 1.0 / 256.0);
}
