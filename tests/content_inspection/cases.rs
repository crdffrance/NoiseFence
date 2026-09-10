use super::*;
use std::io::Write;

fn message(mime: &str, body: &[u8]) -> Vec<u8> {
    format!("From: private@example.invalid\r\nContent-Type: {mime}\r\nContent-Transfer-Encoding: base64\r\n\r\n{}", STANDARD.encode(body)).into_bytes()
}
fn scan(mime: &str, body: &[u8]) -> Report {
    analyze(&message(mime, body), &Settings::default())
}
fn has(r: &Report, id: FindingId) -> bool {
    r.findings.iter().any(|f| f.id == id)
}
fn incomplete(r: &Report) {
    assert_eq!(r.status, Status::Incomplete, "{r:#?}");
}
fn zlib(b: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(b).unwrap();
    e.finish().unwrap()
}
fn chunk(tag: &[u8], data: &[u8]) -> Vec<u8> {
    let mut out = (data.len() as u32).to_be_bytes().to_vec();
    out.extend(tag);
    out.extend(data);
    out.extend(crc32fast::hash(&out[4..]).to_be_bytes());
    out
}
fn png(w: u32, h: u32, rows: &[u8]) -> Vec<u8> {
    png_idat(w, h, 0, &zlib(rows))
}
fn png_idat(w: u32, h: u32, color: u8, compressed: &[u8]) -> Vec<u8> {
    let mut b = b"\x89PNG\r\n\x1a\n".to_vec();
    let mut ihdr = w.to_be_bytes().to_vec();
    ihdr.extend(h.to_be_bytes());
    ihdr.extend([8, color, 0, 0, 0]);
    b.extend(chunk(b"IHDR", &ihdr));
    b.extend(chunk(b"IDAT", compressed));
    b.extend(chunk(b"IEND", &[]));
    b
}
fn gif() -> Vec<u8> {
    STANDARD
        .decode("R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==")
        .unwrap()
}
fn jpeg() -> Vec<u8> {
    vec![
        0xff, 0xd8, 0xff, 0xc0, 0, 11, 8, 0, 1, 0, 2, 1, 1, 0x11, 0, 0xff, 0xda, 0, 8, 1, 1, 0, 0,
        63, 0, 0x42, 0xff, 0, 0xff, 0xd9,
    ]
}
fn pdf(objects: &[&[u8]]) -> Vec<u8> {
    let mut b = b"%PDF-1.7\n".to_vec();
    let mut offsets = Vec::new();
    for (i, obj) in objects.iter().enumerate() {
        offsets.push(b.len());
        b.extend(format!("{} 0 obj\n", i + 1).as_bytes());
        b.extend(*obj);
        b.extend(b"\nendobj\n");
    }
    let xref = b.len();
    b.extend(format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1).as_bytes());
    for offset in offsets {
        b.extend(format!("{offset:010} 00000 n \n").as_bytes());
    }
    b.extend(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
            objects.len() + 1
        )
        .as_bytes(),
    );
    b
}
fn stream(dict: &str, content: &[u8]) -> Vec<u8> {
    let mut out = format!("<< /Length {} {dict} >>\nstream\n", content.len()).into_bytes();
    out.extend(content);
    out.extend(b"\nendstream");
    out
}
fn object_stream(payload: &[u8]) -> Vec<u8> {
    let mut data = b"2 0 ".to_vec();
    data.extend(payload);
    stream(
        "/Type /ObjStm /N 1 /First 4 /Filter /FlateDecode",
        &zlib(&data),
    )
}
const TYPES: &[u8] = b"<Types xmlns='http://schemas.openxmlformats.org/package/2006/content-types'><Default Extension='xml' ContentType='application/xml'/></Types>";
fn zip(entries: &[(&str, &[u8])], deflate: bool) -> Vec<u8> {
    let mut archive = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default().compression_method(if deflate {
        zip::CompressionMethod::Deflated
    } else {
        zip::CompressionMethod::Stored
    });
    for (name, data) in entries {
        archive.start_file(*name, options).unwrap();
        archive.write_all(data).unwrap();
    }
    archive.finish().unwrap().into_inner()
}
fn cfb(names: &[&str]) -> Vec<u8> {
    let mut file = cfb::CompoundFile::create(Cursor::new(Vec::new())).unwrap();
    for name in names {
        file.create_storage_all(name).unwrap();
    }
    file.into_inner().into_inner()
}

#[test]
fn defaults_validate_and_round_trip_with_strict_schema() {
    let s: Settings = serde_json::from_str("{}").unwrap();
    s.validate().unwrap();
    assert_eq!(s, Settings::default());
    assert!(serde_json::from_str::<Settings>("{\"unexpected\":1}").is_err());
    let r = scan("text/plain", b"ordinary body");
    assert_eq!(r.status, Status::Complete);
    assert_eq!(
        serde_json::from_str::<Report>(&serde_json::to_string(&r).unwrap()).unwrap(),
        r
    );
}
#[test]
fn invalid_settings_never_parse_or_panic() {
    let settings = [
        Settings {
            max_parts: 0,
            ..Settings::default()
        },
        Settings {
            max_nesting: usize::MAX,
            ..Settings::default()
        },
        Settings {
            max_total_unpacked_bytes: usize::MAX,
            ..Settings::default()
        },
        Settings {
            max_image_pixels: 0,
            ..Settings::default()
        },
    ];
    for s in settings {
        assert!(s.validate().is_err());
        let r = analyze(b"garbage", &s);
        assert_eq!(r.status, Status::InvalidSettings);
        assert_eq!(r.stats.parts, 0);
    }
}
#[test]
fn raw_and_header_limits_precede_parsing() {
    let s = Settings {
        max_raw_bytes: 3,
        ..Settings::default()
    };
    let r = analyze(b"abcd", &s);
    assert!(has(&r, FindingId::RawLimit));
    assert!(r.truncated);
    assert_eq!(r.stats.parts, 0);
    let s = Settings {
        max_header_bytes: 5,
        ..Settings::default()
    };
    let r = analyze(b"Content-Type: text/html\r\n\r\n<script>", &s);
    assert!(has(&r, FindingId::HeaderLimit));
    incomplete(&r);
}
#[test]
fn decoded_limit_and_invalid_base64_are_explicit() {
    let s = Settings {
        max_part_bytes: 3,
        ..Settings::default()
    };
    let r = analyze(&message("text/plain", b"four"), &s);
    assert!(has(&r, FindingId::DecodedLimit));
    assert!(r.truncated);
    let r = analyze(
        b"Content-Type: text/html\r\nContent-Transfer-Encoding: base64\r\n\r\nPHNj!!!",
        &Settings::default(),
    );
    assert!(has(&r, FindingId::MalformedMime));
    incomplete(&r);
}
#[test]
fn quoted_printable_decoding_precedes_html_parsing() {
    let r = analyze(b"Content-Type: text/html\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n<a href=3D'java=\r\nscript:secret'>x</a>",&Settings::default());
    assert!(has(&r, FindingId::HtmlActiveUrl));
    let r = analyze(
        b"Content-Type: text/html\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n=GG",
        &Settings::default(),
    );
    incomplete(&r);
}
#[test]
fn multipart_missing_close_and_part_budget_never_look_complete() {
    let raw = b"Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/html\r\n\r\n<script>x</script>\r\n";
    let r = analyze(raw, &Settings::default());
    incomplete(&r);
    assert!(has(&r, FindingId::HtmlActiveElement));
    let r = analyze(
        raw,
        &Settings {
            max_parts: 1,
            ..Settings::default()
        },
    );
    assert_eq!(r.stats.parts, 1);
    assert!(has(&r, FindingId::PartLimit));
    assert!(r.truncated);
}
#[test]
fn nested_messages_share_global_byte_and_depth_limits() {
    let leaf = message("text/html", b"<script>private</script>");
    let nested = message("message/rfc822", &message("message/rfc822", &leaf));
    let r = analyze(
        &nested,
        &Settings {
            max_mime_depth: 1,
            ..Settings::default()
        },
    );
    assert!(has(&r, FindingId::MimeDepthLimit));
    incomplete(&r);
    let r = analyze(&nested, &Settings::default());
    assert!(has(&r, FindingId::HtmlActiveElement));
    assert_eq!(r.stats.parts, 3);
}
#[test]
fn duplicate_mime_headers_are_incomplete() {
    let r = analyze(
        b"Content-Type: text/plain\r\nContent-Type: text/html\r\n\r\n<script>x</script>",
        &Settings::default(),
    );
    assert!(has(&r, FindingId::MalformedMime));
    incomplete(&r);
}
#[test]
fn html5_entities_case_and_controls_detect_active_attributes() {
    let r = scan("text/html",b"<A HREF=' &#x6a;ava&#x09;script:secret'>x</A><img oNerror='secret'><iframe srcdoc='secret'></iframe><meta HTTP-EQUIV='Refresh'>");
    for id in [
        FindingId::HtmlActiveUrl,
        FindingId::HtmlEventHandler,
        FindingId::HtmlActiveElement,
        FindingId::HtmlEmbeddedContent,
        FindingId::HtmlRefresh,
    ] {
        assert!(has(&r, id), "{id:?}");
    }
}
#[test]
fn html_text_comments_and_raw_text_do_not_trigger_grep_false_positives() {
    let r = scan("text/html",b"<!-- <script>secret</script> --><textarea><img onerror='secret'></textarea><p>&lt;script&gt; javascript: words</p>");
    assert!(r.findings.is_empty(), "{r:#?}");
}
#[test]
fn html_limits_and_non_utf8_are_reported() {
    let r = analyze(
        &message("text/html", b"<script>x</script>"),
        &Settings {
            max_html_bytes: 5,
            ..Settings::default()
        },
    );
    assert!(has(&r, FindingId::HtmlLimit));
    assert!(r.truncated);
    for data in [&b"\xff<script>"[..], &b"<\0s\0c\0r\0i\0p\0t\0>"[..]] {
        assert!(has(
            &scan("text/html", data),
            FindingId::UnsupportedEncoding
        ));
    }
}
#[test]
fn no_secrets_in_reports_even_when_they_trigger_findings() {
    let r = scan(
        "text/html",
        b"<script>SECRET_BODY</script><a href='javascript:SECRET_LINK'>SECRET_VISIBLE</a>",
    );
    let json = serde_json::to_string(&r).unwrap();
    assert!(!json.contains("SECRET"));
    assert!(!json.contains("private@example"));
    assert!(r.advisory);
    assert_eq!(r.version, REPORT_VERSION);
}
#[test]
fn finding_budget_marks_truncation_even_for_successful_parser() {
    let r = analyze(
        &message("text/html", b"<script>x</script><img onerror='x'>"),
        &Settings {
            max_findings: 1,
            ..Settings::default()
        },
    );
    assert_eq!(r.findings.len(), 1);
    assert!(r.truncated);
    incomplete(&r);
    assert!(!r.parts[0].complete);
}
#[test]
fn structure_budget_is_global() {
    let r = analyze(
        &message("text/html", b"<p>a</p><p>b</p>"),
        &Settings {
            max_structure_nodes: 1,
            ..Settings::default()
        },
    );
    assert!(has(&r, FindingId::StructureLimit));
    assert_eq!(r.stats.structure_nodes, 1);
    incomplete(&r);
}
#[test]
fn png_crc_scanlines_and_dimensions_are_checked() {
    let valid = png(2, 2, &[0, 1, 2, 0, 3, 4]);
    let r = scan("image/png", &valid);
    assert_eq!(r.status, Status::Complete, "{r:#?}");
    assert_eq!((r.parts[0].width, r.parts[0].height), (Some(2), Some(2)));
    assert_eq!(r.stats.images, 1);
    let mut corrupt = valid.clone();
    corrupt[29] ^= 1;
    assert!(has(
        &scan("image/png", &corrupt),
        FindingId::ImageStructureInvalid
    ));
    assert!(has(
        &scan("image/png", &png(2, 2, &[0, 1, 2])),
        FindingId::ImageStructureInvalid
    ));
    assert!(has(
        &scan("image/png", &png(2, 2, &[5, 1, 2, 0, 3, 4])),
        FindingId::ImageStructureInvalid
    ));
}
#[test]
fn png_bombs_large_dimensions_and_trailing_polyglot_are_incomplete() {
    let r = scan("image/png", &png(u32::MAX, u32::MAX, &[0]));
    assert!(has(&r, FindingId::ImageDimensions));
    assert!(has(&r, FindingId::DecompressionLimit));
    incomplete(&r);
    let mut b = png(1, 1, &[0, 0]);
    b.extend(b"<script>secret</script>");
    let r = scan("image/png", &b);
    assert!(has(&r, FindingId::TrailingData));
    incomplete(&r);
}
#[test]
fn png_high_compression_banners_are_complete_with_bounded_row_storage() {
    for (color, channels) in [(0, 1), (2, 3), (6, 4)] {
        let row = 1300 * channels + 1;
        let mut rows = vec![255; row * 650];
        for filter in rows.iter_mut().step_by(row) {
            *filter = 0;
        }
        let compressed = zlib(&rows);
        assert!(rows.len() > compressed.len() * 100);
        let r = scan("image/png", &png_idat(1300, 650, color, &compressed));
        assert_eq!(r.status, Status::Complete, "{r:#?}");
        assert_eq!(r.stats.unpacked_bytes, rows.len());
        assert!(!has(&r, FindingId::DecompressionLimit));
    }
}
#[test]
fn png_row_filters_cross_scratch_buffer_boundaries() {
    for row in [3, 8191, 8192, 8193, 16387] {
        let mut rows = vec![255; row * 7];
        for (i, filter) in rows.iter_mut().step_by(row).enumerate() {
            *filter = (i % 5) as u8;
        }
        assert_eq!(
            scan("image/png", &png((row - 1) as u32, 7, &rows)).status,
            Status::Complete
        );
        // Put the invalid filter beyond the first scratch buffer in every case.
        let bad = if row == 3 { 8193 } else { row * 2 };
        let height = if row == 3 { 3000 } else { 7 };
        if row == 3 {
            rows = vec![0; row * height];
        }
        rows[bad] = 5;
        let r = scan("image/png", &png((row - 1) as u32, height as u32, &rows));
        incomplete(&r);
        assert!(has(&r, FindingId::ImageStructureInvalid));
    }
}
#[test]
fn png_exact_length_rejects_forged_small_dimensions_without_expanding_bomb() {
    let bomb = zlib(&vec![0; 2 * MIB]);
    let r = scan("image/png", &png_idat(1, 1, 0, &bomb));
    incomplete(&r);
    assert!(has(&r, FindingId::ImageStructureInvalid));
    assert_eq!(r.stats.unpacked_bytes, 2);
    let r = scan("image/png", &png(2, 2, &[0; 5]));
    incomplete(&r);
    assert!(has(&r, FindingId::ImageStructureInvalid));
}
#[test]
fn png_stream_checksum_truncation_and_concatenation_are_rejected() {
    let valid = zlib(&vec![0; 20_000]);
    for n in 0..valid.len() {
        let r = scan("image/png", &png_idat(99, 200, 0, &valid[..n]));
        incomplete(&r);
        assert!(has(&r, FindingId::ImageStructureInvalid));
        assert!(r.stats.unpacked_bytes <= 20_000);
    }
    let mut corrupt = valid.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    let mut concatenated = valid.clone();
    concatenated.extend(zlib(&[]));
    let mut trailing = valid;
    trailing.push(0);
    for compressed in [corrupt, concatenated, trailing] {
        let r = scan("image/png", &png_idat(99, 200, 0, &compressed));
        incomplete(&r);
        assert!(has(&r, FindingId::ImageStructureInvalid));
    }
}
#[test]
fn png_absolute_and_shared_unpacked_limits_remain_hard_bounds() {
    let image = png(99, 100, &vec![0; 10_000]);
    let r = analyze(
        &message("image/png", &image),
        &Settings {
            max_unpacked_bytes: 9999,
            ..Settings::default()
        },
    );
    incomplete(&r);
    assert!(has(&r, FindingId::DecompressionLimit));
    assert_eq!(r.stats.unpacked_bytes, 0);
    let mut raw = b"Content-Type: multipart/mixed; boundary=x\r\n\r\n".to_vec();
    for _ in 0..3 {
        raw.extend(b"--x\r\n");
        raw.extend(message("image/png", &image));
        raw.extend(b"\r\n");
    }
    raw.extend(b"--x--\r\n");
    let r = analyze(
        &raw,
        &Settings {
            max_unpacked_bytes: 10_000,
            max_total_unpacked_bytes: 20_000,
            max_compression_ratio: 1,
            ..Settings::default()
        },
    );
    incomplete(&r);
    assert!(has(&r, FindingId::DecompressionLimit));
    assert_eq!(r.stats.unpacked_bytes, 20_000);
    assert!(r.parts[0].complete && r.parts[1].complete && !r.parts[2].complete);
}
#[test]
fn image_type_and_count_consistency() {
    let r = scan("image/jpeg", &png(1, 1, &[0, 1]));
    assert!(has(&r, FindingId::TypeMismatch));
    assert_eq!(r.parts[0].kind, ContentKind::Png);
    let mut raw = b"Content-Type: multipart/mixed; boundary=x\r\n\r\n".to_vec();
    for _ in 0..3 {
        raw.extend(b"--x\r\n");
        raw.extend(message("image/gif", &gif()));
        raw.extend(b"\r\n");
    }
    raw.extend(b"--x--\r\n");
    let r = analyze(
        &raw,
        &Settings {
            max_images: 2,
            ..Settings::default()
        },
    );
    assert_eq!(r.stats.images, 3);
    assert!(has(&r, FindingId::ImageCount));
}
#[test]
fn jpeg_markers_entropy_stuffing_and_gif_frames_are_structural() {
    let r = scan("image/jpeg", &jpeg());
    assert_eq!(r.status, Status::Complete, "{r:#?}");
    assert_eq!(r.parts[0].width, Some(2));
    let r = scan("image/gif", &gif());
    assert_eq!(r.status, Status::Complete, "{r:#?}");
    assert_eq!(r.parts[0].frames, Some(1));
    let mut bad = jpeg();
    bad.truncate(bad.len() - 2);
    incomplete(&scan("image/jpeg", &bad));
    let mut bad = gif();
    bad[24] = 2;
    incomplete(&scan("image/gif", &bad));
}
#[test]
fn unsupported_image_is_never_a_complete_attachment_report() {
    incomplete(&scan("image/webp", b"RIFFxxxxWEBP"));
}
#[test]
fn pdf_escaped_active_names_detected_with_no_leakage() {
    let r = scan("application/pdf",&pdf(&[b"<< /Type /Catalog /Open#41ction << /S /Java#53cript /J#53 (PRIVATE_PDF_PAYLOAD) >> >>"]));
    assert!(has(&r, FindingId::PdfActiveName));
    assert_eq!(r.status, Status::Complete, "{r:#?}");
    assert!(
        !serde_json::to_string(&r)
            .unwrap()
            .contains("PRIVATE_PDF_PAYLOAD")
    );
}
#[test]
fn pdf_strings_comments_hex_and_ordinary_streams_are_not_names() {
    let content = stream("", b"/JS /JavaScript endobj /Launch");
    let r = scan(
        "application/pdf",
        &pdf(&[
            b"<< /Type /Catalog /Title (/JS \\( /JavaScript) /Other <2f4a53> >>\n% /Launch\n",
            &content,
        ]),
    );
    assert!(!has(&r, FindingId::PdfActiveName), "{r:#?}");
}
#[test]
fn flate_pdf_object_stream_detects_escaped_names() {
    let obj = object_stream(b"<< /S /Java#53cript /JS (secret) >>");
    let r = scan("application/pdf", &pdf(&[b"<< /Type /Catalog >>", &obj]));
    assert!(has(&r, FindingId::PdfActiveName));
    assert_eq!(r.status, Status::Complete, "{r:#?}");
    assert!(r.stats.unpacked_bytes > 0);
}
#[test]
fn pdf_object_stream_bombs_and_truncated_flate_report_incomplete() {
    let bomb = object_stream(&vec![b' '; 100_000]);
    let r = scan("application/pdf", &pdf(&[&bomb]));
    assert!(has(&r, FindingId::DecompressionLimit));
    assert!(r.truncated);
    let compressed = zlib(b"2 0 << /JS (x) >>");
    let broken = stream(
        "/Type /ObjStm /N 1 /First 4 /Filter /FlateDecode",
        &compressed[..compressed.len() - 2],
    );
    incomplete(&scan("application/pdf", &pdf(&[&broken])));
}
#[test]
fn pdf_indirect_lengths_unsupported_filters_and_encryption_are_explicit() {
    let r = scan(
        "application/pdf",
        &pdf(&[b"<< /Length 2 0 R >>\nstream\na\nendstream", b"1"]),
    );
    assert!(has(&r, FindingId::PdfUnsupportedStructure));
    incomplete(&r);
    let b = stream("/Filter /LZWDecode", b"garbage");
    let r = scan("application/pdf", &pdf(&[&b]));
    assert!(has(&r, FindingId::PdfUnsupportedFilter));
    incomplete(&r);
    let r = scan(
        "application/pdf",
        &pdf(&[b"<< /Encrypt 2 0 R /EmbeddedFiles 3 0 R >>"]),
    );
    assert!(has(&r, FindingId::PdfEncrypted));
    assert!(has(&r, FindingId::PdfEmbeddedFile));
    incomplete(&r);
}
#[test]
fn pdf_malformed_names_nested_objects_and_duplicate_keys_are_bounded() {
    for obj in [
        &b"<< /Java#XXScript 1 >>"[..],
        &b"<< /JS (x) /JS (y) >>"[..],
        &b"[ [ [ [ [ 1 ] ] ] ] ]"[..],
    ] {
        let r = analyze(
            &message("application/pdf", &pdf(&[obj])),
            &Settings {
                max_nesting: 3,
                ..Settings::default()
            },
        );
        incomplete(&r);
    }
}
#[test]
fn pdf_missing_eof_and_trailing_polyglot_are_incomplete() {
    let mut b = pdf(&[b"<< /Type /Catalog >>"]);
    b.extend(b"PK\x03\x04tail");
    incomplete(&scan("application/pdf", &b));
    let b = pdf(&[b"<< /Type /Catalog >>"]);
    incomplete(&scan("application/pdf", &b[..b.len() - 6]));
}
#[test]
fn office_zip_checks_deflate_and_xml_entities() {
    let types = b"<Types xmlns='http://schemas.openxmlformats.org/package/2006/content-types'><Override PartName='/word/document.xml' ContentType='application/vnd.ms-word.document.macro&#69;nabled.main+xml'/></Types>";
    let archive = zip(&[("[Content_Types].xml", types)], true);
    let r = scan("application/octet-stream", &archive);
    assert!(has(&r, FindingId::OfficeMacroEnabled));
    assert_eq!(r.status, Status::Complete, "{r:#?}");
    let r = scan(
        "application/zip",
        &zip(&[("[Content_Types].xml", TYPES)], false),
    );
    assert_eq!(r.status, Status::Complete, "{r:#?}");
}
#[test]
fn office_macro_words_in_comments_do_not_trigger() {
    let types = b"<Types><!-- <Override ContentType='macroEnabled'/> --><Default Extension='txt' ContentType='text/plain'/></Types>";
    let r = scan(
        "application/zip",
        &zip(
            &[
                ("[Content_Types].xml", types),
                ("word/document.xml", b"macroEnabled vbaProject.bin"),
            ],
            false,
        ),
    );
    assert!(!has(&r, FindingId::OfficeMacroEnabled));
    assert!(!has(&r, FindingId::OfficeVbaProject));
}
#[test]
fn office_xml_xxe_malformed_multiple_roots_and_encoding_are_incomplete() {
    for xml in [
        &b"<!DOCTYPE Types [<!ENTITY x SYSTEM 'file:///secret'>]><Types>&x;</Types>"[..],
        &b"<Types><x></Types>"[..],
        &b"<Types/><Types/>"[..],
        &b"<?xml version='1.0' encoding='UTF-16'?><Types/>"[..],
        &b"<garbage/>"[..],
    ] {
        let r = scan(
            "application/zip",
            &zip(&[("[Content_Types].xml", xml)], false),
        );
        incomplete(&r);
    }
}
#[test]
fn office_external_relationships_and_xlm_macros_are_advisory() {
    let rel = b"<Relationships><Relationship Id='rId1' TargetMode='External' Target='https://PRIVATE.invalid/SECRET' Type='http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink'/></Relationships>";
    let r = scan(
        "application/zip",
        &zip(
            &[
                ("[Content_Types].xml", TYPES),
                ("_rels/.rels", rel),
                ("xl/macrosheets/sheet1.xml", b"<worksheet/>"),
            ],
            false,
        ),
    );
    assert!(has(&r, FindingId::OfficeExternalRelationship));
    assert!(has(&r, FindingId::OfficeXlmMacros));
    assert!(!serde_json::to_string(&r).unwrap().contains("PRIVATE"));
}
#[test]
fn office_vba_cfb_and_encrypted_office_are_structurally_detected() {
    let vba = cfb(&["/VBA"]);
    let r = scan("application/msword", &vba);
    assert!(has(&r, FindingId::OfficeVbaProject));
    assert!(has(&r, FindingId::OfficeLegacyCoverage));
    incomplete(&r);
    let r = scan(
        "application/zip",
        &zip(
            &[
                ("[Content_Types].xml", TYPES),
                ("word/vbaProject.bin", &vba),
            ],
            false,
        ),
    );
    assert!(has(&r, FindingId::OfficeVbaProject));
    assert!(!has(&r, FindingId::CompoundMalformed), "{r:#?}");
    let r = scan(
        "application/msword",
        &cfb(&["/EncryptedPackage", "/EncryptionInfo"]),
    );
    assert!(has(&r, FindingId::OfficeEncrypted));
    incomplete(&r);
}
#[test]
fn cfb_bogus_header_and_cycles_are_incomplete() {
    let mut b = cfb(&["/VBA"]);
    b[48..52].copy_from_slice(&0xfffffffcu32.to_le_bytes());
    incomplete(&scan("application/msword", &b));
    incomplete(&scan("application/msword", b"VBA _VBA_PROJECT"));
}
#[test]
fn zip_entry_limits_precede_archive_open() {
    let b = zip(&[("[Content_Types].xml", TYPES), ("a", b"a")], false);
    let r = analyze(
        &message("application/zip", &b),
        &Settings {
            max_archive_entries: 1,
            ..Settings::default()
        },
    );
    assert!(has(&r, FindingId::ArchiveEntryLimit));
    assert_eq!(r.stats.unpacked_bytes, 0);
    assert!(r.truncated);
}
#[test]
fn zip_bomb_and_aggregate_decompression_budget() {
    let bomb = vec![0; 100_000];
    let b = zip(
        &[("[Content_Types].xml", TYPES), ("word/bomb", &bomb)],
        true,
    );
    let r = scan("application/zip", &b);
    assert!(has(&r, FindingId::DecompressionLimit));
    incomplete(&r);
    let b = zip(
        &[
            ("[Content_Types].xml", TYPES),
            ("a", &[1; 200]),
            ("b", &[2; 200]),
        ],
        false,
    );
    let s = Settings {
        max_unpacked_bytes: 300,
        max_total_unpacked_bytes: 400,
        ..Settings::default()
    };
    let r = analyze(&message("application/zip", &b), &s);
    incomplete(&r);
    assert!(r.stats.unpacked_bytes <= 400);
}
#[test]
fn zip_duplicate_case_names_and_local_central_mismatch_are_incomplete() {
    let b = zip(
        &[("[Content_Types].xml", TYPES), ("a", b"a"), ("A", b"b")],
        false,
    );
    let r = scan("application/zip", &b);
    assert!(has(&r, FindingId::ArchiveAmbiguous));
    incomplete(&r);
    let mut b = zip(&[("[Content_Types].xml", TYPES)], false);
    b[30] = b'X';
    let r = scan("application/zip", &b);
    incomplete(&r);
}
#[test]
fn zip_crc_encryption_zip64_and_polyglot_are_incomplete() {
    let b = zip(&[("[Content_Types].xml", TYPES)], false);
    let mut crc = b.clone();
    let p = 30 + le16(&crc, 26).unwrap() as usize + le16(&crc, 28).unwrap() as usize;
    crc[p] ^= 1;
    incomplete(&scan("application/zip", &crc));
    let mut encrypted = b.clone();
    let central = encrypted
        .windows(4)
        .position(|x| x == b"PK\x01\x02")
        .unwrap();
    encrypted[central + 8] |= 1;
    let r = scan("application/zip", &encrypted);
    assert!(has(&r, FindingId::ArchiveEncrypted));
    let mut zip64 = b.clone();
    zip64[central + 24..central + 28].copy_from_slice(&u32::MAX.to_le_bytes());
    incomplete(&scan("application/zip", &zip64));
    let mut tail = b;
    tail.extend(b"<script>x</script>");
    incomplete(&scan("application/zip", &tail));
}
#[test]
fn zip_paths_embedded_objects_and_generic_archives_are_not_complete() {
    for name in ["../secret", "/secret", "word/%76baProject.bin", "a\\b"] {
        incomplete(&scan("application/zip", &zip(&[(name, b"x")], false)));
    }
    let r = scan(
        "application/zip",
        &zip(
            &[
                ("[Content_Types].xml", TYPES),
                ("word/embeddings/oleObject1.bin", b"x"),
            ],
            false,
        ),
    );
    assert!(has(&r, FindingId::OfficeEmbeddedObject));
    incomplete(&r);
}
#[test]
fn malformed_and_truncated_fixtures_never_panic_or_exceed_report_caps() {
    let fixtures = [
        png(1, 1, &[0, 0]),
        gif(),
        jpeg(),
        pdf(&[b"<< /JS (x) >>"]),
        zip(&[("[Content_Types].xml", TYPES)], true),
        cfb(&["/VBA"]),
    ];
    for data in fixtures {
        for end in (0..data.len()).step_by((data.len() / 80).max(1)) {
            let r = scan("application/octet-stream", &data[..end]);
            assert!(r.findings.len() <= r.limits.max_findings);
            assert!(r.parts.len() <= r.limits.max_parts);
            assert!(r.stats.unpacked_bytes <= r.limits.max_total_unpacked_bytes);
        }
        for n in 0..64 {
            let mut corrupt = data.clone();
            let len = corrupt.len();
            corrupt[n * 97 % len] ^= (n as u8).wrapping_mul(37) | 1;
            let r = scan("application/octet-stream", &corrupt);
            assert!(r.stats.structure_nodes <= r.limits.max_structure_nodes);
        }
    }
}

#[test]
fn office_xml_11_and_late_or_duplicate_declarations_are_incomplete() {
    for xml in [
        &b"<?xml version='1.1'?><Types/>"[..],
        &b"<?xml version='1.0'?><?xml version='1.0'?><Types/>"[..],
        &b"<Types><?xml version='1.0'?></Types>"[..],
    ] {
        incomplete(&scan(
            "application/zip",
            &zip(&[("[Content_Types].xml", xml)], false),
        ));
    }
    let xml = b"<?xml version='1.0'?><Types xmlns='http://schemas.openxmlformats.org/package/2006/content-types'/>";
    assert_eq!(
        scan(
            "application/zip",
            &zip(&[("[Content_Types].xml", xml)], false)
        )
        .status,
        Status::Complete
    );
}
#[test]
fn declared_charset_and_filename_disagreement_are_not_lost() {
    let r = scan("text/html; charset=iso-2022-jp", b"<p>plain</p>");
    incomplete(&r);
    assert!(!r.parts[0].complete);
    let b = png(1, 1, &[0, 0]);
    let raw = format!(
        "Content-Type: image/png\r\nContent-Disposition: attachment; filename=SECRET.jpg\r\nContent-Transfer-Encoding: base64\r\n\r\n{}",
        STANDARD.encode(b)
    );
    let r = analyze(raw.as_bytes(), &Settings::default());
    assert!(has(&r, FindingId::TypeMismatch));
    assert!(!serde_json::to_string(&r).unwrap().contains("SECRET"));
}
#[test]
fn deflate_end_and_actual_expansion_are_checked_independent_of_claimed_size() {
    let mut b = zip(&[("[Content_Types].xml", TYPES)], true);
    let central = b.windows(4).position(|x| x == b"PK\x01\x02").unwrap();
    // Extend the compressed extent with junk and update both headers and EOCD.
    let n = le32(&b, 18).unwrap();
    b[18..22].copy_from_slice(&(n + 1).to_le_bytes());
    b[central + 20..central + 24].copy_from_slice(&(n + 1).to_le_bytes());
    b.insert(central, 0);
    let eocd = b.len() - 22;
    let start = le32(&b, eocd + 16).unwrap();
    b[eocd + 16..eocd + 20].copy_from_slice(&(start + 1).to_le_bytes());
    incomplete(&scan("application/zip", &b));
    let mut bomb = zip(&[("[Content_Types].xml", &vec![0; 100_000])], true);
    let central = bomb.windows(4).position(|x| x == b"PK\x01\x02").unwrap();
    bomb[22..26].copy_from_slice(&1u32.to_le_bytes());
    bomb[central + 24..central + 28].copy_from_slice(&1u32.to_le_bytes());
    let r = scan("application/zip", &bomb);
    assert!(has(&r, FindingId::DecompressionLimit));
    assert!(r.truncated);
}
#[test]
fn unsupported_binary_office_parts_are_coverage_gaps() {
    incomplete(&scan(
        "application/zip",
        &zip(
            &[
                ("[Content_Types].xml", TYPES),
                ("xl/workbook.bin", b"opaque"),
            ],
            false,
        ),
    ));
}
#[test]
fn cfb_fat_read_amplification_is_cut_off_before_full_allocation() {
    let mut b = cfb(&["/VBA"]);
    b[44..48].copy_from_slice(&109u32.to_le_bytes());
    for n in 0..109 {
        b[76 + 4 * n..80 + 4 * n].copy_from_slice(&0u32.to_le_bytes());
    }
    let r = scan("application/msword", &b);
    assert!(has(&r, FindingId::CompoundIoLimit), "{r:#?}");
    assert!(r.truncated);
}
#[test]
fn namespace_mismatch_does_not_claim_complete_office_xml_coverage() {
    for xml in [
        &b"<Types/>"[..],
        &b"<Types xmlns='http://attacker.invalid/fake'/>"[..],
        &b"<x:Types/>"[..],
    ] {
        incomplete(&scan(
            "application/zip",
            &zip(&[("[Content_Types].xml", xml)], false),
        ));
    }
}
#[test]
fn malformed_header_and_empty_multipart_do_not_claim_success() {
    for raw in [
        &b"Not a header\r\n\r\nbody"[..],
        &b" orphan continuation\r\n\r\nbody"[..],
        &b"Content-Type: multipart/mixed; boundary=x\r\n\r\n--x--\r\n"[..],
    ] {
        let r = analyze(raw, &Settings::default());
        assert!(has(&r, FindingId::MalformedMime));
        incomplete(&r);
    }
}
