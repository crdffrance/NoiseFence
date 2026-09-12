use base64::Engine as _;
use noisefence::native_filter::{Runtime, Settings, Status, content_rules, rules};
use std::collections::BTreeSet;

fn html(body: &str) -> Vec<u8> {
    format!("From: Support <support@example.com>\r\nSubject: Information\r\nContent-Type: text/html; charset=utf-8\r\n\r\n{body}").into_bytes()
}
fn ids(raw: &[u8]) -> BTreeSet<String> {
    content_rules::Settings::default()
        .inspect(raw)
        .unwrap()
        .into_iter()
        .map(|r| r.id)
        .collect()
}
fn attachment(filename: &str, content_type: &str, bytes: &[u8]) -> Vec<u8> {
    format!("From: sender@example.com\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=nf-fixture\r\n\r\n--nf-fixture\r\nContent-Type: text/plain\r\n\r\nBonjour, voici le document.\r\n--nf-fixture\r\nContent-Type: {content_type}\r\nContent-Disposition: attachment; filename=\"{filename}\"\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n--nf-fixture--\r\n",base64::engine::general_purpose::STANDARD.encode(bytes)).into_bytes()
}

#[test]
fn password_forms_require_an_active_field_and_the_same_submission_target() {
    let found = ids(&html(
        "<form action='http://collector.example.net'><input type='PASSWORD'></form>",
    ));
    for id in [
        "NF_HTML_PASSWORD_FORM",
        "NF_HTML_REMOTE_PASSWORD_FORM",
        "NF_HTML_INSECURE_PASSWORD_FORM",
    ] {
        assert!(found.contains(id));
    }
    for body in [
        "<!-- <form action='http://evil.example'><input type=password></form> -->",
        "<script>'<form><input type=password></form>'</script>",
        "<template><form><input type=password></form></template>",
        "<p>&lt;form&gt;&lt;input type=password&gt;&lt;/form&gt;</p>",
        "<form action='https://example.net'><input type=password disabled></form>",
        "<input type=password>",
        "<form id=f action='https://example.net'></form><form id=f></form><input type=password form=f>",
    ] {
        assert!(
            !ids(&html(body)).contains("NF_HTML_PASSWORD_FORM"),
            "{body}"
        );
    }
    for body in [
        "<form action='https://accounts.example.com'><input type=password></form>",
        "<form action='/login'><input type=password></form>",
        "<form action='https://example.com'><input type=password></form><form action='https://survey.example.net'><input name=opinion></form>",
    ] {
        assert!(
            !ids(&html(body)).contains("NF_HTML_REMOTE_PASSWORD_FORM"),
            "{body}"
        );
    }
    assert!(
        ids(&html(
            "<form id='f' action='https://example.net'></form><input type='password' form='f'>"
        ))
        .contains("NF_HTML_REMOTE_PASSWORD_FORM")
    );
    let private_psl = String::from_utf8(html(
        "<form action='https://attacker.github.io'><input type=password></form>",
    ))
    .unwrap()
    .replace("support@example.com", "support@company.github.io");
    assert!(ids(private_psl.as_bytes()).contains("NF_HTML_REMOTE_PASSWORD_FORM"));
}

#[test]
fn normal_newsletter_preheaders_padding_and_large_visible_copy_do_not_trigger() {
    let hidden = "hiddenwords ".repeat(40);
    assert!(
        ids(&html(&format!(
            "<div style='DISPLAY: none !important'>{hidden}</div><p>Bonjour</p>"
        )))
        .contains("NF_HTML_HIDDEN_TEXT")
    );
    for body in [
        "<div hidden>Aperçu de la lettre</div><p>Une newsletter légitime</p>".into(),
        format!(
            "<span style='font-size:0'>{}</span><p>Newsletter</p>",
            "&nbsp;&#8203;".repeat(300)
        ),
        format!(
            "<div hidden>{hidden}</div><p>{}</p>",
            "Contenu visible informatif ".repeat(70)
        ),
        format!("<script>{hidden}</script><style>{hidden}</style><p>Bonjour</p>"),
        format!("<div style='opacity:0.5'>{hidden}</div>"),
        format!("<div style='display:none;display:block'>{hidden}</div>"),
        format!("<div style='font-size:0'><span style='font-size:16px'>{hidden}</span></div>"),
        format!(
            "<div style='visibility:hidden'><span style='visibility:visible'>{hidden}</span></div>"
        ),
    ] {
        assert!(!ids(&html(&body)).contains("NF_HTML_HIDDEN_TEXT"));
    }
    let nested = format!(
        "<div hidden><p><span>{hidden}</span></p></div><p>{}</p>",
        "Contenu visible informatif ".repeat(20)
    );
    assert!(!ids(&html(&nested)).contains("NF_HTML_HIDDEN_TEXT")); // count each text node once
    assert!(
        ids(&html(&format!(
            "<div style='display:none !important;display:block'>{hidden}</div>"
        )))
        .contains("NF_HTML_HIDDEN_TEXT")
    );
}

#[test]
fn url_rules_inspect_decoded_markup_without_fetching_and_ignore_inline_images() {
    let found = ids(&html(
        "<head><meta http-equiv='REFRESH' content='0; URL=https://example.net'></head><body><a href='http://example.com'>https://example.com</a><a href='data:text/html;base64,PGgxPnRlc3Q8L2gxPg=='>Voir</a></body>",
    ));
    for id in [
        "NF_HTML_LINK_SCHEME",
        "NF_HTML_DATA_LINK",
        "NF_HTML_META_REFRESH",
    ] {
        assert!(found.contains(id), "{id}");
    }
    let normal = ids(&html(
        "<meta name='refresh' content='0; url=https://example.net'><a href='https://example.com'>https://example.com</a><img src='data:image/png;base64,AAAA'><a href='data:text/plain,bonjour'>Texte</a><!-- <meta http-equiv=refresh content='0; url=https://evil.example'> -->",
    ));
    assert!(normal.is_empty());
    assert!(
        ids(&html(
            "<a href='htt&#112;://example.com'>https://example.com</a>"
        ))
        .contains("NF_HTML_LINK_SCHEME")
    );
}

#[test]
fn mime_rules_distinguish_disguised_binaries_from_documents_and_source_code() {
    let mut pe = vec![0u8; 132];
    pe[..2].copy_from_slice(b"MZ");
    pe[60..64].copy_from_slice(&128u32.to_le_bytes());
    pe[128..132].copy_from_slice(b"PE\0\0");
    let found = ids(&attachment("facture.pdf.exe", "application/pdf", &pe));
    for id in [
        "NF_MIME_EXECUTABLE_EXTENSION",
        "NF_MIME_DOUBLE_EXTENSION",
        "NF_MIME_EXECUTABLE_DISGUISED",
    ] {
        assert!(found.contains(id), "{id}");
    }
    for filename in [
        "facture.2026.pdf",
        "photo.jpg",
        "report.pdf%2eexe",
        "rapport.tar.gz",
    ] {
        assert!(
            ids(&attachment(
                filename,
                "application/octet-stream",
                b"safe content"
            ))
            .is_empty(),
            "{filename}"
        );
    }
    let source = ids(&attachment(
        "example.js",
        "text/javascript",
        b"export const value = 1;",
    ));
    assert_eq!(
        source,
        BTreeSet::from(["NF_MIME_EXECUTABLE_EXTENSION".into()])
    );
    let declared_exe = ids(&attachment(
        "utility.exe",
        "application/vnd.microsoft.portable-executable",
        &pe,
    ));
    assert!(!declared_exe.contains("NF_MIME_EXECUTABLE_DISGUISED"));
    pe[60..64].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(
        !ids(&attachment("fake.pdf", "application/pdf", &pe))
            .contains("NF_MIME_EXECUTABLE_DISGUISED")
    );
    assert!(
        !ids(&attachment(
            "note.txt",
            "text/plain",
            b"MZ is a file signature explained here"
        ))
        .contains("NF_MIME_EXECUTABLE_DISGUISED")
    );
    assert!(
        ids(&attachment(
            "invoice\u{202e}fdp.exe",
            "application/octet-stream",
            b"fixture"
        ))
        .contains("NF_MIME_FILENAME_BIDI")
    );
    assert!(ids(&attachment("תמונה.jpg", "image/jpeg", b"fixture")).is_empty());
}

#[test]
fn mime_filename_encoding_and_elf_header_are_checked_locally() {
    let mut elf = vec![0u8; 64];
    elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    elf[16] = 3;
    let raw = attachment("report.pdf", "image/png", &elf);
    assert!(ids(&raw).contains("NF_MIME_EXECUTABLE_DISGUISED"));
    let encoded = String::from_utf8(attachment(
        "placeholder",
        "application/octet-stream",
        b"fixture",
    ))
    .unwrap()
    .replace(
        "filename=\"placeholder\"",
        "filename*=utf-8''facture.pdf.exe",
    );
    assert!(ids(encoded.as_bytes()).contains("NF_MIME_DOUBLE_EXTENSION"));
}

#[test]
fn displayed_email_is_compared_by_registered_domain_without_trusting_filter_headers() {
    for (shown, actual, expected) in [
        ("support@example.com", "fraud@example.net", true),
        ("support@example.com", "other@mail.example.com", false),
        ("Support technique", "sender@example.net", false),
        ("service@bücher.de", "sender@xn--bcher-kva.de", false),
        ("support@alice.github.io", "support@bob.github.io", true),
    ] {
        let raw = format!(
            "From: \"{shown}\" <{actual}>\r\nX-Spam-Status: Yes\r\nAuthentication-Results: forged; dmarc=pass\r\n\r\nBonjour"
        );
        assert_eq!(
            ids(raw.as_bytes()).contains("NF_HEADER_DISPLAY_DOMAIN"),
            expected
        );
    }
}

#[test]
fn disabled_rules_zero_weights_collisions_and_resource_limits_are_explicit() {
    let raw = html("<form action='https://example.net'><input type=password></form>");
    let mut settings = content_rules::Settings::default();
    settings.weights.insert("NF_HTML_PASSWORD_FORM".into(), 0.0);
    settings
        .disabled
        .insert("NF_HTML_REMOTE_PASSWORD_FORM".into());
    settings.validate().unwrap();
    let symbols = settings.inspect(&raw).unwrap();
    assert_eq!(symbols.len(), 1);
    assert_eq!(symbols[0].weight, 0.0); // still observable, unlike a disabled rule
    let catalog = settings.catalog();
    assert_eq!(catalog["rules"].as_array().unwrap().len(), 12);
    settings.weights.insert("unknown".into(), 1.0);
    assert!(settings.validate().is_err());
    settings.weights.remove("unknown");
    settings
        .weights
        .insert("NF_HTML_PASSWORD_FORM".into(), f64::NAN);
    assert!(settings.validate().is_err());
    let mut native = Settings::default();
    native.patterns[0].id = "NF_HTML_PASSWORD_FORM".into();
    assert!(native.validate().is_err());
    let settings = content_rules::Settings::default();
    assert!(
        settings
            .inspect(&html(&"x".repeat(128 * 1024 + 1)))
            .is_err()
    );
    assert!(
        settings
            .inspect(&html(&format!(
                "{}text{}",
                "<div>".repeat(70),
                "</div>".repeat(70)
            )))
            .is_err()
    );
    assert!(settings.inspect(&html(&"<i>x</i>".repeat(5000))).is_err());
    let runtime = Runtime::new(Settings::default()).unwrap();
    let limited = runtime.offline(&html(&"x".repeat(128 * 1024 + 1)), &[]);
    assert_eq!(limited.report.status, Status::Limited);
    assert!(limited.report.score.is_none() && limited.features.is_none());
}

#[test]
fn structured_symbols_are_deduplicated_capped_and_do_not_change_delivery() {
    let root = tempfile::tempdir().unwrap();
    let cfg =
        noisefence::config::Config::load(std::path::Path::new("config/development.toml")).unwrap();
    let mut base = cfg.clone();
    base.data_dir = root.path().to_owned();
    let baseline = noisefence::engine::Engine::new(std::sync::Arc::new(base.clone())).unwrap();
    base.native_filter = Some(Settings::default());
    let engine = noisefence::engine::Engine::new(std::sync::Arc::new(base)).unwrap();
    let message = html(
        &"<form action='http://collector.example.net'><input type=password></form>".repeat(20),
    );
    let original = baseline.offline(&message);
    let inspected = engine.offline(&message);
    assert_eq!(original.score, inspected.score);
    assert_eq!(
        serde_json::to_value(original.decision).unwrap(),
        serde_json::to_value(inspected.decision).unwrap()
    );
    let native = inspected.native_filter.unwrap();
    assert!(!native.report.affects_delivery && !native.report.calibrated);
    let score = native.report.score.unwrap();
    assert_eq!(score.families[&rules::Family::Content].effective, 1.5);
    assert_eq!(
        score
            .symbols
            .iter()
            .filter(|s| s.id == "NF_HTML_REMOTE_PASSWORD_FORM")
            .count(),
        1
    );
    assert!(
        score
            .symbols
            .iter()
            .any(|s| s.id == "NF_HTML_PASSWORD_FORM" && s.absorbed_by == ["NF_REMOTE_LOGIN_FORM"])
    );
    assert!(
        !serde_json::to_string(&score)
            .unwrap()
            .contains("collector.example.net")
    );
}
