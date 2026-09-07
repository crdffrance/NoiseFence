mod common;
use noisefence::antivirus::{AntivirusConfig, AntivirusStatus};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn independent_advisory_scan_cannot_hide_an_official_malware_result() {
    let root = tempfile::tempdir().unwrap();
    let mut config = (*common::config(root.path())).clone();
    let mut daemons = Vec::new();
    for (name, reply) in [
        ("official", b"stream: Eicar-Signature FOUND\0".as_slice()),
        ("advisory", b"stream: Test.Spam FOUND\0".as_slice()),
    ] {
        let socket = root.path().join(format!("{name}.sock"));
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        daemons.push(tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut command = [0; 10];
            stream.read_exact(&mut command).await.unwrap();
            assert_eq!(&command, b"zINSTREAM\0");
            loop {
                let size = stream.read_u32().await.unwrap() as usize;
                if size == 0 {
                    break;
                }
                let mut bytes = vec![0; size];
                stream.read_exact(&mut bytes).await.unwrap();
            }
            stream.write_all(reply).await.unwrap();
        }));
        let scanner = AntivirusConfig {
            socket,
            timeout_ms: 1000,
            max_bytes: config.smtp.max_message_bytes,
            trusted_unofficial_prefixes: vec![],
        };
        if name == "official" {
            config.antivirus = Some(scanner);
        } else {
            config.signatures = Some(scanner);
        }
    }
    config.validate().unwrap();
    let engine = noisefence::engine::Engine::new(Arc::new(config.clone())).unwrap();
    let (scan, _) = engine
        .process(
            common::MESSAGE,
            "127.0.0.1".parse().unwrap(),
            "sender.example.test",
            "sender@example.test",
            &uuid::Uuid::new_v4().to_string(),
        )
        .await
        .unwrap();
    assert_eq!(scan.antivirus.status, AntivirusStatus::Malware);
    assert_eq!(scan.signatures.status, AntivirusStatus::Suspicious);
    let evidence = scan.evidence.as_ref().unwrap();
    assert_eq!(
        evidence.signatures_state,
        noisefence::evidence::State::Complete
    );
    assert_eq!(
        evidence.signatures.as_ref().unwrap().status,
        AntivirusStatus::Malware,
        "retain the scanner result before the advisory-only policy"
    );
    assert!(
        scan.reasons
            .iter()
            .any(|reason| reason.id == "complementary_signature")
    );
    assert!(scan.reasons.iter().any(|reason| reason.id == "antivirus"));
    for daemon in daemons {
        daemon.await.unwrap();
    }
    config.signatures = config.antivirus.clone();
    assert!(
        config.validate().is_err(),
        "two layers must not share the same daemon"
    );
}

/// Requires a local daemon with official signatures. Never sends an email.
#[tokio::test]
#[ignore = "requires ClamAV; see tests/clamav/Dockerfile"]
async fn live_clamav_detects_eicar_in_mime_and_accepts_clean_mail() {
    use base64::Engine;
    let config = AntivirusConfig {
        socket: std::env::var("NOISEFENCE_TEST_CLAMD")
            .expect("local ClamD socket")
            .into(),
        timeout_ms: 5000,
        max_bytes: 25 * 1024 * 1024,
        trusted_unofficial_prefixes: vec![],
    };
    let clean = noisefence::antivirus::scan(&config, common::MESSAGE).await;
    assert_eq!(clean.status, AntivirusStatus::Clean, "{clean:?}");
    // Standard harmless antivirus test string, constructed only for this test.
    let eicar = [
        b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$".as_slice(),
        b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    ]
    .concat();
    let encoded = base64::engine::general_purpose::STANDARD.encode(eicar);
    let message = format!(
        "From: test@example.test\r\nTo: test@example.test\r\nSubject: Local antivirus test\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=test-boundary\r\n\r\n--test-boundary\r\nContent-Type: text/plain\r\n\r\nHarmless local antivirus test.\r\n--test-boundary\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=eicar.txt\r\nContent-Transfer-Encoding: base64\r\n\r\n{encoded}\r\n--test-boundary--\r\n"
    );
    let infected = noisefence::antivirus::scan(&config, message.as_bytes()).await;
    assert_eq!(infected.status, AntivirusStatus::Malware, "{infected:?}");
    assert!(
        infected
            .signature
            .as_ref()
            .unwrap()
            .to_lowercase()
            .contains("eicar")
    );
}

#[tokio::test]
async fn antivirus_metadata_is_persisted_without_changing_the_original_body() {
    let root = tempfile::tempdir().unwrap();
    let socket = root.path().join("clamd.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let daemon = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut command = [0; 10];
        stream.read_exact(&mut command).await.unwrap();
        loop {
            let length = stream.read_u32().await.unwrap() as usize;
            if length == 0 {
                break;
            }
            let mut part = vec![0; length];
            stream.read_exact(&mut part).await.unwrap();
        }
        stream
            .write_all(b"stream: Eicar-Signature FOUND\0")
            .await
            .unwrap();
    });
    let mut config = (*common::config(root.path())).clone();
    config.antivirus = Some(AntivirusConfig {
        socket,
        timeout_ms: 1000,
        max_bytes: config.smtp.max_message_bytes,
        trusted_unofficial_prefixes: vec![],
    });
    config.validate().unwrap();
    let engine = noisefence::engine::Engine::new(Arc::new(config.clone())).unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    let (scan, raw) = engine
        .process(
            common::MESSAGE,
            "127.0.0.1".parse().unwrap(),
            "sender.example.test",
            "sender@example.test",
            &id,
        )
        .await
        .unwrap();
    assert_eq!(scan.antivirus.status, AntivirusStatus::Malware);
    assert_eq!(scan.antivirus.signature.as_deref(), Some("Eicar-Signature"));
    assert!(!scan.tagged);
    let (_, original_body) = noisefence::message::fields(common::MESSAGE).unwrap();
    let (_, processed_body) = noisefence::message::fields(&raw).unwrap();
    assert_eq!(original_body, processed_body);
    let store = noisefence::store::Store::open(root.path()).unwrap();
    store
        .enqueue(
            id.clone(),
            "sender@example.test".into(),
            vec![config.recipient("alice@example.test").unwrap()],
            scan,
            raw,
        )
        .await
        .unwrap();
    store
        .run(move |db| {
            let saved: String =
                db.query_row("SELECT scan FROM messages WHERE id=?1", [id], |r| r.get(0))?;
            let result: noisefence::engine::Scan = serde_json::from_str(&saved)?;
            assert_eq!(result.antivirus.status, AntivirusStatus::Malware);
            Ok(())
        })
        .await
        .unwrap();
    daemon.await.unwrap();
}

#[tokio::test]
async fn unavailable_antivirus_is_never_recorded_as_clean() {
    let root = tempfile::tempdir().unwrap();
    let mut config = (*common::config(root.path())).clone();
    config.antivirus = Some(AntivirusConfig {
        socket: root.path().join("absent.sock"),
        timeout_ms: 100,
        max_bytes: config.smtp.max_message_bytes,
        trusted_unofficial_prefixes: vec![],
    });
    let engine = noisefence::engine::Engine::new(Arc::new(config)).unwrap();
    let (scan, _) = engine
        .process(
            common::MESSAGE,
            "127.0.0.1".parse().unwrap(),
            "sender.example.test",
            "sender@example.test",
            &uuid::Uuid::new_v4().to_string(),
        )
        .await
        .unwrap();
    assert_eq!(scan.antivirus.status, AntivirusStatus::Unavailable);
    assert!(!scan.complete);
    assert!(!scan.tagged);
}
