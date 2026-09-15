use super::*;

// Intentionally pause archive disk work while asserting SMTP acceptance remains independent.
#[allow(clippy::await_holding_lock)]
#[tokio::test]
async fn smtp_accepts_durably_while_rspamd_is_still_waiting() {
    let root = tempfile::tempdir().unwrap();
    let scanner = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let scanner_address = scanner.local_addr().unwrap();
    let gate = Arc::new(Semaphore::new(0));
    let release = gate.clone();
    let arrived = Arc::new(tokio::sync::Notify::new());
    let seen = arrived.clone();
    let scanner = tokio::spawn(async move {
        axum::serve(
            scanner,
            axum::Router::new().route(
                "/checkv2",
                axum::routing::post(move |raw: axum::body::Bytes| {
                    let gate = release.clone();
                    let arrived = seen.clone();
                    async move {
                        assert!(!String::from_utf8_lossy(&raw).contains("X-NoiseFence-Score:"));
                        arrived.notify_one();
                        let _permit = gate.acquire().await.unwrap();
                        r#"{"score":0,"required_score":6,"action":"no action","symbols":{}}"#
                    }
                }),
            ),
        )
        .await
        .unwrap();
    });
    let mut cfg: Config = toml::from_str(include_str!("../../config/development.toml")).unwrap();
    cfg.data_dir = root.path().into();
    cfg.smtp.minimum_free_bytes = 0;
    cfg.rspamd = Some(crate::rspamd::Settings {
        enabled: true,
        endpoint: scanner_address,
        ..Default::default()
    });
    let cfg = Arc::new(cfg);
    let store = Store::open(root.path()).unwrap();
    store.archive.configure(crate::research_archive::Settings {
        enabled: true,
        collect_until: crate::now() + 3600,
        ..Default::default()
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let state = State {
        config: cfg.clone(),
        store: store.clone(),
        engine: Arc::new(Engine::new(cfg).unwrap()),
        processing: Arc::new(Semaphore::new(1)),
    };
    let rbl = Arc::new(crate::rbl::Runtime::new(None, None).unwrap());
    let server = tokio::spawn(async move {
        let (socket, peer) = listener.accept().await.unwrap();
        session(socket, peer, state, None, None, rbl).await.unwrap();
    });
    let mut wire: Wire = BufReader::new(Box::new(TcpStream::connect(address).await.unwrap()));
    assert_eq!(crate::relay::response(&mut wire).await.unwrap().code, 220);
    for (command, code) in [
        ("EHLO sender.example.org\r\n", 250),
        ("MAIL FROM:<sender@example.org>\r\n", 250),
        ("RCPT TO:<alice@example.test>\r\n", 250),
        ("DATA\r\n", 354),
    ] {
        reply(&mut wire, command).await.unwrap();
        assert_eq!(crate::relay::response(&mut wire).await.unwrap().code, code);
    }
    let archive_gate = store.archive.pause_for_test();
    reply(&mut wire,"From: sender@example.org\r\nTo: alice@example.test\r\nSubject: Original\r\n\r\nOriginal body.\r\n.\r\n").await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), crate::relay::response(&mut wire))
            .await
            .unwrap()
            .unwrap()
            .code,
        250
    );
    // Disk/crypto work is deliberately blocked, yet SMTP has already replied 250.
    drop(archive_gate);
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if store.archive.status().unwrap().messages == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let archives = store.archive.list().unwrap();
    let archive_id = archives[0]["id"].as_str().unwrap();
    let output = root.path().join("research-export");
    store.archive.export(archive_id, &output).unwrap();
    assert_eq!(std::fs::read(output.join("message.eml")).unwrap(),b"From: sender@example.org\r\nTo: alice@example.test\r\nSubject: Original\r\n\r\nOriginal body.\r\n");
    tokio::time::timeout(Duration::from_secs(1), arrived.notified())
        .await
        .unwrap();
    let job = store.claim().await.unwrap().unwrap();
    let raw = tokio::fs::read(
        store
            .root
            .join("spool")
            .join(format!("{}.eml", job.message_id)),
    )
    .await
    .unwrap();
    assert!(String::from_utf8_lossy(&raw).contains("X-NoiseFence-Score:"));
    assert!(!String::from_utf8_lossy(&raw).contains("Rspamd"));
    reply(&mut wire, "QUIT\r\n").await.unwrap();
    server.await.unwrap();
    gate.add_permits(1);
    scanner.abort();
}
