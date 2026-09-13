use super::*;
use crate::smtp_admission::{Mode, Settings};
async fn command(wire: &mut Wire, text: &str, expected: u16) {
    reply(wire, text).await.unwrap();
    assert_eq!(crate::relay::response(wire).await.unwrap().code, expected);
}
#[tokio::test]
async fn greylisting_precedes_data_capacity_and_rate_limit_cannot_be_bypassed_by_rcpt_or_reset() {
    for greylisting in [true, false] {
        let root = tempfile::tempdir().unwrap();
        let mut cfg: Config =
            toml::from_str(include_str!("../../config/development.toml")).unwrap();
        cfg.data_dir = root.path().into();
        cfg.smtp.minimum_free_bytes = 0;
        cfg.smtp_admission = Some(Settings {
            enabled: true,
            mode: Mode::Enforce,
            greylisting,
            rate_burst: 1,
            rate_per_minute: 1,
            retry_delay_seconds: 10,
            tarpit_delay_ms: 10,
            tarpit_session_budget_ms: 15,
            ..Default::default()
        });
        let cfg = Arc::new(cfg);
        let store = Store::open(root.path()).unwrap();
        let (rbl, dns) = crate::rbl::tests::dns_fixture().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let processing = Arc::new(Semaphore::new(1));
        let held = processing.clone().acquire_owned().await.unwrap();
        let state = State {
            config: cfg.clone(),
            store: store.clone(),
            engine: Arc::new(Engine::new(cfg).unwrap()),
            processing,
        };
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            session(
                socket,
                "8.8.8.8:40000".parse().unwrap(),
                state,
                None,
                None,
                Arc::new(rbl),
            )
            .await
        });
        let mut wire: Wire = BufReader::new(Box::new(TcpStream::connect(address).await.unwrap()));
        assert_eq!(crate::relay::response(&mut wire).await.unwrap().code, 220);
        command(&mut wire, "EHLO sender.example.test\r\n", 250).await;
        command(&mut wire, "MAIL FROM:<sender@example.org>\r\n", 250).await;
        command(&mut wire, "RCPT TO:<outside@external.example>\r\n", 550).await;
        command(
            &mut wire,
            "RCPT TO:<alice@example.test>\r\n",
            if greylisting { 451 } else { 250 },
        )
        .await;
        command(&mut wire, "DATA\r\n", if greylisting { 503 } else { 451 }).await;
        command(&mut wire, "RSET\r\n", 250).await;
        command(&mut wire, "MAIL FROM:<sender@example.org>\r\n", 250).await;
        command(&mut wire, "RCPT TO:<alice@example.test>\r\n", 451).await;
        command(&mut wire, "RCPT TO:<alice@example.test>\r\n", 503).await;
        command(&mut wire, "DATA\r\n", 503).await;
        assert_eq!(
            std::fs::read_dir(root.path().join("incoming"))
                .unwrap()
                .count(),
            0
        );
        assert!(store.claim().await.unwrap().is_none());
        command(&mut wire, "QUIT\r\n", 221).await;
        server.await.unwrap().unwrap();
        drop(held);
        dns.abort();
        let _ = dns.await;
    }
}
#[tokio::test]
async fn observation_does_not_sleep_or_change_score_and_records_transport_diagnostics() {
    let root = tempfile::tempdir().unwrap();
    let mut cfg: Config = toml::from_str(include_str!("../../config/development.toml")).unwrap();
    cfg.data_dir = root.path().into();
    cfg.smtp.minimum_free_bytes = 0;
    cfg.smtp_admission = Some(Settings {
        enabled: true,
        mode: Mode::Observe,
        tarpit_delay_ms: 5000,
        ..Default::default()
    });
    let cfg = Arc::new(cfg);
    let store = Store::open(root.path()).unwrap();
    let (rbl, dns) = crate::rbl::tests::dns_fixture().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let state = State {
        config: cfg.clone(),
        store: store.clone(),
        engine: Arc::new(Engine::new(cfg).unwrap()),
        processing: Arc::new(Semaphore::new(1)),
    };
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        session(
            socket,
            "8.8.8.8:40000".parse().unwrap(),
            state,
            None,
            None,
            Arc::new(rbl),
        )
        .await
    });
    let mut wire: Wire = BufReader::new(Box::new(TcpStream::connect(address).await.unwrap()));
    assert_eq!(crate::relay::response(&mut wire).await.unwrap().code, 220);
    command(&mut wire, "EHLO sender.example.test\r\n", 250).await;
    command(&mut wire, "MAIL FROM:<sender@example.org>\r\n", 250).await;
    tokio::time::timeout(
        Duration::from_secs(2),
        command(&mut wire, "RCPT TO:<alice@example.test>\r\n", 250),
    )
    .await
    .unwrap();
    command(&mut wire, "DATA\r\n", 354).await;
    command(&mut wire,"From: sender@example.org\r\nTo: alice@example.test\r\nSubject: Bonjour\r\n\r\nBonjour.\r\n.\r\n",250).await;
    let raw = store
        .read(|db| Ok(db.query_row("SELECT scan FROM messages", [], |r| r.get::<_, String>(0))?))
        .await
        .unwrap();
    let scan: crate::engine::Scan = serde_json::from_str(&raw).unwrap();
    assert_eq!(scan.score, 0.7);
    assert!(!scan.tagged);
    assert_eq!(scan.smtp_admission.len(), 1);
    assert!(scan.smtp_admission[0].would_defer);
    command(&mut wire, "QUIT\r\n", 221).await;
    server.await.unwrap().unwrap();
    dns.abort();
    let _ = dns.await;
}
