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
                Arc::new(crate::recipient_verification::Runtime::default()),
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
            Arc::new(crate::recipient_verification::Runtime::default()),
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

#[tokio::test]
async fn traffic_actions_are_recipient_scoped_and_never_change_content_scores() {
    for (action, observe) in [
        (crate::traffic::Action::Observe, false),
        (crate::traffic::Action::Defer, false),
        (crate::traffic::Action::Quarantine, false),
        (crate::traffic::Action::Quarantine, true),
    ] {
        let root = tempfile::tempdir().unwrap();
        let mut cfg: Config =
            toml::from_str(include_str!("../../config/development.toml")).unwrap();
        cfg.data_dir = root.path().into();
        cfg.smtp.minimum_free_bytes = 0;
        cfg.filter.mode = if observe {
            crate::config::Mode::Observe
        } else {
            crate::config::Mode::Enforce
        };
        let policy = crate::traffic::Policy {
            action,
            sender_limit: 0,
            domain_limit: 0,
            recipient_limit: 0,
            duplicate_limit: 1,
            ..Default::default()
        };
        cfg.smtp_admission = Some(Settings {
            traffic: Some(Box::new(crate::traffic::Settings {
                enabled: true,
                policy: policy.clone(),
                scopes: std::collections::BTreeMap::from([(
                    "bob@example.test".into(),
                    crate::traffic::Policy {
                        duplicate_limit: 0,
                        ..policy
                    },
                )]),
                ..Default::default()
            })),
            ..Default::default()
        });
        let cfg = Arc::new(cfg);
        let store = Store::open(root.path()).unwrap();
        let rbl = crate::rbl::Runtime::new(None, None).unwrap();
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
                Arc::new(crate::recipient_verification::Runtime::default()),
            )
            .await
        });
        let mut wire: Wire = BufReader::new(Box::new(TcpStream::connect(address).await.unwrap()));
        assert_eq!(crate::relay::response(&mut wire).await.unwrap().code, 220);
        command(&mut wire, "EHLO sender.example.test\r\n", 250).await;
        for n in 0..2 {
            command(&mut wire, "MAIL FROM:<sender@example.org>\r\n", 250).await;
            command(&mut wire, "RCPT TO:<alice@example.test>\r\n", 250).await;
            command(&mut wire, "RCPT TO:<bob@example.test>\r\n", 250).await;
            command(&mut wire, "DATA\r\n", 354).await;
            let expected = if n == 1 && action == crate::traffic::Action::Defer && !observe {
                451
            } else {
                250
            };
            command(&mut wire,"From: sender@example.org\r\nTo: alice@example.test\r\nSubject: Hello\r\n\r\nIdentical content.\r\n.\r\n",expected).await;
        }
        let rows=store.read(|db|Ok(db.prepare("SELECT d.address,d.status,m.scan FROM deliveries d JOIN messages m ON m.id=d.message_id ORDER BY d.id")?.query_map([],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?)))?.collect::<rusqlite::Result<Vec<_>>>()?)).await.unwrap();
        assert_eq!(
            rows.len(),
            if action == crate::traffic::Action::Defer && !observe {
                2
            } else {
                4
            }
        );
        let scans: Vec<crate::engine::Scan> = rows
            .iter()
            .map(|r| serde_json::from_str(&r.2).unwrap())
            .collect();
        assert!(scans.iter().all(|s| s.score == scans[0].score));
        let held = rows
            .iter()
            .filter(|r| r.1 == "quarantined")
            .collect::<Vec<_>>();
        if action == crate::traffic::Action::Quarantine && !observe {
            assert_eq!(held.len(), 1);
            assert_eq!(held[0].0, "alice@example.test");
        } else {
            assert!(held.is_empty());
        }
        assert!(
            scans
                .iter()
                .all(|s| s.traffic.is_some() && s.traffic_candidates.is_empty())
        );
        command(&mut wire, "QUIT\r\n", 221).await;
        server.await.unwrap().unwrap();
    }
}
