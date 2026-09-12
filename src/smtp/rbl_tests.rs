use super::*;
use crate::config::Mode;

#[tokio::test]
async fn rbl_denies_before_data_storage_and_scanning_and_observe_preserves_delivery() {
    for mode in [Mode::Enforce, Mode::Observe] {
        let root = tempfile::tempdir().unwrap();
        let mut cfg: Config =
            toml::from_str(include_str!("../../config/development.toml")).unwrap();
        cfg.data_dir = root.path().into();
        cfg.smtp.minimum_free_bytes = 0;
        cfg.filter.mode = mode;
        let cfg = Arc::new(cfg);
        let store = Store::open(root.path()).unwrap();
        let (rbl, dns) = crate::rbl::tests::dns_fixture().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let processing = Arc::new(Semaphore::new(1));
        // A held scan slot proves rejected senders never reach expensive processing.
        let held = processing.clone().acquire_owned().await.unwrap();
        let state = State {
            config: cfg.clone(),
            store: store.clone(),
            engine: Arc::new(Engine::new(cfg).unwrap()),
            processing,
        };
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            // The production accept loop supplies peer from accept(); this fixture supplies
            // a public peer to exercise DNSBL without a public listener or external DNS.
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
        for (command, code) in [
            ("EHLO sender.example.test\r\n", 250),
            ("MAIL FROM:<sender@example.org>\r\n", 250),
            ("RCPT TO:<outside@external.example>\r\n", 550),
            ("DATA\r\n", 503),
            ("RCPT TO:<alice@example.test>\r\n", 250),
        ] {
            reply(&mut wire, command).await.unwrap();
            assert_eq!(crate::relay::response(&mut wire).await.unwrap().code, code);
        }
        if mode == Mode::Observe {
            drop(held);
        }
        reply(&mut wire, "DATA\r\n").await.unwrap();
        let code = crate::relay::response(&mut wire).await.unwrap().code;
        if mode == Mode::Enforce {
            assert_eq!(code, 550);
            assert_eq!(
                std::fs::read_dir(root.path().join("incoming"))
                    .unwrap()
                    .count(),
                0
            );
            assert!(store.claim().await.unwrap().is_none());
            reply(&mut wire, "DATA\r\n").await.unwrap();
            assert_eq!(crate::relay::response(&mut wire).await.unwrap().code, 503);
            reply(
                &mut wire,
                "MAIL FROM:<sender@example.org>\r\nRCPT TO:<alice@example.test>\r\nDATA\r\n",
            )
            .await
            .unwrap();
            for expected in [250, 250, 550] {
                assert_eq!(
                    crate::relay::response(&mut wire).await.unwrap().code,
                    expected
                );
            }
        } else {
            assert_eq!(code, 354);
            reply(&mut wire, "From: sender@example.org\r\nTo: alice@example.test\r\nSubject: Bonjour\r\nX-NoiseFence-RBL: forged\r\n\r\nBonjour.\r\n.\r\n").await.unwrap();
            assert_eq!(crate::relay::response(&mut wire).await.unwrap().code, 250);
            let job = store.claim().await.unwrap().unwrap();
            let scan: String = rusqlite::Connection::open(root.path().join("state.sqlite3"))
                .unwrap()
                .query_row(
                    "SELECT scan FROM messages WHERE id=?",
                    [&job.message_id],
                    |r| r.get(0),
                )
                .unwrap();
            let scan: crate::engine::Scan = serde_json::from_str(&scan).unwrap();
            let rbl = scan.early_rbl.unwrap();
            assert!(rbl.would_block);
            assert_eq!(rbl.effective_action, crate::rbl::Action::Observe);
            assert_eq!(rbl.listed_providers, 2);
            assert!(!scan.tagged);
        }
        reply(&mut wire, "QUIT\r\n").await.unwrap();
        assert_eq!(crate::relay::response(&mut wire).await.unwrap().code, 221);
        server.await.unwrap().unwrap();
        dns.abort();
        let _ = dns.await;
    }
}
