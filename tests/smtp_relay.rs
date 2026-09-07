mod common;
#[path = "common/fusion.rs"]
mod fusion_fixture;
use noisefence::{
    engine::Engine,
    relay::{self, Outcome},
    smtp::{self, State, Wire},
    store::{Job, Store},
};
use std::sync::Arc;
use tokio::{
    io::{AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::{Semaphore, watch},
};
async fn server(
    cfg: Arc<noisefence::config::Config>,
    store: Store,
) -> (
    std::net::SocketAddr,
    watch::Sender<bool>,
    tokio::task::JoinHandle<anyhow::Result<()>>,
) {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, rx) = watch::channel(false);
    let engine = Arc::new(Engine::new(cfg.clone()).unwrap());
    let state = State {
        config: cfg,
        store,
        engine,
        processing: Arc::new(Semaphore::new(2)),
    };
    let task = tokio::spawn(smtp::serve(listener, state, rx));
    (addr, stop, task)
}
async fn client(addr: std::net::SocketAddr) -> Wire {
    let mut io: Wire = BufReader::new(Box::new(TcpStream::connect(addr).await.unwrap()));
    assert_eq!(relay::response(&mut io).await.unwrap().code, 220);
    io
}
async fn command(io: &mut Wire, c: &str) -> u16 {
    smtp::reply(io, c).await.unwrap();
    relay::response(io).await.unwrap().code
}

#[tokio::test]
async fn smtp_fusion_uses_one_decision_and_preserves_legacy_and_limited_observations() {
    use noisefence::{
        config::Mode as FilterMode,
        fusion::runtime::{Mode, Outcome},
        message,
    };
    for mode in [Mode::Observe, Mode::Decision] {
        let root = tempfile::tempdir().unwrap();
        let mut cfg = (*common::config(root.path())).clone();
        // Isolated loopback test of the tagging branch. No Proton report,
        // external relay or production configuration is produced by this fixture.
        cfg.filter.mode = FilterMode::Tag;
        cfg.filter.max_analysis_bytes = 10000;
        cfg.filter.arc_domain = Some("example.org".into());
        cfg.filter.arc_selector = Some("test".into());
        cfg.filter.arc_key = Some(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/public-test-key.txt"),
        );
        fusion_fixture::install(&mut cfg, mode);
        let cfg = Arc::new(cfg);
        let store = Store::open(root.path()).unwrap();
        let (addr, stop, task) = server(cfg.clone(), store.clone()).await;
        let mut io = client(addr).await;
        assert_eq!(command(&mut io, "EHLO example.org\r\n").await, 250);
        for limited in [false, true] {
            assert_eq!(
                command(&mut io, "MAIL FROM:<sender@example.org>\r\n").await,
                250
            );
            assert_eq!(
                command(&mut io, "RCPT TO:<alice@example.test>\r\n").await,
                250
            );
            assert_eq!(command(&mut io, "DATA\r\n").await, 354);
            let mut raw = [
                b"X-NoiseFence-Score: 100\r\nX-NoiseFence-Decision: unwanted\r\n".as_slice(),
                common::MESSAGE,
            ]
            .concat();
            if limited {
                raw.extend_from_slice("long line\r\n".repeat(1100).as_bytes());
            }
            io.write_all(&raw).await.unwrap();
            io.write_all(b".\r\n").await.unwrap();
            io.flush().await.unwrap();
            assert_eq!(relay::response(&mut io).await.unwrap().code, 250);
            let job = store.claim().await.unwrap().unwrap();
            let id = job.message_id.clone();
            let scan: noisefence::engine::Scan = store
                .run(move |db| {
                    let scan: String =
                        db.query_row("SELECT scan FROM messages WHERE id=?1", [id], |r| r.get(0))?;
                    Ok(serde_json::from_str(&scan)?)
                })
                .await
                .unwrap();
            let queued = std::fs::read(store.raw_path(&job.message_id)).unwrap();
            let rendered = String::from_utf8_lossy(&queued);
            assert_eq!(scan.raw_sha256, Some(message::digest(&raw)));
            assert_eq!(
                message::fields(&raw).unwrap().1,
                message::fields(&queued).unwrap().1
            );
            let (headers, _) = message::fields(&queued).unwrap();
            for name in [b"X-NoiseFence-Decision:".as_slice(), b"X-NoiseFence-Score:"] {
                assert_eq!(headers.iter().filter(|h| h.starts_with(name)).count(), 1);
            }
            let decision = scan.decision.as_ref().unwrap();
            assert!(rendered.contains(&format!(
                    "X-NoiseFence-Decision: {}\r\n",
                    serde_json::to_value(decision.outcome)
                        .unwrap()
                        .as_str()
                        .unwrap()
                )));
            assert_eq!(
                scan.evidence.as_ref().unwrap().legacy_score,
                Some(scan.score)
            );
            assert_eq!(scan.tagged, mode == Mode::Decision && !limited);
            assert_eq!(rendered.contains("Subject: [SPAM]"), scan.tagged);
            assert_eq!(scan.complete, !limited);
            if limited {
                assert_eq!(decision.outcome, Outcome::Undetermined);
                assert!(decision.score.is_none());
                assert!(!scan.evidence.as_ref().unwrap().analysis_complete);
            } else if mode == Mode::Decision {
                assert_eq!(decision.outcome, Outcome::Unwanted);
                assert!(decision.score.unwrap() < 1.0 && scan.score < 95.0);
                assert!(scan.evidence.as_ref().unwrap().analysis_complete);
            } else {
                assert_eq!(decision.outcome, Outcome::Legitimate);
            }
        }
        if mode == Mode::Decision {
            let engine = Engine::new(cfg).unwrap();
            let (scan, bytes) = engine
                .process(
                    common::MESSAGE,
                    "192.0.2.1".parse().unwrap(),
                    "example.org",
                    "sender@example.org",
                    "diagnostic",
                )
                .await
                .unwrap();
            assert_eq!(scan.decision.unwrap().outcome, Outcome::Undetermined);
            assert!(!scan.tagged && !String::from_utf8_lossy(&bytes).contains("[SPAM]"));
        }
        assert_eq!(command(&mut io, "QUIT\r\n").await, 221);
        drop(io);
        stop.send(true).unwrap();
        task.await.unwrap().unwrap();
    }
}
#[tokio::test]
async fn smtp_pipeline_alias_open_relay_and_durable_acceptance() {
    let root = tempfile::tempdir().unwrap();
    let cfg = common::config(root.path());
    let store = Store::open(root.path()).unwrap();
    let (addr, stop, task) = server(cfg, store.clone()).await;
    let mut io = client(addr).await;
    assert_eq!(command(&mut io, "EHLO example.org\r\n").await, 250);
    assert_eq!(
        command(&mut io, "MAIL FROM:<sender@example.org> SMTPUTF8\r\n").await,
        555
    );
    assert_eq!(
        command(&mut io, "MAIL FROM:<sender@example.org>\r\n").await,
        250
    );
    assert_eq!(
        command(&mut io, "RCPT TO:<victim@external.test>\r\n").await,
        550
    );
    smtp::reply(
        &mut io,
        "RCPT TO:<billing@example.test>\r\nRCPT TO:<billing@example.test>\r\nDATA\r\n",
    )
    .await
    .unwrap();
    assert_eq!(relay::response(&mut io).await.unwrap().code, 250);
    assert_eq!(relay::response(&mut io).await.unwrap().code, 250);
    assert_eq!(relay::response(&mut io).await.unwrap().code, 354);
    io.write_all(common::MESSAGE).await.unwrap();
    io.write_all(b".\r\n").await.unwrap();
    io.flush().await.unwrap();
    assert_eq!(relay::response(&mut io).await.unwrap().code, 250);
    let job = store.claim().await.unwrap().unwrap();
    assert_eq!(job.destination, "alice@example.test");
    let message_id = job.message_id.clone();
    let source: String = store
        .run(move |db| {
            Ok(db.query_row(
                "SELECT json_extract(scan,'$.evidence.source') FROM messages WHERE id=?1",
                [message_id],
                |r| r.get(0),
            )?)
        })
        .await
        .unwrap();
    assert_eq!(source, "smtp_session");
    assert!(store.raw_path(&job.message_id).is_file());
    assert!(store.claim().await.unwrap().is_none());
    assert_eq!(command(&mut io, "QUIT\r\n").await, 221);
    drop(io);
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn cross_domain_aliases_preserve_wire_content_and_bcc_authorization() {
    use noisefence::{config::Domain, message};
    let root = tempfile::tempdir().unwrap();
    let mut config = (*common::config(root.path())).clone();
    config.domains.push(Domain {
        name: "pilot.example.test".into(),
        next_hops: vec!["unused-route.example.org".into()],
        recipients: vec![],
        accept_all_recipients: false,
        aliases: [
            (
                "probe@pilot.example.test".into(),
                "alice@example.test".into(),
            ),
            (
                "hidden@pilot.example.test".into(),
                "bob@example.test".into(),
            ),
        ]
        .into(),
    });
    config.validate().unwrap();
    let store = Store::open(root.path()).unwrap();
    store
        .run(|db| {
            for user in ["alice", "bob", "other"] {
                db.execute(
                    "INSERT INTO users(username,password,admin) VALUES(?1,'test-only',1)",
                    [user],
                )?;
                db.execute(
                    "INSERT INTO grants(username,address) VALUES(?1,?2)",
                    rusqlite::params![user, format!("{user}@example.test")],
                )?;
            }
            Ok(())
        })
        .await
        .unwrap();
    let (addr, stop, task) = server(Arc::new(config.clone()), store.clone()).await;
    let mut io = client(addr).await;
    assert_eq!(command(&mut io, "EHLO sender.example.org\r\n").await, 250);
    assert_eq!(
        command(&mut io, "MAIL FROM:<sender@example.org>\r\n").await,
        250
    );
    assert_eq!(
        command(&mut io, "RCPT TO:<alice@pilot.example.test>\r\n").await,
        550
    );
    assert_eq!(
        command(&mut io, "RCPT TO:<victim@external.test>\r\n").await,
        550
    );
    for recipient in [
        "probe@PILOT.EXAMPLE.TEST",
        "probe@pilot.example.test",
        "hidden@pilot.example.test",
    ] {
        assert_eq!(
            command(&mut io, &format!("RCPT TO:<{recipient}>\r\n")).await,
            250
        );
    }
    assert_eq!(command(&mut io, "DATA\r\n").await, 354);
    let raw = String::from_utf8(common::MESSAGE.to_vec())
        .unwrap()
        .replace("To: alice@example.test", "To: probe@pilot.example.test")
        .into_bytes();
    io.write_all(&raw).await.unwrap();
    io.write_all(b".\r\n").await.unwrap();
    io.flush().await.unwrap();
    assert_eq!(relay::response(&mut io).await.unwrap().code, 250);
    let first = store.claim().await.unwrap().unwrap();
    let second = store.claim().await.unwrap().unwrap();
    assert!(
        store.claim().await.unwrap().is_none(),
        "case variants duplicated the delivery"
    );
    assert_eq!(first.destination, "alice@example.test");
    assert_eq!(second.destination, "bob@example.test");
    assert_eq!(first.sender, "sender@example.org");
    assert_eq!(first.hosts, config.domains[0].next_hops);
    assert_eq!(second.hosts, first.hosts);
    let queued = std::fs::read(store.raw_path(&first.message_id)).unwrap();
    let (original_headers, original_body) = message::fields(&raw).unwrap();
    let (queued_headers, queued_body) = message::fields(&queued).unwrap();
    assert_eq!(original_body, queued_body);
    assert!(
        original_headers
            .iter()
            .all(|field| queued_headers.contains(field))
    );
    let alice = store
        .list("alice".into(), "".into(), "all".into(), 0, 95.0)
        .await
        .unwrap();
    let bob = store
        .list("bob".into(), "".into(), "all".into(), 0, 95.0)
        .await
        .unwrap();
    assert_eq!(alice[0].recipients.len(), 1);
    assert_eq!(alice[0].recipients[0].address, "probe@pilot.example.test");
    assert_eq!(bob[0].recipients.len(), 1);
    assert_eq!(bob[0].recipients[0].address, "hidden@pilot.example.test");
    assert!(!serde_json::to_string(&alice).unwrap().contains("hidden@"));
    assert!(
        store
            .list("other".into(), "".into(), "all".into(), 0, 95.0)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .feedback("other".into(), first.message_id.clone(), true)
            .await
            .is_err()
    );
    store
        .feedback("alice".into(), first.message_id.clone(), false)
        .await
        .unwrap();
    store.finish(&first, "delivered", "", 0).await.unwrap();
    store.cleanup().await.unwrap();
    assert!(store.raw_path(&first.message_id).exists());
    store.finish(&second, "delivered", "", 0).await.unwrap();
    store.cleanup().await.unwrap();
    assert!(!store.raw_path(&first.message_id).exists());
    assert_eq!(command(&mut io, "QUIT\r\n").await, 221);
    drop(io);
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
}
#[tokio::test]
async fn unlisted_mailboxes_relay_independently_and_keep_exact_console_grants() {
    let root = tempfile::tempdir().unwrap();
    let mut config = (*common::config(root.path())).clone();
    config.domains[0].accept_all_recipients = true;
    config.domains[0].recipients.clear();
    config.validate().unwrap();
    let store = Store::open(root.path()).unwrap();
    store
        .run(|db| {
            for user in ["new", "hidden", "other"] {
                db.execute(
                    "INSERT INTO users(username,password,admin) VALUES(?1,'test-only',1)",
                    [user],
                )?;
                db.execute(
                    "INSERT INTO grants(username,address) VALUES(?1,?2)",
                    rusqlite::params![user, format!("{user}@example.test")],
                )?;
            }
            Ok(())
        })
        .await
        .unwrap();
    let (addr, stop, task) = server(Arc::new(config.clone()), store.clone()).await;
    let mut io = client(addr).await;
    assert_eq!(command(&mut io, "EHLO sender.example.org\r\n").await, 250);
    assert_eq!(
        command(&mut io, "MAIL FROM:<sender@example.org>\r\n").await,
        250
    );
    for external in [
        "victim@external.test",
        "new@sub.example.test",
        "new@example.test.evil",
    ] {
        assert_eq!(
            command(&mut io, &format!("RCPT TO:<{external}>\r\n")).await,
            550
        );
    }
    for accepted in [
        "new@EXAMPLE.TEST",
        "new@example.test",
        "hidden@example.test",
    ] {
        assert_eq!(
            command(&mut io, &format!("RCPT TO:<{accepted}>\r\n")).await,
            250
        );
    }
    assert_eq!(command(&mut io, "DATA\r\n").await, 354);
    let raw = String::from_utf8(common::MESSAGE.to_vec())
        .unwrap()
        .replace("To: alice@example.test", "To: new@example.test");
    io.write_all(raw.as_bytes()).await.unwrap();
    io.write_all(b".\r\n").await.unwrap();
    io.flush().await.unwrap();
    assert_eq!(relay::response(&mut io).await.unwrap().code, 250);
    assert_eq!(command(&mut io, "QUIT\r\n").await, 221);
    drop(io);
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    drop(store);

    // Accepted unlisted destinations survive a restart without consulting a mailbox list.
    let store = Store::open(root.path()).unwrap();
    let first = store.claim().await.unwrap().unwrap();
    let second = store.claim().await.unwrap().unwrap();
    assert!(store.claim().await.unwrap().is_none());
    assert_eq!(first.message_id, second.message_id);
    let queued = std::fs::read(store.raw_path(&first.message_id)).unwrap();
    for (job, destination) in [
        (&first, "new@example.test"),
        (&second, "hidden@example.test"),
    ] {
        assert_eq!(job.destination, destination);
        assert_eq!(job.sender, "sender@example.org");
        assert_eq!(job.hosts, config.domains[0].next_hops);
        let (port, sink_task) = sink(250, true, Some(destination)).await;
        config.relay.port = port;
        assert!(matches!(
            relay::deliver(&config, job, &queued).await,
            Outcome::Delivered
        ));
        assert_eq!(sink_task.await.unwrap(), queued);
        store.finish(job, "delivered", "", 0).await.unwrap();
    }
    for user in ["new", "hidden"] {
        let visible = store
            .list(user.into(), "".into(), "all".into(), 0, 95.0)
            .await
            .unwrap();
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].recipients.len(), 1);
        assert_eq!(
            visible[0].recipients[0].address,
            format!("{user}@example.test")
        );
        store
            .feedback(user.into(), first.message_id.clone(), false)
            .await
            .unwrap();
    }
    assert!(
        store
            .list("other".into(), "".into(), "all".into(), 0, 95.0)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .feedback("other".into(), first.message_id.clone(), true)
            .await
            .is_err()
    );
    store.cleanup().await.unwrap();
    assert!(!store.raw_path(&first.message_id).exists());
}

#[tokio::test]
async fn unfinished_data_is_not_accepted() {
    let root = tempfile::tempdir().unwrap();
    let cfg = common::config(root.path());
    let store = Store::open(root.path()).unwrap();
    let (addr, stop, task) = server(cfg, store.clone()).await;
    let mut io = client(addr).await;
    for c in [
        "EHLO example.org\r\n",
        "MAIL FROM:<sender@example.org>\r\n",
        "RCPT TO:<alice@example.test>\r\n",
    ] {
        assert_eq!(command(&mut io, c).await, 250);
    }
    assert_eq!(command(&mut io, "DATA\r\n").await, 354);
    io.write_all(common::MESSAGE).await.unwrap();
    io.shutdown().await.unwrap();
    drop(io);
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    assert!(store.claim().await.unwrap().is_none());
    assert_eq!(
        std::fs::read_dir(root.path().join("incoming"))
            .unwrap()
            .count(),
        0
    );
}
#[tokio::test]
async fn ambiguous_newline_cannot_smuggle_a_second_message() {
    let root = tempfile::tempdir().unwrap();
    let cfg = common::config(root.path());
    let store = Store::open(root.path()).unwrap();
    let (addr, stop, task) = server(cfg, store.clone()).await;
    let mut io = client(addr).await;
    for c in [
        "EHLO example.org\r\n",
        "MAIL FROM:<sender@example.org>\r\n",
        "RCPT TO:<alice@example.test>\r\n",
    ] {
        command(&mut io, c).await;
    }
    command(&mut io, "DATA\r\n").await;
    io.write_all(b"Subject: bad\r\n\r\nbody\n.\r\nMAIL FROM:<sender@example.org>\r\n")
        .await
        .unwrap();
    io.flush().await.unwrap();
    assert!(relay::response(&mut io).await.is_err());
    drop(io);
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    assert!(store.claim().await.unwrap().is_none());
}
#[tokio::test]
async fn storage_pressure_is_a_temporary_failure() {
    let root = tempfile::tempdir().unwrap();
    let mut cfg = (*common::config(root.path())).clone();
    cfg.smtp.minimum_free_bytes = u64::MAX / 2;
    let store = Store::open(root.path()).unwrap();
    let (addr, stop, task) = server(Arc::new(cfg), store).await;
    let mut io = client(addr).await;
    command(&mut io, "EHLO example.org\r\n").await;
    assert_eq!(
        command(&mut io, "MAIL FROM:<sender@example.org>\r\n").await,
        452
    );
    command(&mut io, "QUIT\r\n").await;
    drop(io);
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
}
fn job() -> Job {
    Job {
        delivery_id: 1,
        message_id: "test".into(),
        created: noisefence::now(),
        sender: "sender@example.org".into(),
        destination: "alice@example.test".into(),
        hosts: vec!["127.0.0.1".into()],
        attempts: 1,
        is_dsn: false,
    }
}
async fn sink(
    final_code: u16,
    disconnect_after_accept: bool,
    expected_recipient: Option<&str>,
) -> (u16, tokio::task::JoinHandle<Vec<u8>>) {
    let expected_recipient = expected_recipient.map(str::to_owned);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut io: Wire = BufReader::new(Box::new(stream));
        smtp::reply(&mut io, "220 sink.test ESMTP\r\n")
            .await
            .unwrap();
        let mut body = Vec::new();
        loop {
            let Some(line) = smtp::line(&mut io, 1024, 10).await.unwrap() else {
                break;
            };
            if line.starts_with(b"EHLO") {
                smtp::reply(
                    &mut io,
                    "250-sink.test\r\n250-SIZE 50000000\r\n250 8BITMIME\r\n",
                )
                .await
                .unwrap();
            } else if line.starts_with(b"MAIL") || line.starts_with(b"RCPT") {
                if line.starts_with(b"RCPT")
                    && let Some(expected) = &expected_recipient
                {
                    assert_eq!(line, format!("RCPT TO:<{expected}>\r\n").as_bytes());
                }
                smtp::reply(&mut io, "250 OK\r\n").await.unwrap();
            } else if line == b"DATA\r\n" {
                smtp::reply(&mut io, "354 DATA\r\n").await.unwrap();
                loop {
                    let l = smtp::line(&mut io, 1001, 10).await.unwrap().unwrap();
                    if l == b".\r\n" {
                        break;
                    }
                    body.extend(l);
                }
                smtp::reply(&mut io, &format!("{final_code} result\r\n"))
                    .await
                    .unwrap();
                if disconnect_after_accept {
                    break;
                }
            } else if line == b"QUIT\r\n" {
                break;
            }
        }
        body
    });
    (port, task)
}
#[tokio::test]
async fn relay_classifies_final_replies_and_ignores_quit_failure() {
    let root = tempfile::tempdir().unwrap();
    for code in [250, 451, 550] {
        let (port, task) = sink(code, true, None).await;
        let mut cfg = (*common::config(root.path())).clone();
        cfg.relay.port = port;
        let outcome = relay::deliver(&cfg, &job(), common::MESSAGE).await;
        assert!(matches!(
            (code, outcome),
            (250, Outcome::Delivered) | (451, Outcome::Temporary(_)) | (550, Outcome::Permanent(_))
        ));
        assert_eq!(task.await.unwrap(), common::MESSAGE);
    }
}
#[tokio::test]
async fn verified_tls_is_required_for_production_relay() {
    let root = tempfile::tempdir().unwrap();
    let (port, task) = sink(250, false, None).await;
    let mut cfg = (*common::config(root.path())).clone();
    cfg.relay.port = port;
    cfg.relay.require_tls = true;
    assert!(matches!(
        relay::deliver(&cfg, &job(), common::MESSAGE).await,
        Outcome::Temporary(_)
    ));
    task.await.unwrap();
}
