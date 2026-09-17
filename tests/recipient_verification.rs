mod common;
use noisefence::{
    config::Config,
    control,
    engine::Engine,
    recipient_verification::{Runtime, Settings, Verdict},
    relay,
    smtp::{self, Wire},
    store::Store,
};
use std::sync::{Arc, Mutex};
use tokio::{
    io::BufReader,
    net::{TcpListener, TcpStream},
    sync::{Semaphore, watch},
};

struct Sink {
    route: String,
    seen: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Sink {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn sink(rcpt: &'static str, mail: &'static str) -> Sink {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let route = listener.local_addr().unwrap().to_string();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let captured = seen.clone();
    let task = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let mut io: Wire = BufReader::new(Box::new(stream));
            smtp::reply(&mut io, "220 sink.test\r\n").await.unwrap();
            while let Ok(Some(bytes)) = smtp::line(&mut io, 512, 5).await {
                let text = String::from_utf8(bytes).unwrap();
                captured.lock().unwrap().push(text.clone());
                let reply = if text.starts_with("EHLO ") {
                    "250 sink.test\r\n"
                } else if text.starts_with("MAIL FROM:") {
                    mail
                } else if text.starts_with("RCPT TO:") {
                    if rcpt == "mixed" {
                        if text == "RCPT TO:<alice@example.test>\r\n" {
                            "250 Accepted\r\n"
                        } else {
                            "550 5.1.1 Unknown\r\n"
                        }
                    } else {
                        rcpt
                    }
                } else if text == "RSET\r\n" {
                    "250 Reset\r\n"
                } else if text == "QUIT\r\n" {
                    break;
                } else {
                    panic!("unexpected content or command: {text}")
                };
                if smtp::reply(&mut io, reply).await.is_err() {
                    break;
                }
            }
        }
    });
    Sink { route, seen, task }
}
fn setup(root: &std::path::Path, routes: &[String]) -> Config {
    let mut cfg = (*common::config(root)).clone();
    cfg.domains[0].next_hops = routes.into();
    cfg.domains[0].accept_all_recipients = true;
    cfg.domains[0].recipient_verification = Some(Settings::default());
    cfg.validate().unwrap();
    cfg
}
fn calls(s: &Sink) -> usize {
    s.seen
        .lock()
        .unwrap()
        .iter()
        .filter(|s| s.starts_with("RCPT TO:"))
        .count()
}

#[tokio::test]
async fn only_explicit_recipient_missing_is_permanent_never_sender_or_policy_failure() {
    for (rcpt, expected) in [
        ("250 2.1.5 Accepted\r\n", Verdict::Accepted),
        ("251 2.1.5 Forwarded\r\n", Verdict::Accepted),
        ("550 5.1.1 Unknown\r\n", Verdict::Unknown),
        (
            "550-5.1.1 Unknown\r\n550 5.1.1 Missing\r\n",
            Verdict::Unknown,
        ),
        ("550 Unknown\r\n", Verdict::Unavailable),
        ("550 5.7.1 Policy\r\n", Verdict::Unavailable),
        (
            "550-5.1.1 Unknown\r\n550 5.7.1 Policy\r\n",
            Verdict::Unavailable,
        ),
        ("552 5.2.2 Quota\r\n", Verdict::Unavailable),
        ("451 4.7.1 Try later\r\n", Verdict::Unavailable),
        ("252 2.1.5 Cannot verify\r\n", Verdict::Unavailable),
        (
            "250-inconsistent\r\n550 5.1.1 Unknown\r\n",
            Verdict::Unavailable,
        ),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let server = sink(rcpt, "250 Sender\r\n").await;
        let cfg = setup(tmp.path(), std::slice::from_ref(&server.route));
        let recipient = cfg.recipient("missing@example.test").unwrap();
        assert_eq!(
            Runtime::default()
                .check(&cfg, &recipient, "original@example.org")
                .await,
            expected
        );
        let seen = server.seen.lock().unwrap();
        assert!(seen.contains(&"MAIL FROM:<original@example.org>\r\n".to_string()));
        assert!(seen.contains(&"RCPT TO:<missing@example.test>\r\n".to_string()));
        assert!(seen.iter().all(|s| !s.contains("DATA")));
    }
    let tmp = tempfile::tempdir().unwrap();
    let server = sink("250 Recipient\r\n", "550 5.1.1 Bad sender\r\n").await;
    let cfg = setup(tmp.path(), std::slice::from_ref(&server.route));
    assert_eq!(
        Runtime::default()
            .check(&cfg, &cfg.recipient("alice@example.test").unwrap(), "")
            .await,
        Verdict::Unavailable
    );
    assert_eq!(calls(&server), 0);
}
#[tokio::test]
async fn route_consensus_and_cache_do_not_cross_sender_destination_or_policy_boundaries() {
    let tmp = tempfile::tempdir().unwrap();
    let missing = sink("550 5.1.1 Unknown\r\n", "250 Sender\r\n").await;
    let valid = sink("250 Recipient\r\n", "250 Sender\r\n").await;
    let busy = sink("451 4.3.0 Busy\r\n", "250 Sender\r\n").await;
    let mut cfg = setup(tmp.path(), std::slice::from_ref(&missing.route));
    let runtime = Runtime::default();
    let r = cfg.recipient("alice@example.test").unwrap();
    assert_eq!(runtime.check(&cfg, &r, "").await, Verdict::Unknown);
    assert_eq!(runtime.check(&cfg, &r, "").await, Verdict::Unknown);
    assert_eq!(calls(&missing), 1);
    assert_eq!(
        runtime.check(&cfg, &r, "sender@example.org").await,
        Verdict::Unknown
    );
    let r2 = cfg.recipient("Alice@example.test").unwrap();
    assert_eq!(runtime.check(&cfg, &r2, "").await, Verdict::Unknown);
    assert_eq!(calls(&missing), 3);
    cfg.domains[0]
        .recipient_verification
        .as_mut()
        .unwrap()
        .negative_cache_seconds = 0;
    for _ in 0..2 {
        assert_eq!(runtime.check(&cfg, &r, "").await, Verdict::Unknown);
    }
    assert_eq!(calls(&missing), 5);
    cfg.domains[0].next_hops.push(busy.route.clone());
    assert_eq!(
        runtime
            .check(&cfg, &cfg.recipient("alice@example.test").unwrap(), "")
            .await,
        Verdict::Unavailable
    );
    cfg.domains[0].next_hops.push(valid.route.clone());
    let r = cfg.recipient("alice@example.test").unwrap();
    assert_eq!(runtime.check(&cfg, &r, "").await, Verdict::Accepted);
    assert_eq!(runtime.check(&cfg, &r, "").await, Verdict::Accepted);
    assert_eq!(calls(&valid), 1);
    cfg.domains[0].recipient_verification = None;
    assert_eq!(runtime.check(&cfg, &r, "").await, Verdict::Accepted);
    assert_eq!(calls(&valid), 1);
}
#[tokio::test]
async fn deadlines_capacity_and_tls_fail_closed_temporarily() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    let tmp = tempfile::tempdir().unwrap();
    let s = sink("250 Accepted\r\n", "250 Sender\r\n").await;
    let mut cfg = setup(tmp.path(), std::slice::from_ref(&s.route));
    cfg.relay.require_tls = true;
    assert_eq!(
        Runtime::default()
            .check(&cfg, &cfg.recipient("alice@example.test").unwrap(), "")
            .await,
        Verdict::Unavailable
    );
    assert_eq!(calls(&s), 0);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut cfg = setup(tmp.path(), &[listener.local_addr().unwrap().to_string()]);
    cfg.domains[0]
        .recipient_verification
        .as_mut()
        .unwrap()
        .timeout_ms = 100;
    let runtime = Arc::new(Runtime::default());
    let start = std::time::Instant::now();
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..16 {
        let cfg = cfg.clone();
        let r = runtime.clone();
        tasks.spawn(async move {
            r.check(&cfg, &cfg.recipient("alice@example.test").unwrap(), "")
                .await
        });
    }
    while let Some(r) = tasks.join_next().await {
        assert_eq!(r.unwrap(), Verdict::Unavailable);
    }
    assert!(start.elapsed() < std::time::Duration::from_secs(2));
    cfg.relay.allow_loopback_plaintext = false;
    assert_eq!(
        runtime
            .check(&cfg, &cfg.recipient("alice@example.test").unwrap(), "")
            .await,
        Verdict::Unavailable
    );
}
#[test]
fn web_policy_roundtrip_validation_and_fallback_are_explicit() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = setup(tmp.path(), &["mx.example.org".into()]);
    let settings = control::Settings::from_config(&cfg);
    let json = serde_json::to_value(&settings).unwrap();
    assert_eq!(
        json["domains"][0]["recipient_verification"]["timeout_ms"],
        8000
    );
    let mut restored: control::Settings = serde_json::from_value(json).unwrap();
    assert_eq!(
        restored.effective(&cfg).unwrap().domains[0].recipient_verification,
        cfg.domains[0].recipient_verification
    );
    restored.domains[0].unknown_recipient_fallback = Some("alice@example.test".into());
    assert!(restored.effective(&cfg).is_err());
    restored.domains[0].unknown_recipient_fallback = None;
    for (deadline, positive, negative) in
        [(99, 60, 30), (15001, 60, 30), (100, 301, 30), (100, 60, 61)]
    {
        restored.domains[0].recipient_verification = Some(Settings {
            timeout_ms: deadline,
            positive_cache_seconds: positive,
            negative_cache_seconds: negative,
        });
        assert!(restored.effective(&cfg).is_err());
    }
    restored.domains[0].recipient_verification = None;
    assert!(
        serde_json::to_value(restored).unwrap()["domains"][0]
            .get("recipient_verification")
            .is_none()
    );
}
async fn send(io: &mut Wire, command: &str) -> u16 {
    smtp::reply(io, command).await.unwrap();
    relay::response(io).await.unwrap().code
}
#[tokio::test]
async fn inbound_refuses_before_data_preserves_aliases_and_does_not_probe_external_recipients() {
    let tmp = tempfile::tempdir().unwrap();
    let missing = sink("550 5.1.1 Unknown\r\n", "250 Sender\r\n").await;
    let cfg = Arc::new(setup(tmp.path(), std::slice::from_ref(&missing.route)));
    let store = Store::open(tmp.path()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, rx) = watch::channel(false);
    let state = smtp::State {
        config: cfg.clone(),
        store: store.clone(),
        engine: Arc::new(Engine::new(cfg).unwrap()),
        processing: Arc::new(Semaphore::new(2)),
    };
    let task = tokio::spawn(smtp::serve(listener, state, rx));
    let mut io: Wire = BufReader::new(Box::new(TcpStream::connect(addr).await.unwrap()));
    assert_eq!(relay::response(&mut io).await.unwrap().code, 220);
    assert_eq!(send(&mut io, "EHLO sender.example.org\r\n").await, 250);
    assert_eq!(
        send(&mut io, "MAIL FROM:<sender@example.org>\r\n").await,
        250
    );
    assert_eq!(
        send(&mut io, "RCPT TO:<elsewhere@external.test>\r\n").await,
        550
    );
    assert_eq!(calls(&missing), 0);
    // The development configuration maps billing to alice.
    assert_eq!(
        send(&mut io, "RCPT TO:<billing@example.test>\r\n").await,
        550
    );
    assert!(
        missing
            .seen
            .lock()
            .unwrap()
            .contains(&"RCPT TO:<alice@example.test>\r\n".into())
    );
    assert_eq!(
        send(&mut io, "RCPT TO:<unlisted@example.test>\r\n").await,
        550
    );
    assert_eq!(send(&mut io, "DATA\r\n").await, 503);
    assert!(store.claim().await.unwrap().is_none());
    assert_eq!(send(&mut io, "QUIT\r\n").await, 221);
    drop(io);
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn untrusted_certificate_never_authorizes_a_recipient() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    let tmp = tempfile::tempdir().unwrap();
    let key = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![key.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(key.signing_key.serialize_der()).into(),
        )
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let cfg = setup(tmp.path(), &[listener.local_addr().unwrap().to_string()]);
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut io: Wire = BufReader::new(Box::new(stream));
        smtp::reply(&mut io, "220 localhost\r\n").await.unwrap();
        assert!(
            smtp::line(&mut io, 512, 5)
                .await
                .unwrap()
                .unwrap()
                .starts_with(b"EHLO ")
        );
        smtp::reply(&mut io, "250-localhost\r\n250 STARTTLS\r\n")
            .await
            .unwrap();
        assert_eq!(
            smtp::line(&mut io, 512, 5).await.unwrap().unwrap(),
            b"STARTTLS\r\n"
        );
        smtp::reply(&mut io, "220 TLS\r\n").await.unwrap();
        assert!(
            tokio_rustls::TlsAcceptor::from(Arc::new(tls))
                .accept(io.into_inner())
                .await
                .is_err()
        );
    });
    assert_eq!(
        Runtime::default()
            .check(&cfg, &cfg.recipient("alice@example.test").unwrap(), "")
            .await,
        Verdict::Unavailable
    );
    task.await.unwrap();
}
#[tokio::test]
async fn mixed_recipients_queue_only_authorized_mailboxes_and_temporary_results_do_not_stick() {
    for (remote_reply, expected, deliver) in
        [("mixed", 250, true), ("451 4.3.0 Busy\r\n", 451, false)]
    {
        let tmp = tempfile::tempdir().unwrap();
        let remote = sink(remote_reply, "250 Sender\r\n").await;
        let cfg = Arc::new(setup(tmp.path(), std::slice::from_ref(&remote.route)));
        let store = Store::open(tmp.path()).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, rx) = watch::channel(false);
        let state = smtp::State {
            config: cfg.clone(),
            store: store.clone(),
            engine: Arc::new(Engine::new(cfg).unwrap()),
            processing: Arc::new(Semaphore::new(2)),
        };
        let task = tokio::spawn(smtp::serve(listener, state, rx));
        let mut io: Wire = BufReader::new(Box::new(TcpStream::connect(addr).await.unwrap()));
        assert_eq!(relay::response(&mut io).await.unwrap().code, 220);
        assert_eq!(send(&mut io, "EHLO sender.example.org\r\n").await, 250);
        assert_eq!(
            send(&mut io, "MAIL FROM:<sender@example.org>\r\n").await,
            250
        );
        smtp::reply(
            &mut io,
            "RCPT TO:<billing@example.test>\r\nRCPT TO:<missing@example.test>\r\nDATA\r\n",
        )
        .await
        .unwrap();
        assert_eq!(relay::response(&mut io).await.unwrap().code, expected);
        assert_eq!(
            relay::response(&mut io).await.unwrap().code,
            if deliver { 550 } else { 451 }
        );
        assert_eq!(
            relay::response(&mut io).await.unwrap().code,
            if deliver { 354 } else { 503 }
        );
        if deliver {
            use tokio::io::AsyncWriteExt;
            io.write_all(common::MESSAGE).await.unwrap();
            io.write_all(b".\r\n").await.unwrap();
            io.flush().await.unwrap();
            assert_eq!(relay::response(&mut io).await.unwrap().code, 250);
            let job = store.claim().await.unwrap().unwrap();
            assert_eq!(job.destination, "alice@example.test");
            assert!(store.claim().await.unwrap().is_none());
        } else {
            assert_eq!(
                send(&mut io, "RCPT TO:<billing@example.test>\r\n").await,
                451
            );
            assert_eq!(calls(&remote), 3);
            assert!(store.claim().await.unwrap().is_none());
        }
        assert_eq!(send(&mut io, "QUIT\r\n").await, 221);
        drop(io);
        stop.send(true).unwrap();
        task.await.unwrap().unwrap();
    }
}
