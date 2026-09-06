mod common;
use noisefence::{
    engine::Engine,
    relay,
    smtp::{self, State, Wire},
    store::Store,
};
use std::sync::Arc;
use tokio::{
    io::BufReader,
    net::{TcpListener, TcpStream},
    sync::{Semaphore, watch},
};

#[tokio::test]
async fn starttls_resets_session_and_uses_a_real_handshake() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    let root = tempfile::tempdir().unwrap();
    let key = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = root.path().join("tls.pem");
    let secret = root.path().join("key.pem");
    std::fs::write(&cert, key.cert.pem()).unwrap();
    std::fs::write(&secret, key.signing_key.serialize_pem()).unwrap();
    let mut cfg = (*common::config(root.path())).clone();
    cfg.smtp.tls_cert = Some(cert);
    cfg.smtp.tls_key = Some(secret);
    let cfg = Arc::new(cfg);
    let store = Store::open(root.path()).unwrap();
    let engine = Arc::new(Engine::new(cfg.clone()).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(smtp::serve(
        listener,
        State {
            config: cfg,
            store,
            engine,
            processing: Arc::new(Semaphore::new(2)),
        },
        rx,
    ));
    let mut io: Wire = BufReader::new(Box::new(TcpStream::connect(addr).await.unwrap()));
    relay::response(&mut io).await.unwrap();
    smtp::reply(&mut io, "EHLO example.org\r\n").await.unwrap();
    let ehlo = relay::response(&mut io).await.unwrap();
    assert!(ehlo.lines.contains(&"STARTTLS".to_string()));
    smtp::reply(&mut io, "MAIL FROM:<sender@example.org>\r\n")
        .await
        .unwrap();
    assert_eq!(relay::response(&mut io).await.unwrap().code, 250);
    smtp::reply(&mut io, "STARTTLS\r\n").await.unwrap();
    assert_eq!(relay::response(&mut io).await.unwrap().code, 220);
    let mut roots = rustls::RootCertStore::empty();
    roots.add(key.cert.der().clone()).unwrap();
    let client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let tls = tokio_rustls::TlsConnector::from(Arc::new(client))
        .connect(
            rustls::pki_types::ServerName::try_from("localhost").unwrap(),
            io.into_inner(),
        )
        .await
        .unwrap();
    let mut io: Wire = BufReader::new(Box::new(tls));
    smtp::reply(&mut io, "RCPT TO:<alice@example.test>\r\n")
        .await
        .unwrap();
    assert_eq!(relay::response(&mut io).await.unwrap().code, 503);
    smtp::reply(&mut io, "EHLO example.org\r\n").await.unwrap();
    let ehlo = relay::response(&mut io).await.unwrap();
    assert!(!ehlo.lines.contains(&"STARTTLS".into()));
    smtp::reply(&mut io, "QUIT\r\n").await.unwrap();
    relay::response(&mut io).await.unwrap();
    drop(io);
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
}
#[tokio::test]
async fn production_relay_rejects_an_untrusted_certificate() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    let root = tempfile::tempdir().unwrap();
    let key = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = root.path().join("tls.pem");
    let secret = root.path().join("key.pem");
    std::fs::write(&cert, key.cert.pem()).unwrap();
    std::fs::write(&secret, key.signing_key.serialize_pem()).unwrap();
    let mut cfg = (*common::config(root.path())).clone();
    cfg.smtp.tls_cert = Some(cert);
    cfg.smtp.tls_key = Some(secret);
    cfg.relay.require_tls = true;
    let tls = smtp::tls_acceptor(&cfg).unwrap().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    cfg.relay.port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut io: Wire = BufReader::new(Box::new(socket));
        smtp::reply(&mut io, "220 localhost\r\n").await.unwrap();
        smtp::line(&mut io, 512, 5).await.unwrap();
        smtp::reply(&mut io, "250-localhost\r\n250 STARTTLS\r\n")
            .await
            .unwrap();
        smtp::line(&mut io, 512, 5).await.unwrap();
        smtp::reply(&mut io, "220 Ready\r\n").await.unwrap();
        let _ = tls.accept(io.into_inner()).await;
    });
    let job = noisefence::store::Job {
        delivery_id: 1,
        message_id: "test".into(),
        created: noisefence::now(),
        sender: "sender@example.org".into(),
        destination: "alice@example.test".into(),
        hosts: vec!["127.0.0.1".into()],
        attempts: 1,
        is_dsn: false,
    };
    assert!(matches!(
        relay::deliver(&cfg, &job, common::MESSAGE).await,
        relay::Outcome::Temporary(_)
    ));
    task.await.unwrap();
}
