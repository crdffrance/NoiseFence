mod common;
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
    assert!(store.raw_path(&job.message_id).is_file());
    assert!(store.claim().await.unwrap().is_none());
    assert_eq!(command(&mut io, "QUIT\r\n").await, 221);
    drop(io);
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
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
) -> (u16, tokio::task::JoinHandle<Vec<u8>>) {
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
        let (port, task) = sink(code, true).await;
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
    let (port, task) = sink(250, false).await;
    let mut cfg = (*common::config(root.path())).clone();
    cfg.relay.port = port;
    cfg.relay.require_tls = true;
    assert!(matches!(
        relay::deliver(&cfg, &job(), common::MESSAGE).await,
        Outcome::Temporary(_)
    ));
    task.await.unwrap();
}
