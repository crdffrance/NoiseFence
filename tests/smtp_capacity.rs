mod common;

use noisefence::{
    engine::Engine,
    relay,
    smtp::{self, State, Wire},
    store::Store,
};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::{Semaphore, watch},
    task::JoinHandle,
};

struct Gateway {
    root: tempfile::TempDir,
    store: Store,
    slots: Arc<Semaphore>,
    addr: SocketAddr,
    shutdown: watch::Sender<bool>,
    task: JoinHandle<anyhow::Result<()>>,
}

impl Gateway {
    async fn start(wait_ms: u64) -> Self {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
        let root = tempfile::tempdir().unwrap();
        let mut cfg = (*common::config(root.path())).clone();
        cfg.smtp.max_processing = 1;
        cfg.smtp.processing_wait_ms = wait_ms;
        cfg.validate().unwrap();
        let cfg = Arc::new(cfg);
        let store = Store::open(root.path()).unwrap();
        let slots = Arc::new(Semaphore::new(1));
        let state = State {
            config: cfg.clone(),
            store: store.clone(),
            engine: Arc::new(Engine::new(cfg).unwrap()),
            processing: slots.clone(),
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (shutdown, receiver) = watch::channel(false);
        let task = tokio::spawn(smtp::serve(listener, state, receiver));
        Self {
            root,
            store,
            slots,
            addr,
            shutdown,
            task,
        }
    }

    async fn client(&self) -> Wire {
        let mut io: Wire = BufReader::new(Box::new(TcpStream::connect(self.addr).await.unwrap()));
        assert_eq!(relay::response(&mut io).await.unwrap().code, 220);
        prepare(&mut io).await;
        io
    }

    async fn assert_no_message(&self) {
        assert_eq!(
            std::fs::read_dir(self.root.path().join("incoming"))
                .unwrap()
                .count(),
            0
        );
        let count = self
            .store
            .run(|db| {
                Ok(db.query_row("SELECT COUNT(*) FROM messages", [], |row| {
                    row.get::<_, i64>(0)
                })?)
            })
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    async fn stop(self) {
        self.shutdown.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(5), self.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(self.slots.available_permits(), 1);
        assert_eq!(
            std::fs::read_dir(self.root.path().join("incoming"))
                .unwrap()
                .count(),
            0
        );
    }
}

async fn command(io: &mut Wire, text: &str) -> u16 {
    smtp::reply(io, text).await.unwrap();
    relay::response(io).await.unwrap().code
}

async fn prepare(io: &mut Wire) {
    assert_eq!(command(io, "EHLO sender.example.org\r\n").await, 250);
    assert_eq!(command(io, "MAIL FROM:<sender@example.org>\r\n").await, 250);
    assert_eq!(command(io, "RCPT TO:<alice@example.test>\r\n").await, 250);
}

#[tokio::test]
async fn waiting_before_354_keeps_spool_empty_then_accepts_durably() {
    let gateway = Gateway::start(5000).await;
    let held = gateway.slots.clone().acquire_owned().await.unwrap();
    let mut io = gateway.client().await;
    smtp::reply(&mut io, "DATA\r\n").await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(20), io.fill_buf())
            .await
            .is_err()
    );
    gateway.assert_no_message().await;
    drop(held);
    assert_eq!(relay::response(&mut io).await.unwrap().code, 354);
    io.write_all(common::MESSAGE).await.unwrap();
    io.write_all(b".\r\n").await.unwrap();
    io.flush().await.unwrap();
    assert_eq!(relay::response(&mut io).await.unwrap().code, 250);
    let count = gateway
        .store
        .run(|db| {
            Ok(db.query_row(
                "SELECT COUNT(*) FROM messages WHERE raw_present=1",
                [],
                |row| row.get::<_, i64>(0),
            )?)
        })
        .await
        .unwrap();
    assert_eq!(count, 1);
    assert_eq!(command(&mut io, "QUIT\r\n").await, 221);
    drop(io);
    gateway.stop().await;
}

#[tokio::test]
async fn busy_or_expired_wait_returns_451_before_storage_and_resets_envelope() {
    for wait_ms in [0, 20] {
        let gateway = Gateway::start(wait_ms).await;
        let held = gateway.slots.clone().acquire_owned().await.unwrap();
        let mut io = gateway.client().await;
        assert_eq!(command(&mut io, "DATA\r\n").await, 451);
        gateway.assert_no_message().await;
        drop(held);
        assert_eq!(command(&mut io, "DATA\r\n").await, 503);
        prepare(&mut io).await;
        assert_eq!(command(&mut io, "DATA\r\n").await, 354);
        // Disconnect without a terminator: the reserved slot and temporary file
        // must be released, and this transaction must remain unaccepted.
        drop(io);
        gateway.stop().await;
    }
}

#[tokio::test]
async fn disconnected_waiter_cannot_leak_a_processing_slot() {
    let gateway = Gateway::start(100).await;
    let held = gateway.slots.clone().acquire_owned().await.unwrap();
    let mut io = gateway.client().await;
    smtp::reply(&mut io, "DATA\r\n").await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(20), io.fill_buf())
            .await
            .is_err()
    );
    drop(io);
    drop(held);
    gateway.stop().await;
}
