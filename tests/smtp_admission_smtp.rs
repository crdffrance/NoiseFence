mod common;
use noisefence::{
    config::{Config, Mode as FilterMode},
    engine::Engine,
    relay,
    smtp::{self, State, Wire},
    smtp_admission::{Mode, Settings},
    store::Store,
};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::{Semaphore, watch},
    task::JoinHandle,
};

struct Server {
    address: SocketAddr,
    processing: Arc<Semaphore>,
    stop: watch::Sender<bool>,
    task: JoinHandle<anyhow::Result<()>>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Server {
    async fn shutdown(mut self) {
        self.stop.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(3), &mut self.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}
fn config(root: &std::path::Path) -> Config {
    let mut cfg = (*common::config(root)).clone();
    // Loopback fixture only: allow explicit admission enforcement independently
    // of the production/global observe guard. No configuration is published.
    cfg.filter.mode = FilterMode::Tag;
    cfg.smtp_admission = Some(Settings {
        enabled: true,
        mode: Mode::Enforce,
        retry_delay_seconds: 1,
        retry_max_age_seconds: 3600,
        ..Settings::default()
    });
    cfg
}
async fn server(cfg: Config, store: Store) -> Server {
    server_controlled(cfg, store, None).await
}
async fn server_controlled(
    cfg: Config,
    store: Store,
    control: Option<Arc<noisefence::control::Controller>>,
) -> Server {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (config, engine) = if let Some(control) = &control {
        let snapshot = control.snapshot();
        (snapshot.config.clone(), snapshot.engine.clone())
    } else {
        let config = Arc::new(cfg);
        let engine = Arc::new(Engine::new(config.clone()).unwrap());
        (config, engine)
    };
    let processing = Arc::new(Semaphore::new(1));
    let (stop, shutdown) = watch::channel(false);
    let task = tokio::spawn(smtp::serve_controlled(
        listener,
        State {
            config,
            store,
            engine,
            processing: processing.clone(),
        },
        control,
        shutdown,
    ));
    Server {
        address,
        processing,
        stop,
        task,
    }
}
async fn client(server: &Server) -> Wire {
    let mut io: Wire = BufReader::new(Box::new(TcpStream::connect(server.address).await.unwrap()));
    assert_eq!(response(&mut io).await, 220);
    io
}
async fn response(io: &mut Wire) -> u16 {
    tokio::time::timeout(Duration::from_secs(5), relay::response(io))
        .await
        .unwrap()
        .unwrap()
        .code
}
async fn command(io: &mut Wire, command: &str) -> u16 {
    smtp::reply(io, command).await.unwrap();
    response(io).await
}
async fn envelope(io: &mut Wire) {
    assert_eq!(command(io, "EHLO sender.example.org\r\n").await, 250);
    assert_eq!(command(io, "MAIL FROM:<sender@example.org>\r\n").await, 250);
}
async fn counts(store: &Store) -> (i64, i64, i64) {
    store
        .run(|db| {
            let messages = db.query_row("SELECT count(*) FROM messages", [], |r| r.get(0))?;
            let deliveries = db.query_row("SELECT count(*) FROM deliveries", [], |r| r.get(0))?;
            let exists: bool = db.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='smtp_admission_entries_v1')",
                [],
                |r| r.get(0),
            )?;
            let entries = if exists {
                db.query_row("SELECT count(*) FROM smtp_admission_entries_v1", [], |r| {
                    r.get(0)
                })?
            } else {
                0
            };
            Ok((messages, deliveries, entries))
        })
        .await
        .unwrap()
}
async fn submit(io: &mut Wire) {
    assert_eq!(command(io, "DATA\r\n").await, 354);
    io.write_all(common::MESSAGE).await.unwrap();
    io.write_all(b".\r\n").await.unwrap();
    io.flush().await.unwrap();
    assert_eq!(response(io).await, 250);
}
async fn quit(mut io: Wire) {
    assert_eq!(command(&mut io, "QUIT\r\n").await, 221);
}

#[tokio::test]
async fn absent_and_disabled_settings_do_not_create_admission_tables_at_startup() {
    for settings in [None, Some(Settings::default())] {
        let root = tempfile::tempdir().unwrap();
        let mut cfg = config(root.path());
        cfg.smtp_admission = settings;
        let store = Store::open(root.path()).unwrap();
        let server = server(cfg, store.clone()).await;
        let mut io = client(&server).await;
        envelope(&mut io).await;
        assert_eq!(
            command(&mut io, "RCPT TO:<alice@example.test>\r\n").await,
            250
        );
        let tables: i64 = store
            .run(|db| {
                Ok(db.query_row(
                    "SELECT count(*) FROM sqlite_master WHERE name LIKE 'smtp_admission_%'",
                    [],
                    |r| r.get(0),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(tables, 0);
        assert_eq!(counts(&store).await, (0, 0, 0));
        quit(io).await;
        server.shutdown().await;
    }
}

#[tokio::test]
async fn real_451_precedes_data_retry_survives_restart_and_mixed_recipients_stay_isolated() {
    let root = tempfile::tempdir().unwrap();
    let cfg = config(root.path());
    let store = Store::open(root.path()).unwrap();
    let first = server(cfg.clone(), store.clone()).await;
    let mut io = client(&first).await;
    envelope(&mut io).await;
    assert_eq!(
        command(&mut io, "RCPT TO:<victim@external.test>\r\n").await,
        550
    );
    assert_eq!(counts(&store).await, (0, 0, 0));
    assert_eq!(
        command(&mut io, "RCPT TO:<alice@example.test>\r\n").await,
        451
    );
    assert_eq!(command(&mut io, "DATA\r\n").await, 503);
    assert_eq!(counts(&store).await, (0, 0, 1));
    quit(io).await;
    first.shutdown().await;
    drop(store);

    // A real retry after the configured minimum; reopen Store and the listener.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let store = Store::open(root.path()).unwrap();
    let restarted = server(cfg, store.clone()).await;
    let mut io = client(&restarted).await;
    envelope(&mut io).await;
    assert_eq!(
        command(&mut io, "RCPT TO:<alice@example.test>\r\n").await,
        250
    );
    // PIPELINING preserves one result per RCPT; neither another mailbox nor an
    // alias sharing Alice's forwarding destination inherits Alice's retry.
    smtp::reply(
        &mut io,
        "RCPT TO:<bob@example.test>\r\nRCPT TO:<billing@example.test>\r\n",
    )
    .await
    .unwrap();
    assert_eq!(response(&mut io).await, 451);
    assert_eq!(response(&mut io).await, 451);
    submit(&mut io).await;
    assert_eq!(counts(&store).await, (1, 1, 3));
    let (address, is_dsn): (String, bool) = store.run(|db| {
        Ok(db.query_row("SELECT address,is_dsn FROM deliveries JOIN messages ON messages.id=deliveries.message_id", [], |r| Ok((r.get(0)?, r.get(1)?)))?)
    }).await.unwrap();
    assert_eq!(address, "alice@example.test");
    assert!(
        !is_dsn,
        "No challenge or locally generated bounce was queued"
    );
    quit(io).await;
    restarted.shutdown().await;
}

#[tokio::test]
async fn observe_on_the_wire_never_defers_or_sleeps_and_global_observe_dominates() {
    for (global, module) in [
        (FilterMode::Tag, Mode::Observe),
        (FilterMode::Observe, Mode::Enforce),
    ] {
        let root = tempfile::tempdir().unwrap();
        let mut cfg = config(root.path());
        cfg.filter.mode = global;
        let settings = cfg.smtp_admission.as_mut().unwrap();
        settings.mode = module;
        settings.tarpit_delay_ms = 5000;
        let store = Store::open(root.path()).unwrap();
        let server = server(cfg, store.clone()).await;
        let mut io = client(&server).await;
        envelope(&mut io).await;
        let code = tokio::time::timeout(
            Duration::from_millis(1000),
            command(&mut io, "RCPT TO:<alice@example.test>\r\n"),
        )
        .await
        .unwrap();
        assert_eq!(code, 250);
        submit(&mut io).await;
        assert_eq!(counts(&store).await, (1, 1, 1));
        let mode: i64 = store
            .run(|db| {
                Ok(
                    db.query_row("SELECT mode FROM smtp_admission_entries_v1", [], |r| {
                        r.get(0)
                    })?,
                )
            })
            .await
            .unwrap();
        assert_eq!(mode, 0);
        quit(io).await;
        server.shutdown().await;
    }
}

#[tokio::test]
async fn tarpit_leaves_data_permits_free_skips_saturated_sleepers_and_keeps_rset_budget() {
    let root = tempfile::tempdir().unwrap();
    let mut cfg = config(root.path());
    let settings = cfg.smtp_admission.as_mut().unwrap();
    settings.tarpit_delay_ms = 1500;
    settings.tarpit_session_budget_ms = 1500;
    settings.tarpit_max_concurrent = 1;
    let store = Store::open(root.path()).unwrap();
    let server = server(cfg, store.clone()).await;
    let mut one = client(&server).await;
    let mut two = client(&server).await;
    envelope(&mut one).await;
    envelope(&mut two).await;
    smtp::reply(&mut one, "RCPT TO:<alice@example.test>\r\n")
        .await
        .unwrap();
    // Wait for the committed tuple, not a guessed scheduling delay.
    tokio::time::timeout(Duration::from_millis(700), async {
        while counts(&store).await.2 != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    // Ensure the first response is actually being delayed before checking the
    // DATA resource; this does not send or acquire any DATA upload itself.
    assert!(
        tokio::time::timeout(Duration::from_millis(50), relay::response(&mut one))
            .await
            .is_err()
    );
    let data_permit = server
        .processing
        .clone()
        .try_acquire_owned()
        .expect("A tarpit must not hold the DATA processing permit");
    let second = tokio::time::timeout(
        Duration::from_millis(700),
        command(&mut two, "RCPT TO:<bob@example.test>\r\n"),
    )
    .await
    .unwrap();
    assert_eq!(second, 451, "Saturation skips sleep, not the deferral");
    drop(data_permit);
    assert_eq!(response(&mut one).await, 451);
    assert_eq!(command(&mut one, "RSET\r\n").await, 250);
    assert_eq!(
        command(&mut one, "RCPT TO:<billing@example.test>\r\n").await,
        503
    );
    assert_eq!(
        command(&mut one, "MAIL FROM:<new@example.org>\r\n").await,
        250
    );
    let next = tokio::time::timeout(
        Duration::from_millis(700),
        command(&mut one, "RCPT TO:<billing@example.test>\r\n"),
    )
    .await
    .unwrap();
    assert_eq!(
        next, 451,
        "RSET and a new MAIL do not replenish the socket budget"
    );
    assert_eq!(command(&mut one, "DATA\r\n").await, 503);
    assert_eq!(counts(&store).await, (0, 0, 3));
    quit(one).await;
    quit(two).await;
    server.shutdown().await;
}

#[tokio::test]
async fn starttls_clears_envelope_without_replenishing_delay_budget_or_losing_greylist_state() {
    let root = tempfile::tempdir().unwrap();
    let mut cfg = config(root.path());
    let settings = cfg.smtp_admission.as_mut().unwrap();
    settings.tarpit_delay_ms = 1000;
    settings.tarpit_session_budget_ms = 1000;
    let key = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = root.path().join("tls.pem");
    let secret = root.path().join("key.pem");
    std::fs::write(&cert, key.cert.pem()).unwrap();
    std::fs::write(&secret, key.signing_key.serialize_pem()).unwrap();
    cfg.smtp.tls_cert = Some(cert);
    cfg.smtp.tls_key = Some(secret);
    let store = Store::open(root.path()).unwrap();
    let server = server(cfg, store.clone()).await;
    let mut io = client(&server).await;
    envelope(&mut io).await;
    assert_eq!(
        command(&mut io, "RCPT TO:<alice@example.test>\r\n").await,
        451
    );
    assert_eq!(command(&mut io, "STARTTLS\r\n").await, 220);
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
    assert_eq!(
        command(&mut io, "RCPT TO:<alice@example.test>\r\n").await,
        503
    );
    assert_eq!(
        command(&mut io, "MAIL FROM:<sender@example.org>\r\n").await,
        503
    );
    envelope(&mut io).await;
    // New recipient, so 451 remains necessary. The connection budget was used
    // before TLS and must prevent another one-second sleep here.
    let code = tokio::time::timeout(
        Duration::from_millis(700),
        command(&mut io, "RCPT TO:<bob@example.test>\r\n"),
    )
    .await
    .unwrap();
    assert_eq!(code, 451);
    assert_eq!(counts(&store).await, (0, 0, 2));
    // The mature Alice tuple survived the handshake, but is checked anew.
    assert_eq!(
        command(&mut io, "RCPT TO:<alice@example.test>\r\n").await,
        250
    );
    assert_eq!(counts(&store).await, (0, 0, 2));
    quit(io).await;
    server.shutdown().await;
}

#[tokio::test]
async fn console_mode_changes_refresh_at_mail_and_share_old_session_sleep_capacity() {
    use noisefence::{
        actions::{Action, Policy},
        control::Controller,
    };
    let root = tempfile::tempdir().unwrap();
    let mut cfg = config(root.path());
    // No content tagging or external delivery is involved in this mode test.
    cfg.actions = Some(Policy {
        spam: Action::Deliver,
        publicity: Action::Deliver,
        malware: Action::Deliver,
        quarantine_days: 14,
    });
    let settings = cfg.smtp_admission.as_mut().unwrap();
    settings.tarpit_delay_ms = 3000;
    settings.tarpit_session_budget_ms = 3000;
    settings.tarpit_max_concurrent = 1;
    cfg.validate().unwrap();
    let store = Store::open(root.path()).unwrap();
    store
        .run(|db| {
            db.execute(
                "INSERT INTO users(username,password,admin) VALUES('admission-test','unused',1)",
                [],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    let control = Controller::load(Arc::new(cfg.clone()), store.clone())
        .await
        .unwrap();
    let server = server_controlled(cfg, store.clone(), Some(control.clone())).await;
    let mut older = client(&server).await;
    let mut newer = client(&server).await;
    envelope(&mut older).await;
    smtp::reply(&mut older, "RCPT TO:<alice@example.test>\r\n")
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_millis(700), async {
        while counts(&store).await.2 != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(50), relay::response(&mut older))
            .await
            .is_err()
    );

    // Both console changes and RCPT replies must finish while the older
    // controller still owns the single sleeper permit.
    tokio::time::timeout(Duration::from_millis(1500), async {
        let mut observe = control.snapshot().settings.clone();
        observe.filters.mode = FilterMode::Observe;
        let revision = control
            .apply(0, observe, "admission-test".into())
            .await
            .unwrap();
        envelope(&mut newer).await;
        assert_eq!(
            command(&mut newer, "RCPT TO:<bob@example.test>\r\n").await,
            250
        );

        let mut enforce = control.snapshot().settings.clone();
        enforce.filters.mode = FilterMode::Tag;
        control
            .apply(revision, enforce, "admission-test".into())
            .await
            .unwrap();
        // The already started MAIL retains its observation policy.
        assert_eq!(
            command(&mut newer, "RCPT TO:<billing@example.test>\r\n").await,
            250
        );
        assert_eq!(command(&mut newer, "RSET\r\n").await, 250);
        assert_eq!(
            command(&mut newer, "MAIL FROM:<sender@example.org>\r\n").await,
            250
        );
        // The new MAIL sees enforcement, but must share the occupied sleeper.
        assert_eq!(
            command(&mut newer, "RCPT TO:<billing@example.test>\r\n").await,
            451
        );
        assert_eq!(command(&mut newer, "DATA\r\n").await, 503);
    })
    .await
    .unwrap();
    assert_eq!(counts(&store).await, (0, 0, 4));
    assert_eq!(server.processing.available_permits(), 1);
    assert_eq!(response(&mut older).await, 451);
    quit(older).await;
    quit(newer).await;
    server.shutdown().await;
}
