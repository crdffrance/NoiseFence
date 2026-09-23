mod common;
use noisefence::{
    cluster::{
        activation::{Acknowledgement, Epoch, Journal, Phase, Progress, gate::Gate},
        artifacts,
    },
    control::Settings,
    store::Store,
};
use rusqlite::Connection;
use std::time::Duration;

async fn participant(
    root: &std::path::Path,
    worker: bool,
) -> std::sync::Arc<noisefence::control::Controller> {
    let mut cfg = (*common::config(root)).clone();
    cfg.cluster = Some(noisefence::cluster::Settings {
        role: if worker {
            noisefence::cluster::Role::Worker
        } else {
            noisefence::cluster::Role::Coordinator
        },
        node_id: if worker { "mx2" } else { "mx1" }.into(),
        coordinator_url: worker.then(|| "http://127.0.0.1:1".into()),
        credential_file: worker.then(|| root.join("identity")),
        poll_seconds: 2,
        max_stale_seconds: 60,
        allow_loopback_http: true,
    });
    let store = Store::open(root).unwrap();
    noisefence::cluster::prepare(&cfg, &store).await.unwrap();
    noisefence::control::Controller::load(std::sync::Arc::new(cfg), store)
        .await
        .unwrap()
}

async fn synchronize(
    control: &std::sync::Arc<noisefence::control::Controller>,
    authority: Journal,
) -> anyhow::Result<Option<Acknowledgement>> {
    control
        .synchronize_activation(
            authority,
            noisefence::credentials::Snapshot::default(),
            noisefence::now(),
        )
        .await
}

#[tokio::test]
async fn replication_setup_preserves_the_activation_database_guard() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut f = Fixture::new();
    let control = participant(f.root.path(), false).await;
    f.initialize();
    let mut config = (*control.base).clone();
    let credential = f.root.path().join("replica-token");
    noisefence::cluster::protocol::private_write(
        &credential,
        noisefence::api::random_token().as_bytes(),
    )
    .unwrap();
    config.replication = Some(noisefence::ha::Settings {
        peer_id: "mx2".into(),
        peer_url: "http://127.0.0.1:1".into(),
        credential_file: credential,
        timeout_seconds: 5,
        max_replica_bytes: 64 * 1024 * 1024,
        allow_loopback_http: true,
    });
    noisefence::ha::initialize(&control.store, &config)
        .await
        .unwrap();
    assert_eq!(
        f.db.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        6
    );
    assert!(!Store::open(f.root.path()).unwrap().activation.ready());
}

#[tokio::test]
async fn enrollment_cannot_rewind_a_previously_synchronized_worker() {
    let mut f = Fixture::new();
    let remote = tempfile::tempdir().unwrap();
    let worker = participant(remote.path(), true).await;
    worker
        .apply_cluster(f.bundle(5, 99.), "a".repeat(64), noisefence::now())
        .await
        .unwrap();
    assert!(worker.cluster_ready());
    f.initialize();
    f.stage(1, 97.);
    assert!(
        worker
            .synchronize_activation(
                f.read(),
                noisefence::credentials::Snapshot::default(),
                i64::MIN
            )
            .await
            .is_err()
    );
    assert!(synchronize(&worker, f.read()).await.is_err());
    assert!(
        worker.cluster_ready(),
        "invalid enrollment must not fence the live policy"
    );
    assert_eq!(worker.snapshot().revision, 5);
    assert_eq!(worker.snapshot().config.filter.threshold, 99.);
    assert!(worker.store.activation.epoch().is_none());
}

#[tokio::test]
async fn actual_participants_prepare_apply_release_and_restart_with_the_same_policy() {
    let mut f = Fixture::new();
    let remote = tempfile::tempdir().unwrap();
    let central = participant(f.root.path(), false).await;
    let worker = participant(remote.path(), true).await;
    f.initialize();
    let epoch = f.stage(1, 97.);
    let preparing = f.read();
    for (id, control) in [("mx1", &central), ("mx2", &worker)] {
        let ack = synchronize(control, preparing.clone())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(ack.progress, Progress::Prepared);
        assert_eq!(ack.epoch, epoch);
        assert!(!control.cluster_ready());
        assert_eq!(control.snapshot().config.filter.threshold, 95.);
        f.ack(&epoch, id, ack.progress);
    }
    let tx = f.db.transaction().unwrap();
    let committed = Journal::commit(&tx, &epoch, 100).unwrap();
    tx.commit().unwrap();
    let ack = synchronize(&central, committed.clone())
        .await
        .unwrap()
        .unwrap();
    f.ack(&epoch, "mx1", ack.progress);
    assert_eq!(central.snapshot().config.filter.threshold, 97.);
    assert_eq!(worker.snapshot().config.filter.threshold, 95.);
    assert!(!central.store.activation.ready());
    assert!(!worker.store.activation.ready());
    // Lost commit delivery: neither the authority nor the already updated MX
    // resumes acceptance until the second participant actually installs it.
    let tx = f.db.transaction().unwrap();
    assert!(Journal::release(&tx, &epoch, 100).is_err());
    drop(tx);
    let ack = synchronize(&worker, committed.clone())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ack.progress, Progress::Applied);
    f.ack(&epoch, "mx2", ack.progress);
    drop(worker);
    let worker = participant(remote.path(), true).await;
    assert!(!worker.cluster_ready());
    assert_eq!(worker.snapshot().activation_epoch.as_ref(), Some(&epoch));
    assert_eq!(worker.snapshot().config.filter.threshold, 97.);
    let tx = f.db.transaction().unwrap();
    let released = Journal::release(&tx, &epoch, 100).unwrap();
    tx.commit().unwrap();
    for control in [&central, &worker] {
        synchronize(control, released.clone()).await.unwrap();
        assert!(control.cluster_ready());
        assert_eq!(control.snapshot().activation_epoch.as_ref(), Some(&epoch));
        let lease = control.store.activation.enter(Some(&epoch)).unwrap();
        // A repeated release with a lost reply must not fence active traffic.
        synchronize(control, released.clone()).await.unwrap();
        assert!(control.store.activation.ready());
        assert!(synchronize(control, preparing.clone()).await.is_err());
        assert!(control.store.activation.ready());
        drop(lease);
    }
    assert_eq!(
        central.snapshot().engine.offline(common::MESSAGE).score,
        worker.snapshot().engine.offline(common::MESSAGE).score
    );
    drop(worker);
    let worker = participant(remote.path(), true).await;
    assert!(
        !worker.cluster_ready(),
        "released journal alone cannot prove the resident runtime"
    );
    synchronize(&worker, released).await.unwrap();
    assert!(worker.cluster_ready());
    assert!(
        worker
            .apply_cluster(
                committed.current().clone(),
                "a".repeat(64),
                noisefence::now()
            )
            .await
            .is_err()
    );
}

#[tokio::test]
async fn participant_abort_and_partial_commit_recovery_preserve_admission_fences() {
    let mut f = Fixture::new();
    let remote = tempfile::tempdir().unwrap();
    let worker = participant(remote.path(), true).await;
    f.initialize();
    let first = f.stage(1, 97.);
    synchronize(&worker, f.read()).await.unwrap();
    let tx = f.db.transaction().unwrap();
    let aborted = Journal::abort(&tx, &first, 100).unwrap();
    tx.commit().unwrap();
    synchronize(&worker, aborted).await.unwrap();
    assert!(worker.cluster_ready());
    assert_eq!(worker.snapshot().config.filter.threshold, 95.);
    let next = f.stage(2, 98.);
    synchronize(&worker, f.read()).await.unwrap();
    f.ack(&next, "mx1", Progress::Prepared);
    f.ack(&next, "mx2", Progress::Prepared);
    let tx = f.db.transaction().unwrap();
    let committed = Journal::commit(&tx, &next, 100).unwrap();
    tx.commit().unwrap();
    synchronize(&worker, committed).await.unwrap();
    assert_eq!(worker.snapshot().config.filter.threshold, 98.);
    assert!(!worker.cluster_ready());
    let restore = f.bundle(3, 95.);
    let tx = f.db.transaction().unwrap();
    let recovering = Journal::recover_previous(&tx, &next, restore, 100).unwrap();
    tx.commit().unwrap();
    let recovery = recovering.rollout().unwrap().epoch().clone();
    synchronize(&worker, recovering.clone()).await.unwrap();
    assert!(!worker.cluster_ready());
    drop(worker);
    let worker = participant(remote.path(), true).await;
    synchronize(&worker, recovering).await.unwrap();
    f.ack(&recovery, "mx1", Progress::Prepared);
    f.ack(&recovery, "mx2", Progress::Prepared);
    let tx = f.db.transaction().unwrap();
    let committed = Journal::commit(&tx, &recovery, 100).unwrap();
    tx.commit().unwrap();
    synchronize(&worker, committed).await.unwrap();
    f.ack(&recovery, "mx1", Progress::Applied);
    f.ack(&recovery, "mx2", Progress::Applied);
    let tx = f.db.transaction().unwrap();
    let released = Journal::release(&tx, &recovery, 100).unwrap();
    tx.commit().unwrap();
    synchronize(&worker, released).await.unwrap();
    assert!(worker.cluster_ready());
    assert_eq!(worker.snapshot().config.filter.threshold, 95.);
    assert_eq!(worker.snapshot().revision, 3);
}

#[tokio::test]
async fn participant_verifies_real_model_bytes_before_readiness_and_after_restart() {
    let mut f = Fixture::new();
    let remote = tempfile::tempdir().unwrap();
    let worker = participant(remote.path(), true).await;
    f.initialize();
    let model = noisefence::engine::Model {
        version: "activation-test".into(),
        algorithm: noisefence::engine::Algorithm::Logistic,
        feature_version: 1,
        bias: -4.,
        weights: vec![0.; noisefence::engine::FEATURE_COUNT],
        idf: vec![],
        trained_at: noisefence::now(),
        examples: 2,
    };
    let bytes = serde_json::to_vec(&model).unwrap();
    let path = f.root.path().join("candidate.json");
    std::fs::write(&path, &bytes).unwrap();
    f.config.filter.model = Some(path);
    let epoch = f.stage(1, 97.);
    let preparing = f.read();
    let bundle = preparing.rollout().unwrap().candidate();
    let cache = artifacts::directory(remote.path(), bundle);
    std::fs::create_dir_all(&cache).unwrap();
    let path = cache.join(bundle.files.keys().next().unwrap());
    std::fs::write(&path, b"corrupted").unwrap();
    assert!(synchronize(&worker, preparing.clone()).await.is_err());
    assert!(!worker.cluster_ready());
    let pending = worker
        .store
        .run(|db| {
            let tx = db.transaction()?;
            Ok(
                noisefence::cluster::activation::participant::Local::read(&tx)?
                    .unwrap()
                    .acknowledgement(),
            )
        })
        .await
        .unwrap();
    assert!(
        pending.is_none(),
        "corrupt files cannot earn a prepared receipt"
    );
    std::fs::write(&path, &bytes).unwrap();
    assert_eq!(
        synchronize(&worker, preparing)
            .await
            .unwrap()
            .unwrap()
            .progress,
        Progress::Prepared
    );
    f.ack(&epoch, "mx1", Progress::Prepared);
    f.ack(&epoch, "mx2", Progress::Prepared);
    let tx = f.db.transaction().unwrap();
    let committed = Journal::commit(&tx, &epoch, 100).unwrap();
    tx.commit().unwrap();
    synchronize(&worker, committed).await.unwrap();
    let config = worker.base.clone();
    drop(worker);
    std::fs::write(&path, b"corrupted after durable installation").unwrap();
    let store = Store::open(remote.path()).unwrap();
    assert!(!store.activation.ready());
    assert!(
        noisefence::control::Controller::load(config.clone(), store)
            .await
            .is_err()
    );
    std::fs::write(&path, &bytes).unwrap();
    let store = Store::open(remote.path()).unwrap();
    let worker = noisefence::control::Controller::load(config, store)
        .await
        .unwrap();
    assert!(!worker.cluster_ready());
    let unseen = tempfile::tempdir().unwrap();
    let stranger = participant(unseen.path(), true).await;
    assert!(
        synchronize(&stranger, f.read()).await.is_err(),
        "commit cannot enroll an unprepared node"
    );
}

struct Fixture {
    root: tempfile::TempDir,
    db: Connection,
    config: noisefence::config::Config,
}
impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        drop(Store::open(root.path()).unwrap());
        let db = Connection::open(root.path().join("state.sqlite3")).unwrap();
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; INSERT INTO cluster_state VALUES('role','coordinator'); INSERT INTO cluster_state VALUES('node_id','mx1');").unwrap();
        let config = (*common::config(root.path())).clone();
        Self { root, db, config }
    }
    fn bundle(&self, revision: i64, threshold: f64) -> artifacts::Bundle {
        let mut config = self.config.clone();
        config.filter.threshold = threshold;
        artifacts::capture(&config, Settings::from_config(&config), revision)
            .unwrap()
            .bundle
    }
    fn initialize(&mut self) {
        let active = self.bundle(0, 95.);
        let tx = self.db.transaction().unwrap();
        Journal::initialize(&tx, "mx1", active).unwrap();
        tx.commit().unwrap();
    }
    fn stage(&mut self, revision: i64, threshold: f64) -> Epoch {
        let bundle = self.bundle(revision, threshold);
        let tx = self.db.transaction().unwrap();
        let state = Journal::begin(&tx, bundle, vec!["mx1".into(), "mx2".into()], 100).unwrap();
        let epoch = state.rollout().unwrap().epoch().clone();
        tx.commit().unwrap();
        epoch
    }
    fn ack(&mut self, epoch: &Epoch, node: &str, progress: Progress) {
        let tx = self.db.transaction().unwrap();
        Journal::acknowledge(
            &tx,
            node,
            &Acknowledgement {
                epoch: epoch.clone(),
                progress,
            },
            100,
        )
        .unwrap();
        tx.commit().unwrap();
    }
    fn read(&mut self) -> Journal {
        let tx = self.db.transaction().unwrap();
        Journal::read(&tx).unwrap().unwrap()
    }
}

#[test]
fn all_participants_must_prepare_and_apply_before_release() {
    let mut f = Fixture::new();
    f.initialize();
    let epoch = f.stage(1, 97.);
    let tx = f.db.transaction().unwrap();
    assert!(Journal::commit(&tx, &epoch, 100).is_err());
    assert!(Journal::release(&tx, &epoch, 100).is_err());
    for (node, proof) in [
        (
            "unknown",
            Acknowledgement {
                epoch: epoch.clone(),
                progress: Progress::Prepared,
            },
        ),
        (
            "mx1",
            Acknowledgement {
                epoch: Epoch {
                    digest: "0".repeat(64),
                    ..epoch.clone()
                },
                progress: Progress::Prepared,
            },
        ),
        (
            "mx1",
            Acknowledgement {
                epoch: epoch.clone(),
                progress: Progress::Applied,
            },
        ),
    ] {
        assert!(Journal::acknowledge(&tx, node, &proof, 100).is_err());
    }
    drop(tx);
    f.ack(&epoch, "mx1", Progress::Prepared);
    assert_eq!(f.read().current().revision, 0);
    f.ack(&epoch, "mx2", Progress::Prepared);
    // Simulated crash: neither the console revision nor the activation commit
    // may survive independently when the shared SQLite transaction rolls back.
    let tx = f.db.transaction().unwrap();
    tx.execute(
        "INSERT INTO console_revisions(id,created,username,settings) VALUES(1,100,'fixture','{}')",
        [],
    )
    .unwrap();
    Journal::commit(&tx, &epoch, 100).unwrap();
    drop(tx);
    assert_eq!(f.read().rollout().unwrap().phase(), Phase::Preparing);
    assert_eq!(
        f.db.query_row("SELECT COUNT(*) FROM console_revisions", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    let tx = f.db.transaction().unwrap();
    Journal::commit(&tx, &epoch, 100).unwrap();
    tx.commit().unwrap();
    assert_eq!(f.read().current_epoch(), epoch);
    f.ack(&epoch, "mx1", Progress::Applied);
    let tx = f.db.transaction().unwrap();
    assert!(Journal::release(&tx, &epoch, 100).is_err());
    assert!(Journal::abort(&tx, &epoch, 100).is_err());
    drop(tx);
    f.ack(&epoch, "mx2", Progress::Applied);
    f.ack(&epoch, "mx1", Progress::Prepared); // delayed old receipt cannot undo Applied
    let tx = f.db.transaction().unwrap();
    Journal::release(&tx, &epoch, 100).unwrap();
    Journal::release(&tx, &epoch, 100).unwrap();
    tx.commit().unwrap();
    assert!(f.read().released());
    assert!(
        f.read()
            .rollout()
            .unwrap()
            .participants()
            .values()
            .all(|p| *p == Progress::Applied)
    );
    // Even a released durable journal starts CLOSED until its exact runtime is
    // validated and reattached by the coordinated controller recovery driver.
    let reopened = Store::open(f.root.path()).unwrap();
    assert!(!reopened.activation.ready());
    assert_eq!(reopened.activation.epoch(), Some(epoch.clone()));
    assert!(reopened.activation.enter(Some(&epoch)).is_err());
    let next = f.stage(2, 98.);
    let tx = f.db.transaction().unwrap();
    assert!(
        Journal::acknowledge(
            &tx,
            "mx2",
            &Acknowledgement {
                epoch,
                progress: Progress::Applied
            },
            100
        )
        .is_err()
    );
    assert!(Journal::commit(&tx, &next, 100).is_err());
}

#[test]
fn precommit_abort_and_partial_commit_recovery_do_not_rewind_versions() {
    let mut f = Fixture::new();
    f.initialize();
    let first = f.stage(1, 97.);
    f.ack(&first, "mx1", Progress::Prepared);
    let tx = f.db.transaction().unwrap();
    Journal::abort(&tx, &first, 100).unwrap();
    tx.commit().unwrap();
    assert_eq!(f.read().current().revision, 0);
    let next = f.stage(1, 97.);
    assert!(next.sequence > first.sequence);
    for node in ["mx1", "mx2"] {
        f.ack(&next, node, Progress::Prepared);
    }
    let tx = f.db.transaction().unwrap();
    Journal::commit(&tx, &next, 100).unwrap();
    tx.commit().unwrap();
    f.ack(&next, "mx1", Progress::Applied);
    let rollback = f.bundle(2, 95.);
    let wrong = f.bundle(2, 98.);
    let tx = f.db.transaction().unwrap();
    assert!(Journal::recover_previous(&tx, &next, wrong, 100).is_err());
    let recovered = Journal::recover_previous(&tx, &next, rollback, 100).unwrap();
    let recovery = recovered.rollout().unwrap().epoch().clone();
    assert_eq!(recovered.rollout().unwrap().recovery_of(), Some(&next));
    assert!(!recovered.rollout().unwrap().abortable());
    assert!(Journal::abort(&tx, &recovery, 100).is_err());
    tx.commit().unwrap();
    for node in ["mx1", "mx2"] {
        f.ack(&recovery, node, Progress::Prepared);
    }
    let tx = f.db.transaction().unwrap();
    Journal::commit(&tx, &recovery, 100).unwrap();
    tx.commit().unwrap();
    for node in ["mx1", "mx2"] {
        f.ack(&recovery, node, Progress::Applied);
    }
    let tx = f.db.transaction().unwrap();
    Journal::release(&tx, &recovery, 100).unwrap();
    tx.commit().unwrap();
    let state = f.read();
    assert_eq!(state.current().revision, 2);
    assert_eq!(state.current().settings.filters.threshold, 95.);
    assert_eq!(state.current_epoch(), recovery);
}

#[test]
fn malformed_membership_candidate_and_journal_never_enable_activation() {
    let mut f = Fixture::new();
    f.initialize();
    let candidate = f.bundle(1, 97.);
    let tx = f.db.transaction().unwrap();
    for participants in [
        vec![],
        vec!["mx2".into()],
        vec!["mx1".into(), "mx1".into()],
        vec!["mx1".into(), "BAD NODE".into()],
    ] {
        assert!(Journal::begin(&tx, candidate.clone(), participants, 100).is_err());
    }
    let mut invalid = candidate.clone();
    invalid.digest = "0".repeat(64);
    assert!(Journal::begin(&tx, invalid, vec!["mx1".into()], 100).is_err());
    assert!(Journal::read(&tx).unwrap().unwrap().rollout().is_none());
    drop(tx);
    f.db.execute_batch("PRAGMA user_version=5").unwrap();
    assert!(Store::open(f.root.path()).is_err());
    f.db.execute_batch("PRAGMA user_version=6").unwrap();
    f.db.execute(
        "UPDATE cluster_state SET value='other' WHERE key='node_id'",
        [],
    )
    .unwrap();
    assert!(Store::open(f.root.path()).is_err());
    f.db.execute(
        "UPDATE cluster_state SET value='mx1' WHERE key='node_id'",
        [],
    )
    .unwrap();
    // A durable format marker cannot silently fall back to standalone policy.
    f.db.execute(
        "DELETE FROM cluster_state WHERE key='coordinated_activation'",
        [],
    )
    .unwrap();
    assert!(Store::open(f.root.path()).is_err());
}

fn epoch(sequence: u64) -> Epoch {
    Epoch {
        sequence,
        revision: sequence as i64,
        digest: noisefence::message::digest(&sequence.to_be_bytes()),
    }
}

#[tokio::test]
async fn smtp_rejects_an_old_epoch_after_release_and_accepts_the_next_transaction() {
    use std::sync::Arc;
    use tokio::{
        io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
        net::{TcpListener, TcpStream},
    };
    async fn response(io: &mut BufReader<TcpStream>) -> String {
        let mut line = String::new();
        loop {
            line.clear();
            assert!(
                tokio::time::timeout(Duration::from_secs(5), io.read_line(&mut line))
                    .await
                    .unwrap()
                    .unwrap()
                    > 0
            );
            if line.as_bytes().get(3) != Some(&b'-') {
                return line;
            }
        }
    }
    async fn activate(
        f: &mut Fixture,
        worker: &Arc<noisefence::control::Controller>,
        revision: i64,
    ) -> Epoch {
        let epoch = f.stage(revision, 95. + revision as f64);
        synchronize(worker, f.read()).await.unwrap();
        for id in ["mx1", "mx2"] {
            f.ack(&epoch, id, Progress::Prepared);
        }
        let tx = f.db.transaction().unwrap();
        let committed = Journal::commit(&tx, &epoch, 100).unwrap();
        tx.commit().unwrap();
        synchronize(worker, committed).await.unwrap();
        for id in ["mx1", "mx2"] {
            f.ack(&epoch, id, Progress::Applied);
        }
        let tx = f.db.transaction().unwrap();
        let released = Journal::release(&tx, &epoch, 100).unwrap();
        tx.commit().unwrap();
        synchronize(worker, released).await.unwrap();
        epoch
    }
    let mut f = Fixture::new();
    let remote = tempfile::tempdir().unwrap();
    let worker = participant(remote.path(), true).await;
    f.initialize();
    activate(&mut f, &worker, 1).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, stopping) = tokio::sync::watch::channel(false);
    let snapshot = worker.snapshot();
    let state = noisefence::smtp::State {
        config: snapshot.config.clone(),
        engine: snapshot.engine.clone(),
        store: worker.store.clone(),
        processing: Arc::new(tokio::sync::Semaphore::new(2)),
    };
    let server = tokio::spawn(noisefence::smtp::serve_controlled(
        listener,
        state,
        Some(worker.clone()),
        stopping,
    ));
    let mut io = BufReader::new(TcpStream::connect(address).await.unwrap());
    assert!(response(&mut io).await.starts_with("220"));
    for command in [
        "EHLO sender.example.test\r\n",
        "MAIL FROM:<sender@example.org>\r\n",
        "RCPT TO:<alice@example.test>\r\n",
    ] {
        io.write_all(command.as_bytes()).await.unwrap();
        assert!(response(&mut io).await.starts_with("250"));
    }
    let current = activate(&mut f, &worker, 2).await;
    assert!(worker.cluster_ready());
    for expected in ["451", "250"] {
        io.write_all(b"DATA\r\n").await.unwrap();
        assert!(response(&mut io).await.starts_with("354"));
        io.write_all(b"X-NoiseFence-Activation: forged\r\n")
            .await
            .unwrap();
        io.write_all(common::MESSAGE).await.unwrap();
        io.write_all(b".\r\n").await.unwrap();
        assert!(response(&mut io).await.starts_with(expected));
        if expected == "451" {
            for command in [
                "RSET\r\n",
                "MAIL FROM:<sender@example.org>\r\n",
                "RCPT TO:<alice@example.test>\r\n",
            ] {
                io.write_all(command.as_bytes()).await.unwrap();
                assert!(response(&mut io).await.starts_with("250"));
            }
        }
    }
    let records = worker
        .store
        .read(|db| {
            Ok(db
                .prepare("SELECT id, scan FROM messages")?
                .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .await
        .unwrap();
    assert_eq!(records.len(), 1);
    let scan: noisefence::engine::Scan = serde_json::from_str(&records[0].1).unwrap();
    assert_eq!(scan.activation_epoch.as_ref(), Some(&current));
    assert_eq!(
        scan.analysis_result
            .as_ref()
            .unwrap()
            .activation_epoch
            .as_ref(),
        Some(&current)
    );
    assert_eq!(
        scan.recipient_decision
            .as_ref()
            .unwrap()
            .activation_epoch
            .as_ref(),
        Some(&current)
    );
    noisefence::scoring::validate_transport(&scan).unwrap();
    let wire = std::fs::read(worker.store.raw_path(&records[0].0)).unwrap();
    let (fields, _) = noisefence::message::fields(&wire).unwrap();
    let values: Vec<_> = fields
        .iter()
        .filter(|f| noisefence::message::name(f) == "x-noisefence-activation")
        .map(|f| {
            std::str::from_utf8(f)
                .unwrap()
                .split_once(':')
                .unwrap()
                .1
                .split_ascii_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect();
    assert_eq!(
        values,
        vec![format!(
            "sequence={}; revision={}; bundle-sha256={};",
            current.sequence, current.revision, current.digest
        )]
    );
    assert!(
        fields
            .iter()
            .any(|f| f.starts_with(b"X-NoiseFence-Header-Version: 7\r\n"))
    );

    io.write_all(b"QUIT\r\n").await.unwrap();
    assert!(response(&mut io).await.starts_with("221"));
    drop(io);
    stop.send(true).unwrap();
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn cancelled_drain_stays_closed_and_stale_or_foreign_proofs_cannot_release() {
    let gate = Gate::legacy();
    let lease = gate.enter(None).unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(20), gate.drain(&epoch(1)))
            .await
            .is_err()
    );
    assert!(!gate.ready());
    assert!(gate.enter(None).is_err());
    drop(lease);
    let proof = gate.drain(&epoch(1)).await.unwrap();
    let other = Gate::legacy();
    assert!(other.resume(&proof, &epoch(1)).is_err());
    gate.bind_initial(&proof, &epoch(0)).unwrap();
    gate.resume(&proof, &epoch(0)).unwrap(); // prepare aborted, old runtime retained
    let lease = gate.enter(Some(&epoch(0))).unwrap();
    gate.resume(&proof, &epoch(0)).unwrap(); // duplicate release with traffic in flight
    assert!(gate.enter(None).is_err());
    drop(lease);
    let next = gate.drain(&epoch(2)).await.unwrap();
    assert!(gate.resume(&proof, &epoch(0)).is_err());
    gate.resume(&next, &epoch(2)).unwrap();
    assert!(gate.enter(Some(&epoch(0))).is_err());
    assert!(gate.enter(Some(&epoch(2))).is_ok());
    assert!(
        gate.drain(&Epoch {
            digest: "0".repeat(64),
            ..epoch(2)
        })
        .await
        .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_spool_waiter_keeps_acceptance_lease_until_owned_disk_commit_finishes() {
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path()).unwrap();
    let cfg = common::config(root.path());
    let (locked, lock_ready) = tokio::sync::oneshot::channel();
    let (unlock, unlocked) = std::sync::mpsc::channel();
    let locked_store = store.clone();
    let blocker = tokio::spawn(async move {
        locked_store
            .run(move |_| {
                locked.send(()).unwrap();
                unlocked.recv().unwrap();
                Ok(())
            })
            .await
            .unwrap();
    });
    lock_ready.await.unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    let path = store.raw_path(&id);
    let writing_store = store.clone();
    let writing_id = id.clone();
    let writer = tokio::spawn(async move {
        writing_store
            .enqueue(
                writing_id,
                "sender@example.org".into(),
                vec![cfg.recipient("alice@example.test").unwrap()],
                noisefence::engine::extract(common::MESSAGE, 10000),
                common::MESSAGE.to_vec(),
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        while !path.exists() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
    writer.abort();
    assert!(writer.await.unwrap_err().is_cancelled());
    assert!(
        tokio::time::timeout(Duration::from_millis(20), store.activation.drain(&epoch(1)))
            .await
            .is_err()
    );
    unlock.send(()).unwrap();
    blocker.await.unwrap();
    let proof = tokio::time::timeout(Duration::from_secs(5), store.activation.drain(&epoch(1)))
        .await
        .unwrap()
        .unwrap();
    let key = id.clone();
    assert!(
        store
            .read(move |db| Ok(db.query_row(
                "SELECT EXISTS(SELECT 1 FROM messages WHERE id=?1)",
                [key],
                |r| r.get::<_, bool>(0)
            )?))
            .await
            .unwrap()
    );
    assert_eq!(std::fs::read(path).unwrap(), common::MESSAGE);
    assert!(!store.activation.ready());
    store.activation.resume(&proof, &epoch(1)).unwrap();
    // Old unbound sessions cannot enter a newly installed policy generation.
    assert!(store.activation.enter(None).is_err());
    assert!(store.activation.enter(Some(&epoch(1))).is_ok());
}

#[tokio::test]
async fn smtp_defers_existing_and_new_transactions_while_accepted_mail_keeps_its_queue() {
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use tokio::{
        io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
        net::{TcpListener, TcpStream},
    };
    use tower::ServiceExt;
    async fn response(io: &mut BufReader<TcpStream>) -> String {
        loop {
            let mut line = String::new();
            assert!(io.read_line(&mut line).await.unwrap() > 0);
            if line.as_bytes().get(3) == Some(&b' ') {
                return line;
            }
        }
    }
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path()).unwrap();
    let cfg = common::config(root.path());
    let accepted = uuid::Uuid::new_v4().to_string();
    store
        .enqueue(
            accepted.clone(),
            "sender@example.org".into(),
            vec![cfg.recipient("alice@example.test").unwrap()],
            noisefence::engine::extract(common::MESSAGE, 10000),
            common::MESSAGE.to_vec(),
        )
        .await
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, stopping) = tokio::sync::watch::channel(false);
    let state = noisefence::smtp::State {
        config: cfg.clone(),
        store: store.clone(),
        engine: Arc::new(noisefence::engine::Engine::new(cfg.clone()).unwrap()),
        processing: Arc::new(tokio::sync::Semaphore::new(2)),
    };
    let server = tokio::spawn(noisefence::smtp::serve(listener, state, stopping));
    let mut io = BufReader::new(TcpStream::connect(address).await.unwrap());
    assert!(response(&mut io).await.starts_with("220"));
    for command in [
        "EHLO sender.example.test\r\n",
        "MAIL FROM:<sender@example.org>\r\n",
        "RCPT TO:<alice@example.test>\r\n",
    ] {
        io.write_all(command.as_bytes()).await.unwrap();
        assert!(response(&mut io).await.starts_with("250"));
    }
    let _drained = store.activation.drain(&epoch(1)).await.unwrap();
    io.write_all(b"DATA\r\n").await.unwrap();
    assert!(response(&mut io).await.starts_with("354"));
    io.write_all(common::MESSAGE).await.unwrap();
    io.write_all(b".\r\n").await.unwrap();
    assert!(response(&mut io).await.starts_with("451"));
    io.write_all(b"MAIL FROM:<sender@example.org>\r\n")
        .await
        .unwrap();
    assert!(response(&mut io).await.starts_with("451"));
    let router = noisefence::api::router(cfg, store.clone()).unwrap();
    let health = router
        .oneshot(
            axum::http::Request::builder()
                .uri("/healthz")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let health: serde_json::Value =
        serde_json::from_slice(&health.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(health["smtp_ready"], false);
    assert_eq!(
        store
            .read(|db| Ok(
                db.query_row("SELECT COUNT(*) FROM messages", [], |r| r.get::<_, i64>(0))?
            ))
            .await
            .unwrap(),
        1
    );
    assert_eq!(store.claim().await.unwrap().unwrap().message_id, accepted);
    io.write_all(b"QUIT\r\n").await.unwrap();
    assert!(response(&mut io).await.starts_with("221"));
    drop(io);
    stop.send(true).unwrap();
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn participant_uses_exact_received_credentials_and_old_snapshots_stay_immutable() {
    use noisefence::{
        cluster::protocol,
        credentials::Snapshot,
        protection::{Provider, save_key},
    };
    use std::collections::BTreeMap;
    let mut f = Fixture::new();
    let remote = tempfile::tempdir().unwrap();
    save_key(
        remote.path(),
        Provider::Crdf,
        "synthetic-local-old-key-12345",
    )
    .unwrap();
    let worker = participant(remote.path(), true).await;
    let old = worker.snapshot();
    f.initialize();
    let epoch = f.stage(1, 97.);
    let keys = Snapshot::from_map(BTreeMap::from([(
        "crdf".into(),
        "synthetic-authority-key-56789".into(),
    )]))
    .unwrap();
    worker
        .synchronize_activation(f.read(), keys.clone(), noisefence::now())
        .await
        .unwrap();
    save_key(
        remote.path(),
        Provider::Crdf,
        "synthetic-unrelated-disk-key-98765",
    )
    .unwrap();
    for id in ["mx1", "mx2"] {
        f.ack(&epoch, id, Progress::Prepared);
    }
    let tx = f.db.transaction().unwrap();
    let committed = Journal::commit(&tx, &epoch, 100).unwrap();
    tx.commit().unwrap();
    worker
        .synchronize_activation(committed, keys.clone(), noisefence::now())
        .await
        .unwrap();
    for id in ["mx1", "mx2"] {
        f.ack(&epoch, id, Progress::Applied);
    }
    let tx = f.db.transaction().unwrap();
    let released = Journal::release(&tx, &epoch, 100).unwrap();
    tx.commit().unwrap();
    worker
        .synchronize_activation(released.clone(), keys, noisefence::now())
        .await
        .unwrap();
    assert!(worker.cluster_ready());
    assert_eq!(
        protocol::secrets(&old.config).unwrap()["crdf"],
        "synthetic-local-old-key-12345"
    );
    assert_eq!(
        protocol::secrets(&worker.snapshot().config).unwrap()["crdf"],
        "synthetic-authority-key-56789"
    );
    assert!(
        worker
            .synchronize_activation(released, Snapshot::default(), noisefence::now())
            .await
            .is_err()
    );
    assert!(worker.cluster_ready());
    assert_eq!(
        protocol::secrets(&worker.snapshot().config).unwrap()["crdf"],
        "synthetic-authority-key-56789"
    );
}
