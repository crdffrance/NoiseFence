#[allow(dead_code)]
mod common;
use noisefence::{
    central::import::{SourceLocks, session::PROTOCOL},
    store::Store,
};
use std::{
    io::{Read, Write},
    os::unix::{fs::PermissionsExt, net::UnixStream},
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
impl Process {
    fn wait(&mut self) -> std::process::ExitStatus {
        let limit = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                return status;
            }
            assert!(
                Instant::now() < limit,
                "session must terminate within test deadline"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
fn send(stream: &mut UnixStream, value: serde_json::Value) {
    let bytes = serde_json::to_vec(&value).unwrap();
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .unwrap();
    stream.write_all(&bytes).unwrap();
}
fn receive(stream: &mut UnixStream) -> serde_json::Value {
    let mut header = [0; 4];
    stream.read_exact(&mut header).unwrap();
    let length = u32::from_be_bytes(header) as usize;
    assert!(length <= 5 * 1024 * 1024);
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}
fn spawn_source(root: &Path, lease: u64) -> Process {
    Process(
        Command::new(env!("CARGO_BIN_EXE_noisefence"))
            .arg("--config")
            .arg(root.join("config.toml"))
            .arg("management-freeze-source")
            .arg("--export-parent")
            .arg(root)
            .arg("--socket")
            .arg(root.join("control.sock"))
            .arg("--lease-seconds")
            .arg(lease.to_string())
            .args(if root.join("resume.json").exists() {
                vec![
                    std::ffi::OsString::from("--resume-selection"),
                    root.join("resume.json").into_os_string(),
                ]
            } else {
                vec![]
            })
            .args(if root.join("preserve.marker").exists() {
                vec!["--preserve-source-generations"]
            } else {
                vec![]
            })
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    )
}
fn start(root: &Path, lease: u64) -> (Process, UnixStream) {
    let mut child = spawn_source(root, lease);
    let limit = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(stream) = UnixStream::connect(root.join("control.sock")) {
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            return (child, stream);
        }
        if let Some(status) = child.0.try_wait().unwrap() {
            let mut error = String::new();
            child
                .0
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut error)
                .unwrap();
            panic!("session startup failed {status}: {error}");
        }
        assert!(
            Instant::now() < limit,
            "session did not bind its control socket"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn request(ready: &serde_json::Value, sequence: u32, action: &str) -> serde_json::Value {
    serde_json::json!({"protocol":PROTOCOL,"session":ready["session"],"sequence":sequence,"command":{"action":action}})
}
fn setup() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().canonicalize().unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut config = (*common::config(&path)).clone();
    config.cluster = Some(toml::from_str("role='coordinator'\nnode_id='mx1'").unwrap());
    drop(Store::open(&path).unwrap());
    let db = rusqlite::Connection::open(path.join("state.sqlite3")).unwrap();
    db.execute_batch("INSERT INTO cluster_state VALUES('role','coordinator'),('node_id','mx1'); PRAGMA user_version=6;").unwrap();
    std::fs::write(path.join("config.toml"), toml::to_string(&config).unwrap()).unwrap();
    root
}
fn assert_released(root: &Path, ready: &serde_json::Value) {
    assert!(!Path::new(ready["export_path"].as_str().unwrap()).exists());
    assert!(!root.join("control.sock").exists());
    assert!(SourceLocks::acquire(root).is_ok());
    let mut db = rusqlite::Connection::open(root.join("state.sqlite3")).unwrap();
    db.busy_timeout(Duration::ZERO).unwrap();
    let tx = db
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .unwrap();
    assert_eq!(
        tx.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        6
    );
    tx.rollback().unwrap();
}

#[test]
fn cli_holds_source_until_abort_then_removes_export_and_socket() {
    let root = setup();
    let root = root.path().canonicalize().unwrap();
    let (mut child, mut stream) = start(&root, 10);
    let ready = receive(&mut stream);
    assert_eq!(ready["protocol"], PROTOCOL);
    assert_eq!(ready["state"], "frozen");
    assert_eq!(
        std::fs::metadata(root.join("control.sock"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert!(SourceLocks::acquire(&root).is_err());
    send(&mut stream, request(&ready, 1, "check"));
    assert_eq!(receive(&mut stream)["state"], "held");
    send(&mut stream, request(&ready, 2, "abort"));
    assert_eq!(receive(&mut stream)["state"], "aborted");
    assert!(child.wait().success());
    assert_released(&root, &ready);
}

#[test]
fn cli_expires_idle_peer_and_rejects_replayed_or_foreign_session_requests() {
    let root = setup();
    let root = root.path().canonicalize().unwrap();
    for case in ["idle", "foreign", "replay", "oversized", "disconnect"] {
        let (mut child, mut stream) = start(&root, if case == "idle" { 1 } else { 10 });
        let ready = receive(&mut stream);
        match case {
            "idle" => {}
            "foreign" => {
                let mut r = request(&ready, 1, "check");
                r["session"] = "another-session".into();
                send(&mut stream, r);
            }
            "replay" => {
                send(&mut stream, request(&ready, 1, "check"));
                receive(&mut stream);
                send(&mut stream, request(&ready, 1, "check"));
            }
            "oversized" => {
                stream
                    .write_all(&(5 * 1024 * 1024 + 1u32).to_be_bytes())
                    .unwrap();
            }
            "disconnect" => {
                stream.shutdown(std::net::Shutdown::Both).unwrap();
            }
            _ => unreachable!(),
        }
        assert!(!child.wait().success(), "{case} must fail closed");
        assert_released(&root, &ready);
    }
}

fn enroll(root: &Path) -> noisefence::cluster::activation::Journal {
    use noisefence::{
        cluster::{
            activation::{Acknowledgement, Journal, Progress},
            artifacts,
        },
        control::Settings,
    };
    let config = noisefence::config::Config::load(&root.join("config.toml")).unwrap();
    noisefence::mfa::Key::open(root).unwrap();
    let base = artifacts::capture(&config, Settings::from_config(&config), 0).unwrap();
    let publication = artifacts::bind_credentials(
        artifacts::capture(&config, Settings::from_config(&config), 1).unwrap(),
    )
    .unwrap();
    artifacts::freeze(root, &publication, 0).unwrap();
    let mut db = rusqlite::Connection::open(root.join("state.sqlite3")).unwrap();
    let tx = db.transaction().unwrap();
    let scan = serde_json::to_string(&noisefence::engine::Scan::default()).unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    tx.execute(
        "INSERT INTO messages(id,created,sender,scan) VALUES(?1,1,'sender@example.test',?2)",
        rusqlite::params![id, scan],
    )
    .unwrap();
    tx.execute("INSERT INTO deliveries(message_id,address,destination,hosts,next_attempt) VALUES(?1,'alice@example.test','alice@example.test','[]',0)",[&id]).unwrap();
    Journal::initialize(&tx, "mx1", base.bundle).unwrap();
    tx.execute(
        "INSERT INTO console_revisions VALUES(1,1,'operator',?1)",
        [serde_json::to_string(&publication.bundle.settings).unwrap()],
    )
    .unwrap();
    let journal = Journal::begin(&tx, publication.bundle, vec!["mx1".into()], 1).unwrap();
    let epoch = journal.rollout().unwrap().epoch().clone();
    Journal::acknowledge(
        &tx,
        "mx1",
        &Acknowledgement {
            epoch: epoch.clone(),
            progress: Progress::Prepared,
        },
        2,
    )
    .unwrap();
    Journal::commit(&tx, &epoch, 3).unwrap();
    Journal::acknowledge(
        &tx,
        "mx1",
        &Acknowledgement {
            epoch: epoch.clone(),
            progress: Progress::Applied,
        },
        4,
    )
    .unwrap();
    let released = Journal::release(&tx, &epoch, 5).unwrap();
    let local = serde_json::json!({"version":1,"node":"mx1","authority":released,"installed":released.current(),"installed_epoch":epoch,"prepared":epoch});
    tx.execute(
        "INSERT INTO cluster_state VALUES('activation_participant',?1)",
        [local.to_string()],
    )
    .unwrap();
    tx.commit().unwrap();
    released
}

#[test]
fn cli_selection_acknowledges_exact_export_and_stays_committed_after_disconnect() {
    use noisefence::central::{
        binding::Binding,
        selection::{Selection, key_digest},
    };
    let root = setup();
    let root = root.path().canonicalize().unwrap();
    let authority = enroll(&root);
    for incorrect in [true, false] {
        let (mut child, mut stream) = start(&root, 10);
        let ready = receive(&mut stream);
        let selected = Selection::new(
            Binding {
                instance: uuid::Uuid::new_v4().to_string(),
                source_digest: "a".repeat(64),
            },
            serde_json::from_value(ready["receipt"]["journal"]["identity"].clone()).unwrap(),
            noisefence::cluster::Role::Coordinator,
            authority.current_epoch(),
            Some(key_digest(&root).unwrap()),
        )
        .unwrap();
        let mut command = request(&ready, 1, "select");
        command["command"] = serde_json::json!({"action":"select","authority":authority,"selection":selected,
            "source_sequence":ready["receipt"]["journal"]["sequence"],
            "export_sha256":if incorrect {serde_json::Value::String("b".repeat(64))} else {ready["receipt"]["sha256"].clone()}});
        send(&mut stream, command);
        if incorrect {
            assert!(!child.wait().success());
            assert_released(&root, &ready);
            continue;
        }
        let reply = receive(&mut stream);
        assert_eq!(reply["state"], "selected");
        assert_eq!(
            serde_json::from_value::<Selection>(reply["selection"].clone()).unwrap(),
            selected
        );
        assert!(SourceLocks::acquire(&root).is_err());
        stream.shutdown(std::net::Shutdown::Both).unwrap();
        assert!(!child.wait().success());
        assert!(SourceLocks::acquire(&root).is_ok());
        assert!(!Path::new(ready["export_path"].as_str().unwrap()).exists());
        let db = rusqlite::Connection::open(root.join("state.sqlite3")).unwrap();
        assert_eq!(Selection::read(&db).unwrap(), Some(selected.clone()));
        assert!(Store::open(&root).is_err());
        std::fs::write(
            root.join("resume.json"),
            serde_json::to_vec(&selected).unwrap(),
        )
        .unwrap();
        // A resumed source is already committed, even before a new acknowledgement.
        let (mut recovery, mut channel) = start(&root, 10);
        let resumed = receive(&mut channel);
        assert_eq!(
            resumed["existing_selection"],
            serde_json::to_value(&selected).unwrap()
        );
        assert_eq!(resumed["receipt"]["journal"], ready["receipt"]["journal"]);
        send(&mut channel, request(&resumed, 1, "abort"));
        assert!(!recovery.wait().success());
        assert_eq!(Selection::read(&db).unwrap(), Some(selected.clone()));
        // Roll forward using the exact selection and the newly verified export.
        let (mut recovery, mut channel) = start(&root, 10);
        let resumed = receive(&mut channel);
        let mut command = request(&resumed, 1, "select");
        command["command"] = serde_json::json!({"action":"select","authority":authority,"selection":selected,
            "source_sequence":resumed["receipt"]["journal"]["sequence"],"export_sha256":resumed["receipt"]["sha256"]});
        send(&mut channel, command);
        assert_eq!(receive(&mut channel)["state"], "selected");
        send(&mut channel, request(&resumed, 2, "release"));
        assert_eq!(receive(&mut channel)["state"], "released");
        assert!(recovery.wait().success());
        assert_eq!(Selection::read(&db).unwrap(), Some(selected));
        assert_eq!(
            noisefence::central::outbox::status(&db).unwrap().sequence,
            resumed["receipt"]["journal"]["sequence"].as_i64().unwrap()
        );
        assert!(!Path::new(resumed["export_path"].as_str().unwrap()).exists());
    }
}

#[path = "common/postgres.rs"]
mod postgres;
fn clone_export(root: &Path, ready: &serde_json::Value) -> tempfile::TempDir {
    fn copy_tree(source: &Path, target: &Path) {
        std::fs::create_dir(target).unwrap();
        std::fs::set_permissions(target, std::fs::Permissions::from_mode(0o700)).unwrap();
        for entry in std::fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                copy_tree(&entry.path(), &target.join(entry.file_name()));
            } else if kind.is_file() {
                std::fs::copy(entry.path(), target.join(entry.file_name())).unwrap();
            } else {
                panic!("unexpected fixture artifact type");
            }
        }
    }
    let clone = tempfile::tempdir().unwrap();
    std::fs::set_permissions(clone.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    copy_tree(&root.join("cluster"), &clone.path().join("cluster"));
    std::fs::copy(root.join("mfa.key"), clone.path().join("mfa.key")).unwrap();
    let bytes = std::fs::read(ready["export_path"].as_str().unwrap()).unwrap();
    assert_eq!(
        noisefence::message::digest(&bytes),
        ready["receipt"]["sha256"].as_str().unwrap()
    );
    std::fs::write(clone.path().join("state.sqlite3"), bytes).unwrap();
    let mut config = noisefence::config::Config::load(&root.join("config.toml")).unwrap();
    config.data_dir = clone.path().canonicalize().unwrap();
    std::fs::write(
        clone.path().join("config.toml"),
        toml::to_string(&config).unwrap(),
    )
    .unwrap();
    clone
}
async fn invoke(args: &[&str]) -> std::process::Output {
    tokio::time::timeout(
        Duration::from_secs(30),
        tokio::process::Command::new(env!("CARGO_BIN_EXE_noisefence"))
            .args(args)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap()
    .unwrap()
}
#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn cli_activation_recovers_after_lost_local_receipt_then_commits_same_binding() {
    use noisefence::central::{binding::Binding, import::session::COMMIT_PROTOCOL};
    use std::os::unix::net::UnixListener;
    let fixture = postgres::Fixture::new().await;
    let root = setup();
    let root = root.path().canonicalize().unwrap();
    enroll(&root);
    let mut binding: Option<Binding> = None;
    for fail in [true, false] {
        let (mut child, mut stream) = start(&root, 90);
        let ready = receive(&mut stream);
        let clone = clone_export(&root, &ready);
        let clone = clone.path().canonicalize().unwrap();
        let plan = clone.join("import.toml");
        std::fs::write(&plan,format!("[database]\n{}\n[[sources]]\nnode_id='mx1'\nrole='coordinator'\ndata_dir={}\nconfig={}\n",
            toml::to_string(&fixture.settings).unwrap(),toml::Value::String(clone.display().to_string()),
            toml::Value::String(clone.join("config.toml").display().to_string()))).unwrap();
        if fail {
            let staged = invoke(&[
                "management-stage",
                "--plan",
                plan.to_str().unwrap(),
                "--preserve-source-generations",
            ])
            .await;
            assert!(
                staged.status.success(),
                "{}",
                String::from_utf8_lossy(&staged.stderr)
            );
            let staged: serde_json::Value = serde_json::from_slice(&staged.stdout).unwrap();
            binding = Some(serde_json::from_value(staged["database"].clone()).unwrap());
        }
        let binding = binding.as_ref().unwrap();
        let socket = clone.join("commit.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let source_ready = ready.clone();
        let controller = std::thread::spawn(move || {
            let limit = Instant::now() + Duration::from_secs(10);
            let mut peer = loop {
                match listener.accept() {
                    Ok((s, _)) => break s,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            Instant::now() < limit,
                            "activation did not contact supervisor"
                        );
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(e) => panic!("{e}"),
                }
            };
            peer.set_nonblocking(false).unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            peer.set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let barrier = receive(&mut peer);
            assert_eq!(barrier["protocol"], COMMIT_PROTOCOL);
            let mut command = request(&source_ready, 1, "select");
            command["command"] = serde_json::json!({"action":"select","authority":barrier["authority"],
                "selection":barrier["selections"][0],"export_sha256":source_ready["receipt"]["sha256"],
                "source_sequence":source_ready["receipt"]["journal"]["sequence"]});
            send(&mut stream, command);
            let selected = receive(&mut stream);
            assert_eq!(selected["state"], "selected");
            // The first transaction loses the source acknowledgement AFTER the
            // source committed. The second forwards the real durable receipt.
            let selections = if fail {
                vec![]
            } else {
                vec![selected["selection"].clone()]
            };
            send(
                &mut peer,
                serde_json::json!({"protocol":COMMIT_PROTOCOL,"request":barrier["request"],
                "database":barrier["database"],"selections":selections}),
            );
            (stream, selected["selection"].clone())
        });
        let activated = invoke(&[
            "management-activate",
            "--plan",
            plan.to_str().unwrap(),
            "--instance",
            &binding.instance,
            "--source-digest",
            &binding.source_digest,
            "--commit-socket",
            socket.to_str().unwrap(),
        ])
        .await;
        let (mut stream, selected) = controller.join().unwrap();
        let pg = fixture.connect().await;
        let active: bool = pg
            .query_one(
                "SELECT activated_at IS NOT NULL FROM noisefence.migration_state",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        let inspected = invoke(&[
            "management-status",
            "--plan",
            plan.to_str().unwrap(),
            "--instance",
            &binding.instance,
            "--source-digest",
            &binding.source_digest,
        ])
        .await;
        assert!(
            inspected.status.success(),
            "{}",
            String::from_utf8_lossy(&inspected.stderr)
        );
        let inspected: serde_json::Value = serde_json::from_slice(&inspected.stdout).unwrap();
        assert_eq!(
            inspected["phase"],
            if fail {
                "copied_not_activated"
            } else {
                "active"
            }
        );
        assert_eq!(
            inspected["selections"].as_array().unwrap().len(),
            if fail { 0 } else { 1 }
        );
        let wrong = invoke(&[
            "management-status",
            "--plan",
            plan.to_str().unwrap(),
            "--instance",
            &uuid::Uuid::new_v4().to_string(),
            "--source-digest",
            &binding.source_digest,
        ])
        .await;
        assert!(
            !wrong.status.success(),
            "unknown binding must never be reported inactive"
        );
        if fail {
            assert!(!activated.status.success());
            assert!(!active);
            stream.shutdown(std::net::Shutdown::Both).unwrap();
            assert!(!child.wait().success());
            std::fs::write(
                root.join("resume.json"),
                serde_json::to_vec(&selected).unwrap(),
            )
            .unwrap();
        } else {
            assert!(
                activated.status.success(),
                "{}",
                String::from_utf8_lossy(&activated.stderr)
            );
            assert!(active);
            let response: serde_json::Value = serde_json::from_slice(&activated.stdout).unwrap();
            assert_eq!(response["status"], "activated");
            assert_eq!(response["database"], serde_json::to_value(binding).unwrap());
            noisefence::central::Central::new_bound(&fixture.settings, binding)
                .unwrap()
                .health()
                .await
                .unwrap();
            send(&mut stream, request(&ready, 2, "release"));
            assert_eq!(receive(&mut stream)["state"], "released");
            assert!(child.wait().success());
            pg.batch_execute("UPDATE noisefence.migration_state SET report=report-'phase'")
                .await
                .unwrap();
            let corrupt = invoke(&[
                "management-status",
                "--plan",
                plan.to_str().unwrap(),
                "--instance",
                &binding.instance,
                "--source-digest",
                &binding.source_digest,
            ])
            .await;
            assert!(!corrupt.status.success());
            assert!(!String::from_utf8_lossy(&corrupt.stderr).contains("panicked"));
        }
        assert!(!Path::new(ready["export_path"].as_str().unwrap()).exists());
        assert!(SourceLocks::acquire(&root).is_ok());
    }
    fixture.finish().await;
}

#[test]
fn cli_seeded_resume_preserves_the_unselected_peer_journal() {
    let root = setup();
    let root = root.path().canonicalize().unwrap();
    enroll(&root);
    let (mut child, mut stream) = start(&root, 10);
    let ready = receive(&mut stream);
    send(&mut stream, request(&ready, 1, "abort"));
    receive(&mut stream);
    assert!(child.wait().success());
    std::fs::write(root.join("preserve.marker"), b"resume").unwrap();
    let (mut child, mut stream) = start(&root, 10);
    let resumed = receive(&mut stream);
    assert_eq!(resumed["receipt"]["journal"], ready["receipt"]["journal"]);
    send(&mut stream, request(&resumed, 1, "abort"));
    receive(&mut stream);
    assert!(child.wait().success());
    let db = rusqlite::Connection::open(root.join("state.sqlite3")).unwrap();
    db.execute("DELETE FROM management_outbox", []).unwrap();
    let (mut child, _stream) = start(&root, 10);
    assert!(
        !child.wait().success(),
        "missing events must fail rather than silently reseeding"
    );
}

#[test]
fn python_supervisor_interoperates_with_native_frozen_source() {
    let root = setup();
    let root = root.path().canonicalize().unwrap();
    let mut child = spawn_source(&root, 15);
    let output = Command::new("python3")
        .env(
            "PYTHONPATH",
            Path::new(env!("CARGO_MANIFEST_DIR")).join("deploy/postgresql"),
        )
        .arg("-c")
        .arg(
            r#"
import json, pathlib, sys, time
from migration_protocol import SourceSession
path = pathlib.Path(sys.argv[1])
deadline = time.monotonic() + 10
while not path.exists():
    assert time.monotonic() < deadline, 'Native socket did not appear'
    time.sleep(0.02)
source = SourceSession(path, 'mx1', deadline)
try:
    assert source.command({'action':'check'})['state'] == 'held'
    assert source.command({'action':'abort'})['state'] == 'aborted'
    print(json.dumps(source.ready))
finally:
    source.close()
"#,
        )
        .arg(root.join("control.sock"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let ready: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(child.wait().success());
    assert_released(&root, &ready);
}
