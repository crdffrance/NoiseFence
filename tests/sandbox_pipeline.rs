//! Real primary SQLite/spool plus a synthetic loopback CAPE service. No real Office execution.
use axum::{
    Router,
    body::Bytes,
    extract::{Path, State},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use noisefence::{engine::Scan, sandbox, sandbox_pipeline as pipeline, store::Store};
use rusqlite::params;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncWriteExt, BufReader};

const SAMPLE: &[u8] = b"synthetic-office-fixture-PRIVATE_DOCUMENT";
fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn message(samples: &[(&str, &[u8])]) -> Vec<u8> {
    let mut raw="From: sender@example.test\r\nSubject: PRIVATE_SUBJECT\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=outer\r\n\r\n--outer\r\nContent-Type: text/plain\r\n\r\nRoutine body\r\n".to_owned();
    for (name, bytes) in samples {
        raw.push_str(&format!("--outer\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"{name}\"\r\nContent-Transfer-Encoding: base64\r\n\r\n{}\r\n",STANDARD.encode(bytes)));
    }
    raw.push_str("--outer--\r\n");
    raw.into_bytes()
}
fn scan(raw: &[u8]) -> Scan {
    Scan {
        raw_sha256: Some(sha(raw)),
        complete: true,
        ..Default::default()
    }
}

#[derive(Default)]
struct FakeState {
    tasks: Vec<Value>,
    uploads: usize,
    lost_reply: bool,
    reported: bool,
    incomplete: bool,
}
#[derive(Clone, Default)]
struct Fake(Arc<Mutex<FakeState>>);
fn field(body: &str, name: &str) -> String {
    body.split(&format!("name=\"{name}\"\r\n\r\n"))
        .nth(1)
        .unwrap()
        .split("\r\n")
        .next()
        .unwrap()
        .to_owned()
}
async fn submit(
    State(fake): State<Fake>,
    body: Bytes,
) -> (axum::http::StatusCode, axum::Json<Value>) {
    let body = std::str::from_utf8(&body).unwrap();
    let payload = body
        .split("Content-Type: application/octet-stream\r\n\r\n")
        .nth(1)
        .unwrap()
        .split("\r\n--")
        .next()
        .unwrap();
    let mut state = fake.0.lock().unwrap();
    let id = state.tasks.len() + 1;
    state.uploads += 1;
    state.tasks.push(json!({"id":id,"custom":field(body,"custom"),"category":"file","package":field(body,"package"),"sample":{"sha256":sha(payload.as_bytes())},"status":"pending","errors":[]}));
    if state.lost_reply {
        (
            axum::http::StatusCode::BAD_GATEWAY,
            axum::Json(json!({"error":"PRIVATE_ERROR"})),
        )
    } else {
        (
            axum::http::StatusCode::OK,
            axum::Json(json!({"error":false,"data":{"task_ids":[id]}})),
        )
    }
}
async fn view(State(fake): State<Fake>, Path(id): Path<usize>) -> axum::Json<Value> {
    let state = fake.0.lock().unwrap();
    let mut task = state.tasks[id - 1].clone();
    if state.reported {
        task["status"] = json!("reported");
    }
    axum::Json(json!({"error":false,"data":task}))
}
async fn search(State(fake): State<Fake>, Path(digest): Path<String>) -> axum::Json<Value> {
    let state = fake.0.lock().unwrap();
    axum::Json(
        json!({"error":false,"data":state.tasks.iter().filter(|t|t["sample"]["sha256"]==digest).collect::<Vec<_>>()}),
    )
}
async fn report(State(fake): State<Fake>, Path(id): Path<usize>) -> axum::Json<Value> {
    let state = fake.0.lock().unwrap();
    let task = &state.tasks[id - 1];
    axum::Json(
        json!({"info":{"id":id,"custom":task["custom"],"category":"file","package":task["package"],"version":"2.5","duration":60,"machine":{"name":"office-vm"}},
        "target":{"file":{"sha256":task["sample"]["sha256"]}},"signatures":[],"debug":{"errors":if state.incomplete {vec!["PRIVATE_ERROR"]}else{vec![]}},"malscore":0.0}),
    )
}
async fn backend(root: &std::path::Path) -> (sandbox::Settings, Fake, tokio::task::JoinHandle<()>) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let fake = Fake::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = Router::new()
        .route("/apiv2/tasks/create/file/", post(submit))
        .route("/apiv2/tasks/view/{id}/", get(view))
        .route("/apiv2/tasks/search/sha256/{digest}/", get(search))
        .route("/apiv2/tasks/get/report/{id}/json/", get(report))
        .with_state(fake.clone());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let settings = sandbox::Settings {
        enabled: true,
        state_dir: root.join("cape"),
        endpoint: format!("http://127.0.0.1:{port}/apiv2/"),
        machine: "office-vm".into(),
        expected_version: Some("2.5".into()),
        poll_interval_ms: 100,
        request_timeout_ms: 200,
        ..Default::default()
    };
    (settings, fake, server)
}
fn configured(backend: &sandbox::Settings, quarantine: bool) -> pipeline::Settings {
    let mut settings = pipeline::Settings::default();
    settings.enabled = true;
    settings.quarantine_selected = quarantine;
    settings.bind_backend(backend).unwrap();
    settings
}
async fn store(root: &std::path::Path) -> Store {
    let store = Store::open(root).unwrap();
    store.run(|db| pipeline::install(db)).await.unwrap();
    store
}
/// Same atomic boundary required of Store::enqueue, using the real Store writer.
async fn accept(
    store: &Store,
    id: &str,
    raw: &[u8],
    scan: Scan,
    plan: pipeline::Plan,
    commit: bool,
) -> anyhow::Result<()> {
    std::fs::write(store.raw_path(id), raw)?;
    let id = id.to_owned();
    let cleanup = store.raw_path(&id);
    let result=store.run(move|db| {
        let tx=db.transaction()?;
        tx.execute("INSERT INTO messages(id,created,sender,scan) VALUES(?1,?2,'sender@example.test',?3)",params![id,noisefence::now(),serde_json::to_string(&scan)?])?;
        for address in ["one@example.test","two@example.test"] {
            tx.execute("INSERT INTO deliveries(message_id,address,destination,hosts,status,next_attempt) VALUES(?1,?2,?2,'[]','pending',?3)",params![id,address,noisefence::now()])?;
            tx.execute("INSERT INTO delivery_policy(delivery_id,action) VALUES(?1,'deliver')",[tx.last_insert_rowid()])?;
        }
        pipeline::record(&tx,&id,&scan,&plan)?;
        if commit { tx.commit()?; } else { anyhow::bail!("synthetic crash before commit"); }
        Ok(())
    }).await;
    if result.is_err() {
        std::fs::remove_file(cleanup)?;
    }
    result
}
async fn raw_needed(store: &Store, id: &str) -> bool {
    let id = id.to_owned();
    store
        .run(move |db| pipeline::needs_raw(db, &id))
        .await
        .unwrap()
}
async fn enqueue_message(store: &Store, id: &str, raw: &[u8], settings: &pipeline::Settings) {
    let scan = scan(raw);
    let plan = pipeline::prepare(raw, &scan, settings).unwrap();
    accept(store, id, raw, scan, plan, true).await.unwrap();
}

#[tokio::test]
async fn selected_research_is_atomic_and_cleanup_retains_raw_until_local_handoff() {
    let root = tempfile::tempdir().unwrap();
    let (backend, fake, server) = backend(root.path()).await;
    let store = store(&root.path().join("primary")).await;
    let settings = configured(&backend, false);
    let raw = message(&[("private.docm", SAMPLE)]);
    enqueue_message(&store, "mail_one", &raw, &settings).await;
    assert!(raw_needed(&store, "mail_one").await);
    assert_eq!(fake.0.lock().unwrap().uploads, 0);
    let retained = store
        .run(|db| {
            db.execute("UPDATE deliveries SET status='delivered'", [])?;
            Ok(db.query_row(
                &format!(
                    "SELECT COUNT(*) FROM messages m WHERE m.raw_present=1 AND NOT ({})",
                    pipeline::NEEDS_RAW_SQL
                ),
                [],
                |r| r.get::<_, usize>(0),
            )?)
        })
        .await
        .unwrap();
    assert_eq!(retained, 0);
    let client = sandbox::Client::new(backend).unwrap();
    let worker = pipeline::Worker::new(settings).unwrap();
    let tick = worker.tick(&store, &client).await.unwrap();
    assert_eq!(tick.handed_off, 1);
    assert!(!raw_needed(&store, "mail_one").await);
    assert_eq!(
        pipeline::list(&store, "mail_one").await.unwrap()[0].state,
        pipeline::State::Submitted
    );
    assert_eq!(fake.0.lock().unwrap().uploads, 1);
    // Primary cleanup may now remove its copy: the connector payload/intent is durable.
    std::fs::remove_file(store.raw_path("mail_one")).unwrap();
    fake.0.lock().unwrap().reported = true;
    tokio::time::sleep(std::time::Duration::from_millis(120)).await;
    worker.tick(&store, &client).await.unwrap();
    let entries = pipeline::list(&store, "mail_one").await.unwrap();
    assert_eq!(entries[0].state, pipeline::State::Complete);
    assert_eq!(
        entries[0].result.as_ref().unwrap().outcome,
        sandbox::Outcome::NoFindings
    );
    server.abort();
}

#[tokio::test]
async fn transaction_failure_never_leaves_accepted_mail_without_required_outbox() {
    let root = tempfile::tempdir().unwrap();
    let (backend, _, server) = backend(root.path()).await;
    let store = store(&root.path().join("primary")).await;
    let settings = configured(&backend, false);
    let raw = message(&[("file.doc", SAMPLE)]);
    let scan = scan(&raw);
    let plan = pipeline::prepare(&raw, &scan, &settings).unwrap();
    assert!(
        accept(&store, "rolled_back", &raw, scan, plan, false)
            .await
            .is_err()
    );
    let counts = store
        .run(|db| {
            Ok((
                db.query_row("SELECT COUNT(*) FROM messages", [], |r| {
                    r.get::<_, usize>(0)
                })?,
                db.query_row("SELECT COUNT(*) FROM sandbox_pipeline_outbox", [], |r| {
                    r.get::<_, usize>(0)
                })?,
            ))
        })
        .await
        .unwrap();
    assert_eq!(counts, (0, 0));
    assert!(!store.raw_path("rolled_back").exists());
    server.abort();
}

#[tokio::test]
async fn primary_quotas_reject_whole_transaction_before_smtp_acceptance() {
    let root = tempfile::tempdir().unwrap();
    let (backend, _, server) = backend(root.path()).await;
    for raw_quota in [false, true] {
        let store = store(&root.path().join(if raw_quota { "bytes" } else { "count" })).await;
        let mut settings = configured(&backend, false);
        if raw_quota {
            settings.max_pending_raw_bytes = 1;
        } else {
            settings.max_outbox_jobs = 1;
        }
        let raw = message(&[("one.doc", SAMPLE), ("two.xls", b"another fixture")]);
        let scan = scan(&raw);
        let plan = pipeline::prepare(&raw, &scan, &settings).unwrap();
        assert!(
            accept(&store, "over_quota", &raw, scan, plan, true)
                .await
                .is_err()
        );
        assert_eq!(
            store
                .run(
                    |db| Ok(db.query_row("SELECT COUNT(*) FROM messages", [], |r| r
                        .get::<_, usize>(0))?)
                )
                .await
                .unwrap(),
            0
        );
    }
    server.abort();
}

#[tokio::test]
async fn crash_after_connector_commit_and_lost_remote_response_does_not_duplicate_jobs() {
    let root = tempfile::tempdir().unwrap();
    let (backend, fake, server) = backend(root.path()).await;
    fake.0.lock().unwrap().lost_reply = true;
    let primary = root.path().join("primary");
    let store = store(&primary).await;
    let settings = configured(&backend, false);
    let raw = message(&[("file.docm", SAMPLE)]);
    enqueue_message(&store, "restart_mail", &raw, &settings).await;
    let client = sandbox::Client::new(backend.clone()).unwrap();
    let created = store
        .run(|db| {
            Ok(
                db.query_row("SELECT created FROM sandbox_pipeline_messages", [], |r| {
                    r.get::<_, i64>(0)
                })?,
            )
        })
        .await
        .unwrap();
    // Simulate a process dying after secondary commit but before primary ACK.
    let job = client
        .enqueue_created_at(
            &sha(&raw),
            SAMPLE,
            sandbox::OfficeKind::Docm,
            sandbox::Disposition::ResearchOnly,
            created * 1000,
        )
        .await
        .unwrap();
    client.tick().await.unwrap();
    assert_eq!(fake.0.lock().unwrap().uploads, 1);
    drop(client);
    drop(store);
    let store = Store::open(&primary).unwrap();
    let client = sandbox::Client::new(backend).unwrap();
    let worker = pipeline::Worker::new(settings).unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(120)).await;
    worker.tick(&store, &client).await.unwrap();
    let entry = pipeline::list(&store, "restart_mail")
        .await
        .unwrap()
        .remove(0);
    assert_eq!(entry.job_id.as_deref(), Some(job.job_id.as_str()));
    assert_eq!(client.list(0, 100).await.unwrap().len(), 1);
    assert_eq!(fake.0.lock().unwrap().uploads, 1);
    server.abort();
}

#[tokio::test]
async fn connector_quota_or_unavailable_http_never_loses_pending_research() {
    let root = tempfile::tempdir().unwrap();
    let (mut backend, _, server) = backend(root.path()).await;
    backend.max_jobs = 1;
    let store = store(&root.path().join("primary")).await;
    let settings = configured(&backend, false);
    let client = sandbox::Client::new(backend).unwrap();
    client
        .enqueue_created_at(
            &sha(b"occupied"),
            b"fixture",
            sandbox::OfficeKind::Doc,
            sandbox::Disposition::ResearchOnly,
            noisefence::now() * 1000,
        )
        .await
        .unwrap();
    let raw = message(&[("file.xlsm", SAMPLE)]);
    enqueue_message(&store, "queued", &raw, &settings).await;
    server.abort(); // Backend availability is irrelevant to primary admission.
    let tick = pipeline::Worker::new(settings)
        .unwrap()
        .tick(&store, &client)
        .await
        .unwrap();
    assert_eq!(tick.retrying, 1);
    assert!(raw_needed(&store, "queued").await);
    assert_eq!(
        pipeline::list(&store, "queued").await.unwrap()[0].state,
        pipeline::State::Pending
    );
}

#[tokio::test]
async fn missing_changed_or_symlinked_spool_is_inconclusive_never_malicious() {
    let root = tempfile::tempdir().unwrap();
    let (backend, fake, server) = backend(root.path()).await;
    let store = store(&root.path().join("primary")).await;
    let settings = configured(&backend, false);
    let raw = message(&[("file.pptm", SAMPLE)]);
    for id in ["missing", "changed", "symlink"] {
        enqueue_message(&store, id, &raw, &settings).await;
        std::fs::remove_file(store.raw_path(id)).unwrap();
        if id == "changed" {
            std::fs::write(store.raw_path(id), b"changed").unwrap();
        }
        if id == "symlink" {
            let other = root.path().join("other");
            std::fs::write(&other, &raw).unwrap();
            std::os::unix::fs::symlink(other, store.raw_path(id)).unwrap();
        }
    }
    let client = sandbox::Client::new(backend).unwrap();
    pipeline::Worker::new(settings)
        .unwrap()
        .tick(&store, &client)
        .await
        .unwrap();
    for id in ["missing", "changed", "symlink"] {
        let entries = pipeline::list(&store, id).await.unwrap();
        assert_eq!(entries[0].state, pipeline::State::Inconclusive);
        assert!(entries[0].result.is_none());
        assert!(!raw_needed(&store, id).await);
    }
    assert_eq!(fake.0.lock().unwrap().uploads, 0);
    server.abort();
}

#[tokio::test]
async fn explicit_selected_quarantine_holds_every_recipient_and_never_auto_releases() {
    let root = tempfile::tempdir().unwrap();
    let (backend, fake, server) = backend(root.path()).await;
    let store = store(&root.path().join("primary")).await;
    let settings = configured(&backend, true);
    let raw = message(&[("file.docx", SAMPLE)]);
    enqueue_message(&store, "held", &raw, &settings).await;
    let client = sandbox::Client::new(backend).unwrap();
    let worker = pipeline::Worker::new(settings).unwrap();
    worker.tick(&store, &client).await.unwrap();
    fake.0.lock().unwrap().reported = true;
    tokio::time::sleep(std::time::Duration::from_millis(120)).await;
    worker.tick(&store, &client).await.unwrap();
    let statuses = store
        .run(|db| {
            let mut q = db.prepare("SELECT status FROM deliveries ORDER BY id")?;
            Ok(q.query_map([], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?)
        })
        .await
        .unwrap();
    assert_eq!(statuses, ["quarantined", "quarantined"]);
    assert_eq!(
        pipeline::list(&store, "held").await.unwrap()[0]
            .result
            .as_ref()
            .unwrap()
            .outcome,
        sandbox::Outcome::NoFindings
    );
    let saved = store
        .run(|db| {
            Ok(
                db.query_row("SELECT scan FROM messages WHERE id='held'", [], |r| {
                    r.get::<_, String>(0)
                })?,
            )
        })
        .await
        .unwrap();
    let saved: Value = serde_json::from_str(&saved).unwrap();
    assert_eq!(saved["action"]["reason"], "sandbox_selected");
    assert_eq!(saved["score"], 0.0);
    server.abort();
}

#[tokio::test]
async fn rewritten_spool_is_bound_without_changing_original_message_identity() {
    let root = tempfile::tempdir().unwrap();
    let (backend, _, server) = backend(root.path()).await;
    let store = store(&root.path().join("primary")).await;
    let settings = configured(&backend, false);
    let raw = message(&[("file.xlsx", SAMPLE)]);
    let scan = scan(&raw);
    let mut plan = pipeline::prepare(&raw, &scan, &settings).unwrap();
    let delivered = [
        b"X-NoiseFence-Test: rewritten\r\n".as_slice(),
        raw.as_slice(),
    ]
    .concat();
    plan.bind_queued(&delivered).unwrap();
    accept(&store, "rewritten", &delivered, scan, plan, true)
        .await
        .unwrap();
    let client = sandbox::Client::new(backend).unwrap();
    pipeline::Worker::new(settings)
        .unwrap()
        .tick(&store, &client)
        .await
        .unwrap();
    let entries = pipeline::list(&store, "rewritten").await.unwrap();
    let result = entries[0].result.as_ref().unwrap();
    assert_eq!(result.message_sha256, sha(&raw));
    assert_eq!(result.attachment_sha256, sha(SAMPLE));
    server.abort();
}

#[tokio::test]
async fn expired_pending_releases_research_retention_and_primary_results_purge_without_backend() {
    let root = tempfile::tempdir().unwrap();
    let (backend, _, server) = backend(root.path()).await;
    let store = store(&root.path().join("primary")).await;
    let settings = configured(&backend, false);
    let raw = message(&[("file.doc", SAMPLE)]);
    enqueue_message(&store, "expired", &raw, &settings).await;
    store
        .run(|db| {
            db.execute(
                "UPDATE sandbox_pipeline_messages SET submission_deadline=?1",
                [noisefence::now() - 1],
            )?;
            pipeline::expire_pending(db, noisefence::now())?;
            Ok(())
        })
        .await
        .unwrap();
    assert!(!raw_needed(&store, "expired").await);
    assert_eq!(
        pipeline::list(&store, "expired").await.unwrap()[0].detail,
        Some(pipeline::Detail::SubmissionExpired)
    );
    store
        .run(|db| {
            db.execute(
                "UPDATE sandbox_pipeline_messages SET expires=?1",
                [noisefence::now() - 1],
            )?;
            assert_eq!(pipeline::prune_primary(db, noisefence::now())?, 1);
            Ok(())
        })
        .await
        .unwrap();
    assert!(pipeline::list(&store, "expired").await.unwrap().is_empty());
    server.abort();
}

#[tokio::test]
async fn active_lease_is_not_reclaimed_but_crashed_lease_is_recovered() {
    let root = tempfile::tempdir().unwrap();
    let (backend, fake, server) = backend(root.path()).await;
    let store = store(&root.path().join("primary")).await;
    let settings = configured(&backend, false);
    let raw = message(&[("file.doc", SAMPLE)]);
    enqueue_message(&store, "leased", &raw, &settings).await;
    store.run(|db|{db.execute("UPDATE sandbox_pipeline_outbox SET state='submitting',lease_token='crashed',lease_until=?1",[noisefence::now()+100])?;Ok(())}).await.unwrap();
    let client = sandbox::Client::new(backend).unwrap();
    let worker = pipeline::Worker::new(settings).unwrap();
    assert_eq!(worker.tick(&store, &client).await.unwrap().claimed, 0);
    assert!(raw_needed(&store, "leased").await);
    store
        .run(|db| {
            db.execute("UPDATE sandbox_pipeline_outbox SET lease_until=0", [])?;
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(worker.tick(&store, &client).await.unwrap().handed_off, 1);
    assert_eq!(fake.0.lock().unwrap().uploads, 1);
    server.abort();
}

#[tokio::test]
async fn policy_changes_never_reroute_a_retained_attachment() {
    let root = tempfile::tempdir().unwrap();
    let (backend, fake, server) = backend(root.path()).await;
    let store = store(&root.path().join("primary")).await;
    let settings = configured(&backend, false);
    let raw = message(&[("file.doc", SAMPLE)]);
    enqueue_message(&store, "old_policy", &raw, &settings).await;
    let mut changed = settings.clone();
    changed.max_attempts -= 1;
    let client = sandbox::Client::new(backend.clone()).unwrap();
    pipeline::Worker::new(changed)
        .unwrap()
        .tick(&store, &client)
        .await
        .unwrap();
    assert_eq!(
        pipeline::list(&store, "old_policy").await.unwrap()[0].detail,
        Some(pipeline::Detail::PolicyChanged)
    );
    assert_eq!(fake.0.lock().unwrap().uploads, 0);
    let mut other = backend;
    other.state_dir = root.path().join("other_cape");
    other.environment_id = "different-lab".into();
    let wrong = sandbox::Client::new(other).unwrap();
    assert!(
        pipeline::Worker::new(settings)
            .unwrap()
            .tick(&store, &wrong)
            .await
            .is_err()
    );
    server.abort();
}

#[tokio::test]
async fn selection_is_bounded_decoded_deduplicated_and_does_not_keep_private_names() {
    let root = tempfile::tempdir().unwrap();
    let (backend, _, server) = backend(root.path()).await;
    let mut settings = configured(&backend, false);
    let raw = message(&[
        ("PRIVATE_NAME.DOCM", SAMPLE),
        ("duplicate.docm", SAMPLE),
        ("notes.txt", b"not selected"),
    ]);
    let plan = pipeline::prepare(&raw, &scan(&raw), &settings).unwrap();
    assert_eq!(plan.report().selected, 1);
    let serialized = serde_json::to_string(&plan.report()).unwrap();
    let debug = format!("{plan:?}");
    for private in ["PRIVATE_NAME", "PRIVATE_DOCUMENT", "PRIVATE_SUBJECT"] {
        assert!(!serialized.contains(private));
        assert!(!debug.contains(private));
    }
    settings.max_attachment_bytes = 1;
    let limited = pipeline::prepare(&raw, &scan(&raw), &settings).unwrap();
    assert_eq!(limited.report().status, pipeline::Preparation::Limited);
    settings.quarantine_selected = true;
    assert!(pipeline::prepare(&raw, &scan(&raw), &settings).is_err());
    assert!(pipeline::prepare(&raw, &Scan::default(), &configured(&backend, false)).is_err());
    server.abort();
}

#[test]
fn default_disabled_and_unbound_deserialized_settings_cannot_enable_uploads() {
    let settings = pipeline::Settings::default();
    settings.validate().unwrap();
    assert!(!settings.enabled);
    assert!(!settings.quarantine_selected);
    let report = pipeline::prepare(b"invalid", &Scan::default(), &settings)
        .unwrap()
        .report();
    assert_eq!(report.status, pipeline::Preparation::Disabled);
    let settings: pipeline::Settings = serde_json::from_value(json!({"enabled":true})).unwrap();
    assert!(pipeline::Worker::new(settings).is_err());
    assert!(
        serde_json::from_value::<pipeline::Settings>(json!({"backend_policy":"forged"})).is_err()
    );
    for value in [0, 31] {
        let settings: pipeline::Settings =
            serde_json::from_value(json!({"retention_days":value})).unwrap();
        assert!(settings.validate().is_err());
    }
}

fn smtp_config(
    root: &std::path::Path,
    backend: &sandbox::Settings,
    quarantine: bool,
) -> noisefence::config::Config {
    let mut config: noisefence::config::Config =
        toml::from_str(include_str!("../config/development.toml")).unwrap();
    config.data_dir = root.into();
    config.smtp.minimum_free_bytes = 0;
    config.smtp.listen = "127.0.0.1:0".parse().unwrap();
    config.sandbox = Some(backend.clone());
    config.sandbox_pipeline = Some(configured(backend, quarantine));
    if quarantine {
        config.filter.mode = noisefence::config::Mode::Tag;
        config.actions = Some(noisefence::actions::Policy {
            spam: noisefence::actions::Action::Deliver,
            publicity: noisefence::actions::Action::Deliver,
            malware: noisefence::actions::Action::Deliver,
            quarantine_days: 14,
        });
    }
    config.validate().unwrap();
    config
}

/// Enter through the real SMTP DATA handler, which invokes private process_smtp
/// and Store::enqueue, instead of calling an exposed test-only engine shortcut.
async fn smtp_accept(config: noisefence::config::Config, store: &Store, raw: &[u8]) -> u16 {
    let config = Arc::new(config);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, receiver) = tokio::sync::watch::channel(false);
    let engine = Arc::new(noisefence::engine::Engine::new(config.clone()).unwrap());
    let state = noisefence::smtp::State {
        config,
        store: store.clone(),
        engine,
        processing: Arc::new(tokio::sync::Semaphore::new(2)),
    };
    let serving = tokio::spawn(noisefence::smtp::serve(listener, state, receiver));
    let mut io: noisefence::smtp::Wire = BufReader::new(Box::new(
        tokio::net::TcpStream::connect(address).await.unwrap(),
    ));
    assert_eq!(
        noisefence::relay::response(&mut io).await.unwrap().code,
        220
    );
    for (command, expected) in [
        ("EHLO example.test\r\n", 250),
        ("MAIL FROM:<sender@example.test>\r\n", 250),
        ("RCPT TO:<alice@example.test>\r\n", 250),
        ("RCPT TO:<bob@example.test>\r\n", 250),
        ("DATA\r\n", 354),
    ] {
        noisefence::smtp::reply(&mut io, command).await.unwrap();
        assert_eq!(
            noisefence::relay::response(&mut io).await.unwrap().code,
            expected
        );
    }
    io.write_all(raw).await.unwrap();
    io.write_all(b".\r\n").await.unwrap();
    io.flush().await.unwrap();
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        noisefence::relay::response(&mut io),
    )
    .await
    .unwrap()
    .unwrap();
    noisefence::smtp::reply(&mut io, "QUIT\r\n").await.unwrap();
    assert_eq!(
        noisefence::relay::response(&mut io).await.unwrap().code,
        221
    );
    drop(io);
    stop.send(true).unwrap();
    serving.await.unwrap().unwrap();
    response.code
}

#[tokio::test]
async fn actual_smtp_enqueue_cleanup_and_authorized_diagnostics_preserve_the_contract() {
    for quarantine in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let (backend, fake, server) = backend(root.path()).await;
        let primary = root.path().join("primary");
        let store = Store::open(&primary).unwrap();
        let config = smtp_config(&primary, &backend, quarantine);
        let settings = configured(&backend, quarantine);
        for (name, address) in [
            ("alice", "alice@example.test"),
            ("outsider", "nobody@example.test"),
        ] {
            noisefence::api::create_user(
                &store,
                name.into(),
                "synthetic long test password".into(),
                vec![address.into()],
                false,
            )
            .await
            .unwrap();
        }
        let raw = message(&[("PRIVATE_NAME.docm", SAMPLE)]);
        assert_eq!(smtp_accept(config, &store, &raw).await, 250);
        assert_eq!(fake.0.lock().unwrap().uploads, 0);
        assert!(
            !backend.state_dir.exists(),
            "SMTP engine must not even open the connector queue"
        );
        let (id, saved) = store
            .run(|db| {
                Ok(db.query_row("SELECT id,scan FROM messages", [], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
                })?)
            })
            .await
            .unwrap();
        let saved: Scan = serde_json::from_str(&saved).unwrap();
        assert!(saved.sandbox_pipeline_plan.is_none());
        assert_eq!(saved.raw_sha256, Some(sha(&raw)));
        assert_eq!(saved.sandbox_pipeline.as_ref().unwrap().selected, 1);
        assert_eq!(
            saved.action.as_ref().unwrap().effective,
            if quarantine {
                noisefence::actions::Action::Quarantine
            } else {
                noisefence::actions::Action::Deliver
            }
        );
        if quarantine {
            assert_eq!(saved.action.as_ref().unwrap().reason, "sandbox_selected");
        }
        assert!(raw_needed(&store, &id).await);
        let retained = std::fs::read(store.raw_path(&id)).unwrap();
        assert_eq!(
            noisefence::message::fields(&raw).unwrap().1,
            noisefence::message::fields(&retained).unwrap().1
        );
        if !quarantine {
            store
                .run(|db| {
                    db.execute("UPDATE deliveries SET status='delivered'", [])?;
                    Ok(())
                })
                .await
                .unwrap();
        }
        store.cleanup().await.unwrap();
        assert!(
            store.raw_path(&id).exists(),
            "pending outbox retains delivered research mail"
        );
        let client = sandbox::Client::new(backend).unwrap();
        let worker = pipeline::Worker::new(settings).unwrap();
        worker.tick(&store, &client).await.unwrap();
        fake.0.lock().unwrap().reported = true;
        tokio::time::sleep(std::time::Duration::from_millis(120)).await;
        worker.tick(&store, &client).await.unwrap();
        let diagnostics = store
            .diagnostics("alice".into(), id.clone())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(diagnostics.recipients.len(), 1);
        assert_eq!(diagnostics.recipients[0].address, "alice@example.test");
        assert!(
            store
                .diagnostics("outsider".into(), id.clone())
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(diagnostics.sandbox_results.len(), 1);
        assert_eq!(
            diagnostics.sandbox_results[0].state,
            pipeline::State::Complete
        );
        let safe = serde_json::to_string(&diagnostics.sandbox_results).unwrap();
        for forbidden in [
            "job_id",
            "remote_task_id",
            "attachment_sha256",
            "message_sha256",
            "policy_sha256",
            "instance_id",
            "environment_id",
            "office-vm",
            "PRIVATE_",
        ] {
            assert!(!safe.contains(forbidden), "{forbidden}: {safe}");
        }
        store.cleanup().await.unwrap();
        assert_eq!(store.raw_path(&id).exists(), quarantine);
        let statuses = store
            .run(|db| {
                let mut q = db.prepare("SELECT status FROM deliveries ORDER BY id")?;
                Ok(q.query_map([], |r| r.get::<_, String>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?)
            })
            .await
            .unwrap();
        assert!(statuses.iter().all(|s| s
            == if quarantine {
                "quarantined"
            } else {
                "delivered"
            }));
        server.abort();
    }
}

#[tokio::test]
async fn actual_smtp_returns_451_for_selection_or_atomic_outbox_quota_failure() {
    for quarantine in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let (backend, fake, server) = backend(root.path()).await;
        let primary = root.path().join("primary");
        let store = Store::open(&primary).unwrap();
        let mut config = smtp_config(&primary, &backend, quarantine);
        let settings = config.sandbox_pipeline.as_mut().unwrap();
        if quarantine {
            settings.max_attachment_bytes = 1;
        } else {
            settings.max_outbox_jobs = 1;
        }
        config.validate().unwrap();
        let raw = message(&[
            ("one.doc", SAMPLE),
            ("two.xls", b"another synthetic fixture"),
        ]);
        assert_eq!(smtp_accept(config, &store, &raw).await, 451);
        assert_eq!(
            store
                .run(
                    |db| Ok(db.query_row("SELECT COUNT(*) FROM messages", [], |r| r
                        .get::<_, usize>(0))?)
                )
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            store
                .run(|db| Ok(db.query_row(
                    "SELECT COUNT(*) FROM sandbox_pipeline_outbox",
                    [],
                    |r| r.get::<_, usize>(0)
                )?))
                .await
                .unwrap(),
            0
        );
        assert_eq!(std::fs::read_dir(primary.join("spool")).unwrap().count(), 0);
        assert_eq!(fake.0.lock().unwrap().uploads, 0);
        server.abort();
    }
}

#[tokio::test]
async fn incomplete_backend_processing_remains_inconclusive_and_held() {
    let root = tempfile::tempdir().unwrap();
    let (backend, fake, server) = backend(root.path()).await;
    let store = store(&root.path().join("primary")).await;
    let settings = configured(&backend, true);
    let raw = message(&[("file.docm", SAMPLE)]);
    enqueue_message(&store, "incomplete", &raw, &settings).await;
    let client = sandbox::Client::new(backend).unwrap();
    let worker = pipeline::Worker::new(settings).unwrap();
    worker.tick(&store, &client).await.unwrap();
    {
        let mut state = fake.0.lock().unwrap();
        state.reported = true;
        state.incomplete = true;
    }
    tokio::time::sleep(std::time::Duration::from_millis(120)).await;
    worker.tick(&store, &client).await.unwrap();
    let entry = pipeline::list(&store, "incomplete")
        .await
        .unwrap()
        .remove(0);
    assert_eq!(entry.state, pipeline::State::Inconclusive);
    assert_eq!(
        entry.result.unwrap().outcome,
        sandbox::Outcome::Inconclusive
    );
    assert_eq!(
        store
            .run(|db| Ok(db.query_row(
                "SELECT COUNT(*) FROM deliveries WHERE status='quarantined'",
                [],
                |r| r.get::<_, usize>(0)
            )?))
            .await
            .unwrap(),
        2
    );
    server.abort();
}

#[tokio::test]
async fn unchanged_backend_summary_is_not_counted_as_a_new_result() {
    let root = tempfile::tempdir().unwrap();
    let (mut backend, _, server) = backend(root.path()).await;
    backend.poll_interval_ms = 300_000;
    let store = store(&root.path().join("primary")).await;
    let settings = configured(&backend, false);
    let raw = message(&[("file.docm", SAMPLE)]);
    enqueue_message(&store, "quiet", &raw, &settings).await;
    let client = sandbox::Client::new(backend).unwrap();
    let worker = pipeline::Worker::new(settings).unwrap();
    assert_eq!(worker.tick(&store, &client).await.unwrap().handed_off, 1);
    let idle = worker.tick(&store, &client).await.unwrap();
    assert_eq!(idle.claimed, 0);
    assert_eq!(idle.results_updated, 0);
    assert_eq!(idle.backend_advanced, 0);
    server.abort();
}

#[tokio::test]
async fn cancelling_a_worker_waiter_keeps_its_lock_until_durable_work_finishes() {
    let root = tempfile::tempdir().unwrap();
    let (backend, fake, server) = backend(root.path()).await;
    let store = store(&root.path().join("primary")).await;
    let settings = configured(&backend, false);
    let raw = message(&[("file.docm", SAMPLE)]);
    enqueue_message(&store, "cancelled", &raw, &settings).await;
    let client = sandbox::Client::new(backend).unwrap();
    let worker = pipeline::Worker::new(settings).unwrap();
    let (release, blocked) = std::sync::mpsc::channel();
    let (ready, waiting) = tokio::sync::oneshot::channel();
    let locked = store.clone();
    let holder = tokio::spawn(async move {
        locked
            .run(move |_| {
                let _ = ready.send(());
                let _ = blocked.recv_timeout(std::time::Duration::from_secs(3));
                Ok(())
            })
            .await
    });
    waiting.await.unwrap();
    let (running, queued, backend) = (worker.clone(), store.clone(), client.clone());
    let waiter = tokio::spawn(async move { running.tick(&queued, &backend).await });
    tokio::time::sleep(std::time::Duration::from_millis(15)).await;
    waiter.abort();
    let _ = waiter.await;
    assert!(worker.tick(&store, &client).await.unwrap().busy);
    release.send(()).unwrap();
    holder.await.unwrap().unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            if !worker.tick(&store, &client).await.unwrap().busy {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(fake.0.lock().unwrap().uploads, 1);
    assert!(!raw_needed(&store, "cancelled").await);
    assert_eq!(client.list(0, 100).await.unwrap().len(), 1);
    server.abort();
}
