mod common;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use noisefence::{
    api,
    cluster::{self, Role, artifacts, budget, history, protocol},
    config::Config,
    control::Controller,
    engine,
    store::Store,
};
use rusqlite::params;
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Arc};
use tower::ServiceExt;

fn config(root: &std::path::Path, role: Role) -> Arc<Config> {
    let mut c = (*common::config(root)).clone();
    c.hostname = if role == Role::Coordinator {
        "mx1.example.test"
    } else {
        "mx2.example.test"
    }
    .into();
    let credential = root.join("identity");
    protocol::private_write(&credential, api::random_token().as_bytes()).unwrap();
    c.cluster = Some(cluster::Settings {
        role,
        node_id: if role == Role::Coordinator {
            "mx1"
        } else {
            "mx2"
        }
        .into(),
        coordinator_url: (role == Role::Worker).then(|| "http://127.0.0.1:1".into()),
        credential_file: (role == Role::Worker).then_some(credential),
        poll_seconds: 2,
        max_stale_seconds: 60,
        allow_loopback_http: true,
    });
    c.validate().unwrap();
    Arc::new(c)
}
async fn prepare(c: &Config) -> Store {
    let s = Store::open(&c.data_dir).unwrap();
    cluster::prepare(c, &s).await.unwrap();
    s
}
async fn account(store: &Store, name: &str, admin: bool, addresses: &[&str]) -> String {
    let name = name.to_owned();
    let addresses: Vec<_> = addresses.iter().map(|s| s.to_string()).collect();
    let token = api::random_token();
    let hash = noisefence::message::digest(token.as_bytes());
    store
        .run(move |db| {
            db.execute(
                "INSERT INTO users VALUES(?1,'unused-test-hash',?2,0)",
                params![name, admin],
            )?;
            for a in addresses {
                db.execute("INSERT INTO grants VALUES(?1,?2)", params![name, a])?;
            }
            db.execute(
                "INSERT INTO sessions VALUES(?1,?2,'test-csrf',?3)",
                params![hash, name, noisefence::now() + 3600],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    token
}
async fn node(store: &Store, id: &str) -> String {
    let token = api::random_token();
    let hash = noisefence::message::digest(token.as_bytes());
    let id = id.to_owned();
    store
        .run(move |db| {
            db.execute(
                "INSERT INTO cluster_nodes(id,name,token_hash,created) VALUES(?1,?1,?2,?3)",
                params![id, hash, noisefence::now()],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    token
}
async fn message(store: &Store, cfg: &Config, quarantined: bool) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    store
        .enqueue(
            id.clone(),
            "sender@example.org".into(),
            ["alice@example.test", "bob@example.test"]
                .into_iter()
                .map(|a| cfg.recipient(a).unwrap())
                .collect(),
            engine::extract(common::MESSAGE, 1024 * 1024),
            common::MESSAGE.to_vec(),
        )
        .await
        .unwrap();
    if quarantined {
        let key = id.clone();
        store.run(move|db|{db.execute("UPDATE deliveries SET status='quarantined' WHERE message_id=?1",[&key])?;db.execute("INSERT OR REPLACE INTO delivery_policy SELECT id,'quarantine',?2,NULL FROM deliveries WHERE message_id=?1",params![key,noisefence::now()+86400])?;Ok(())}).await.unwrap();
    }
    id
}
async fn browser(
    app: &Router,
    token: &str,
    path: &str,
    data: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .uri(format!("/api/v1{path}"))
        .header("cookie", format!("noisefence_session={token}"));
    let body = if let Some(data) = data {
        builder = builder
            .method("POST")
            .header("content-type", "application/json")
            .header("origin", "http://127.0.0.1:3000")
            .header("x-csrf-token", "test-csrf");
        Body::from(data.to_string())
    } else {
        Body::empty()
    };
    let response = app
        .clone()
        .oneshot(builder.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}
fn llm() -> noisefence::llm::LlmConfig {
    noisefence::llm::LlmConfig {
        project_id: "11111111-1111-4111-8111-111111111111".into(),
        model: "test-model".into(),
        api_key_env: "NOISEFENCE_TEST_UNUSED_CLUSTER_KEY".into(),
        monthly_budget_micro_eur: 200_000,
        input_micro_eur_per_million: 150000,
        output_micro_eur_per_million: 350000,
        pricing_checked_at: noisefence::now(),
        timeout_ms: 500,
        max_text_bytes: 12000,
        max_output_tokens: 128,
        score_low: 0.,
        score_high: 100.,
        review_unconfirmed_high: true,
        max_parallel: 2,
    }
}

#[test]
fn transport_rejects_plaintext_credentials_and_ambiguous_origins() {
    let root = tempfile::tempdir().unwrap();
    let mut c = (*config(root.path(), Role::Worker)).clone();
    for url in [
        "http://mx1.example.test",
        "https://user:secret@example.test",
        "https://example.test/path",
        "https://example.test/?key=x",
        "ftp://127.0.0.1",
    ] {
        c.cluster.as_mut().unwrap().coordinator_url = Some(url.into());
        assert!(c.validate().is_err(), "{url}");
    }
    c.cluster.as_mut().unwrap().coordinator_url = Some("https://mx1.example.test".into());
    c.validate().unwrap();
    c.cluster.as_mut().unwrap().node_id = "../mx2".into();
    assert!(c.validate().is_err());
}

#[tokio::test]
async fn new_worker_waits_for_authority_and_resumes_a_cached_policy_until_expiry() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let authority = config(a.path(), Role::Coordinator);
    let worker = config(b.path(), Role::Worker);
    let store = prepare(&worker).await;
    let control = Controller::load(worker.clone(), store.clone())
        .await
        .unwrap();
    assert!(!control.cluster_ready());
    let mut policy = noisefence::control::Settings::from_config(&authority);
    policy.filters.threshold = 97.;
    let effective = policy.effective(&authority).unwrap();
    let publication = artifacts::capture(&effective, policy, 1).unwrap();
    let digest = publication.bundle.digest.clone();
    control
        .apply_cluster(
            publication.bundle.clone(),
            "test-keys".into(),
            noisefence::now(),
        )
        .await
        .unwrap();
    assert!(control.cluster_ready());
    assert_eq!(control.snapshot().config.hostname, "mx2.example.test");
    assert_eq!(control.snapshot().config.data_dir, b.path());
    assert_eq!(control.snapshot().config.filter.threshold, 97.);
    let resumed = Controller::load(worker.clone(), store.clone())
        .await
        .unwrap();
    assert!(resumed.cluster_ready());
    assert_eq!(resumed.cluster_digest(), digest);
    let mut bad = publication.bundle;
    bad.revision = 2;
    bad.shared["filter"]["threshold"] = json!(200);
    bad.digest = bad.hash().unwrap();
    assert!(
        resumed
            .apply_cluster(bad, "test-keys".into(), noisefence::now())
            .await
            .is_err()
    );
    assert_eq!(resumed.cluster_digest(), digest);
    store
        .run(|db| {
            db.execute(
                "UPDATE cluster_state SET value=?1 WHERE key='last_sync'",
                [(noisefence::now() - 61).to_string()],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    assert!(
        !Controller::load(worker, store)
            .await
            .unwrap()
            .cluster_ready()
    );
}

#[tokio::test]
async fn replicated_history_is_scoped_idempotent_and_never_becomes_a_local_queue() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let ca = config(a.path(), Role::Coordinator);
    let cb = config(b.path(), Role::Worker);
    let central = prepare(&ca).await;
    let remote = prepare(&cb).await;
    node(&central, "mx2").await;
    account(&central, "alice", false, &["alice@example.test"]).await;
    account(&central, "nobody", false, &[]).await;
    let id = message(&remote, &cb, false).await;
    let records = history::export(&remote).await.unwrap();
    let receipts = central
        .run(move |db| history::ingest(db, "mx2", records, noisefence::now()))
        .await
        .unwrap();
    assert!(central.claim().await.unwrap().is_none());
    assert!(central.failed().await.unwrap().is_empty());
    central.recover().await.unwrap();
    central.cleanup().await.unwrap();
    assert!(!central.raw_path(&id).exists());
    assert!(remote.raw_path(&id).exists());
    let visible = central
        .list("alice".into(), "".into(), "all".into(), 0, 95.)
        .await
        .unwrap();
    assert_eq!(visible.len(), 1);
    assert_eq!(visible[0].node_id.as_deref(), Some("mx2"));
    assert_eq!(visible[0].recipients.len(), 1);
    assert_eq!(visible[0].recipients[0].address, "alice@example.test");
    assert!(
        central
            .list("nobody".into(), "".into(), "all".into(), 0, 95.)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        central
            .diagnostics("alice".into(), id.clone())
            .await
            .unwrap()
            .unwrap()
            .recipients
            .len(),
        1
    );
    let job = remote.claim().await.unwrap().unwrap();
    remote.finish(&job, "delivered", "", 0).await.unwrap();
    history::acknowledge(&remote, receipts).await.unwrap();
    assert_eq!(
        history::export(&remote).await.unwrap().len(),
        1,
        "a newer delivery update must survive an older acknowledgement"
    );
    let records = history::export(&remote).await.unwrap();
    let receipts = central
        .run(move |db| history::ingest(db, "mx2", records, noisefence::now()))
        .await
        .unwrap();
    history::acknowledge(&remote, receipts).await.unwrap();
    assert!(history::export(&remote).await.unwrap().is_empty());
    assert!(central.claim().await.unwrap().is_none());
}

#[tokio::test]
async fn a_remote_node_cannot_overwrite_local_or_other_node_messages() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let ca = config(a.path(), Role::Coordinator);
    let cb = config(b.path(), Role::Worker);
    let central = prepare(&ca).await;
    let remote = prepare(&cb).await;
    node(&central, "mx2").await;
    node(&central, "mx3").await;
    let local_id = message(&central, &ca, false).await;
    message(&remote, &cb, false).await;
    let mut records = history::export(&remote).await.unwrap();
    records[0].id = local_id.clone();
    assert!(
        central
            .run(move |db| history::ingest(db, "mx2", records, noisefence::now()))
            .await
            .is_err()
    );
    assert!(central.raw_path(&local_id).exists());
    let records = history::export(&remote).await.unwrap();
    central
        .run(move |db| history::ingest(db, "mx2", records, noisefence::now()))
        .await
        .unwrap();
    let records = history::export(&remote).await.unwrap();
    assert!(
        central
            .run(move |db| history::ingest(db, "mx3", records, noisefence::now()))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn remote_quarantine_commands_recheck_grants_and_execute_once_per_recipient() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let ca = config(a.path(), Role::Coordinator);
    let cb = config(b.path(), Role::Worker);
    let central = prepare(&ca).await;
    let remote = prepare(&cb).await;
    node(&central, "mx2").await;
    let token = account(&central, "alice", false, &["alice@example.test"]).await;
    let hash = noisefence::message::digest(token.as_bytes());
    let id = message(&remote, &cb, true).await;
    let records = history::export(&remote).await.unwrap();
    central
        .run(move |db| history::ingest(db, "mx2", records, noisefence::now()))
        .await
        .unwrap();
    use noisefence::quarantine::{Change, Command};
    assert!(matches!(
        central
            .quarantine_action(
                "alice".into(),
                hash.clone(),
                id.clone(),
                "bob@example.test".into(),
                Command::Release
            )
            .await
            .unwrap(),
        Change::NotFound
    ));
    let result = central
        .quarantine_action(
            "alice".into(),
            hash,
            id.clone(),
            "alice@example.test".into(),
            Command::Release,
        )
        .await
        .unwrap();
    let Change::Queued(command_id) = result else {
        panic!("must queue a remote command")
    };
    assert!(central.claim().await.unwrap().is_none());
    let command = history::Command {
        id: command_id,
        message_id: id,
        recipient: "alice@example.test".into(),
        command: Command::Release.into(),
        username: "alice".into(),
        expires: noisefence::now() + 300,
    };
    let result = history::execute(&remote, vec![command.clone()])
        .await
        .unwrap();
    assert_eq!(result[0].result, "done");
    assert_eq!(
        history::execute(&remote, vec![command]).await.unwrap()[0].result,
        "done"
    );
    assert_eq!(
        remote.claim().await.unwrap().unwrap().destination,
        "alice@example.test"
    );
    assert!(
        remote.claim().await.unwrap().is_none(),
        "hidden Bob recipient remains quarantined"
    );
}

#[test]
fn llm_credits_are_charged_once_globally_and_survive_retries_and_restart() {
    let root = tempfile::tempdir().unwrap();
    let mut cfg = (*config(root.path(), Role::Coordinator)).clone();
    cfg.llm = Some(llm());
    let request = budget::Request {
        known: BTreeMap::new(),
        replenish: vec!["llm".into()],
    };
    let now = noisefence::now();
    let a = budget::grant(&cfg, "mx2", &request, now).unwrap();
    assert_eq!(a[0].amount, 100_000);
    assert_eq!(
        budget::grant(&cfg, "mx2", &request, now).unwrap()[0].amount,
        100_000,
        "lost reply must not mint more credit"
    );
    assert_eq!(
        budget::grant(&cfg, "mx3", &request, now).unwrap()[0].amount,
        100_000
    );
    assert_eq!(
        budget::grant(&cfg, "mx4", &request, now).unwrap()[0].amount,
        0
    );
    let usage = noisefence::llm::Budget::open(&root.path().join("llm-budget.sqlite3"))
        .unwrap()
        .current()
        .unwrap();
    assert_eq!(usage["accounted_micro_eur"], 200_000);
    let worker = tempfile::tempdir().unwrap();
    budget::enable_worker(worker.path()).unwrap();
    budget::install(worker.path(), &a, now).unwrap();
    let db = rusqlite::Connection::open(worker.path().join("llm-budget.sqlite3")).unwrap();
    assert_eq!(
        budget::ceiling(&db, "llm", &a[0].window, 200_000).unwrap(),
        100_000
    );
    assert_eq!(budget::ceiling(&db, "llm", "2099-01", 200_000).unwrap(), 0);
}

#[tokio::test]
async fn browser_permissions_and_node_credentials_are_separate_and_revocable() {
    let root = tempfile::tempdir().unwrap();
    let cfg = config(root.path(), Role::Coordinator);
    let store = prepare(&cfg).await;
    let admin = account(&store, "admin", true, &[]).await;
    let alice = account(&store, "alice", false, &["alice@example.test"]).await;
    let control = Controller::load(cfg.clone(), store.clone()).await.unwrap();
    let app = api::router_controlled(cfg, store.clone(), Some(control)).unwrap();
    let edit = json!({"id":"mx2","name":"Second MX","enabled":true,"version":-1});
    assert_eq!(
        browser(&app, &alice, "/admin/cluster/nodes", Some(edit.clone()))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let (status, created) = browser(&app, &admin, "/admin/cluster/nodes", Some(edit)).await;
    assert_eq!(status, StatusCode::OK, "{created}");
    let secret = created["credential"].as_str().unwrap();
    assert_eq!(secret.len(), 64);
    let (status, view) = browser(&app, &admin, "/admin/cluster", None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(!view.to_string().contains(secret));
    assert!(!view.to_string().contains("token_hash"));
    let poll = json!({"build":env!("CARGO_PKG_VERSION"),"revision":0,"digest":"","budget":{"known":{},"replenish":[]},"records":[],"results":[],"status":{"hostname":"mx2.example.test"}});
    for (id, credential, expected) in [
        ("mx2", admin.as_str(), StatusCode::UNAUTHORIZED),
        ("mx3", secret, StatusCode::UNAUTHORIZED),
        ("mx2", secret, StatusCode::OK),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/cluster/v1/sync")
                    .header("authorization", format!("Bearer {credential}"))
                    .header("x-noisefence-node", id)
                    .header("content-type", "application/json")
                    .body(Body::from(poll.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
    assert_eq!(
        browser(
            &app,
            &admin,
            "/admin/cluster/nodes",
            Some(json!({"id":"mx2","name":"Second MX","enabled":false,"version":1}))
        )
        .await
        .0,
        StatusCode::OK
    );
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/cluster/v1/sync")
                .header("authorization", format!("Bearer {secret}"))
                .header("x-noisefence-node", "mx2")
                .header("content-type", "application/json")
                .body(Body::from(poll.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

fn lexical_model(path: &std::path::Path, version: &str) {
    std::fs::write(
        path,
        serde_json::to_vec(&engine::Model {
            version: version.into(),
            algorithm: engine::Algorithm::Logistic,
            feature_version: 1,
            bias: -4.,
            weights: vec![0.; engine::FEATURE_COUNT],
            idf: vec![],
            trained_at: noisefence::now(),
            examples: 2,
        })
        .unwrap(),
    )
    .unwrap();
}

#[tokio::test]
async fn disk_model_replacement_cannot_silently_diverge_from_the_resident_coordinator() {
    let root = tempfile::tempdir().unwrap();
    let mut cfg = (*config(root.path(), Role::Coordinator)).clone();
    let path = root.path().join("model.json");
    lexical_model(&path, "original");
    cfg.filter.model = Some(path.clone());
    let cfg = Arc::new(cfg);
    let store = prepare(&cfg).await;
    account(&store, "admin", true, &[]).await;
    let control = Controller::load(cfg.clone(), store.clone()).await.unwrap();
    lexical_model(&path, "replacement");
    assert!(control.publication().await.is_err());
    let settings = control.snapshot().settings.clone();
    control.apply(0, settings, "admin".into()).await.unwrap();
    assert!(
        control.publication().await.is_err(),
        "a preference revision cannot activate new model bytes"
    );
    let restarted = Controller::load(cfg, store).await.unwrap();
    assert!(restarted.publication().await.is_ok());
}

#[tokio::test]
async fn a_node_identity_cannot_be_removed_or_rebound_to_a_copied_queue() {
    let root = tempfile::tempdir().unwrap();
    let c = config(root.path(), Role::Worker);
    let store = prepare(&c).await;
    let mut changed = (*c).clone();
    changed.cluster = None;
    assert!(cluster::prepare(&changed, &store).await.is_err());
    changed.cluster = c.cluster.clone();
    changed.cluster.as_mut().unwrap().node_id = "mx3".into();
    assert!(cluster::prepare(&changed, &store).await.is_err());
    let other = tempfile::tempdir().unwrap();
    let cfg = config(other.path(), Role::Worker);
    let copied = Store::open(other.path()).unwrap();
    message(&copied, &cfg, false).await;
    assert!(cluster::prepare(&cfg, &copied).await.is_err());
}

#[test]
fn concurrent_nodes_cannot_multiply_shared_llm_or_provider_limits() {
    let root = tempfile::tempdir().unwrap();
    let mut c = (*config(root.path(), Role::Coordinator)).clone();
    c.llm = Some(llm());
    let mut protection = noisefence::protection::Settings::default();
    protection.policy.crdf = true;
    protection.crdf_per_day = 60;
    protection.crdf_per_minute = 3;
    c.protection = Some(protection);
    let now = noisefence::now();
    let c = Arc::new(c);
    let handles: Vec<_> = (0..8)
        .map(|i| {
            let c = c.clone();
            std::thread::spawn(move || {
                for attempt in 0..20 {
                    match budget::grant(
                        &c,
                        &format!("mx{i}"),
                        &budget::Request {
                            known: Default::default(),
                            replenish: vec!["llm".into(), "crdf-day".into(), "crdf-minute".into()],
                        },
                        now,
                    ) {
                        Ok(credits) => return credits,
                        Err(error) if attempt == 19 => {
                            panic!("budget failed after retries: {error}")
                        }
                        Err(_) => std::thread::sleep(std::time::Duration::from_millis(50)),
                    }
                }
                unreachable!()
            })
        })
        .collect();
    let credits: Vec<_> = handles
        .into_iter()
        .flat_map(|h| h.join().unwrap())
        .collect();
    for (resource, maximum) in [("llm", 200000), ("crdf-day", 60), ("crdf-minute", 3)] {
        assert_eq!(
            credits
                .iter()
                .filter(|c| c.resource == resource)
                .map(|c| c.amount)
                .sum::<u64>(),
            maximum
        );
    }
    let worker = tempfile::tempdir().unwrap();
    budget::enable_worker(worker.path()).unwrap();
    assert!(
        budget::install(
            worker.path(),
            &[budget::Credit {
                resource: "llm".into(),
                window: "2026-09".into(),
                amount: 0,
                unlimited: true
            }],
            now
        )
        .is_err()
    );
}

async fn until(mut condition: impl AsyncFnMut() -> bool) {
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        loop {
            if condition().await {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("cluster did not converge");
}

#[tokio::test]
async fn two_live_instances_sync_models_smtp_history_commands_and_recover_an_authority_outage() {
    use noisefence::{relay, smtp};
    use tokio::{
        io::{AsyncWriteExt, BufReader},
        net::{TcpListener, TcpStream},
        sync::{Semaphore, watch},
    };
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_test_writer()
        .try_init();
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let mut ca = (*config(a.path(), Role::Coordinator)).clone();
    let model = a.path().join("lexical.json");
    lexical_model(&model, "cluster-test");
    ca.filter.model = Some(model);
    let ca = Arc::new(ca);
    let central = prepare(&ca).await;
    let admin = account(&central, "admin", true, &[]).await;
    let identity = node(&central, "mx2").await;
    let authority = Controller::load(ca.clone(), central.clone()).await.unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = listener.local_addr().unwrap();
    let mut cb = (*config(b.path(), Role::Worker)).clone();
    cb.cluster.as_mut().unwrap().coordinator_url = Some(format!("http://{origin}"));
    protocol::private_write(
        cb.cluster
            .as_ref()
            .unwrap()
            .credential_file
            .as_ref()
            .unwrap(),
        identity.as_bytes(),
    )
    .unwrap();
    let cb = Arc::new(cb);
    let remote = prepare(&cb).await;
    let worker = Controller::load(cb.clone(), remote.clone()).await.unwrap();
    let api = api::router_controlled(ca.clone(), central.clone(), Some(authority.clone())).unwrap();
    let remote_api =
        api::router_controlled(cb.clone(), remote.clone(), Some(worker.clone())).unwrap();
    assert_eq!(
        remote_api
            .oneshot(
                Request::builder()
                    .uri("/api/v1/admin/cluster")
                    .body(Body::empty())
                    .unwrap()
            )
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    let (halt, rx) = watch::channel(false);
    let smtp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let smtp_addr = smtp_listener.local_addr().unwrap();
    let smtp_task = tokio::spawn(smtp::serve_controlled(
        smtp_listener,
        smtp::State {
            config: cb.clone(),
            store: remote.clone(),
            engine: worker.snapshot().engine.clone(),
            processing: Arc::new(Semaphore::new(2)),
        },
        Some(worker.clone()),
        rx.clone(),
    ));
    let mut wire: smtp::Wire =
        BufReader::new(Box::new(TcpStream::connect(smtp_addr).await.unwrap()));
    assert_eq!(relay::response(&mut wire).await.unwrap().code, 220);
    smtp::reply(&mut wire, "EHLO sender.example.org\r\n")
        .await
        .unwrap();
    assert_eq!(relay::response(&mut wire).await.unwrap().code, 250);
    smtp::reply(&mut wire, "MAIL FROM:<sender@example.org>\r\n")
        .await
        .unwrap();
    assert_eq!(relay::response(&mut wire).await.unwrap().code, 451);
    let serving = api.clone();
    let server = tokio::spawn(async move { axum::serve(listener, serving).await.unwrap() });
    let sync = tokio::spawn(cluster::run(worker.clone(), rx));
    until(async || worker.cluster_ready()).await;
    assert_eq!(worker.snapshot().config.hostname, "mx2.example.test");
    let installed = worker.snapshot().config.filter.model.clone().unwrap();
    assert!(installed.starts_with(b.path()));
    assert_eq!(
        engine::Model::load(&installed).unwrap().version,
        "cluster-test"
    );
    for (command, code) in [
        ("MAIL FROM:<sender@example.org>", 250),
        ("RCPT TO:<outsider@other.test>", 550),
        ("RCPT TO:<alice@example.test>", 250),
        ("DATA", 354),
    ] {
        smtp::reply(&mut wire, &format!("{command}\r\n"))
            .await
            .unwrap();
        assert_eq!(relay::response(&mut wire).await.unwrap().code, code);
    }
    wire.write_all(common::MESSAGE).await.unwrap();
    wire.write_all(b".\r\n").await.unwrap();
    assert_eq!(relay::response(&mut wire).await.unwrap().code, 250);
    drop(wire);
    until(async || {
        central
            .read(|db| {
                Ok(
                    db.query_row("SELECT COUNT(*) FROM cluster_origin", [], |r| {
                        r.get::<_, i64>(0)
                    })? == 1,
                )
            })
            .await
            .unwrap()
    })
    .await;
    assert!(central.claim().await.unwrap().is_none());
    let (status, queue) = browser(&api, &admin, "/admin/queue", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(queue[0]["node_id"], "mx2");
    let (status, reply) = browser(
        &api,
        &admin,
        "/admin/queue/retry",
        Some(json!({"id":queue[0]["id"]})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(reply["status"], "queued");
    until(async || {
        central
            .read(|db| {
                Ok(db.query_row(
                    "SELECT COUNT(*) FROM cluster_commands WHERE result='done'",
                    [],
                    |r| r.get::<_, i64>(0),
                )? == 1)
            })
            .await
            .unwrap()
    })
    .await;
    server.abort();
    let _ = server.await;
    assert!(
        worker.cluster_ready(),
        "cached policy continues serving during an outage"
    );
    let id = message(&remote, &cb, false).await;
    let mut settings = authority.snapshot().settings.clone();
    settings.filters.threshold = 98.;
    authority.apply(0, settings, "admin".into()).await.unwrap();
    let listener = TcpListener::bind(origin).await.unwrap();
    let serving = api.clone();
    let server = tokio::spawn(async move { axum::serve(listener, serving).await.unwrap() });
    until(async || worker.snapshot().revision == 1).await;
    assert_eq!(worker.snapshot().config.filter.threshold, 98.);
    assert_eq!(
        worker.snapshot().config.filter.model.as_ref(),
        Some(&installed),
        "a policy change reuses the verified model directory"
    );
    until(async || history::export(&remote).await.unwrap().is_empty()).await;
    assert!(remote.raw_path(&id).exists());
    assert!(!central.raw_path(&id).exists());
    halt.send(true).unwrap();
    sync.await.unwrap().unwrap();
    smtp_task.await.unwrap().unwrap();
    server.abort();
    let restarted = Controller::load(cb.clone(), remote.clone()).await.unwrap();
    assert!(restarted.cluster_ready());
    assert_eq!(restarted.snapshot().revision, 1);
    remote
        .read(|db| {
            assert_eq!(
                db.query_row("SELECT COUNT(*) FROM cluster_command_receipts", [], |r| r
                    .get::<_, i64>(
                    0
                ))?,
                1
            );
            Ok(())
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn remote_failure_notifications_have_globally_scoped_durable_ids() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let ca = config(a.path(), Role::Coordinator);
    let cb = config(b.path(), Role::Worker);
    let central = prepare(&ca).await;
    let remote = prepare(&cb).await;
    node(&central, "mx2").await;
    message(&remote, &cb, false).await;
    let job = remote.claim().await.unwrap().unwrap();
    remote
        .finish(&job, "failed", "550 unknown", 0)
        .await
        .unwrap();
    remote
        .enqueue_dsn(
            job.clone(),
            common::MESSAGE.to_vec(),
            vec!["127.0.0.1".into()],
        )
        .await
        .unwrap();
    remote
        .enqueue_dsn(job, common::MESSAGE.to_vec(), vec!["127.0.0.1".into()])
        .await
        .unwrap();
    let records = history::export(&remote).await.unwrap();
    assert_eq!(records.iter().filter(|r| r.is_dsn).count(), 1);
    assert!(records.iter().all(|r| uuid::Uuid::parse_str(&r.id).is_ok()));
    central
        .run(move |db| history::ingest(db, "mx2", records, noisefence::now()))
        .await
        .unwrap();
    assert!(central.claim().await.unwrap().is_none());
    assert!(central.failed().await.unwrap().is_empty());
}

#[tokio::test]
async fn cluster_prepare_never_downgrades_the_mfa_schema_guard() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(dir.path(), Role::Coordinator);
    let store = prepare(&cfg).await;
    store
        .run(|db| {
            db.execute_batch("PRAGMA user_version=4")?;
            Ok(())
        })
        .await
        .unwrap();
    cluster::prepare(&cfg, &store).await.unwrap();
    store
        .run(|db| {
            assert_eq!(
                db.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))?,
                4
            );
            Ok(())
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn rolling_upgrade_serves_old_peers_and_reopens_their_cache_without_changing_policy() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let cfg = config(a.path(), Role::Coordinator);
    let store = prepare(&cfg).await;
    let secret = node(&store, "mx2").await;
    let authority = Controller::load(cfg.clone(), store.clone()).await.unwrap();
    let publication = authority.publication().await.unwrap();
    let app = api::router_controlled(cfg, store, Some(authority)).unwrap();
    let worker = config(b.path(), Role::Worker);
    let worker_store = prepare(&worker).await;
    let worker_control = Controller::load(worker.clone(), worker_store.clone())
        .await
        .unwrap();
    for build in [
        "0.14.0",
        "0.15.0",
        env!("CARGO_PKG_VERSION"),
        "0.13.0",
        "9.99.0",
        "0.14.0-unknown",
    ] {
        let poll = json!({"build":build,"revision":0,"digest":"","budget":{"known":{},"replenish":[]},"records":[],"results":[],"status":{"hostname":"mx2.example.test"}});
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/cluster/v1/sync")
                    .header("authorization", format!("Bearer {secret}"))
                    .header("x-noisefence-node", "mx2")
                    .header("content-type", "application/json")
                    .body(Body::from(poll.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        if matches!(build, "0.13.0" | "9.99.0" | "0.14.0-unknown") {
            assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
            continue;
        }
        assert_eq!(response.status(), StatusCode::OK);
        let reply: protocol::Reply =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        // The original 0.14 reader checks its exact build and the digest before materializing.
        assert_eq!(reply.bundle.build, build);
        assert_eq!(reply.bundle.digest, reply.bundle.hash().unwrap());
        assert_eq!(reply.bundle.shared, publication.bundle.shared);
        assert_eq!(
            serde_json::to_value(&reply.bundle.settings).unwrap(),
            serde_json::to_value(&publication.bundle.settings).unwrap()
        );
        assert_eq!(
            serde_json::to_value(&reply.bundle.files).unwrap(),
            serde_json::to_value(&publication.bundle.files).unwrap()
        );
        worker_control
            .apply_cluster(
                reply.bundle.clone(),
                "unchanged-keys".into(),
                noisefence::now(),
            )
            .await
            .unwrap();
        let restarted = Controller::load(worker.clone(), worker_store.clone())
            .await
            .unwrap();
        assert!(restarted.cluster_ready());
        assert_eq!(restarted.cluster_digest(), reply.bundle.digest);
        let mut tampered = reply.bundle;
        tampered.build = "9.99.0".into();
        tampered.digest = tampered.hash().unwrap();
        assert!(
            restarted
                .apply_cluster(tampered, "unchanged-keys".into(), noisefence::now())
                .await
                .is_err()
        );
    }
}
