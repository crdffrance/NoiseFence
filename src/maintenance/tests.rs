use super::*;
use crate::{
    central::outbox,
    cluster::{
        Role,
        activation::{Acknowledgement, Journal, Progress},
        artifacts,
    },
    control::Settings,
};
use axum::{
    body::{Body, to_bytes},
    http::Request as HttpRequest,
};
use tower::ServiceExt;

fn uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}
fn plan() -> Plan {
    let policy = Epoch {
        sequence: 1,
        revision: 1,
        digest: "a".repeat(64),
    };
    Plan {
        protocol: PROTOCOL.into(),
        operation: uuid(),
        selection: Selection::new(
            Binding {
                instance: uuid(),
                source_digest: "b".repeat(64),
            },
            Identity {
                node: "mx2".into(),
                epoch: uuid(),
            },
            Role::Worker,
            policy.clone(),
            None,
        )
        .unwrap(),
        policy,
        peer: Peer {
            identity: Identity {
                node: "mx1".into(),
                epoch: uuid(),
            },
            binary_sha256: "c".repeat(64),
        },
        config_sha256: "d".repeat(64),
        binary_sha256: "e".repeat(64),
        expires_at: crate::now() + 600,
    }
}

async fn fixture() -> (tempfile::TempDir, Session) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let root = tempfile::tempdir().unwrap();
    let mut config: Config = toml::from_str(include_str!("../../config/development.toml")).unwrap();
    config.data_dir = root.path().to_owned();
    config.smtp.listen = "127.0.0.1:0".parse().unwrap();
    config.web.listen = "127.0.0.1:0".parse().unwrap();
    config.smtp.minimum_free_bytes = 0;
    let key = root.path().join("key");
    crate::cluster::protocol::private_write(&key, "f".repeat(64).as_bytes()).unwrap();
    config.cluster = Some(toml::from_str("role='worker'\nnode_id='mx2'\ncoordinator_url='http://127.0.0.1:1'\ncredential_file='/unused'\nallow_loopback_http=true").unwrap());
    config.cluster.as_mut().unwrap().credential_file = Some(key.clone());
    config.replication = Some(crate::ha::Settings {
        peer_id: "mx1".into(),
        peer_url: "http://127.0.0.1:1".into(),
        credential_file: key,
        timeout_seconds: 5,
        max_replica_bytes: 64 * 1024 * 1024,
        allow_loopback_http: true,
    });
    config.management = Some(crate::central::bootstrap::Management::Coordinator {});
    config.validate().unwrap();
    drop(Store::open(root.path()).unwrap());
    let mut db = rusqlite::Connection::open(root.path().join("state.sqlite3")).unwrap();
    db.execute_batch("INSERT INTO cluster_state VALUES('role','worker'),('node_id','mx2');")
        .unwrap();
    outbox::initialize(&mut db, "mx2").unwrap();
    let base = artifacts::bind_credentials(
        artifacts::capture(&config, Settings::from_config(&config), 0).unwrap(),
    )
    .unwrap();
    let mut publication = base.clone();
    publication.bundle.revision = 1;
    publication.bundle.digest = publication.bundle.hash().unwrap();
    artifacts::freeze(root.path(), &publication, 0).unwrap();
    let mut authority_db = rusqlite::Connection::open_in_memory().unwrap();
    authority_db.execute_batch("CREATE TABLE cluster_state(key TEXT PRIMARY KEY,value TEXT NOT NULL); INSERT INTO cluster_state VALUES('role','coordinator'),('node_id','mx1');").unwrap();
    let tx = authority_db.transaction().unwrap();
    Journal::initialize(&tx, "mx1", base.bundle).unwrap();
    let staged =
        Journal::begin(&tx, publication.bundle, vec!["mx1".into(), "mx2".into()], 1).unwrap();
    let epoch = staged.rollout().unwrap().epoch().clone();
    for node in ["mx1", "mx2"] {
        Journal::acknowledge(
            &tx,
            node,
            &Acknowledgement {
                epoch: epoch.clone(),
                progress: Progress::Prepared,
            },
            2,
        )
        .unwrap();
    }
    Journal::commit(&tx, &epoch, 3).unwrap();
    for node in ["mx1", "mx2"] {
        Journal::acknowledge(
            &tx,
            node,
            &Acknowledgement {
                epoch: epoch.clone(),
                progress: Progress::Applied,
            },
            4,
        )
        .unwrap();
    }
    let journal = Journal::release(&tx, &epoch, 5).unwrap();
    let local = json!({"version":1,"node":"mx2","authority":journal,"installed":journal.current(),"installed_epoch":epoch,"prepared":epoch});
    db.execute(
        "INSERT INTO cluster_state VALUES('activation_participant',?1)",
        [local.to_string()],
    )
    .unwrap();
    db.pragma_update(None, "user_version", 6).unwrap();
    let mut plan = plan();
    plan.selection.node = outbox::identity(&db).unwrap();
    plan.selection.baseline = epoch.clone();
    plan.policy = epoch;
    let tx = db.transaction().unwrap();
    plan.selection.install(&tx).unwrap();
    tx.commit().unwrap();
    drop(db);
    let store = Store::open_bound(root.path(), &plan.selection, None).unwrap();
    let config = Arc::new(config);
    let control = Controller::load(config.clone(), store.clone())
        .await
        .unwrap();
    let replica = crate::ha::Runtime::new(&config).unwrap();
    (
        root,
        Session {
            plan,
            config,
            store,
            control,
            replica,
            started: Instant::now(),
            lifetime: Duration::from_secs(600),
            replica_seen: AtomicU64::new(0),
            policy_seen: AtomicU64::new(0),
            capacity: Arc::new(tokio::sync::Semaphore::new(4)),
        },
    )
}
fn peer_probe(s: &Session) -> Probe {
    Probe {
        node: s.plan.peer.identity.clone(),
        binary_sha256: s.plan.peer.binary_sha256.clone(),
        ..s.probe(uuid())
    }
}
async fn response(
    s: Arc<Session>,
    path: &str,
    method: &str,
    key: Option<&str>,
    data: Vec<u8>,
) -> Response {
    let mut request = HttpRequest::builder()
        .uri(path)
        .method(method)
        .header("content-type", "application/json");
    if let Some(key) = key {
        request = request.header("authorization", format!("Bearer {key}"));
    }
    router(s)
        .oneshot(request.body(Body::from(data)).unwrap())
        .await
        .unwrap()
}
async fn json_response(response: Response) -> Value {
    serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.unwrap()).unwrap()
}
async fn state(store: &Store) -> String {
    store
        .read(|db| {
            let mut query = db.prepare("SELECT key,value FROM cluster_state ORDER BY key")?;
            let rows = query
                .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(serde_json::to_string(&rows)?)
        })
        .await
        .unwrap()
}

#[test]
fn authorization_refuses_expired_extended_unknown_and_mismatched_plans() {
    let p = plan();
    p.validate(crate::now()).unwrap();
    let now = crate::now();
    for expires_at in [now - 1, now, now + 3601, i64::MAX] {
        let mut changed = p.clone();
        changed.expires_at = expires_at;
        assert!(changed.validate(now).is_err());
    }
    for key in ["operation", "protocol", "binary_sha256", "config_sha256"] {
        let mut raw = serde_json::to_value(&p).unwrap();
        raw[key] = json!("invalid");
        assert!(
            serde_json::from_value::<Plan>(raw)
                .unwrap()
                .validate(now)
                .is_err()
        );
    }
    let mut raw = serde_json::to_value(&p).unwrap();
    raw["smtp_enabled"] = json!(true);
    assert!(serde_json::from_value::<Plan>(raw).is_err());
    let mut changed = p.clone();
    changed.peer.identity = p.selection.node.clone();
    assert!(changed.validate(now).is_err());
    let mut changed = p;
    changed.policy.digest = "0".repeat(64);
    assert!(changed.validate(now).is_err());
}

#[tokio::test]
async fn challenge_binds_operation_authority_epoch_runtime_and_distinct_machine() {
    let (_root, mut s) = fixture().await;
    let good = peer_probe(&s);
    s.check_probe(&good, Some(&good.nonce)).unwrap();
    for field in ["operation", "version", "binary_sha256", "nonce", "protocol"] {
        let mut raw = serde_json::to_value(&good).unwrap();
        raw[field] = json!("different");
        assert!(
            s.check_probe(&serde_json::from_value(raw).unwrap(), Some(&good.nonce))
                .is_err(),
            "{field}"
        );
    }
    let mut p = good.clone();
    p.node.epoch = uuid();
    assert!(s.check_probe(&p, None).is_err());
    let mut p = good.clone();
    p.database.instance = uuid();
    assert!(s.check_probe(&p, None).is_err());
    let mut p = good.clone();
    p.policy.sequence += 1;
    assert!(s.check_probe(&p, None).is_err());
    assert!(s.check_probe(&good, Some(&uuid())).is_err());
    s.replica.settings.allow_loopback_http = false;
    s.replica.machine = "0".repeat(64);
    let mut p = good;
    p.machine = s.replica.machine.clone();
    assert!(s.check_probe(&p, None).is_err());
    p.machine = "1".repeat(64);
    s.check_probe(&p, None).unwrap();
    // Distinct peer binary hashes are allowed (e.g. amd64 versus arm64),
    // but only the explicitly authorized peer hash is accepted.
    assert_ne!(p.binary_sha256, s.plan.binary_sha256);
}

#[tokio::test]
async fn probes_never_open_smtp_or_application_routes_or_mutate_policy() {
    let (_root, s) = fixture().await;
    s.local().await.unwrap();
    let before = state(&s.store).await;
    let s = Arc::new(s);
    let health = json_response(response(s.clone(), "/healthz", "GET", None, vec![]).await).await;
    assert_eq!(health["validation_ready"], false);
    for path in [
        "/api/login",
        "/api/admin/settings",
        "/api/messages",
        "/api/v1/cluster/v3/sync",
        "/api/v1/replication/v1/upload",
        "/",
        "/api/quarantine/release",
    ] {
        assert_eq!(
            response(
                s.clone(),
                path,
                "POST",
                Some(&s.replica.key),
                b"{}".to_vec()
            )
            .await
            .status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "{path}"
        );
    }
    let p = peer_probe(&s);
    let body = serde_json::to_vec(&p).unwrap();
    assert_eq!(
        response(s.clone(), REPLICA_PATH, "POST", None, body.clone())
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        response(s.clone(), REPLICA_PATH, "POST", Some("wrong"), body.clone())
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let valid = response(
        s.clone(),
        REPLICA_PATH,
        "POST",
        Some(&s.replica.key),
        body.clone(),
    )
    .await;
    assert_eq!(valid.status(), StatusCode::OK);
    assert_eq!(json_response(valid).await["nonce"], p.nonce);
    assert_eq!(
        response(s.clone(), POLICY_PATH, "POST", Some(&s.replica.key), body)
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        response(
            s.clone(),
            REPLICA_PATH,
            "POST",
            Some(&s.replica.key),
            vec![b' '; 4097]
        )
        .await
        .status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    s.seen(&s.replica_seen);
    s.seen(&s.policy_seen);
    let ready = json_response(response(s.clone(), "/healthz", "GET", None, vec![]).await).await;
    assert_eq!(ready["validation_ready"], true);
    for flag in ["smtp_ready", "delivery_enabled", "administration_enabled"] {
        assert_eq!(ready[flag], false);
    }
    assert_eq!(state(&s.store).await, before);
    s.store
        .run(|db| {
            db.execute(
                "DELETE FROM cluster_state WHERE key='activation_participant'",
                [],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    let stale = json_response(response(s.clone(), "/healthz", "GET", None, vec![]).await).await;
    assert_eq!(stale["validation_ready"], false);
    assert_eq!(stale["local_runtime_valid"], false);
}

#[tokio::test]
async fn freshness_capacity_and_monotonic_expiry_fail_closed() {
    let (_root, mut s) = fixture().await;
    s.started = Instant::now() - Duration::from_secs(30);
    s.replica_seen.store(1, Ordering::Release);
    assert!(!s.fresh(&s.replica_seen));
    s.replica_seen.store(u64::MAX, Ordering::Release);
    assert!(!s.fresh(&s.replica_seen));
    s.seen(&s.replica_seen);
    assert!(s.fresh(&s.replica_seen));
    s.lifetime = Duration::from_secs(20);
    assert!(s.live().is_err());
    let s = Arc::new(s);
    assert_eq!(
        response(s, "/healthz", "GET", None, vec![]).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let (_root, s) = fixture().await;
    let s = Arc::new(s);
    let permit = s.capacity.clone().acquire_many_owned(4).await.unwrap();
    assert_eq!(
        response(s.clone(), "/healthz", "GET", None, vec![])
            .await
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    drop(permit);
    assert_eq!(
        response(s, "/healthz", "GET", None, vec![]).await.status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn failed_peer_checks_clear_previous_readiness_and_stop_cleanly() {
    let (_root, s) = fixture().await;
    s.seen(&s.replica_seen);
    s.seen(&s.policy_seen);
    let s = Arc::new(s);
    let (stop, rx) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(s.clone().observe(rx));
    tokio::time::timeout(Duration::from_secs(3), async {
        while s.fresh(&s.replica_seen) || s.fresh(&s.policy_seen) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    stop.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[test]
fn daemon_lock_rejects_concurrent_links_and_special_files_without_initializing_store() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("daemon.lock");
    let lock = Store::daemon_lock_at(root.path()).unwrap();
    assert!(Store::daemon_lock_at(root.path()).is_err());
    assert!(!root.path().join("state.sqlite3").exists());
    drop(lock);
    drop(Store::daemon_lock_at(root.path()).unwrap());
    std::fs::hard_link(&path, root.path().join("hardlink")).unwrap();
    assert!(Store::daemon_lock_at(root.path()).is_err());
    std::fs::remove_file(&path).unwrap();
    symlink(root.path().join("hardlink"), &path).unwrap();
    assert!(Store::daemon_lock_at(root.path()).is_err());
    std::fs::remove_file(&path).unwrap();
    let cpath = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: cpath is a live NUL-terminated path within this temporary directory.
    assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0);
    assert!(Store::daemon_lock_at(root.path()).is_err());
}

#[tokio::test]
async fn authorization_expiring_during_a_request_never_returns_success() {
    let (_root, mut s) = fixture().await;
    s.started = Instant::now();
    s.lifetime = Duration::from_millis(100);
    let s = Arc::new(s);
    let entered = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let observed = entered.clone();
    let app = Router::new()
        .route(
            "/slow",
            get(move || async move {
                observed.store(true, Ordering::Release);
                tokio::time::sleep(Duration::from_millis(150)).await;
                StatusCode::OK
            }),
        )
        .layer(middleware::from_fn_with_state(s, guard));
    let reply = app
        .oneshot(
            HttpRequest::builder()
                .uri("/slow")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(entered.load(Ordering::Acquire));
    assert_eq!(reply.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn outbound_probe_checks_fresh_nonce_bounds_response_and_refuses_redirects() {
    use std::sync::atomic::AtomicUsize;
    let (_root, mut s) = fixture().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    s.replica.settings.peer_url = format!("http://{address}");
    let mode = Arc::new(AtomicUsize::new(0));
    let visits = Arc::new(AtomicUsize::new(0));
    let response_probe = peer_probe(&s);
    let expected_key = format!("Bearer {}", s.replica.key);
    let chosen = mode.clone();
    let target_visits = visits.clone();
    let app = Router::new()
        .route(
            REPLICA_PATH,
            post(move |headers: HeaderMap, Json(request): Json<Probe>| {
                let mode = chosen.clone();
                let mut reply = response_probe.clone();
                let key = expected_key.clone();
                async move {
                    assert_eq!(headers.get("authorization").unwrap(), key.as_str());
                    match mode.load(Ordering::Acquire) {
                        0 => {
                            reply.nonce = request.nonce;
                            Json(reply).into_response()
                        }
                        1 => Json(reply).into_response(), // Previous, unrelated nonce.
                        2 => (StatusCode::OK, vec![b' '; 4097]).into_response(),
                        _ => (
                            StatusCode::TEMPORARY_REDIRECT,
                            [("location", format!("http://{address}/target"))],
                        )
                            .into_response(),
                    }
                }
            }),
        )
        .route(
            "/target",
            post(move || async move {
                target_visits.fetch_add(1, Ordering::AcqRel);
                StatusCode::OK
            }),
        );
    let server = tokio::spawn(axum::serve(listener, app).into_future());
    s.replica_probe().await.unwrap();
    assert!(s.fresh(&s.replica_seen));
    for value in [1, 2, 3] {
        mode.store(value, Ordering::Release);
        assert!(s.replica_probe().await.is_err(), "response mode {value}");
    }
    assert_eq!(visits.load(Ordering::Acquire), 0);
    server.abort();
    let _ = server.await;
}
