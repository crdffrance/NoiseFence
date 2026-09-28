#[allow(dead_code)]
mod common;
#[path = "common/postgres.rs"]
mod postgres;
use noisefence::{
    central::{history, logs, outbox, transport},
    cluster,
    control::{Controller, Settings},
    engine::Engine,
    store::Store,
};
use reqwest::{
    StatusCode,
    header::{AUTHORIZATION, HeaderMap, HeaderValue},
};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

fn client(secret: &str) -> reqwest::Client {
    let mut headers = HeaderMap::new();
    headers.insert("x-noisefence-node", HeaderValue::from_static("mx2"));
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {secret}")).unwrap(),
    );
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .default_headers(headers)
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .unwrap()
}
#[tokio::test]
#[ignore = "requires disposable PostgreSQL on 127.0.0.1:15432 and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn authenticated_http_metadata_survives_lost_replies_rotation_and_outage() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let f = postgres::Fixture::new().await;
    let db = f.connect().await;
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let mut cfg = (*common::config(a.path())).clone();
    cfg.cluster = Some(cluster::Settings {
        role: cluster::Role::Coordinator,
        node_id: "mx1".into(),
        coordinator_url: None,
        credential_file: None,
        poll_seconds: 2,
        max_stale_seconds: 60,
        allow_loopback_http: true,
    });
    let origin = cfg.web.public_origin.clone();
    let cfg = Arc::new(cfg);
    let local = Store::open(a.path()).unwrap();
    cluster::prepare(&cfg, &local).await.unwrap();
    let owner = local.run(|db| outbox::initialize(db, "mx1")).await.unwrap();
    let worker = Store::open(b.path()).unwrap();
    let peer = worker
        .run(|db| outbox::initialize(db, "mx2"))
        .await
        .unwrap();
    f.central.register_source(&owner).await.unwrap();
    f.central.register_source(&peer).await.unwrap();
    let secret = "a".repeat(64);
    let hash = noisefence::message::digest(secret.as_bytes());
    f.central
        .enroll_node(&peer, "Secondary MX", &hash)
        .await
        .unwrap();
    f.central
        .enroll_node(&peer, "Secondary MX", &hash)
        .await
        .unwrap();
    assert!(
        f.central
            .enroll_node(&peer, "Replacement", &"b".repeat(64))
            .await
            .is_err()
    );
    let base = cluster::artifacts::capture(&cfg, Settings::from_config(&cfg), 0).unwrap();
    f.central
        .initialize_policy(&owner, base.bundle)
        .await
        .unwrap();
    // A valid legacy key must never become an authentication fallback.
    let local_hash = hash.clone();
    local.run(move|db|{db.execute("INSERT INTO cluster_nodes(id,name,token_hash,enabled,created) VALUES('mx2','old',?1,1,0)",[local_hash])?;Ok(())}).await.unwrap();
    let central_store = local
        .clone()
        .with_management(f.central.clone())
        .await
        .unwrap();
    let control = Controller::load(cfg.clone(), central_store.clone())
        .await
        .unwrap();
    let lost = Arc::new(AtomicBool::new(true));
    let lost_response = lost.clone();
    let lost_command = Arc::new(AtomicBool::new(false));
    let lost_command_response = lost_command.clone();
    let router = noisefence::api::router_controlled(cfg, central_store, Some(control))
        .unwrap()
        .layer(axum::middleware::from_fn(
            move |request: axum::extract::Request, next: axum::middleware::Next| {
                let lost = lost_response.clone();
                let lost_command = lost_command_response.clone();
                async move {
                    use axum::response::IntoResponse;
                    let drop_reply = request.uri().path().ends_with("/v3/history")
                        && lost.swap(false, Ordering::SeqCst)
                        || (request.uri().path().ends_with("/v3/commands")
                            && lost_command.swap(false, Ordering::SeqCst));
                    let response = next.run(request).await;
                    if drop_reply && response.status().is_success() {
                        axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response()
                    } else {
                        response
                    }
                }
            },
        ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    let http = client(&secret);
    assert_eq!(
        transport::synchronize_runtime_history(&worker, &http, &url)
            .await
            .unwrap(),
        0
    );
    let wrong = transport::RuntimePoll {
        protocol: transport::PROTOCOL.into(),
        epoch: "wrong-epoch".into(),
    };
    assert_eq!(
        http.post(format!("{url}/api/v1/cluster/v3/runtime-history"))
            .json(&wrong)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );

    let id = uuid::Uuid::new_v4().to_string();
    let insert = id.clone();
    let raw = serde_json::to_string(
        &Engine::new(common::config(b.path()))
            .unwrap()
            .offline(common::MESSAGE),
    )
    .unwrap();
    worker.run(move|db| {
        let tx=db.transaction()?;
        tx.execute("INSERT INTO messages(id,created,sender,scan) VALUES(?1,?2,'sender@example.org',?3)",rusqlite::params![insert,noisefence::now(),raw])?;
        tx.execute("INSERT INTO deliveries(message_id,address,destination,hosts,next_attempt) VALUES(?1,'alice@example.test','alice@example.test','[]',0)",[insert])?;
        let delivery=tx.last_insert_rowid();
        let trace=noisefence::delivery_log::Attempt{route:"mx.example.test".into(),peer:None,started:1,elapsed_ms:0,outcome:"deferred".into(),truncated:false,events:Vec::new()};
        tx.execute("INSERT INTO delivery_attempts(delivery_id,attempt,trace) VALUES(?1,1,?2)",rusqlite::params![delivery,serde_json::to_string(&trace)?])?;
        tx.commit()?;Ok(())
    }).await.unwrap();
    assert!(
        transport::synchronize_metadata_once(&worker, &http, &url)
            .await
            .is_err()
    );
    assert_eq!(
        db.query_one("SELECT count(*) FROM noisefence.messages", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    assert_eq!(
        worker
            .read(|db| Ok(outbox::status(db)?.pending))
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        transport::synchronize_metadata_once(&worker, &http, &url)
            .await
            .unwrap(),
        2
    );
    assert_eq!(
        transport::synchronize_runtime_history(&worker, &http, &url)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        db.query_one("SELECT count(*) FROM noisefence.delivery_logs", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    assert_eq!(
        transport::synchronize_metadata_once(&worker, &http, &url)
            .await
            .unwrap(),
        0
    );
    // Reject epoch rebinding and private identities supplied in place of credentials.
    let request = transport::History {
        protocol: transport::PROTOCOL.into(),
        epoch: uuid::Uuid::new_v4().to_string(),
        events: Vec::new(),
    };
    assert_eq!(
        http.post(format!("{url}/api/v1/cluster/v3/history"))
            .json(&request)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        client(&"f".repeat(64))
            .post(format!("{url}/api/v1/cluster/v3/history"))
            .json(&request)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        reqwest::Client::new()
            .post(format!("{url}/api/v1/cluster/v3/history"))
            .json(&request)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let authenticated = f
        .central
        .authenticate_node("mx2", &hash)
        .await
        .unwrap()
        .unwrap();
    let next_secret = "c".repeat(64);
    let next_hash = noisefence::message::digest(next_secret.as_bytes());
    db.execute(
        "UPDATE noisefence.cluster_nodes SET token_hash=$1,version=version+1 WHERE node='mx2'",
        &[&next_hash],
    )
    .await
    .unwrap();
    assert!(
        f.central
            .ingest_from_node(&authenticated, &mut [])
            .await
            .is_err()
    );
    assert!(
        f.central
            .ingest_logs_from_node(&authenticated, &mut [])
            .await
            .is_err()
    );
    assert!(
        f.central
            .pending_commands_for_node(&authenticated)
            .await
            .is_err()
    );
    assert!(
        f.central
            .acknowledge_commands_for_node(&authenticated, &[])
            .await
            .is_err()
    );
    assert_eq!(
        http.post(format!("{url}/api/v1/cluster/v3/history"))
            .json(&request)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert!(
        f.central
            .runtime_history(Some(&authenticated))
            .await
            .is_err()
    );
    assert!(
        transport::synchronize_runtime_history(&worker, &http, &url)
            .await
            .is_err()
    );
    let http = client(&next_secret);
    worker
        .run(|db| {
            db.execute("UPDATE delivery_attempts SET attempt=2", [])?;
            Ok(())
        })
        .await
        .unwrap();
    f.suspend().await;
    assert!(
        transport::synchronize_metadata_once(&worker, &http, &url)
            .await
            .is_err()
    );
    assert!(
        worker
            .read(|db| Ok(outbox::status(db)?.pending > 0))
            .await
            .unwrap()
    );
    // Reopen the local journal: the failed network operation did not consume it.
    let reopened = Store::open(b.path()).unwrap();
    f.resume().await;
    assert_eq!(
        transport::synchronize_metadata_once(&reopened, &http, &url)
            .await
            .unwrap(),
        2
    );
    let db = f.connect().await;
    assert_eq!(
        db.query_one("SELECT attempt FROM noisefence.delivery_logs", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        2
    );
    // Execute a quarantined release once, then lose the acknowledgement reply.
    let admin_token = "d".repeat(64);
    let user_session = noisefence::message::digest(admin_token.as_bytes());
    db.execute(
        "INSERT INTO noisefence.users(username,password,admin) VALUES('admin','synthetic',true)",
        &[],
    )
    .await
    .unwrap();
    db.execute("INSERT INTO noisefence.sessions(token_hash,username,csrf,expires) VALUES($1,'admin','synthetic',$2)",&[&user_session,&(noisefence::now()+3600)]).await.unwrap();
    worker.run(|db|{db.execute("UPDATE deliveries SET status='quarantined'",[])?;db.execute("INSERT INTO delivery_policy(delivery_id,action,held_until) SELECT id,'quarantine',?1 FROM deliveries",[noisefence::now()+3600])?;Ok(())}).await.unwrap();
    transport::synchronize_metadata_once(&worker, &http, &url)
        .await
        .unwrap();
    let queued = f
        .central
        .queue_quarantine(
            "admin",
            &user_session,
            &id,
            "alice@example.test",
            noisefence::quarantine::Command::Release,
        )
        .await
        .unwrap();
    assert!(matches!(queued, noisefence::quarantine::Change::Queued(_)));
    assert_eq!(
        transport::synchronize_commands_once(&worker, &http, &url)
            .await
            .unwrap(),
        1
    );
    worker
        .run(|db| {
            db.execute("UPDATE deliveries SET next_attempt=4242", [])?;
            Ok(())
        })
        .await
        .unwrap();
    lost_command.store(true, Ordering::SeqCst);
    assert!(
        transport::synchronize_commands_once(&worker, &http, &url)
            .await
            .is_err()
    );
    assert_eq!(
        noisefence::central::commands::pending_receipts(&worker, &peer)
            .await
            .unwrap()
            .len(),
        1
    );
    let reopened = Store::open(b.path()).unwrap();
    assert_eq!(
        transport::synchronize_commands_once(&reopened, &http, &url)
            .await
            .unwrap(),
        1
    );
    assert!(
        noisefence::central::commands::pending_receipts(&reopened, &peer)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        worker
            .read(|db| Ok(
                db.query_row("SELECT next_attempt FROM deliveries", [], |r| r
                    .get::<_, i64>(0))?
            ))
            .await
            .unwrap(),
        4242
    );
    assert_eq!(
        db.query_one(
            "SELECT execution_result FROM noisefence.queue_commands",
            &[]
        )
        .await
        .unwrap()
        .get::<_, String>(0),
        "done"
    );
    let (nodes, commands) = f.central.node_overview("admin").await.unwrap();
    assert_eq!(nodes.len(), 1);
    assert_eq!(commands.len(), 1);
    assert!(
        !serde_json::to_string(&nodes)
            .unwrap()
            .contains("token_hash")
    );
    assert!(f.central.node_overview("unknown").await.is_err());
    let web = reqwest::Client::builder().no_proxy().build().unwrap();
    let edit =
        serde_json::json!({"id":"mx2","name":"Secondary MX renamed","enabled":true,"version":1});
    let response = web
        .post(format!("{url}/api/v1/admin/cluster/nodes"))
        .header("cookie", format!("noisefence_session={admin_token}"))
        .header("origin", &origin)
        .header("x-csrf-token", "synthetic")
        .json(&edit)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let edited: serde_json::Value = response.json().await.unwrap();
    assert_eq!(edited["version"], 2);
    assert!(edited["credential"].is_null());
    assert_eq!(
        web.post(format!("{url}/api/v1/admin/cluster/nodes"))
            .header("cookie", format!("noisefence_session={admin_token}"))
            .header("origin", &origin)
            .header("x-csrf-token", "synthetic")
            .json(&edit)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    // A late metadata event cannot bring back a message removed by retention.
    worker
        .run(|db| {
            db.execute("UPDATE messages SET raw_present=0", [])?;
            Ok(())
        })
        .await
        .unwrap();
    let (_, old) = history::export(&worker).await.unwrap();
    worker
        .run(|db| {
            db.execute("DELETE FROM messages", [])?;
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(
        transport::synchronize_metadata_once(&worker, &http, &url)
            .await
            .unwrap(),
        1
    );
    let response = http
        .post(format!("{url}/api/v1/cluster/v3/history"))
        .json(&transport::Batch {
            protocol: transport::PROTOCOL.to_owned(),
            epoch: peer.epoch.clone(),
            events: old,
        })
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    assert_eq!(
        db.query_one("SELECT count(*) FROM noisefence.messages", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    assert_eq!(
        db.query_one("SELECT count(*) FROM noisefence.delivery_logs", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    assert!(logs::export(&worker).await.unwrap().1.is_empty());
    let disable =
        serde_json::json!({"id":"mx2","name":"Secondary MX renamed","enabled":false,"version":2});
    assert_eq!(
        web.post(format!("{url}/api/v1/admin/cluster/nodes"))
            .header("cookie", format!("noisefence_session={admin_token}"))
            .header("origin", &origin)
            .header("x-csrf-token", "synthetic")
            .json(&disable)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        http.post(format!("{url}/api/v1/cluster/v3/history"))
            .json(&request)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    stop.send(()).unwrap();
    server.await.unwrap();
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL on 127.0.0.1:15432 and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn independent_policy_and_history_loops_activate_both_mxs_over_http() {
    use cluster::{activation::transport::PROTOCOL, artifacts};
    let _ = rustls::crypto::ring::default_provider().install_default();
    let f = postgres::Fixture::new().await;
    let db = f.connect().await;
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let mut cfg = (*common::config(a.path())).clone();
    cfg.cluster = Some(cluster::Settings {
        role: cluster::Role::Coordinator,
        node_id: "mx1".into(),
        coordinator_url: None,
        credential_file: None,
        poll_seconds: 2,
        max_stale_seconds: 60,
        allow_loopback_http: true,
    });
    let cfg = Arc::new(cfg);
    let local = Store::open(a.path()).unwrap();
    cluster::prepare(&cfg, &local).await.unwrap();
    let owner = local.run(|db| outbox::initialize(db, "mx1")).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let secret = "a".repeat(64);
    let token_file = b.path().join("cluster-token");
    cluster::protocol::private_write(&token_file, secret.as_bytes()).unwrap();
    let mut worker_cfg = (*common::config(b.path())).clone();
    worker_cfg.cluster = Some(cluster::Settings {
        role: cluster::Role::Worker,
        node_id: "mx2".into(),
        coordinator_url: Some(url.clone()),
        credential_file: Some(token_file),
        poll_seconds: 2,
        max_stale_seconds: 60,
        allow_loopback_http: true,
    });
    let worker_cfg = Arc::new(worker_cfg);
    let worker_store = Store::open(b.path()).unwrap();
    cluster::prepare(&worker_cfg, &worker_store).await.unwrap();
    let peer = worker_store
        .run(|db| {
            let id = outbox::initialize(db, "mx2")?;
            db.execute(
                "INSERT INTO cluster_state VALUES('management_transport',?1)",
                [transport::PROTOCOL],
            )?;
            Ok(id)
        })
        .await
        .unwrap();
    for node in [&owner, &peer] {
        f.central.register_source(node).await.unwrap();
    }
    f.central
        .enroll_node(
            &peer,
            "Secondary MX",
            &noisefence::message::digest(secret.as_bytes()),
        )
        .await
        .unwrap();
    let publication = artifacts::bind_credentials(
        artifacts::capture(&cfg, Settings::from_config(&cfg), 0).unwrap(),
    )
    .unwrap();
    artifacts::freeze(a.path(), &publication, 0).unwrap();
    f.central
        .initialize_policy(&owner, publication.bundle.clone())
        .await
        .unwrap();
    // Bootstrap a staged test rollout; production imports the existing released
    // epoch instead of resetting a live cluster to this synthetic initial state.
    f.central
        .report_policy_peer(
            &peer,
            PROTOCOL,
            env!("CARGO_PKG_VERSION"),
            0,
            &publication.bundle.digest,
        )
        .await
        .unwrap();
    let session = "a".repeat(64);
    db.execute(
        "INSERT INTO noisefence.users(username,password,admin) VALUES('admin','synthetic',true)",
        &[],
    )
    .await
    .unwrap();
    db.execute("INSERT INTO noisefence.sessions(token_hash,username,csrf,expires) VALUES($1,'admin','synthetic',$2)",&[&session,&(noisefence::now()+3600)]).await.unwrap();
    let store = local
        .clone()
        .with_management(f.central.clone())
        .await
        .unwrap();
    let control = Controller::load(cfg.clone(), store.clone()).await.unwrap();
    let mut settings = publication.bundle.settings;
    settings.filters.threshold = 96.;
    control
        .stage_activation_session(0, settings, "admin".into(), session.clone())
        .await
        .unwrap();
    let outage = Arc::new(AtomicBool::new(true));
    let disrupt = outage.clone();
    let router = noisefence::api::router_controlled(cfg, store, Some(control.clone()))
        .unwrap()
        .layer(axum::middleware::from_fn(
            move |request: axum::extract::Request, next: axum::middleware::Next| {
                let disrupt = disrupt.clone();
                async move {
                    use axum::response::IntoResponse;
                    if request.uri().path().ends_with("/v3/history")
                        && disrupt.load(Ordering::SeqCst)
                    {
                        axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response()
                    } else {
                        next.run(request).await
                    }
                }
            },
        ));
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let mut server_stop = stopped.clone();
    let server = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async move {
                let _ = server_stop.changed().await;
            })
            .await
            .unwrap();
    });
    let worker = Controller::load(worker_cfg, worker_store.clone())
        .await
        .unwrap();
    let coordinator_job = tokio::spawn(cluster::run(control.clone(), stopped.clone()));
    let worker_job = tokio::spawn(cluster::run(worker.clone(), stopped.clone()));
    let id = uuid::Uuid::new_v4().to_string();
    let insert = id.clone();
    let raw = serde_json::to_string(
        &Engine::new(common::config(b.path()))
            .unwrap()
            .offline(common::MESSAGE),
    )
    .unwrap();
    worker_store.run(move|db| {db.execute("INSERT INTO messages(id,created,sender,scan) VALUES(?1,?2,'sender@example.org',?3)",rusqlite::params![insert,noisefence::now(),raw])?;db.execute("INSERT INTO deliveries(message_id,address,destination,hosts,next_attempt) VALUES(?1,'alice@example.test','alice@example.test','[]',0)",[insert])?;Ok(())}).await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            if control.cluster_ready()
                && worker.cluster_ready()
                && control.snapshot().revision == 1
                && worker.snapshot().revision == 1
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(control.snapshot().settings.filters.threshold, 96.);
    assert_eq!(worker.snapshot().settings.filters.threshold, 96.);
    assert_eq!(
        db.query_one("SELECT count(*) FROM noisefence.messages", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    assert_eq!(
        worker_store
            .read(|db| Ok(outbox::status(db)?.pending))
            .await
            .unwrap(),
        1
    );
    let (nodes, _) = f.central.node_overview("admin").await.unwrap();
    assert_eq!(nodes[0]["applied_revision"], 1);
    outage.store(false, Ordering::SeqCst);
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if db
                .query_one("SELECT count(*) FROM noisefence.messages", &[])
                .await
                .unwrap()
                .get::<_, i64>(0)
                == 1
                && worker_store
                    .read(|db| Ok(outbox::status(db)?.pending))
                    .await
                    .unwrap()
                    == 0
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap();
    // A second rollout uses the actual authenticated worker readiness report.
    let mut settings = control.snapshot().settings.clone();
    settings.filters.threshold = 97.;
    control
        .stage_activation_session(1, settings, "admin".into(), session)
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            if control.cluster_ready()
                && worker.cluster_ready()
                && control.snapshot().revision == 2
                && worker.snapshot().revision == 2
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap();
    stop.send(true).unwrap();
    coordinator_job.await.unwrap().unwrap();
    worker_job.await.unwrap().unwrap();
    server.await.unwrap();
    assert_eq!(
        db.query_one(
            "SELECT revision FROM noisefence.policy_head WHERE activated_at IS NOT NULL",
            &[]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        2
    );
    f.finish().await;
}
