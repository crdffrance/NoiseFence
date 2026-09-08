mod common;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use noisefence::{
    api,
    config::Domain,
    control::{Controller, ManagedDomain},
    engine::extract,
    store::Store,
};
use rusqlite::params;
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

async fn account(store: &Store, name: &str, admin: bool, grants: Vec<&str>) -> String {
    let name = name.to_owned();
    let grants: Vec<String> = grants.into_iter().map(str::to_owned).collect();
    let token = api::random_token();
    let hash = noisefence::message::digest(token.as_bytes());
    store.run(move|db| {
        db.execute("INSERT INTO users(username,password,admin) VALUES(?1,'unused-in-test',?2)",params![name,admin])?;
        for g in grants {db.execute("INSERT INTO grants(username,address) VALUES(?1,?2)",params![name,g])?;}
        db.execute("INSERT INTO sessions(token_hash,username,csrf,expires) VALUES(?1,?2,'test-csrf',?3)",params![hash,name,noisefence::now()+3600])?;Ok(())
    }).await.unwrap();
    token
}
async fn request(
    app: &Router,
    token: &str,
    path: &str,
    data: Option<Value>,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .uri(format!("/api/v1{path}"))
        .header("cookie", format!("noisefence_session={token}"));
    let body = if let Some(data) = data {
        req = req
            .method("POST")
            .header("content-type", "application/json")
            .header("origin", "http://127.0.0.1:3000")
            .header("x-csrf-token", "test-csrf");
        Body::from(data.to_string())
    } else {
        Body::empty()
    };
    let response = app.clone().oneshot(req.body(body).unwrap()).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| json!({"body":String::from_utf8_lossy(&bytes)})),
    )
}
async fn message(store: &Store, cfg: &noisefence::config::Config, addresses: &[&str]) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    store
        .enqueue(
            id.clone(),
            "sender@example.org".into(),
            addresses
                .iter()
                .map(|a| cfg.recipient(a).unwrap())
                .collect(),
            extract(common::MESSAGE, 10000),
            common::MESSAGE.to_vec(),
        )
        .await
        .unwrap();
    id
}
#[tokio::test]
async fn domain_acl_covers_aliases_bcc_search_feedback_stats_and_disabled_accounts() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = (*common::config(dir.path())).clone();
    cfg.domains[0].accept_all_recipients = true;
    cfg.domains.push(Domain {
        name: "other.test".into(),
        next_hops: vec!["127.0.0.1".into()],
        accept_all_recipients: true,
        recipients: vec![],
        aliases: Default::default(),
    });
    cfg.validate().unwrap();
    let cfg = Arc::new(cfg);
    let store = Store::open(dir.path()).unwrap();
    let domain = account(&store, "domain", false, vec!["*@example.test"]).await;
    let alice = account(&store, "alice", false, vec!["alice@example.test"]).await;
    let admin = account(&store, "admin", true, vec![]).await;
    let outsider = account(&store, "outsider", false, vec!["*@ample.test"]).await;
    let id = message(&store, &cfg, &["billing@example.test", "secret@other.test"]).await;
    message(&store, &cfg, &["new@example.test"]).await;
    message(&store, &cfg, &["\"x@y\"@example.test"]).await;
    message(&store, &cfg, &["secret@other.test"]).await;
    let app = api::router(cfg, store.clone()).unwrap();
    for (token, count, recipient_count) in [
        (&domain, 3, 1),
        (&alice, 1, 1),
        (&admin, 4, 2),
        (&outsider, 0, 0),
    ] {
        let (code, body) = request(&app, token, "/messages", None).await;
        assert_eq!(code, StatusCode::OK, "{body}");
        let mails = body.as_array().unwrap();
        assert_eq!(mails.len(), count);
        if let Some(m) = mails.iter().find(|m| m["id"] == id) {
            assert_eq!(m["recipients"].as_array().unwrap().len(), recipient_count);
        }
        let (_, stats) = request(&app, token, "/stats", None).await;
        assert_eq!(stats["received"], count);
        if token != &admin {
            assert!(!body.to_string().contains("secret@other.test"));
        }
    }
    let (_, hidden) = request(&app, &domain, "/messages?q=secret%40other.test", None).await;
    assert_eq!(hidden, json!([]));
    let (_, scope) = request(&app, &domain, "/messages?domain=other.test", None).await;
    assert_eq!(scope, json!([]));
    let (_, stats) = request(&app, &admin, "/stats?domain=other.test", None).await;
    assert_eq!(stats["received"], 2);
    assert_eq!(
        request(
            &app,
            &domain,
            &format!("/messages/{id}/feedback"),
            Some(json!({"spam":true}))
        )
        .await
        .0,
        StatusCode::OK
    );
    for path in [
        "/admin/users",
        "/admin/audit",
        "/admin/queue",
        "/admin/config",
        "/admin/revisions",
        "/metrics",
    ] {
        assert_eq!(
            request(&app, &domain, path, None).await.0,
            StatusCode::FORBIDDEN
        );
    }
    store
        .run(|db| {
            db.execute("UPDATE users SET disabled=1 WHERE username='domain'", [])?;
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(
        request(&app, &domain, "/messages", None).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert!(store.feedback("domain".into(), id, true).await.is_err());
}
#[tokio::test]
async fn durable_configuration_validation_conflicts_recovery_and_routes() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = common::config(dir.path());
    let store = Store::open(dir.path()).unwrap();
    let token = account(&store, "admin", true, vec![]).await;
    let control = Controller::load(cfg.clone(), store.clone()).await.unwrap();
    let app = api::router_controlled(cfg.clone(), store.clone(), Some(control.clone())).unwrap();
    let original = control.snapshot();
    // A console round trip must preserve bootstrap routes including custom ports.
    assert_eq!(
        original
            .settings
            .effective(&cfg)
            .unwrap()
            .recipient("alice@example.test")
            .unwrap()
            .hosts,
        cfg.recipient("alice@example.test").unwrap().hosts
    );
    let id = message(&store, &cfg, &["alice@example.test"]).await;
    let mut desired = original.settings.clone();
    desired.gateways[0].port = 2527;
    desired.domains.push(ManagedDomain {
        name: "new.test".into(),
        gateway: Some(desired.gateways[0].id.clone()),
        enabled: true,
        accept_all_recipients: true,
        recipients: vec![],
        aliases: Default::default(),
    });
    let (status, body) = request(
        &app,
        &token,
        "/admin/config",
        Some(json!({"revision":0,"settings":desired})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let rev = body["revision"].as_i64().unwrap();
    assert!(rev > 0);
    assert_eq!(
        control
            .snapshot()
            .config
            .recipient("any@new.test")
            .unwrap()
            .hosts,
        vec!["127.0.0.1:2527"]
    );
    assert_eq!(
        store.claim().await.unwrap().unwrap().hosts,
        vec!["127.0.0.1"]
    );
    assert!(store.raw_path(&id).exists());
    assert_eq!(
        request(
            &app,
            &token,
            "/admin/config",
            Some(json!({"revision":0,"settings":desired}))
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let mut invalid = desired.clone();
    invalid.gateways[0].hosts = vec!["https://user:secret@elsewhere.test".into()];
    assert_eq!(
        request(
            &app,
            &token,
            "/admin/config",
            Some(json!({"revision":rev,"settings":invalid}))
        )
        .await
        .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    invalid = desired.clone();
    invalid.filters.mode = noisefence::config::Mode::Tag;
    assert_eq!(
        request(
            &app,
            &token,
            "/admin/config",
            Some(json!({"revision":rev,"settings":invalid}))
        )
        .await
        .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    invalid = desired.clone();
    invalid.filters.vision = true;
    assert_eq!(
        request(
            &app,
            &token,
            "/admin/config",
            Some(json!({"revision":rev,"settings":invalid}))
        )
        .await
        .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(control.snapshot().revision, rev);
    let recovered = Controller::load(cfg, Store::open(dir.path()).unwrap())
        .await
        .unwrap();
    assert_eq!(recovered.snapshot().settings, desired);
    let (_, history) = request(&app, &token, "/admin/revisions", None).await;
    assert_eq!(history.as_array().unwrap().len(), 1);
    let (_, saved) = request(&app, &token, &format!("/admin/revisions/{rev}"), None).await;
    assert_eq!(saved, json!(desired));
    let (code, _) = request(
        &app,
        &token,
        "/admin/config",
        Some(json!({"revision":rev,"settings":original.settings})),
    )
    .await;
    assert_eq!(code, StatusCode::OK);
    assert!(
        control
            .snapshot()
            .config
            .recipient("any@new.test")
            .is_none()
    );
    let (_, audit) = request(&app, &token, "/admin/audit", None).await;
    assert_eq!(audit.as_array().unwrap().len(), 2);
    let (code, queue) = request(&app, &token, "/admin/queue", None).await;
    assert_eq!(code, StatusCode::OK, "{queue}");
    assert_eq!(queue[0]["status"], "sending");
    assert_eq!(
        request(
            &app,
            &token,
            "/admin/queue/retry",
            Some(json!({"id":queue[0]["id"]}))
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
}
#[tokio::test]
async fn accounts_require_admin_csrf_and_current_version_and_revoke_sessions() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = common::config(dir.path());
    let store = Store::open(dir.path()).unwrap();
    let token = account(&store, "admin", true, vec![]).await;
    let alice = account(&store, "alice", false, vec!["alice@example.test"]).await;
    let app = api::router(cfg, store.clone()).unwrap();
    let body = json!({"username":"alice","admin":false,"disabled":false,"addresses":["*@example.test"],"password":null,"version":0});
    assert_eq!(
        request(&app, &alice, "/admin/users", Some(body.clone()))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let response = app
        .clone()
        .oneshot(
            Request::post("/api/v1/admin/users")
                .header("cookie", format!("noisefence_session={token}"))
                .header("origin", "http://127.0.0.1:3000")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let (code, result) = request(&app, &token, "/admin/users", Some(body.clone())).await;
    assert_eq!(code, StatusCode::OK, "{result}");
    assert_eq!(
        request(&app, &alice, "/messages", None).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        request(&app, &token, "/admin/users", Some(body)).await.0,
        StatusCode::CONFLICT
    );
    let (_, users) = request(&app, &token, "/admin/users", None).await;
    assert!(!users.to_string().contains("unused-in-test"));
    let alice = users
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["username"] == "alice")
        .unwrap();
    assert_eq!(alice["addresses"], json!(["*@example.test"]));
    assert_eq!(alice["version"], 1);
    let remove_self = json!({"username":"admin","admin":false,"disabled":true,"addresses":[],"password":null,"version":0});
    assert_eq!(
        request(&app, &token, "/admin/users", Some(remove_self))
            .await
            .0,
        StatusCode::CONFLICT
    );
    assert_eq!(request(&app, &token, "/me", None).await.0, StatusCode::OK);
    let create = json!({"username":"new-user","admin":false,"disabled":false,"addresses":["billing@example.test"],"password":"secure-test-password","version":-1});
    let (code, result) = request(&app, &token, "/admin/users", Some(create)).await;
    assert_eq!(code, StatusCode::OK, "{result}");
    let (_, users) = request(&app, &token, "/admin/users", None).await;
    assert_eq!(
        users
            .as_array()
            .unwrap()
            .iter()
            .find(|u| u["username"] == "new-user")
            .unwrap()["addresses"],
        json!(["alice@example.test"])
    );
}
#[tokio::test]
async fn smtp_pins_configuration_until_data_and_refreshes_next_transaction() {
    use tokio::{
        io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
        net::{TcpListener, TcpStream},
        sync::Semaphore,
    };
    let dir = tempfile::tempdir().unwrap();
    let cfg = common::config(dir.path());
    let store = Store::open(dir.path()).unwrap();
    account(&store, "admin", true, vec![]).await;
    let control = Controller::load(cfg.clone(), store.clone()).await.unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, rx) = tokio::sync::watch::channel(false);
    let state = noisefence::smtp::State {
        config: cfg,
        store: store.clone(),
        engine: control.snapshot().engine.clone(),
        processing: Arc::new(Semaphore::new(1)),
    };
    let server = tokio::spawn(noisefence::smtp::serve_controlled(
        listener,
        state,
        Some(control.clone()),
        rx,
    ));
    let mut io = BufReader::new(TcpStream::connect(addr).await.unwrap());
    async fn reply(io: &mut BufReader<TcpStream>) -> String {
        let mut out = String::new();
        loop {
            let mut l = String::new();
            io.read_line(&mut l).await.unwrap();
            assert!(!l.is_empty());
            let done = l.as_bytes()[3] == b' ';
            out.push_str(&l);
            if done {
                return out;
            }
        }
    }
    assert!(reply(&mut io).await.starts_with("220"));
    io.write_all(b"EHLO sender.test\r\n").await.unwrap();
    assert!(reply(&mut io).await.starts_with("250"));
    let mut first = control.snapshot().settings.clone();
    first.domains[0].recipients.push("new@example.test".into());
    let revision = control.apply(0, first, "admin".into()).await.unwrap();
    io.write_all(b"MAIL FROM:<sender@example.org>\r\nRCPT TO:<new@example.test>\r\nRSET\r\nMAIL FROM:<sender@example.org>\r\n").await.unwrap();
    for _ in 0..4 {
        assert!(reply(&mut io).await.starts_with("250"));
    }
    let mut settings = control.snapshot().settings.clone();
    settings.domains[0]
        .recipients
        .retain(|a| a != "bob@example.test");
    control
        .apply(revision, settings, "admin".into())
        .await
        .unwrap();
    io.write_all(b"RCPT TO:<bob@example.test>\r\nDATA\r\n")
        .await
        .unwrap();
    assert!(reply(&mut io).await.starts_with("250"));
    assert!(reply(&mut io).await.starts_with("354"));
    io.write_all(common::MESSAGE).await.unwrap();
    io.write_all(b".\r\n").await.unwrap();
    assert!(reply(&mut io).await.starts_with("250"));
    io.write_all(b"MAIL FROM:<sender@example.org>\r\nRCPT TO:<bob@example.test>\r\nQUIT\r\n")
        .await
        .unwrap();
    assert!(reply(&mut io).await.starts_with("250"));
    assert!(reply(&mut io).await.starts_with("550"));
    assert!(reply(&mut io).await.starts_with("221"));
    assert_eq!(
        store
            .list("admin".into(), "".into(), "all".into(), 0, 95.0)
            .await
            .unwrap()
            .len(),
        1
    );
    stop.send(true).unwrap();
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn slow_console_queries_do_not_block_durable_writes_and_are_interrupted() {
    use std::time::{Duration, Instant};
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let copy = store.clone();
    let (started, ready) = tokio::sync::oneshot::channel();
    let begin = Instant::now();
    let query = tokio::spawn(async move {
        copy.read(move|db| {
        db.query_row("SELECT COUNT(*) FROM users",[],|r|r.get::<_,i64>(0))?;
        let _=started.send(());
        Ok(db.query_row("WITH RECURSIVE numbers(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM numbers WHERE x<1000000000) SELECT SUM(x) FROM numbers",[],|r|r.get::<_,i64>(0))?)
    }).await
    });
    ready.await.unwrap();
    tokio::time::timeout(
        Duration::from_millis(500),
        store.run(|db| {
            db.execute(
                "INSERT INTO users(username,password) VALUES('writer','test')",
                [],
            )?;
            Ok(())
        }),
    )
    .await
    .expect("reader blocked queue connection")
    .unwrap();
    assert!(query.await.unwrap().is_err());
    assert!(begin.elapsed() < Duration::from_secs(5));
    assert_eq!(
        store
            .read(|db| Ok(db.query_row("SELECT COUNT(*) FROM users", [], |r| r.get::<_, i64>(0))?))
            .await
            .unwrap(),
        1
    );
}
#[tokio::test]
async fn concurrent_configuration_changes_never_overwrite_and_cli_matches_saved_revision() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = common::config(dir.path());
    let store = Store::open(dir.path()).unwrap();
    account(&store, "admin", true, vec![]).await;
    let control = Controller::load(cfg.clone(), store.clone()).await.unwrap();
    let mut a = control.snapshot().settings.clone();
    a.domains[0].accept_all_recipients = true;
    let mut b = a.clone();
    b.filters.threshold = 96.0;
    let (one, two) = tokio::join!(
        control.apply(0, a, "admin".into()),
        control.apply(0, b, "admin".into())
    );
    assert_ne!(one.is_ok(), two.is_ok());
    let cli = noisefence::control::effective_from_disk(cfg).unwrap();
    assert_eq!(
        cli.filter.threshold,
        control.snapshot().config.filter.threshold
    );
    assert!(cli.recipient("new@example.test").is_some());
}

#[tokio::test]
async fn configuration_reuses_loaded_lexical_artifact_until_explicit_restart() {
    use noisefence::{
        engine::{Algorithm, Model},
        features,
    };
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = (*common::config(dir.path())).clone();
    let path = dir.path().join("model.json");
    let mut model = Model {
        version: "ORIGINAL-TEST-ONLY".into(),
        algorithm: Algorithm::Logistic,
        feature_version: features::VERSION,
        bias: -4.0,
        weights: vec![0.0; features::DIMENSION],
        idf: vec![1.0; features::DIMENSION],
        trained_at: noisefence::now(),
        examples: 10,
    };
    std::fs::write(&path, serde_json::to_vec(&model).unwrap()).unwrap();
    cfg.filter.model = Some(path.clone());
    let cfg = Arc::new(cfg);
    let store = Store::open(dir.path()).unwrap();
    let token = account(&store, "admin", true, vec![]).await;
    let control = Controller::load(cfg.clone(), store.clone()).await.unwrap();
    let initial = control.snapshot().engine.offline(common::MESSAGE);
    model.version = "REPLACEMENT-TEST-ONLY".into();
    model.bias = 4.0;
    std::fs::write(&path, serde_json::to_vec(&model).unwrap()).unwrap();
    let mut settings = control.snapshot().settings.clone();
    settings.domains.push(ManagedDomain {
        name: "disabled.test".into(),
        gateway: Some(settings.gateways[0].id.clone()),
        enabled: false,
        accept_all_recipients: true,
        recipients: vec![],
        aliases: Default::default(),
    });
    control.apply(0, settings, "admin".into()).await.unwrap();
    let after = control.snapshot().engine.offline(common::MESSAGE);
    assert_eq!(after.model, initial.model);
    assert_eq!(after.score, initial.score);
    assert_eq!(
        after.evidence.unwrap().artifacts.lexical_model_sha256,
        initial.evidence.unwrap().artifacts.lexical_model_sha256
    );
    let app = api::router_controlled(cfg.clone(), store.clone(), Some(control)).unwrap();
    let (_, domains) = request(&app, &token, "/domains", None).await;
    assert_eq!(domains, json!(["example.test", "disabled.test"]));
    let restarted = Controller::load(cfg, store).await.unwrap();
    assert_ne!(
        restarted.snapshot().engine.offline(common::MESSAGE).model,
        initial.model
    );
}

#[tokio::test]
async fn protection_credentials_stay_private_and_policy_changes_preserve_the_score() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = (*common::config(dir.path())).clone();
    cfg.protection = Some(Default::default());
    let cfg = Arc::new(cfg);
    let store = Store::open(dir.path()).unwrap();
    let admin = account(&store, "admin", true, vec![]).await;
    let reader = account(&store, "reader", false, vec![]).await;
    let control = Controller::load(cfg.clone(), store.clone()).await.unwrap();
    let app = api::router_controlled(cfg.clone(), store.clone(), Some(control.clone())).unwrap();
    assert_eq!(
        request(&app, &reader, "/admin/protection", None).await.0,
        StatusCode::FORBIDDEN
    );
    let key = "synthetic-provider-key-123456789";
    assert_eq!(
        request(
            &app,
            &reader,
            "/admin/protection/keys/crdf",
            Some(json!({"key":key}))
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(
            &app,
            &admin,
            "/admin/protection/keys/other",
            Some(json!({"key":key}))
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        request(
            &app,
            &admin,
            "/admin/protection/keys/crdf",
            Some(json!({"key":"bad\r\nheader"}))
        )
        .await
        .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        request(
            &app,
            &admin,
            "/admin/protection/keys/crdf",
            Some(json!({"key":key}))
        )
        .await
        .0,
        StatusCode::OK
    );
    let (status, body) = request(&app, &admin, "/admin/protection", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["keys"]["crdf"], true);
    assert!(!body.to_string().contains(key));
    for path in ["/admin/config", "/admin/audit", "/admin/revisions"] {
        let (_, body) = request(&app, &admin, path, None).await;
        assert!(!body.to_string().contains(key));
    }
    let req = Request::builder()
        .uri("/api/v1/admin/protection/keys/crdf")
        .method("POST")
        .header("content-type", "application/json")
        .header("origin", "http://127.0.0.1:3000")
        .header("cookie", format!("noisefence_session={admin}"))
        .body(Body::from(json!({"key":key}).to_string()))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let old = control.snapshot().engine.offline(common::MESSAGE);
    let mut settings = control.snapshot().settings.clone();
    settings.protection.as_mut().unwrap().crdf = true;
    control.apply(0, settings, "admin".into()).await.unwrap();
    let new = control.snapshot().engine.offline(common::MESSAGE);
    assert_eq!(old.score, new.score);
    assert_eq!(old.features, new.features);
    assert!(new.protection.unwrap().observation_only);
    let resumed = Controller::load(cfg, store).await.unwrap();
    assert!(
        resumed
            .snapshot()
            .settings
            .protection
            .as_ref()
            .unwrap()
            .crdf
    );
}
