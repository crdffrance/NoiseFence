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

#[tokio::test]
async fn sensitivity_catalog_and_profiles_are_admin_only_atomic_and_persistent() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = common::config(dir.path());
    let store = Store::open(dir.path()).unwrap();
    let token = account(&store, "admin", true, vec![]).await;
    let reader = account(&store, "alice", false, vec!["alice@example.test"]).await;
    let control = Controller::load(cfg.clone(), store.clone()).await.unwrap();
    let app = api::router_controlled(cfg.clone(), store.clone(), Some(control.clone())).unwrap();
    let (status, view) = request(&app, &token, "/admin/config", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(view["sensitivity_locked"], false);
    assert_eq!(view["sensitivity_levels"].as_array().unwrap().len(), 5);
    let mut settings = view["settings"].clone();
    settings["custom_filtering"] = json!({"profiles":[{"id":"strict","name":"Strict","threshold":90.0,"require_corroboration":true,"spam":"quarantine","publicity":"deliver","review":"deliver","quarantine_days":14}],"bindings":[{"scope":"*","profile":"strict"}],"rules":[]});
    let payload = json!({"revision":0,"settings":settings});
    assert_eq!(
        request(&app, &reader, "/admin/config", Some(payload.clone()))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(&app, "", "/admin/config", Some(payload.clone()))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        request(&app, &token, "/admin/config", Some(payload.clone()))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        request(&app, &token, "/admin/config", Some(payload))
            .await
            .0,
        StatusCode::CONFLICT
    );
    let snapshot = control.snapshot();
    assert_eq!(snapshot.config.filter.threshold, cfg.filter.threshold);
    assert_eq!(snapshot.config.filter.mode, cfg.filter.mode);
    assert_eq!(
        serde_json::to_value(&snapshot.settings.filters).unwrap(),
        view["settings"]["filters"]
    );
    let resumed = Controller::load(cfg, store).await.unwrap();
    assert_eq!(
        resumed.snapshot().settings.custom_filtering,
        snapshot.settings.custom_filtering
    );
    let preview = json!({"policy":settings["custom_filtering"],"recipient":"alice@example.test","sender":"sender@example.org","subject":"Fixture","body":"Synthetic only","score":92.0});
    assert_eq!(
        request(
            &app,
            &reader,
            "/admin/filtering/preview",
            Some(preview.clone())
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let (status, simulated) =
        request(&app, &token, "/admin/filtering/preview", Some(preview)).await;
    assert_eq!(status, StatusCode::OK, "{simulated}");
    assert_eq!(simulated["assessment"]["category"], "undetermined");
    assert_eq!(simulated["assessment"]["threshold"], 90.0);
    assert_eq!(simulated["assessment"]["action"]["effective"], "deliver");
    settings["custom_filtering"]["profiles"][0]["threshold"] = json!(1);
    assert_eq!(
        request(
            &app,
            &token,
            "/admin/config",
            Some(json!({"revision":1,"settings":settings}))
        )
        .await
        .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(control.snapshot().revision, 1);
}

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
async fn confirmation_audit_is_aggregate_read_only_and_rechecks_human_grants() {
    use noisefence::{confirmation, fusion::runtime::Decision, llm};
    let dir = tempfile::tempdir().unwrap();
    let cfg = common::config(dir.path());
    let store = Store::open(dir.path()).unwrap();
    account(&store, "alice", false, vec!["alice@example.test"]).await;
    account(&store, "reviewer", true, vec![]).await;
    let mut ids = Vec::new();
    for (index, spam) in [false, false, false, false, true, true, true]
        .into_iter()
        .enumerate()
    {
        let id = uuid::Uuid::new_v4().to_string();
        let mut scan = extract(common::MESSAGE, 10000);
        scan.score = if index == 0 { 90. } else { 99. };
        scan.decision = Some(Decision::legacy(&scan, 95.));
        if index == 1 {
            scan.llm.status = llm::LlmStatus::Complete;
            scan.llm.verdict = Some(llm::Verdict {
                category: llm::Category::Legitimate,
                confidence: 0.95,
                spam_probability: 0.05,
                explanation: "Fixture".into(),
            });
        } else if spam {
            scan.llm.status = llm::LlmStatus::Complete;
            scan.llm.verdict = Some(llm::Verdict {
                category: llm::Category::Phishing,
                confidence: 0.95,
                spam_probability: 0.95,
                explanation: "Fixture".into(),
            });
        }
        store
            .enqueue(
                id.clone(),
                "PRIVATE SENDER".into(),
                vec![cfg.recipient("alice@example.test").unwrap()],
                scan,
                common::MESSAGE.to_vec(),
            )
            .await
            .unwrap();
        store
            .feedback("alice".into(), id.clone(), spam)
            .await
            .unwrap();
        ids.push(id);
    }
    let snapshot = || {
        let db = rusqlite::Connection::open_with_flags(
            dir.path().join("state.sqlite3"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let mut q = db.prepare("SELECT scan FROM messages ORDER BY id").unwrap();
        q.query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
    };
    let before = snapshot();
    let report = confirmation::audit(&dir.path().join("state.sqlite3")).unwrap();
    assert_eq!(report.evaluated, 7);
    assert_eq!(report.before.false_positives, 3);
    assert_eq!(report.with_confirmation.false_positives, 0);
    assert_eq!(report.with_confirmation.legitimate_to_review, 3);
    assert_eq!(report.with_confirmation.spam_detected, 0);
    assert_eq!(report.with_confirmation.spam_to_review, 3);
    assert_eq!(report.with_confirmation.legitimate, 1);
    assert_eq!(report.with_decision_policy.false_positives, 0);
    assert_eq!(report.with_decision_policy.legitimate_to_review, 3);
    assert_eq!(report.with_decision_policy.spam_detected, 0);
    assert_eq!(report.with_arbitration.false_positives, 2);
    assert_eq!(report.with_arbitration.legitimate_to_review, 1);
    assert_eq!(report.with_arbitration.spam_detected, 3);
    assert_eq!(report.recent.considered, 7);
    assert_eq!(
        report
            .recent
            .transitions
            .iter()
            .map(|t| t.count)
            .sum::<usize>(),
        7
    );
    let text = serde_json::to_string(&report).unwrap();
    assert!(!text.contains("PRIVATE") && !text.contains("alice") && !text.contains(&ids[0]));
    assert_eq!(before, snapshot());
    store
        .feedback("reviewer".into(), ids[0].clone(), true)
        .await
        .unwrap();
    let report = confirmation::audit(&dir.path().join("state.sqlite3")).unwrap();
    assert_eq!(report.conflicting, 1);
    assert_eq!(report.evaluated, 6);
    store
        .run(|db| {
            db.execute("UPDATE users SET disabled=1 WHERE username='reviewer'", [])?;
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(
        confirmation::audit(&dir.path().join("state.sqlite3"))
            .unwrap()
            .evaluated,
        7
    );
    store
        .run(|db| {
            db.execute("DELETE FROM grants WHERE username='alice'", [])?;
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(
        confirmation::audit(&dir.path().join("state.sqlite3"))
            .unwrap()
            .considered,
        0
    );
    let missing = dir.path().join("nonexistent.sqlite3");
    assert!(confirmation::audit(&missing).is_err());
    assert!(!missing.exists());
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
    assert!(!desired.filters.require_corroboration);
    desired.filters.require_corroboration = true;
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
async fn provider_quota_overrides_are_authorized_versioned_and_survive_reload() {
    use noisefence::protection::{Policy, Provider, Quota};
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = (*common::config(dir.path())).clone();
    cfg.protection = Some(noisefence::protection::Settings {
        crdf_per_minute: 17,
        crdf_per_day: 600,
        ..Default::default()
    });
    let cfg = Arc::new(cfg);
    let store = Store::open(dir.path()).unwrap();
    let admin = account(&store, "admin", true, vec![]).await;
    let reader = account(&store, "reader", false, vec![]).await;
    let control = Controller::load(cfg.clone(), store.clone()).await.unwrap();
    let app = api::router_controlled(cfg.clone(), store.clone(), Some(control.clone())).unwrap();
    let mut settings = serde_json::to_value(control.snapshot().settings.clone()).unwrap();
    // Older revisions have no quota fields and inherit the configured budget.
    settings["protection"]
        .as_object_mut()
        .unwrap()
        .remove("crdf_quota");
    settings["protection"]
        .as_object_mut()
        .unwrap()
        .remove("virustotal_quota");
    let old: noisefence::control::Settings = serde_json::from_value(settings.clone()).unwrap();
    assert!(
        serde_json::to_value(&old).unwrap()["protection"]
            .get("crdf_quota")
            .is_none()
    );
    let effective = old.effective(&cfg).unwrap();
    let protection = effective.protection.unwrap();
    assert_eq!(
        protection.quota(Provider::Crdf, &protection.policy),
        Quota {
            minute: 17,
            day: 600
        }
    );
    for bad in [
        json!({"minute":0}),
        json!({"minute":null,"day":0}),
        json!({"minute":-1,"day":0}),
        json!({"minute":1.5,"day":0}),
        json!({"minute":4294967296_u64,"day":0}),
    ] {
        let mut policy = json!({"crdf_quota":bad});
        assert!(serde_json::from_value::<Policy>(policy.take()).is_err());
    }
    settings["protection"]["crdf_quota"] = json!({"minute":0,"day":0});
    let body = json!({"revision":0,"settings":settings});
    assert_eq!(
        request(&app, &reader, "/admin/config", Some(body.clone()))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let req = Request::builder()
        .uri("/api/v1/admin/config")
        .method("POST")
        .header("content-type", "application/json")
        .header("origin", "http://127.0.0.1:3000")
        .header("cookie", format!("noisefence_session={admin}"))
        .body(Body::from(body.to_string()))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(&app, &admin, "/admin/config", Some(body.clone()))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        request(&app, &admin, "/admin/config", Some(body)).await.0,
        StatusCode::CONFLICT
    );
    let (_, state) = request(&app, &admin, "/admin/protection", None).await;
    assert_eq!(state["quotas"]["crdf"], json!({"minute":0,"day":0}));
    assert_eq!(
        state["bootstrap_quotas"]["crdf"],
        json!({"minute":17,"day":600})
    );
    assert_eq!(state["quotas"]["virustotal"], json!({"minute":4,"day":500}));
    assert_eq!(state["usage"]["crdf"]["day_used"], 0);
    let resumed = Controller::load(cfg, store).await.unwrap();
    assert_eq!(
        resumed
            .snapshot()
            .settings
            .protection
            .as_ref()
            .unwrap()
            .crdf_quota,
        Some(Quota { minute: 0, day: 0 })
    );
    let revision = resumed.snapshot().revision;
    resumed.apply(revision, old, "admin".into()).await.unwrap();
    let snapshot = resumed.snapshot();
    let protection = snapshot.config.protection.as_ref().unwrap();
    assert_eq!(
        protection.quota(Provider::Crdf, &protection.policy),
        Quota {
            minute: 17,
            day: 600
        }
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
    settings.protection.as_mut().unwrap().follow_urls = true;
    control.apply(0, settings, "admin".into()).await.unwrap();
    let new = control.snapshot().engine.offline(common::MESSAGE);
    assert_eq!(old.score, new.score);
    assert_eq!(old.features, new.features);
    assert!(new.protection.unwrap().observation_only);
    let resumed = Controller::load(cfg, store).await.unwrap();
    assert!(
        resumed
            .snapshot()
            .config
            .protection
            .as_ref()
            .unwrap()
            .policy
            .follow_urls
    );
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

#[tokio::test]
async fn publicity_filters_stats_feedback_and_bcc_obey_security_decision_and_acl() {
    use noisefence::{
        fusion::runtime::{Decision, DecisionSource, Outcome},
        mailing::{self, Policy},
    };
    let dir = tempfile::tempdir().unwrap();
    let cfg = common::config(dir.path());
    let store = Store::open(dir.path()).unwrap();
    let alice = account(&store, "alice", false, vec!["alice@example.test"]).await;
    let bob = account(&store, "bob", false, vec!["bob@example.test"]).await;
    let raw=b"From: a@example.org\r\nSubject: Weekly newsletter\r\nList-ID: News <news.example.org>\r\n\r\nHello.\r\n";
    let mut public_id = String::new();
    let mut hidden_id = String::new();
    for (name, outcome, complete, pub_candidate, addresses) in [
        (
            "publicity",
            Outcome::Legitimate,
            true,
            true,
            vec!["alice@example.test", "bob@example.test"],
        ),
        (
            "spam",
            Outcome::Unwanted,
            true,
            true,
            vec!["alice@example.test"],
        ),
        (
            "legitimate",
            Outcome::Legitimate,
            true,
            false,
            vec!["alice@example.test"],
        ),
        (
            "incomplete",
            Outcome::Undetermined,
            false,
            true,
            vec!["alice@example.test"],
        ),
        (
            "review",
            Outcome::Undetermined,
            true,
            true,
            vec!["alice@example.test"],
        ),
        (
            "hidden",
            Outcome::Legitimate,
            true,
            true,
            vec!["bob@example.test"],
        ),
    ] {
        let id = uuid::Uuid::new_v4().to_string();
        if name == "publicity" {
            public_id = id.clone();
        }
        if name == "hidden" {
            hidden_id = id.clone();
        }
        let mut scan = extract(raw, 10000);
        scan.subject = name.into();
        scan.complete = complete;
        scan.score = 99.;
        scan.decision = Some(Decision {
            source: DecisionSource::Fusion,
            outcome,
            score: complete.then_some(99.),
            model: "TEST ONLY".into(),
        });
        if pub_candidate {
            scan.mailing = Some(mailing::inspect(raw, &Policy::default(), 10000));
        }
        store
            .enqueue(
                id,
                "a@example.org".into(),
                addresses
                    .into_iter()
                    .map(|a| cfg.recipient(a).unwrap())
                    .collect(),
                scan,
                raw.to_vec(),
            )
            .await
            .unwrap();
    }
    let app = api::router(cfg, store.clone()).unwrap();
    for (filter, category) in [
        ("publicity", "publicity"),
        ("spam", "spam"),
        ("legitimate", "legitimate"),
        ("incomplete", "undetermined"),
        ("review", "undetermined"),
    ] {
        let (code, body) = request(&app, &alice, &format!("/messages?filter={filter}"), None).await;
        assert_eq!(code, StatusCode::OK, "{body}");
        let rows = body.as_array().unwrap();
        assert_eq!(rows.len(), 1, "{body}");
        assert_eq!(rows[0]["category"], category);
        assert!(!body.to_string().contains("bob@example.test"));
    }
    let (_, stats) = request(&app, &alice, "/stats", None).await;
    assert_eq!(stats["received"], 5);
    assert_eq!(stats["publicity"], 1);
    let (code, signals) = request(&app, &alice, "/messages?filter=publicity_signal", None).await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(signals.as_array().unwrap().len(), 4);
    assert!(!signals.to_string().contains("bob@example.test"));
    let (_, hidden_signals) = request(
        &app,
        &alice,
        "/messages?filter=publicity_signal&domain=elsewhere.test",
        None,
    )
    .await;
    assert_eq!(hidden_signals, serde_json::json!([]));
    assert_eq!(stats["flagged"], 1);
    let path = format!("/messages/{public_id}/feedback");
    assert_eq!(
        request(&app, &alice, &path, Some(json!({"category":"publicity"})))
            .await
            .0,
        StatusCode::OK
    );
    let (_, rows) = request(&app, &alice, "/messages?filter=publicity", None).await;
    assert_eq!(rows[0]["feedback_category"], "publicity");
    assert_eq!(rows[0]["feedback"], false);
    let (_, rows) = request(&app, &bob, "/messages?filter=publicity", None).await;
    assert!(
        rows.as_array()
            .unwrap()
            .iter()
            .all(|r| r["feedback_category"].is_null())
    );
    assert_eq!(
        request(
            &app,
            &alice,
            &format!("/messages/{hidden_id}/feedback"),
            Some(json!({"category":"publicity"}))
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    for data in [json!({}), json!({"category":"publicity","spam":true})] {
        assert_eq!(
            request(&app, &alice, &path, Some(data)).await.0,
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        request(&app, &alice, &path, Some(json!({"category":"invalid"})))
            .await
            .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    // A legacy client updating the same false vote must invalidate the explicit subtype.
    assert_eq!(
        request(&app, &alice, &path, Some(json!({"spam":false})))
            .await
            .0,
        StatusCode::OK
    );
    let (_, rows) = request(&app, &alice, "/messages?filter=publicity", None).await;
    assert!(rows[0]["feedback_category"].is_null());
    assert_eq!(
        request(&app, &alice, &path, Some(json!({"category":"legitimate"})))
            .await
            .0,
        StatusCode::OK
    );
    let (_, rows) = request(&app, &alice, "/messages?filter=publicity", None).await;
    assert_eq!(rows[0]["feedback_category"], "legitimate");
    assert_eq!(rows[0]["category"], "publicity");
    store
        .run(move |db| {
            db.execute("DELETE FROM messages WHERE id=?1", [public_id])?;
            let count: i64 =
                db.query_row("SELECT count(*) FROM feedback_categories", [], |r| r.get(0))?;
            assert_eq!(count, 0);
            Ok(())
        })
        .await
        .unwrap();
}

async fn held_message(store: &Store, cfg: &noisefence::config::Config) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    let mut scan = extract(common::MESSAGE, 10000);
    scan.score = 99.;
    scan.action = Some(noisefence::actions::Applied {
        requested: noisefence::actions::Action::Quarantine,
        effective: noisefence::actions::Action::Quarantine,
        reason: "category".into(),
        quarantine_days: 14,
    });
    store
        .enqueue(
            id.clone(),
            "sender@example.org".into(),
            ["alice@example.test", "bob@example.test"]
                .map(|a| cfg.recipient(a).unwrap())
                .to_vec(),
            scan,
            common::MESSAGE.to_vec(),
        )
        .await
        .unwrap();
    id
}

#[tokio::test]
async fn quarantine_is_durable_and_recipient_actions_recheck_acl_session_and_state() {
    let root = tempfile::tempdir().unwrap();
    let cfg = common::config(root.path());
    let store = Store::open(root.path()).unwrap();
    let alice = account(&store, "alice", false, vec!["alice@example.test"]).await;
    let bob = account(&store, "bob", false, vec!["bob@example.test"]).await;
    let admin = account(&store, "admin", true, vec![]).await;
    let id = held_message(&store, &cfg).await;
    assert!(store.claim().await.unwrap().is_none());
    store.cleanup().await.unwrap();
    drop(store);
    let store = Store::open(root.path()).unwrap();
    store.recover().await.unwrap();
    assert!(store.raw_path(&id).is_file());
    assert!(store.claim().await.unwrap().is_none());
    let app = api::router(cfg, store.clone()).unwrap();
    let (code, list) = request(&app, &alice, "/messages?filter=quarantined", None).await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert_eq!(list[0]["recipients"].as_array().unwrap().len(), 1);
    assert_eq!(list[0]["recipients"][0]["address"], "alice@example.test");
    assert!(list[0]["recipients"][0]["held_until"].as_i64().unwrap() > noisefence::now());
    let (_, stats) = request(&app, &alice, "/stats", None).await;
    assert_eq!(stats["quarantined"], 1);
    assert_eq!(stats["pending"], 0);
    let path = format!("/messages/{id}/quarantine");
    for command in ["release", "delete"] {
        assert_eq!(
            request(
                &app,
                &alice,
                &path,
                Some(json!({"recipient":"bob@example.test","action":command}))
            )
            .await
            .0,
            StatusCode::NOT_FOUND
        );
    }
    // Mutation routes require CSRF, including for an authenticated administrator.
    let req = Request::builder()
        .uri(format!("/api/v1{path}"))
        .method("POST")
        .header("cookie", format!("noisefence_session={admin}"))
        .header("origin", "http://127.0.0.1:3000")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"recipient":"alice@example.test","action":"release"}).to_string(),
        ))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    // Late release gets a fresh delivery retry lifetime; history stays unchanged.
    store
        .run(|db| {
            db.execute(
                "UPDATE messages SET created=?1",
                [noisefence::now() - 20 * 86400],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    let response = request(
        &app,
        &alice,
        &path,
        Some(json!({"recipient":"alice@example.test","action":"release"})),
    )
    .await;
    assert_eq!(response.0, StatusCode::OK);
    assert_eq!(response.1["status"], "pending");
    assert_eq!(
        request(
            &app,
            &alice,
            &path,
            Some(json!({"recipient":"alice@example.test","action":"release"}))
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let job = store.claim().await.unwrap().unwrap();
    assert_eq!(job.destination, "alice@example.test");
    assert!(job.created >= noisefence::now() - 2);
    store.finish(&job, "delivered", "", 0).await.unwrap();
    store.cleanup().await.unwrap();
    assert!(store.raw_path(&id).is_file()); // Bob's hidden copy is still retained.
    assert_eq!(
        request(&app, &alice, "/messages?filter=quarantined", None)
            .await
            .1,
        json!([])
    );
    let hash = noisefence::message::digest(bob.as_bytes());
    store
        .run(|db| {
            db.execute("DELETE FROM grants WHERE username='bob'", [])?;
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(
        request(
            &app,
            &bob,
            &path,
            Some(json!({"recipient":"bob@example.test","action":"delete"}))
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert!(matches!(
        store
            .quarantine_action(
                "bob".into(),
                hash,
                id.clone(),
                "bob@example.test".into(),
                noisefence::quarantine::Command::Release
            )
            .await
            .unwrap(),
        noisefence::quarantine::Change::NotFound
    ));
    assert_eq!(
        request(
            &app,
            &admin,
            &path,
            Some(json!({"recipient":"bob@example.test","action":"delete"}))
        )
        .await
        .0,
        StatusCode::OK
    );
    store.cleanup().await.unwrap();
    assert!(!store.raw_path(&id).is_file());
    assert!(store.claim().await.unwrap().is_none());
    let (_, metrics) = request(&app, &admin, "/metrics", None).await;
    assert_eq!(metrics["quarantined_deliveries"], 0);
    store.run(|db|{
        assert_eq!(db.query_row("SELECT COUNT(*) FROM audit WHERE action IN ('quarantine_release','quarantine_delete')",[],|r|r.get::<_,i64>(0))?,2);
        assert_eq!(db.query_row("PRAGMA user_version",[],|r|r.get::<_,i64>(0))?,2);
        Ok(())
    }).await.unwrap();
}

#[tokio::test]
async fn quarantine_expiry_never_releases_mail_and_expired_sessions_cannot_mutate() {
    let root = tempfile::tempdir().unwrap();
    let cfg = common::config(root.path());
    let store = Store::open(root.path()).unwrap();
    let token = account(&store, "admin", true, vec![]).await;
    let id = held_message(&store, &cfg).await;
    store
        .run(|db| {
            db.execute("UPDATE sessions SET expires=?1", [noisefence::now() - 1])?;
            Ok(())
        })
        .await
        .unwrap();
    assert!(matches!(
        store
            .quarantine_action(
                "admin".into(),
                noisefence::message::digest(token.as_bytes()),
                id.clone(),
                "alice@example.test".into(),
                noisefence::quarantine::Command::Release
            )
            .await
            .unwrap(),
        noisefence::quarantine::Change::NotFound
    ));
    store
        .run(|db| {
            db.execute(
                "UPDATE delivery_policy SET held_until=?1",
                [noisefence::now() - 1],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    store.cleanup().await.unwrap();
    store.cleanup().await.unwrap();
    assert!(store.claim().await.unwrap().is_none());
    assert!(!store.raw_path(&id).is_file());
    store
        .run(|db| {
            assert_eq!(
                db.query_row(
                    "SELECT COUNT(*) FROM deliveries WHERE status='expired'",
                    [],
                    |r| r.get::<_, i64>(0)
                )?,
                2
            );
            assert_eq!(
                db.query_row(
                    "SELECT COUNT(*) FROM audit WHERE action='quarantine_expire'",
                    [],
                    |r| r.get::<_, i64>(0)
                )?,
                2
            );
            Ok(())
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn console_persists_actions_and_rule_weights_without_reclassifying_accepted_mail() {
    let root = tempfile::tempdir().unwrap();
    let cfg = common::config(root.path());
    let store = Store::open(root.path()).unwrap();
    let token = account(&store, "admin", true, vec![]).await;
    let id = held_message(&store, &cfg).await;
    let control = Controller::load(cfg.clone(), store.clone()).await.unwrap();
    let app = api::router_controlled(cfg.clone(), store.clone(), Some(control.clone())).unwrap();
    let (_, view) = request(&app, &token, "/admin/config", None).await;
    assert_eq!(view["rules"].as_array().unwrap().len(), 8);
    assert_eq!(view["tag_ready"], false);
    let mut settings = view["settings"].clone();
    settings["filters"]["mode"] = json!("enforce");
    settings["filters"]["rule_weights"] = json!({"urgency":0.0,"financial_lure":2.0});
    settings["actions"] = json!({"spam":"quarantine","publicity":"deliver","malware":"quarantine","quarantine_days":2});
    let (code, value) = request(
        &app,
        &token,
        "/admin/config",
        Some(json!({"revision":0,"settings":settings})),
    )
    .await;
    assert_eq!(code, StatusCode::OK, "{value}");
    assert_eq!(control.snapshot().config.filter.rule_weights["urgency"], 0.);
    let restored = Controller::load(cfg.clone(), store.clone()).await.unwrap();
    assert_eq!(restored.snapshot().settings, control.snapshot().settings);
    assert_eq!(
        noisefence::control::effective_from_disk(cfg)
            .unwrap()
            .actions,
        control.snapshot().config.actions
    );
    let rows = store
        .list("admin".into(), "".into(), "quarantined".into(), 0, 95.)
        .await
        .unwrap();
    assert_eq!(rows[0].id, id);
    assert!(rows[0].recipients[0].held_until.unwrap() > noisefence::now() + 13 * 86400);
    settings["filters"]["rule_weights"] = json!({"malware_priority":0.0});
    assert_eq!(
        request(
            &app,
            &token,
            "/admin/config",
            Some(json!({"revision":1,"settings":settings}))
        )
        .await
        .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(control.snapshot().revision, 1);
}

#[tokio::test]
async fn quality_sampling_and_dual_labels_enforce_sessions_csrf_and_recipient_access() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = common::config(dir.path());
    let store = Store::open(dir.path()).unwrap();
    let alice = account(&store, "alice", false, vec!["alice@example.test"]).await;
    let bob = account(&store, "bob", false, vec!["bob@example.test"]).await;
    let id = message(&store, &cfg, &["alice@example.test"]).await;
    let foreign = message(&store, &cfg, &["bob@example.test"]).await;
    store
        .run(|db| {
            db.execute("UPDATE messages SET created=created-5", [])?;
            Ok(())
        })
        .await
        .unwrap();
    let app = api::router(cfg.clone(), store.clone()).unwrap();
    let now = noisefence::now();
    assert_eq!(
        request(&app, "", "/quality/samples", None).await.0,
        StatusCode::UNAUTHORIZED
    );
    let (status, result) = request(
        &app,
        &alice,
        "/quality/samples",
        Some(json!({"since":now-1000,"until":now,"count":25,"domain":"example.test"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let path = format!("/quality/samples/{}", result["id"].as_str().unwrap());
    let (status, rows) = request(&app, &alice, &path, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(rows.as_array().unwrap().len(), 1);
    assert_eq!(rows[0]["id"], id);
    assert!(rows[0].get("score").is_none());
    assert_eq!(
        request(&app, &bob, &path, None).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        request(
            &app,
            &alice,
            &format!("/messages/{foreign}/quality-label"),
            Some(json!({"risk":"spam","kind":"promotion"}))
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let bad = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/messages/{id}/quality-label"))
        .header("content-type", "application/json")
        .header("cookie", format!("noisefence_session={alice}"))
        .header("origin", "http://127.0.0.1:3000")
        .header("x-csrf-token", "wrong")
        .body(Body::from(
            json!({"risk":"legitimate","kind":"notification"}).to_string(),
        ))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(bad).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(
            &app,
            &alice,
            &format!("/messages/{id}/quality-label"),
            Some(json!({"risk":"legitimate","kind":"notification"}))
        )
        .await
        .0,
        StatusCode::OK
    );
    let (_, rows) = request(&app, &alice, &path, None).await;
    assert_eq!(rows[0]["kind"], "notification");
    assert_eq!(
        request(
            &app,
            &alice,
            &format!("/messages/{id}/quality-label"),
            Some(json!({"risk":"legitimate","kind":"invalid"}))
        )
        .await
        .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let (status, _) = request(
        &app,
        &alice,
        &format!("/messages/{id}/feedback"),
        Some(json!({"category":"spam"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, rows) = request(&app, &alice, &path, None).await;
    assert!(
        rows[0]["risk"].is_null(),
        "A later old-style correction invalidates its prior dual annotation"
    );
}

#[tokio::test]
async fn web_detection_parameters_are_validated_hot_applied_and_restored_without_paths_or_keys() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = (*common::config(dir.path())).clone();
    cfg.native_filter = Some(Default::default());
    cfg.smtp_policy = Some(Default::default());
    cfg.vision = Some(Default::default());
    cfg.protection = Some(Default::default());
    let cfg = Arc::new(cfg);
    let store = Store::open(dir.path()).unwrap();
    let admin = account(&store, "admin", true, vec![]).await;
    let control = Controller::load(cfg.clone(), store.clone()).await.unwrap();
    let app = api::router_controlled(cfg.clone(), store.clone(), Some(control.clone())).unwrap();
    let (_, view) = request(&app, &admin, "/admin/config", None).await;
    let mut settings = view["settings"].clone();
    let raw = settings["detection"].to_string();
    for forbidden in [
        "socket",
        "bayes_model",
        "api_key_env",
        "encoder_dir",
        "data_dir",
    ] {
        assert!(!raw.contains(forbidden), "{forbidden}");
    }
    settings["detection"]["modules"]["native"]["timeout_ms"] = json!(800);
    settings["detection"]["modules"]["native"]["max_parallel"] = json!(1);
    settings["detection"]["modules"]["native"]["content_rules"]["disabled"] =
        json!(["NF_HTML_PASSWORD_FORM"]);
    settings["detection"]["modules"]["vision"]["max_parts"] = json!(3);
    settings["detection"]["modules"]["smtp_policy"]["timeout_ms"] = json!(500);
    settings["detection"]["modules"]["protection"]["url_resolution"]["max_redirects"] = json!(2);
    settings["rbl"]["timeout_ms"] = json!(900);
    let result = request(
        &app,
        &admin,
        "/admin/config",
        Some(json!({"revision":0,"settings":settings})),
    )
    .await;
    assert_eq!(result.0, StatusCode::OK, "{}", result.1);
    let s = control.snapshot();
    assert_eq!(s.config.native_filter.as_ref().unwrap().timeout_ms, 800);
    assert_eq!(s.config.vision.as_ref().unwrap().max_parts, 3);
    assert_eq!(
        s.config
            .protection
            .as_ref()
            .unwrap()
            .url_resolution
            .max_redirects,
        2
    );
    let resumed = Controller::load(cfg.clone(), store.clone()).await.unwrap();
    assert_eq!(resumed.snapshot().settings, s.settings);
    let mut bad = settings.clone();
    bad["detection"]["modules"]["vision"]["socket"] = json!("/tmp/exfil.sock");
    assert_eq!(
        request(
            &app,
            &admin,
            "/admin/config/validate",
            Some(json!({"settings":bad}))
        )
        .await
        .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let mut bad = settings.clone();
    bad["detection"]["modules"]["native"]["content_rules"]["weights"] =
        json!({"NF_HTML_PASSWORD_FORM":999});
    assert_eq!(
        request(
            &app,
            &admin,
            "/admin/config",
            Some(json!({"revision":s.revision,"settings":bad}))
        )
        .await
        .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(control.snapshot().revision, s.revision);
}

#[tokio::test]
async fn preferences_are_scoped_revocable_durable_and_cannot_update_global_settings() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = common::config(dir.path());
    let store = Store::open(dir.path()).unwrap();
    let admin = account(&store, "admin", true, vec![]).await;
    let alice = account(&store, "alice", false, vec!["alice@example.test"]).await;
    let bob = account(&store, "bob", false, vec!["bob@example.test"]).await;
    let control = Controller::load(cfg.clone(), store.clone()).await.unwrap();
    let app = api::router_controlled(cfg.clone(), store.clone(), Some(control.clone())).unwrap();
    let preference = json!({"profile":{"id":"personal","name":"Personnel","threshold":95.0,"require_corroboration":true,"spam":"quarantine","publicity":"deliver","review":"deliver","quarantine_days":14},"rules":[]});
    let edit =
        |revision, scope: &str, p: Value| json!({"revision":revision,"scope":scope,"preference":p});
    for scope in [
        "*",
        "*@example.test",
        "bob@example.test",
        "alice@foreign.test",
    ] {
        assert_eq!(
            request(
                &app,
                &alice,
                "/preferences",
                Some(edit(0, scope, preference.clone()))
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
    }
    let mut bad = preference.clone();
    bad["profile"]["threshold"] = json!(60);
    assert_eq!(
        request(
            &app,
            &alice,
            "/preferences",
            Some(edit(0, "alice@example.test", bad))
        )
        .await
        .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let result = request(
        &app,
        &alice,
        "/preferences",
        Some(edit(0, "alice@example.test", preference.clone())),
    )
    .await;
    assert_eq!(result.0, StatusCode::OK, "{}", result.1);
    let id = result.1["revision"].as_i64().unwrap();
    assert_eq!(
        request(
            &app,
            &alice,
            "/preferences",
            Some(edit(0, "alice@example.test", preference.clone()))
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let (_, visible) = request(&app, &alice, "/preferences", None).await;
    assert_eq!(
        visible["settings"]["mailboxes"]["alice@example.test"],
        preference
    );
    assert!(!visible.to_string().contains("bob@example.test"));
    let (_, hidden) = request(&app, &bob, "/preferences", None).await;
    assert_eq!(hidden["settings"]["mailboxes"], json!({}));
    assert!(!hidden.to_string().contains("alice@example.test"));
    assert_eq!(
        control.snapshot().config.filter.threshold,
        cfg.filter.threshold
    );
    assert_eq!(control.snapshot().config.filter.mode, cfg.filter.mode);
    assert_eq!(
        Controller::load(cfg.clone(), store.clone())
            .await
            .unwrap()
            .snapshot()
            .settings
            .preferences,
        control.snapshot().settings.preferences
    );
    store
        .run(|db| {
            db.execute("DELETE FROM grants WHERE username='alice'", [])?;
            Ok(())
        })
        .await
        .unwrap();
    assert!(
        control
            .apply_preferences(
                id,
                "alice@example.test".into(),
                None,
                "alice".into(),
                noisefence::message::digest(alice.as_bytes())
            )
            .await
            .is_err()
    );
    assert_eq!(
        request(
            &app,
            &alice,
            "/preferences",
            Some(edit(id, "alice@example.test", Value::Null))
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let (_, mut global) = request(&app, &admin, "/admin/config", None).await;
    global["settings"]["preferences"]["enabled"] = json!(false);
    let result = request(
        &app,
        &admin,
        "/admin/config",
        Some(json!({"revision":id,"settings":global["settings"]})),
    )
    .await;
    assert_eq!(result.0, StatusCode::OK);
    assert_eq!(
        request(
            &app,
            &bob,
            "/preferences",
            Some(edit(
                result.1["revision"].as_i64().unwrap(),
                "bob@example.test",
                preference
            ))
        )
        .await
        .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
}

#[tokio::test]
async fn old_revisions_inherit_bootstrap_rbl_while_explicit_empty_lists_survive_restart() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = (*common::config(dir.path())).clone();
    cfg.rbl=Some(serde_json::from_value(json!({"lists":[{"id":"psbl","provider":"psbl","zone":"psbl.surriel.com","listed_codes":["127.0.0.2"]}]})).unwrap());
    let cfg = Arc::new(cfg);
    let store = Store::open(dir.path()).unwrap();
    account(&store, "admin", true, vec![]).await;
    let mut old = serde_json::to_value(noisefence::control::Settings::from_config(&cfg)).unwrap();
    for k in ["rbl", "detection", "preferences"] {
        old.as_object_mut().unwrap().remove(k);
    }
    store
        .run(move |db| {
            db.execute(
                "INSERT INTO console_revisions(created,username,settings) VALUES(0,'admin',?1)",
                [old.to_string()],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    let control = Controller::load(cfg.clone(), store.clone()).await.unwrap();
    assert_eq!(
        control
            .snapshot()
            .settings
            .rbl
            .as_ref()
            .unwrap()
            .lists
            .len(),
        1
    );
    assert!(control.snapshot().settings.rbl.as_ref().unwrap().lists[0].enabled);
    let mut settings = control.snapshot().settings.clone();
    settings.rbl.as_mut().unwrap().lists.clear();
    let id = control.snapshot().revision;
    control.apply(id, settings, "admin".into()).await.unwrap();
    assert!(
        Controller::load(cfg, store)
            .await
            .unwrap()
            .snapshot()
            .config
            .rbl
            .as_ref()
            .unwrap()
            .lists
            .is_empty()
    );
}

#[tokio::test]
async fn managed_keys_are_private_admin_only_and_cannot_leak_in_configuration_or_audit() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let cfg = common::config(dir.path());
    let store = Store::open(dir.path()).unwrap();
    let admin = account(&store, "admin", true, vec![]).await;
    let user = account(&store, "alice", false, vec!["alice@example.test"]).await;
    let control = Controller::load(cfg.clone(), store.clone()).await.unwrap();
    let app = api::router_controlled(cfg, store.clone(), Some(control.clone())).unwrap();
    let invalid = request(
        &app,
        &admin,
        "/admin/keys",
        Some(json!({"revision":0,"provider":"spamhaus","key":"bad"})),
    )
    .await;
    assert_eq!(invalid.0, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(!dir.path().join("credentials/spamhaus.key").exists());
    let key = "SYNTHETIC_DQS_KEY_123456".replace('_', "");
    let body = json!({"revision":0,"provider":"spamhaus","key":key});
    assert_eq!(
        request(&app, &user, "/admin/keys", Some(body.clone()))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let saved = request(&app, &admin, "/admin/keys", Some(body)).await;
    assert_eq!(saved.0, StatusCode::OK, "{}", saved.1);
    assert_eq!(saved.1["active"], true);
    let (_, view) = request(&app, &admin, "/admin/config", None).await;
    assert_eq!(view["available"]["reputation"], true);
    assert_eq!(view["settings"]["filters"]["reputation"], false);
    assert!(!view.to_string().contains(&key));
    let (_, audit) = request(&app, &admin, "/admin/audit", None).await;
    assert!(!audit.to_string().contains(&key));
    assert_eq!(
        std::fs::metadata(dir.path().join("credentials/spamhaus.key"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let mut settings = view["settings"].clone();
    settings["filters"]["reputation"] = json!(true);
    let result = request(
        &app,
        &admin,
        "/admin/config",
        Some(json!({"revision":view["revision"],"settings":settings})),
    )
    .await;
    assert_eq!(result.0, StatusCode::OK, "{}", result.1);
    assert_eq!(
        control.snapshot().config.filter.spamhaus_key_env.as_deref(),
        Some(noisefence::management::WEB_DQS)
    );
}

#[tokio::test]
async fn configuration_apply_rechecks_the_administrative_session_at_commit() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = common::config(dir.path());
    let store = Store::open(dir.path()).unwrap();
    let token = account(&store, "admin", true, vec![]).await;
    let hash = noisefence::message::digest(token.as_bytes());
    let control = Controller::load(cfg, store.clone()).await.unwrap();
    let mut settings = control.snapshot().settings.clone();
    settings.filters.threshold = 96.;
    store
        .run(|db| {
            db.execute("DELETE FROM sessions WHERE username='admin'", [])?;
            Ok(())
        })
        .await
        .unwrap();
    assert!(
        control
            .apply_session(0, settings, "admin".into(), hash)
            .await
            .is_err()
    );
    assert_eq!(control.snapshot().revision, 0);
}
