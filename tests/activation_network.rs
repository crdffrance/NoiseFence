mod common;
use axum::{
    middleware::{self, Next},
    response::IntoResponse,
};
use noisefence::{
    api,
    cluster::{
        self, Role,
        activation::{Journal, Phase, Progress},
        artifacts, protocol,
    },
    control::Controller,
    engine,
    store::Store,
};
use rusqlite::params;
use serde_json::{Value, json};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{net::TcpListener, sync::watch, task::JoinHandle};

async fn account(store: &Store, name: &str, admin: bool) -> String {
    let token = api::random_token();
    let hash = noisefence::message::digest(token.as_bytes());
    let name = name.to_owned();
    store
        .run(move |db| {
            db.execute(
                "INSERT INTO users VALUES(?1,'unused-test-password',?2,0)",
                params![name, admin],
            )?;
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
fn config(root: &std::path::Path, worker: bool, url: &str) -> Arc<noisefence::config::Config> {
    let mut c = (*common::config(root)).clone();
    c.hostname = if worker {
        "mx2.example.test"
    } else {
        "mx1.example.test"
    }
    .into();
    c.cluster = Some(cluster::Settings {
        role: if worker {
            Role::Worker
        } else {
            Role::Coordinator
        },
        node_id: if worker { "mx2" } else { "mx1" }.into(),
        coordinator_url: worker.then(|| url.into()),
        credential_file: worker.then(|| root.join("identity")),
        poll_seconds: 2,
        max_stale_seconds: 60,
        allow_loopback_http: true,
    });
    Arc::new(c)
}
struct Harness {
    _central_root: tempfile::TempDir,
    _remote_root: tempfile::TempDir,
    central: Arc<Controller>,
    worker: Arc<Controller>,
    client: reqwest::Client,
    url: String,
    admin: String,
    identity: String,
    outage: Arc<AtomicBool>,
    legacy_only: Arc<AtomicBool>,
    legacy_calls: Arc<AtomicUsize>,
    lose_reply: Arc<AtomicBool>,
    stop: watch::Sender<bool>,
    server: JoinHandle<()>,
    jobs: Vec<JoinHandle<anyhow::Result<()>>>,
}
impl Harness {
    async fn new(model: bool, start_worker: bool) -> Self {
        Self::with_crdf(model, start_worker, None).await
    }
    async fn with_crdf(model: bool, start_worker: bool, key: Option<&str>) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let mut ca = (*config(a.path(), false, &url)).clone();
        if let Some(key) = key {
            ca.protection = Some(Default::default());
            noisefence::protection::save_key(a.path(), noisefence::protection::Provider::Crdf, key)
                .unwrap();
        }
        if model {
            let path = a.path().join("source-model.json");
            let model = engine::Model {
                version: "network-activation-fixture".into(),
                algorithm: engine::Algorithm::Logistic,
                feature_version: 1,
                bias: -4.,
                weights: vec![0.; engine::FEATURE_COUNT],
                idf: vec![],
                trained_at: noisefence::now(),
                examples: 2,
            };
            std::fs::write(&path, serde_json::to_vec(&model).unwrap()).unwrap();
            ca.filter.model = Some(path);
        }
        let ca = Arc::new(ca);
        let cb = config(b.path(), true, &url);
        let sa = Store::open(a.path()).unwrap();
        cluster::prepare(&ca, &sa).await.unwrap();
        let sb = Store::open(b.path()).unwrap();
        cluster::prepare(&cb, &sb).await.unwrap();
        let admin = account(&sa, "admin", true).await;
        let identity = api::random_token();
        let hash = noisefence::message::digest(identity.as_bytes());
        sa.run(move|db|{db.execute("INSERT INTO cluster_nodes(id,name,token_hash,created) VALUES('mx2','Secondary',?1,?2)",params![hash,noisefence::now()])?;Ok(())}).await.unwrap();
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
        let central = Controller::load(ca.clone(), sa.clone()).await.unwrap();
        let worker = Controller::load(cb, sb).await.unwrap();
        let outage = Arc::new(AtomicBool::new(false));
        let legacy_only = Arc::new(AtomicBool::new(false));
        let legacy_calls = Arc::new(AtomicUsize::new(0));
        let legacy = legacy_only.clone();
        let calls = legacy_calls.clone();
        let lose_reply = Arc::new(AtomicBool::new(false));
        let blocked = outage.clone();
        let lost = lose_reply.clone();
        let router = api::router_controlled(ca, sa, Some(central.clone()))
            .unwrap()
            .layer(middleware::from_fn(
                move |request: axum::extract::Request, next: Next| {
                    let blocked = blocked.clone();
                    let lost = lost.clone();
                    let legacy = legacy.clone();
                    let calls = calls.clone();
                    async move {
                        let sync = request.uri().path() == "/api/v1/cluster/v2/sync";
                        if request.uri().path() == "/api/v1/cluster/v1/sync" {
                            calls.fetch_add(1, Ordering::SeqCst);
                        }
                        if sync && legacy.load(Ordering::SeqCst) {
                            return axum::http::StatusCode::METHOD_NOT_ALLOWED.into_response();
                        }
                        if sync && blocked.load(Ordering::SeqCst) {
                            return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
                        }
                        let response = next.run(request).await;
                        if sync && lost.swap(false, Ordering::SeqCst) {
                            axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response()
                        } else {
                            response
                        }
                    }
                },
            ));
        let (stop, mut stopped) = watch::channel(false);
        let server = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    let _ = stopped.changed().await;
                })
                .await
                .unwrap();
        });
        let mut h = Self {
            _central_root: a,
            _remote_root: b,
            central,
            worker,
            client: reqwest::Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap(),
            url,
            admin,
            identity,
            outage,
            legacy_only,
            legacy_calls,
            lose_reply,
            stop,
            server,
            jobs: vec![],
        };
        if start_worker {
            h.jobs.push(tokio::spawn(cluster::run(
                h.worker.clone(),
                h.stop.subscribe(),
            )));
            h.ready_peer().await;
        }
        h
    }
    async fn ready_peer(&self) {
        let digest = self
            .central
            .publication()
            .await
            .unwrap()
            .bundle
            .digest
            .clone();
        tokio::time::timeout(Duration::from_secs(12), async {
            loop {
                let raw = self
                    .central
                    .store
                    .read(|db| {
                        use rusqlite::OptionalExtension;
                        Ok(db
                            .query_row(
                                "SELECT value FROM cluster_state WHERE key='activation_peer:mx2'",
                                [],
                                |r| r.get::<_, String>(0),
                            )
                            .optional()?)
                    })
                    .await
                    .unwrap();
                if raw
                    .and_then(|s| serde_json::from_str::<Value>(&s).ok())
                    .is_some_and(|v| v["digest"] == digest)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("worker capability and base policy report");
    }
    async fn browser(&self, token: &str, path: &str, body: Value, csrf: bool) -> reqwest::Response {
        let mut request = self
            .client
            .post(format!("{}/api/v1{path}", self.url))
            .header("cookie", format!("noisefence_session={token}"))
            .header("origin", &self.central.base.web.public_origin);
        if csrf {
            request = request.header("x-csrf-token", "test-csrf");
        }
        request.json(&body).send().await.unwrap()
    }
    async fn stage(&self, threshold: f64) -> Journal {
        self.outage.store(true, Ordering::SeqCst);
        let s = self.central.snapshot();
        let mut settings = s.settings.clone();
        settings.filters.threshold = threshold;
        let response = self
            .browser(
                &self.admin,
                "/admin/cluster/activation",
                json!({"revision":s.revision,"settings":settings}),
                true,
            )
            .await;
        let status = response.status();
        let body = response.text().await.unwrap();
        assert!(status.is_success(), "{status}: {body}");
        serde_json::from_value(serde_json::from_str::<Value>(&body).unwrap()["activation"].clone())
            .unwrap()
    }
    async fn all_prepared(&self) -> Journal {
        // First authority step prepares the coordinator; no hidden test receipts.
        self.central.advance_activation().await.unwrap();
        self.outage.store(false, Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(12), async {
            loop {
                let j = self.central.activation_journal().await.unwrap().unwrap();
                if j.rollout()
                    .unwrap()
                    .participants()
                    .values()
                    .all(|p| *p == Progress::Prepared)
                {
                    return j;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("every real participant prepared")
    }
    async fn finish(&self) -> Journal {
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let j = self.central.advance_activation().await.unwrap().unwrap();
                if j.rollout().unwrap().phase() == Phase::Released
                    && self.central.cluster_ready()
                    && self.worker.cluster_ready()
                {
                    return j;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("coordinated release")
    }
    async fn close(self) {
        self.stop.send(true).unwrap();
        for job in self.jobs {
            job.await.unwrap().unwrap();
        }
        self.server.await.unwrap();
    }
    fn poll(&self) -> Value {
        json!({"build":env!("CARGO_PKG_VERSION"),"revision":self.worker.snapshot().revision,"digest":self.worker.cluster_digest(),"budget":{"known":{},"replenish":[]},"records":[],"results":[],"status":{"hostname":"mx2.example.test"}})
    }
    async fn node_post(&self, version: &str, body: Value, key: &str) -> reqwest::Response {
        self.client
            .post(format!("{}/api/v1/cluster/{version}/sync", self.url))
            .bearer_auth(key)
            .header("x-noisefence-node", "mx2")
            .json(&body)
            .send()
            .await
            .unwrap()
    }
}

#[tokio::test]
async fn actual_network_rollout_freezes_models_and_keeps_both_nodes_closed_through_partition() {
    let mut h = Harness::new(true, true).await;
    let staged = h.stage(97.).await;
    let candidate = staged.rollout().unwrap().candidate();
    let cache = artifacts::directory(&h.worker.base.data_dir, candidate);
    for name in candidate.files.keys() {
        std::fs::remove_file(cache.join(name)).unwrap();
    }
    // Original mutable source is no longer available. v2 must serve the frozen
    // manifest bytes, and neither side may silently fall back to that old path.
    std::fs::remove_file(h.central.base.filter.model.as_ref().unwrap()).unwrap();
    // Crash window: the proposal is durable, but the authority has not created
    // its participant journal yet. Startup must use the frozen base, not the now
    // missing installation source, and must keep acceptance fenced.
    let recovering = Controller::load(
        h.central.base.clone(),
        Store::open(&h.central.base.data_dir).unwrap(),
    )
    .await
    .unwrap();
    assert!(!recovering.cluster_ready());
    assert_eq!(recovering.snapshot().revision, 0);
    assert_eq!(
        recovering.snapshot().activation_epoch.as_ref(),
        Some(staged.rollout().unwrap().base_epoch())
    );
    drop(recovering);
    h.all_prepared().await;
    assert!(!h.central.cluster_ready() && !h.worker.cluster_ready());
    assert_eq!(h.central.snapshot().config.filter.threshold, 95.);
    assert_eq!(h.worker.snapshot().config.filter.threshold, 95.);
    h.outage.store(true, Ordering::SeqCst);
    let committed = h.central.advance_activation().await.unwrap().unwrap();
    assert_eq!(committed.rollout().unwrap().phase(), Phase::Committed);
    h.central.advance_activation().await.unwrap();
    assert_eq!(h.central.snapshot().config.filter.threshold, 97.);
    assert_eq!(h.worker.snapshot().config.filter.threshold, 95.);
    tokio::time::sleep(Duration::from_millis(2200)).await;
    assert!(!h.central.cluster_ready() && !h.worker.cluster_ready());
    let rows = h
        .central
        .store
        .read(|db| {
            Ok(db.query_row(
                "SELECT COUNT(*) FROM console_revisions WHERE id=1",
                [],
                |r| r.get::<_, i64>(0),
            )?)
        })
        .await
        .unwrap();
    assert_eq!(
        rows, 1,
        "console revision committed with the authority decision"
    );
    let status: Value = h
        .client
        .get(format!("{}/api/v1/admin/cluster/activation", h.url))
        .header("cookie", format!("noisefence_session={}", h.admin))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(status["installed_revision"], 1);
    assert_eq!(status["committed_revision"], 1);
    assert_eq!(status["activation"]["rollout"]["phase"], "committed");
    assert_eq!(
        status["smtp_ready"], false,
        "installed does not mean released for SMTP acceptance"
    );
    // The next real request loses its response after the authority processes it.
    h.lose_reply.store(true, Ordering::SeqCst);
    h.outage.store(false, Ordering::SeqCst);
    h.jobs.push(tokio::spawn(cluster::run(
        h.central.clone(),
        h.stop.subscribe(),
    )));
    let released = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if h.central.cluster_ready() && h.worker.cluster_ready() {
                break h.central.activation_journal().await.unwrap().unwrap();
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("authority loop and worker resume after lost reply");
    assert_eq!(released.rollout().unwrap().phase(), Phase::Released);
    assert_eq!(
        h.central.snapshot().activation_epoch,
        h.worker.snapshot().activation_epoch
    );
    assert_eq!(
        h.central.snapshot().engine.offline(common::MESSAGE).score,
        h.worker.snapshot().engine.offline(common::MESSAGE).score
    );
    assert_eq!(h.worker.snapshot().config.filter.threshold, 97.);
    for original in [&h.central, &h.worker] {
        let disk = noisefence::control::effective_from_disk(original.base.clone()).unwrap();
        assert_eq!(disk.filter.threshold, 97.);
        assert!(disk.filter.model.as_ref().unwrap().is_file());
        let store = Store::open(&original.base.data_dir).unwrap();
        let restarted = Controller::load(original.base.clone(), store)
            .await
            .unwrap();
        assert!(!restarted.cluster_ready());
        assert!(
            restarted.activation_receipt().is_none(),
            "persisted readiness is not a runtime receipt after restart"
        );
        assert_eq!(
            restarted.snapshot().activation_epoch,
            original.snapshot().activation_epoch
        );
    }
    let v1 = h.node_post("v1", h.poll(), &h.identity).await;
    assert_eq!(v1.status(), reqwest::StatusCode::CONFLICT);
    h.close().await;
}

#[tokio::test]
async fn legacy_success_is_not_readiness_and_browser_and_node_authorities_remain_separate() {
    let h = Harness::new(false, false).await;
    let token = account(&h.central.store, "reader", false).await;
    let body = json!({"revision":0,"settings":h.central.snapshot().settings});
    assert_eq!(
        h.browser(&h.admin, "/admin/cluster/activation", body.clone(), false)
            .await
            .status(),
        reqwest::StatusCode::FORBIDDEN
    );
    assert_eq!(
        h.browser(&token, "/admin/cluster/activation", body.clone(), true)
            .await
            .status(),
        reqwest::StatusCode::FORBIDDEN
    );
    let request = json!({"protocol":cluster::activation::transport::PROTOCOL,"poll":h.poll(),"acknowledgement":null});
    assert_eq!(
        h.node_post("v2", request, &h.admin).await.status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
    let reply: protocol::Reply = h
        .node_post("v1", h.poll(), &h.identity)
        .await
        .json()
        .await
        .unwrap();
    h.worker
        .apply_cluster(
            reply.bundle,
            noisefence::message::digest(b"{}"),
            reply.server_time,
        )
        .await
        .unwrap();
    assert!(
        h.node_post("v1", h.poll(), &h.identity)
            .await
            .status()
            .is_success()
    );
    let refused = h
        .browser(&h.admin, "/admin/cluster/activation", body, true)
        .await;
    assert_eq!(refused.status(), reqwest::StatusCode::CONFLICT);
    assert!(h.central.activation_journal().await.unwrap().is_none());
    assert!(h.central.cluster_ready());
    h.close().await;
}

#[tokio::test]
async fn revoked_staging_admin_cannot_commit_and_another_admin_can_abort() {
    let h = Harness::new(false, true).await;
    let backup = account(&h.central.store, "backup", true).await;
    let staged = h.stage(97.).await;
    h.all_prepared().await;
    h.central
        .store
        .run(|db| {
            db.execute("UPDATE users SET disabled=1 WHERE username='admin'", [])?;
            Ok(())
        })
        .await
        .unwrap();
    assert!(h.central.advance_activation().await.is_err());
    assert_eq!(
        h.central
            .activation_journal()
            .await
            .unwrap()
            .unwrap()
            .rollout()
            .unwrap()
            .phase(),
        Phase::Preparing
    );
    let revisions = h
        .central
        .store
        .read(|db| {
            Ok(
                db.query_row("SELECT COUNT(*) FROM console_revisions", [], |r| {
                    r.get::<_, i64>(0)
                })?,
            )
        })
        .await
        .unwrap();
    assert_eq!(revisions, 0);
    let response = h
        .browser(
            &backup,
            "/admin/cluster/activation/abort",
            json!({"epoch":staged.rollout().unwrap().epoch()}),
            true,
        )
        .await;
    assert!(
        response.status().is_success(),
        "{}",
        response.text().await.unwrap()
    );
    tokio::time::timeout(Duration::from_secs(12), async {
        loop {
            h.central.advance_activation().await.unwrap();
            if h.central.cluster_ready() && h.worker.cluster_ready() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(h.worker.snapshot().config.filter.threshold, 95.);
    assert!(h.worker.activation_receipt().is_none());
    h.close().await;
}

#[tokio::test]
async fn partial_network_commit_recovers_at_a_higher_revision_without_mixed_admission() {
    let h = Harness::new(false, true).await;
    let staged = h.stage(98.).await;
    h.all_prepared().await;
    h.outage.store(true, Ordering::SeqCst);
    h.central.advance_activation().await.unwrap();
    h.central.advance_activation().await.unwrap();
    assert_eq!(h.central.snapshot().revision, 1);
    assert_eq!(h.worker.snapshot().revision, 0);
    assert!(!h.central.cluster_ready() && !h.worker.cluster_ready());
    let epoch = staged.rollout().unwrap().epoch();
    assert_eq!(
        h.browser(
            &h.admin,
            "/admin/cluster/activation/abort",
            json!({"epoch":epoch}),
            true
        )
        .await
        .status(),
        reqwest::StatusCode::CONFLICT
    );
    let response = h
        .browser(
            &h.admin,
            "/admin/cluster/activation/recover",
            json!({"epoch":epoch}),
            true,
        )
        .await;
    assert!(
        response.status().is_success(),
        "{}",
        response.text().await.unwrap()
    );
    h.outage.store(false, Ordering::SeqCst);
    let released = h.finish().await;
    assert_eq!(released.current().revision, 2);
    assert_eq!(h.central.snapshot().config.filter.threshold, 95.);
    assert_eq!(h.worker.snapshot().config.filter.threshold, 95.);
    assert_eq!(
        h.central.snapshot().activation_epoch,
        h.worker.snapshot().activation_epoch
    );
    h.close().await;
}

#[tokio::test]
async fn abort_before_first_prepare_allows_the_unchanged_policy_and_a_later_rollout() {
    let h = Harness::new(false, true).await;
    let staged = h.stage(97.).await; // worker transport is deliberately paused
    let response = h
        .browser(
            &h.admin,
            "/admin/cluster/activation/abort",
            json!({"epoch":staged.rollout().unwrap().epoch()}),
            true,
        )
        .await;
    assert!(response.status().is_success());
    h.central.advance_activation().await.unwrap();
    h.outage.store(false, Ordering::SeqCst);
    tokio::time::timeout(Duration::from_secs(12), async {
        loop {
            if h.worker.store.activation.epoch().is_some() && h.worker.cluster_ready() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("abort reaches a participant that never prepared");
    assert_eq!(h.worker.snapshot().config.filter.threshold, 95.);
    h.ready_peer().await;
    let next = h.stage(98.).await;
    assert!(next.rollout().unwrap().epoch().sequence > staged.rollout().unwrap().epoch().sequence);
    h.outage.store(false, Ordering::SeqCst);
    h.finish().await;
    assert_eq!(
        h.worker.snapshot().revision,
        1,
        "aborted proposals do not masquerade as applied revisions"
    );
    h.close().await;
}

#[tokio::test]
async fn lost_release_can_be_followed_by_a_new_prepare_without_reopening_an_old_epoch() {
    let h = Harness::new(false, true).await;
    h.stage(97.).await;
    h.all_prepared().await;
    let j = h.central.advance_activation().await.unwrap().unwrap();
    assert_eq!(j.rollout().unwrap().phase(), Phase::Committed);
    h.central.advance_activation().await.unwrap();
    tokio::time::timeout(Duration::from_secs(12), async {
        loop {
            let j = h.central.activation_journal().await.unwrap().unwrap();
            if j.rollout()
                .unwrap()
                .participants()
                .values()
                .all(|p| *p == Progress::Applied)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    h.outage.store(true, Ordering::SeqCst);
    h.central.advance_activation().await.unwrap(); // records release
    h.central.advance_activation().await.unwrap(); // opens authority only
    assert!(h.central.cluster_ready());
    assert!(!h.worker.cluster_ready());
    assert_eq!(h.worker.snapshot().revision, 1);
    h.stage(98.).await;
    h.outage.store(false, Ordering::SeqCst);
    h.finish().await;
    assert_eq!(h.worker.snapshot().revision, 2);
    assert_eq!(
        h.worker.snapshot().activation_epoch,
        h.central.snapshot().activation_epoch
    );
    h.close().await;
}

#[tokio::test]
async fn older_router_fallback_is_allowed_only_before_enrollment() {
    let mut h = Harness::new(false, false).await;
    h.legacy_only.store(true, Ordering::SeqCst);
    h.jobs.push(tokio::spawn(cluster::run(
        h.worker.clone(),
        h.stop.subscribe(),
    )));
    tokio::time::timeout(Duration::from_secs(8), async {
        while !h.worker.cluster_ready() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("legacy coordinator remains usable before enrollment");
    assert!(h.legacy_calls.load(Ordering::SeqCst) > 0);
    h.legacy_only.store(false, Ordering::SeqCst);
    h.ready_peer().await;
    h.stage(97.).await;
    h.outage.store(false, Ordering::SeqCst);
    h.finish().await;
    let calls = h.legacy_calls.load(Ordering::SeqCst);
    h.legacy_only.store(true, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert_eq!(
        h.legacy_calls.load(Ordering::SeqCst),
        calls,
        "an enrolled worker must not send a legacy downgrade request"
    );
    assert_eq!(h.worker.snapshot().revision, 1);
    h.close().await;
}

async fn view(h: &Harness, token: &str, path: &str) -> Value {
    let response = h
        .client
        .get(format!("{}/api/v1{path}", h.url))
        .header("cookie", format!("noisefence_session={token}"))
        .send()
        .await
        .unwrap();
    assert!(
        response.status().is_success(),
        "{}",
        response.text().await.unwrap()
    );
    response.json().await.unwrap()
}
async fn grant(h: &Harness, name: &str) -> String {
    let token = account(&h.central.store, name, false).await;
    let name = name.to_owned();
    h.central
        .store
        .run(move |db| {
            db.execute(
                "INSERT INTO grants(username,address) VALUES(?1,'alice@example.test')",
                [name],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    token
}
#[tokio::test]
async fn web_saves_stage_scoped_preferences_and_never_expose_global_proposals() {
    let h = Harness::new(false, true).await;
    let alice = grant(&h, "alice").await;
    let bob = account(&h.central.store, "bob", false).await;
    h.stage(97.).await;
    h.all_prepared().await;
    h.finish().await;
    h.ready_peer().await;
    h.outage.store(true, Ordering::SeqCst);
    let before = h.central.snapshot();
    let edit = json!({"revision":before.revision,"scope":"alice@example.test","preference":{"profile":null,"rules":[]}});
    assert_eq!(
        h.browser(&alice, "/preferences", edit.clone(), false)
            .await
            .status(),
        reqwest::StatusCode::FORBIDDEN
    );
    assert_eq!(
        h.browser(&bob, "/preferences", edit.clone(), true)
            .await
            .status(),
        reqwest::StatusCode::FORBIDDEN
    );
    let mut injected = edit.clone();
    injected["settings"] = json!({"filters":{"threshold":0}});
    assert!(
        !h.browser(&alice, "/preferences", injected, true)
            .await
            .status()
            .is_success()
    );
    let response = h.browser(&alice, "/preferences", edit, true).await;
    assert!(
        response.status().is_success(),
        "{}",
        response.text().await.unwrap()
    );
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["staged"], true);
    assert_eq!(body.as_object().unwrap().len(), 2);
    assert_eq!(h.central.snapshot().revision, before.revision);
    let pending = view(&h, &alice, "/preferences/activation").await;
    assert_eq!(pending["pending"], true);
    assert_eq!(pending["personal_change"]["scope"], "alice@example.test");
    for hidden in ["participants", "epoch", "committed_revision"] {
        assert!(pending[hidden].is_null());
    }
    let other = view(&h, &bob, "/preferences/activation").await;
    assert!(other["personal_change"].is_null());
    assert!(!other.to_string().contains("alice"));
    assert!(!other.to_string().contains("example.test"));
    // Ordinary account cannot stage a whole settings object or read admin status.
    assert_eq!(
        h.browser(
            &alice,
            "/admin/config",
            json!({"revision":before.revision,"settings":before.settings}),
            true
        )
        .await
        .status(),
        reqwest::StatusCode::FORBIDDEN
    );
    h.all_prepared().await;
    h.finish().await;
    assert_eq!(
        h.central
            .snapshot()
            .settings
            .preferences
            .mailboxes
            .get("alice@example.test"),
        Some(&noisefence::preferences::Preference {
            profile: None,
            rules: vec![]
        })
    );
    assert_eq!(h.central.snapshot().settings, h.worker.snapshot().settings);
    assert_eq!(
        h.central.snapshot().settings.filters,
        before.settings.filters
    );
    let done = view(&h, &alice, "/preferences/activation").await;
    assert_eq!(done["phase"], "released");
    assert_eq!(done["pending"], false);
    h.ready_peer().await;
    h.outage.store(true, Ordering::SeqCst);
    let current = h.central.snapshot();
    let mut settings = current.settings.clone();
    settings.filters.threshold = 98.;
    let response = h
        .browser(
            &h.admin,
            "/admin/config",
            json!({"revision":current.revision,"settings":settings}),
            true,
        )
        .await;
    assert!(
        response.status().is_success(),
        "{}",
        response.text().await.unwrap()
    );
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["staged"], true);
    assert_eq!(h.central.snapshot().config.filter.threshold, 97.);
    h.all_prepared().await;
    h.finish().await;
    assert_eq!(h.worker.snapshot().config.filter.threshold, 98.);
    h.close().await;
}

#[tokio::test]
async fn preference_grant_revocation_blocks_commit_and_incident_is_scoped() {
    let h = Harness::new(false, true).await;
    let alice = grant(&h, "alice").await;
    let bob = account(&h.central.store, "bob", false).await;
    h.stage(97.).await;
    h.all_prepared().await;
    h.finish().await;
    h.ready_peer().await;
    h.outage.store(true, Ordering::SeqCst);
    let revision = h.central.snapshot().revision;
    let response = h.browser(&alice,"/preferences",json!({"revision":revision,"scope":"alice@example.test","preference":{"profile":null,"rules":[]}}),true).await;
    assert!(
        response.status().is_success(),
        "{}",
        response.text().await.unwrap()
    );
    h.all_prepared().await;
    // Check the actual grant again, even if an out-of-band edit did not bump the version.
    h.central
        .store
        .run(|db| {
            db.execute("DELETE FROM grants WHERE username='alice'", [])?;
            Ok(())
        })
        .await
        .unwrap();
    assert!(h.central.advance_activation().await.is_err());
    assert_eq!(h.central.snapshot().revision, revision);
    let admin = view(&h, &h.admin, "/admin/cluster/activation/view").await;
    assert_eq!(admin["incident"]["code"], "approval_changed");
    assert_eq!(admin["abortable"], true);
    assert_eq!(admin["smtp_ready"], false);
    for token in [&alice, &bob] {
        let personal = view(&h, token, "/preferences/activation").await;
        assert!(personal["personal_change"].is_null());
        assert!(personal["incident"].is_null());
    }
    // Restoring the address alone cannot restore an approval invalidated by an
    // account-version change. Its owner may see the incident, never its bundle hash.
    h.central
        .store
        .run(|db| {
            db.execute(
                "INSERT INTO grants(username,address) VALUES('alice','alice@example.test')",
                [],
            )?;
            db.execute(
                "INSERT INTO console_user_versions(username,version) VALUES('alice',1)",
                [],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    assert!(h.central.advance_activation().await.is_err());
    let own = view(&h, &alice, "/preferences/activation").await;
    assert_eq!(own["incident"]["code"], "approval_changed");
    assert_eq!(own["incident"].as_object().unwrap().len(), 2);
    assert!(
        !own.to_string()
            .contains(admin["epoch"]["digest"].as_str().unwrap())
    );
    let abort = h
        .browser(
            &h.admin,
            "/admin/cluster/activation/abort",
            json!({"epoch":admin["epoch"]}),
            true,
        )
        .await;
    assert!(
        abort.status().is_success(),
        "{}",
        abort.text().await.unwrap()
    );
    h.central.advance_activation().await.unwrap();
    let restored = view(&h, &h.admin, "/admin/cluster/activation/view").await;
    assert!(restored["incident"].is_null());
    assert_eq!(restored["phase"], "aborted");
    assert_eq!(h.central.snapshot().revision, revision);
    h.close().await;
}

#[tokio::test]
async fn web_progress_remains_readable_while_activation_waits_for_a_durable_write() {
    let h = Harness::new(false, true).await;
    let lease = h.central.store.activation.enter(None).unwrap();
    h.stage(97.).await;
    let c = h.central.clone();
    let preparing = tokio::spawn(async move { c.advance_activation().await });
    tokio::time::timeout(Duration::from_secs(3), async {
        while h.central.cluster_ready() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(!preparing.is_finished());
    let status = tokio::time::timeout(
        Duration::from_secs(2),
        view(&h, &h.admin, "/admin/cluster/activation/view"),
    )
    .await
    .expect("Status must not wait for the serialized activation job");
    assert_eq!(status["pending"], true);
    assert_eq!(status["smtp_ready"], false);
    assert_eq!(status["phase"], "preparing");
    drop(lease);
    preparing.await.unwrap().unwrap();
    h.all_prepared().await;
    h.finish().await;
    h.close().await;
}

#[tokio::test]
async fn runtime_generation_pressure_is_visible_and_retries_after_analyses_finish() {
    let h = Harness::new(false, true).await;
    let mut retained = Vec::new();
    for threshold in [96., 97., 98.] {
        h.ready_peer().await;
        h.stage(threshold).await;
        h.all_prepared().await;
        h.finish().await;
        if threshold < 98. {
            retained.push(h.central.snapshot().engine.clone());
        }
    }
    h.ready_peer().await;
    let staged = h.stage(99.).await;
    assert!(h.central.advance_activation().await.is_err());
    let status = view(&h, &h.admin, "/admin/cluster/activation/view").await;
    assert_eq!(status["incident"]["code"], "runtime_generation_busy");
    assert_eq!(status["phase"], "preparing");
    assert_eq!(status["smtp_ready"], false);
    assert_eq!(h.central.snapshot().config.filter.threshold, 98.);
    assert_eq!(
        h.central
            .activation_journal()
            .await
            .unwrap()
            .unwrap()
            .rollout()
            .unwrap()
            .epoch(),
        staged.rollout().unwrap().epoch()
    );
    // Releasing a completed old analysis permits the same durable proposal.
    // No restaging, fabricated readiness receipt or threshold change is needed.
    retained.remove(0);
    h.all_prepared().await;
    h.finish().await;
    let status = view(&h, &h.admin, "/admin/cluster/activation/view").await;
    assert!(status["incident"].is_null());
    assert_eq!(status["smtp_ready"], true);
    for node in [&h.central, &h.worker] {
        assert_eq!(node.snapshot().config.filter.threshold, 99.);
        assert_eq!(
            node.snapshot().activation_epoch.as_ref(),
            Some(staged.rollout().unwrap().epoch())
        );
    }
    drop(retained);
    h.close().await;
}

#[tokio::test]
async fn settings_keep_installed_models_until_an_explicit_digest_bound_selection() {
    let h = Harness::new(true, true).await;
    let alice = grant(&h, "alice").await;
    h.stage(97.).await;
    h.all_prepared().await;
    h.finish().await;
    h.ready_peer().await;
    let initial = h.central.publication().await.unwrap();
    let initial_models = artifacts::model_digest(&initial.bundle).unwrap();
    let source = h.central.base.filter.model.as_ref().unwrap();
    let mut model: Value = serde_json::from_slice(&std::fs::read(source).unwrap()).unwrap();
    model["version"] = json!("explicit-model-v2");
    model["bias"] = json!(-8.0);
    std::fs::write(source, serde_json::to_vec(&model).unwrap()).unwrap();
    // Replacing an installation file does not select it during an ordinary save.
    let same = h.stage(98.).await;
    assert_eq!(
        artifacts::model_digest(same.rollout().unwrap().candidate()).unwrap(),
        initial_models
    );
    h.all_prepared().await;
    h.finish().await;
    h.ready_peer().await;
    let current = h.central.snapshot();
    let preview_body = json!({"revision":current.revision,"settings":current.settings});
    assert_eq!(
        h.browser(
            &alice,
            "/admin/cluster/models/preview",
            preview_body.clone(),
            true
        )
        .await
        .status(),
        reqwest::StatusCode::FORBIDDEN
    );
    assert_eq!(
        h.browser(
            &h.admin,
            "/admin/cluster/models/preview",
            preview_body.clone(),
            false
        )
        .await
        .status(),
        reqwest::StatusCode::FORBIDDEN
    );
    let preview = h
        .browser(
            &h.admin,
            "/admin/cluster/models/preview",
            preview_body.clone(),
            true,
        )
        .await;
    assert!(
        preview.status().is_success(),
        "{}",
        preview.text().await.unwrap()
    );
    let preview: Value = preview.json().await.unwrap();
    assert_eq!(preview["installed_sha256"], initial_models);
    assert_ne!(preview["installation_sha256"], initial_models);
    assert_eq!(preview["qualification"], "not_evaluated");
    assert!(!preview.to_string().contains(source.to_str().unwrap()));
    // A preview never grants permission to silently consume subsequently changed bytes.
    model["version"] = json!("explicit-model-v3");
    model["bias"] = json!(-7.0);
    std::fs::write(source, serde_json::to_vec(&model).unwrap()).unwrap();
    let mut request = preview_body.clone();
    request["installation_models_sha256"] = preview["installation_sha256"].clone();
    let response = h
        .browser(&h.admin, "/admin/config", request.clone(), true)
        .await;
    assert_eq!(response.status(), reqwest::StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        response
            .text()
            .await
            .unwrap()
            .contains("changed after preview")
    );
    assert_eq!(h.central.snapshot().revision, current.revision);
    let preview: Value = h
        .browser(
            &h.admin,
            "/admin/cluster/models/preview",
            preview_body,
            true,
        )
        .await
        .json()
        .await
        .unwrap();
    request["installation_models_sha256"] = preview["installation_sha256"].clone();
    h.outage.store(true, Ordering::SeqCst);
    let response = h.browser(&h.admin, "/admin/config", request, true).await;
    assert!(
        response.status().is_success(),
        "{}",
        response.text().await.unwrap()
    );
    assert_eq!(response.json::<Value>().await.unwrap()["staged"], true);
    std::fs::remove_file(source).unwrap();
    h.all_prepared().await;
    h.finish().await;
    h.ready_peer().await;
    let installed = h.central.publication().await.unwrap();
    assert_eq!(
        artifacts::model_digest(&installed.bundle).unwrap(),
        preview["installation_sha256"]
    );
    assert_ne!(
        artifacts::model_digest(&installed.bundle).unwrap(),
        initial_models
    );
    let worker = h.worker.snapshot();
    let worker_publication =
        artifacts::capture(&worker.config, worker.settings.clone(), worker.revision).unwrap();
    assert_eq!(
        artifacts::model_digest(&worker_publication.bundle).unwrap(),
        preview["installation_sha256"]
    );
    assert_eq!(
        worker.engine.quality_artifacts_sha256(),
        h.central.snapshot().engine.quality_artifacts_sha256()
    );
    // Another settings change, plus draft validation, use immutable cached files.
    let settings = h.central.snapshot().settings.clone();
    let valid = h
        .browser(
            &h.admin,
            "/admin/config/validate",
            json!({"settings":settings}),
            true,
        )
        .await;
    assert!(
        valid.status().is_success(),
        "{}",
        valid.text().await.unwrap()
    );
    let retained = h.stage(98.5).await;
    assert_eq!(
        artifacts::model_digest(retained.rollout().unwrap().candidate()).unwrap(),
        preview["installation_sha256"]
    );
    h.all_prepared().await;
    h.finish().await;
    h.close().await;
}

#[tokio::test]
async fn managed_shadow_selection_stages_and_survives_source_removal_then_disables() {
    use noisefence::{message::digest, quality};
    let h = Harness::new(false, true).await;
    h.stage(97.).await;
    h.all_prepared().await;
    h.finish().await;
    h.ready_peer().await;
    let job = uuid::Uuid::new_v4().to_string();
    let path = h
        .central
        .base
        .data_dir
        .join("calibration")
        .join(&job)
        .join("candidate/model.json");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let model = json!({"schema":"noisefence-quality-model-2","version":"SOFTWARE-TEST-ONLY",
        "protocol_sha256":quality::protocol_hash(),"artifacts_sha256":h.central.snapshot().engine.quality_artifacts_sha256(),
        "dataset_sha256":digest(b"synthetic"),"trained_at":noisefence::now(),"profiles":["fixture"],
        "risk":{"bias":0.,"weights":vec![0.;quality::specs().len()]},"calibration":[1.,0.],"thresholds":[0.2,0.8],
        "kinds":[],"kind_models":[],"kind_profiles":[],"kind_temperature":1.,"training_manifest_sha256":digest(b"fixture manifest")});
    let bytes = serde_json::to_vec(&model).unwrap();
    std::fs::write(&path, &bytes).unwrap();
    quality::Model::load(&path).unwrap();
    let sha = digest(&bytes);
    let key = job.clone();
    h.central.store.run(move|db| {
        db.execute("INSERT INTO quality_batches VALUES('fixture','admin',?1,?1,?1,'example.test','fixture',0,0)",[noisefence::now()])?;
        db.execute("INSERT INTO quality_jobs(id,username,batch_id,operation,status,created,model_sha256) VALUES(?1,'admin','fixture','train','complete',?2,?3)",params![key,noisefence::now(),sha])?;
        Ok(())
    }).await.unwrap();
    h.outage.store(true, Ordering::SeqCst);
    let response = h
        .browser(
            &h.admin,
            "/quality/candidate",
            json!({"revision":h.central.snapshot().revision,"job":job}),
            true,
        )
        .await;
    assert!(
        response.status().is_success(),
        "{}",
        response.text().await.unwrap()
    );
    let response: Value = response.json().await.unwrap();
    assert_eq!(response["staged"], true);
    assert_eq!(response["observation_only"], true);
    std::fs::remove_file(&path).unwrap();
    h.all_prepared().await;
    h.finish().await;
    h.ready_peer().await;
    let selected = h.central.snapshot();
    assert!(
        selected
            .config
            .quality
            .as_ref()
            .unwrap()
            .candidate
            .as_ref()
            .unwrap()
            .is_file()
    );
    let config = view(&h, &h.admin, "/admin/config").await;
    assert_eq!(config["settings"]["quality_candidate"]["job"], job);
    // Same selected job remains usable after the original research file is gone.
    h.stage(98.).await;
    h.all_prepared().await;
    h.finish().await;
    h.ready_peer().await;
    let cleared = h
        .browser(
            &h.admin,
            "/quality/candidate",
            json!({"revision":h.central.snapshot().revision,"job":null}),
            true,
        )
        .await;
    assert!(
        cleared.status().is_success(),
        "{}",
        cleared.text().await.unwrap()
    );
    h.all_prepared().await;
    h.finish().await;
    h.ready_peer().await;
    assert!(
        h.central
            .snapshot()
            .config
            .quality
            .as_ref()
            .unwrap()
            .candidate
            .is_none()
    );
    h.stage(99.).await;
    h.all_prepared().await;
    h.finish().await;
    assert!(
        h.worker
            .snapshot()
            .config
            .quality
            .as_ref()
            .unwrap()
            .candidate
            .is_none()
    );
    h.close().await;
}

#[tokio::test]
async fn credential_rotation_freezes_both_generations_and_survives_source_loss() {
    use noisefence::{
        credentials::generations,
        protection::{Provider, save_key},
    };
    let old_key = "synthetic-original-crdf-key-123456";
    let new_key = "synthetic-replacement-crdf-key-654321";
    let h = Harness::with_crdf(false, true, Some(old_key)).await;
    h.stage(95.).await;
    h.all_prepared().await;
    h.finish().await;
    h.ready_peer().await;
    let original = h.central.snapshot();
    let response = h
        .browser(
            &h.admin,
            "/admin/protection/keys/crdf",
            json!({"revision":1,"key":new_key}),
            true,
        )
        .await;
    let status = response.status();
    let reply: Value = response.json().await.unwrap();
    assert!(status.is_success(), "{reply}");
    assert_eq!(reply["staged"], true);
    assert_eq!(reply["active"], false);
    assert!(!reply.to_string().contains(new_key));
    assert_eq!(
        std::fs::read_to_string(h.central.base.data_dir.join("protection/crdf.key"))
            .unwrap()
            .trim(),
        old_key,
        "Staging must not replace the installation key"
    );
    let staged = h.central.activation_journal().await.unwrap().unwrap();
    let rollout = staged.rollout().unwrap();
    assert_ne!(
        rollout.base().credential_generation,
        rollout.candidate().credential_generation
    );
    assert_eq!(
        generations::load(
            &h.central.base.data_dir,
            rollout.base().credential_generation.as_ref().unwrap()
        )
        .unwrap()
        .get("crdf"),
        Some(old_key)
    );
    assert_eq!(
        generations::load(
            &h.central.base.data_dir,
            rollout.candidate().credential_generation.as_ref().unwrap()
        )
        .unwrap()
        .get("crdf"),
        Some(new_key)
    );
    // Private generations never become downloadable model artifacts, even for
    // a valid node credential. Browser projections expose no provider values.
    for version in ["v1", "v2"] {
        let response = h
            .client
            .get(format!(
                "{}/api/v1/cluster/{version}/artifacts/{}",
                h.url,
                rollout.candidate().credential_generation.as_ref().unwrap()
            ))
            .bearer_auth(&h.identity)
            .header("x-noisefence-node", "mx2")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
        assert!(!response.text().await.unwrap().contains(new_key));
    }
    for endpoint in [
        "/admin/config",
        "/admin/cluster/activation",
        "/admin/protection",
    ] {
        let response = view(&h, &h.admin, endpoint).await.to_string();
        assert!(!response.contains(old_key) && !response.contains(new_key));
    }
    save_key(
        &h.central.base.data_dir,
        Provider::Crdf,
        "synthetic-unrelated-source-key-98765",
    )
    .unwrap();
    std::fs::remove_file(h.worker.base.data_dir.join("protection/crdf.key")).unwrap();
    h.all_prepared().await;
    h.outage.store(true, Ordering::SeqCst);
    h.central.advance_activation().await.unwrap();
    h.central.advance_activation().await.unwrap();
    assert!(!h.central.cluster_ready() && !h.worker.cluster_ready());
    assert_eq!(
        h.central
            .snapshot()
            .config
            .provider_credentials
            .as_ref()
            .unwrap()
            .get("crdf"),
        Some(new_key)
    );
    assert_eq!(
        h.worker
            .snapshot()
            .config
            .provider_credentials
            .as_ref()
            .unwrap()
            .get("crdf"),
        Some(old_key)
    );
    let restart = Controller::load(
        h.central.base.clone(),
        Store::open(&h.central.base.data_dir).unwrap(),
    )
    .await
    .unwrap();
    assert!(!restart.cluster_ready());
    assert_eq!(
        restart
            .snapshot()
            .config
            .provider_credentials
            .as_ref()
            .unwrap()
            .get("crdf"),
        Some(new_key)
    );
    drop(restart);
    h.outage.store(false, Ordering::SeqCst);
    h.finish().await;
    h.ready_peer().await;
    for node in [&h.central, &h.worker] {
        assert_eq!(
            node.snapshot()
                .config
                .provider_credentials
                .as_ref()
                .unwrap()
                .get("crdf"),
            Some(new_key)
        );
    }
    assert_eq!(
        original
            .config
            .provider_credentials
            .as_ref()
            .unwrap()
            .get("crdf"),
        Some(old_key)
    );
    let view = view(&h, &h.admin, "/admin/protection").await;
    assert_eq!(view["loaded_keys"]["crdf"], true);
    assert_eq!(view["pending_keys"]["crdf"], false);
    assert!(!view.to_string().contains(new_key));
    // A settings-only save retains the installed generation despite changed sources.
    let keep = h.stage(97.).await;
    assert_eq!(
        keep.rollout().unwrap().candidate().credential_generation,
        rollout.candidate().credential_generation
    );
    h.all_prepared().await;
    h.finish().await;
    h.close().await;
}

#[tokio::test]
async fn credential_abort_and_partial_commit_recovery_restore_the_original_set() {
    let old_key = "synthetic-recovery-crdf-original-12345";
    let dqs = "syntheticStagedDqsKey123456789";
    let h = Harness::with_crdf(false, true, Some(old_key)).await;
    h.stage(95.).await;
    h.all_prepared().await;
    h.finish().await;
    h.ready_peer().await;
    let stage_key = || {
        h.browser(
            &h.admin,
            "/admin/keys",
            json!({"revision":1,"provider":"spamhaus","key":dqs}),
            true,
        )
    };
    h.outage.store(true, Ordering::SeqCst);
    let reply = stage_key().await;
    assert!(reply.status().is_success());
    let reply: Value = reply.json().await.unwrap();
    assert_eq!(reply["staged"], true);
    assert_eq!(reply["active"], false);
    assert!(
        !h.central
            .base
            .data_dir
            .join("credentials/spamhaus.key")
            .exists()
    );
    let aborted = h
        .browser(
            &h.admin,
            "/admin/cluster/activation/abort",
            json!({"epoch":reply["epoch"]}),
            true,
        )
        .await;
    assert!(aborted.status().is_success());
    h.central.advance_activation().await.unwrap();
    h.outage.store(false, Ordering::SeqCst);
    h.ready_peer().await;
    assert!(h.central.cluster_ready() && h.worker.cluster_ready());
    assert!(
        h.central
            .snapshot()
            .config
            .provider_credentials
            .as_ref()
            .unwrap()
            .get("spamhaus")
            .is_none()
    );
    let response = stage_key().await;
    let status = response.status();
    let staged: Value = response.json().await.unwrap();
    assert!(status.is_success(), "{staged}");
    h.all_prepared().await;
    h.outage.store(true, Ordering::SeqCst);
    h.central.advance_activation().await.unwrap();
    h.central.advance_activation().await.unwrap();
    assert_eq!(
        h.central
            .snapshot()
            .config
            .provider_credentials
            .as_ref()
            .unwrap()
            .get("spamhaus"),
        Some(dqs)
    );
    assert!(
        h.worker
            .snapshot()
            .config
            .provider_credentials
            .as_ref()
            .unwrap()
            .get("spamhaus")
            .is_none()
    );
    assert!(!h.central.cluster_ready() && !h.worker.cluster_ready());
    for node in [&h.central, &h.worker] {
        noisefence::management::save_key(
            &node.base.data_dir,
            "spamhaus",
            "syntheticUnrelatedSourceDqs123456",
        )
        .unwrap();
    }
    let response = h
        .browser(
            &h.admin,
            "/admin/cluster/activation/recover",
            json!({"epoch":staged["epoch"]}),
            true,
        )
        .await;
    let status = response.status();
    let recovery: Value = response.json().await.unwrap();
    assert!(status.is_success(), "{recovery}");
    assert!(!recovery.to_string().contains(old_key));
    assert!(!recovery.to_string().contains(dqs));
    h.outage.store(false, Ordering::SeqCst);
    let final_state = h.finish().await;
    assert_eq!(final_state.current().revision, 3);
    for node in [&h.central, &h.worker] {
        let snapshot = node.snapshot();
        let keys = snapshot.config.provider_credentials.as_ref().unwrap();
        assert_eq!(keys.get("crdf"), Some(old_key));
        assert!(keys.get("spamhaus").is_none());
        let cold = Controller::load(node.base.clone(), Store::open(&node.base.data_dir).unwrap())
            .await
            .unwrap();
        assert!(!cold.cluster_ready());
        assert!(
            cold.snapshot()
                .config
                .provider_credentials
                .as_ref()
                .unwrap()
                .get("spamhaus")
                .is_none()
        );
    }
    let status = view(&h, &h.admin, "/admin/keys").await;
    assert_eq!(status["spamhaus"], false);
    let settings = view(&h, &h.admin, "/admin/config").await;
    assert_eq!(settings["available"]["reputation"], false);
    h.close().await;
}
