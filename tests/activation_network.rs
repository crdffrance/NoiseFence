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
        let _ = rustls::crypto::ring::default_provider().install_default();
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let mut ca = (*config(a.path(), false, &url)).clone();
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
