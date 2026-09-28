#[allow(dead_code)]
mod common;
#[path = "common/postgres.rs"]
mod postgres;
use noisefence::{
    central::{Central, binding::Binding, outbox::Identity, transport},
    cluster,
    store::Store,
};
use std::sync::Arc;
#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn bound_coordinator_rejects_missing_wrong_and_duplicated_database_identity_before_json() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let f = postgres::Fixture::new().await;
    let pg = f.connect().await;
    let binding = Binding {
        instance: uuid::Uuid::new_v4().to_string(),
        source_digest: "a".repeat(64),
    };
    pg.execute(
        "INSERT INTO noisefence.migration_state VALUES(1,$1,1,2,$2)",
        &[
            &binding.source_digest,
            &serde_json::json!({"instance":binding.instance}),
        ],
    )
    .await
    .unwrap();
    let peer = Identity {
        node: "mx2".into(),
        epoch: uuid::Uuid::new_v4().to_string(),
    };
    f.central.register_source(&peer).await.unwrap();
    let secret = "d".repeat(64);
    f.central
        .enroll_node(
            &peer,
            "Worker",
            &noisefence::message::digest(secret.as_bytes()),
        )
        .await
        .unwrap();
    let root = tempfile::tempdir().unwrap();
    let mut cfg = (*common::config(root.path())).clone();
    cfg.cluster = Some(toml::from_str("role='coordinator'\nnode_id='mx1'").unwrap());
    let cfg = Arc::new(cfg);
    let store = Store::open(root.path()).unwrap();
    cluster::prepare(&cfg, &store).await.unwrap();
    let owner = store
        .run(|db| noisefence::central::outbox::initialize(db, "mx1"))
        .await
        .unwrap();
    f.central.register_source(&owner).await.unwrap();
    let publication =
        cluster::artifacts::capture(&cfg, noisefence::control::Settings::from_config(&cfg), 0)
            .unwrap();
    f.central
        .initialize_policy(&owner, publication.bundle)
        .await
        .unwrap();
    let store = store
        .with_management(Central::new_bound(&f.settings, &binding).unwrap())
        .await
        .unwrap();
    let control = noisefence::control::Controller::load(cfg.clone(), store.clone())
        .await
        .unwrap();
    let app = noisefence::api::router_controlled(cfg, store, Some(control)).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let http = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let correct = format!("{}:{}", binding.instance, binding.source_digest);
    for endpoint in ["history", "logs", "commands", "sync", "runtime-history"] {
        for bad in [None, Some("wrong")] {
            let mut request = http
                .post(format!("{url}/api/v1/cluster/v3/{endpoint}"))
                .bearer_auth(&secret)
                .header("x-noisefence-node", "mx2")
                .header("content-type", "application/json")
                .body("not-json");
            if let Some(value) = bad {
                request = request.header(noisefence::central::binding::HEADER, value);
            }
            assert_eq!(
                request.send().await.unwrap().status(),
                reqwest::StatusCode::CONFLICT,
                "{endpoint}"
            );
        }
        let response = http
            .post(format!("{url}/api/v1/cluster/v3/{endpoint}"))
            .bearer_auth(&secret)
            .header("x-noisefence-node", "mx2")
            .header(noisefence::central::binding::HEADER, &correct)
            .header(noisefence::central::binding::HEADER, &correct)
            .header("content-type", "application/json")
            .body("not-json")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::CONFLICT);
    }
    let response = http
        .post(format!("{url}/api/v1/cluster/v3/history"))
        .bearer_auth(&secret)
        .header("x-noisefence-node", "mx2")
        .header(noisefence::central::binding::HEADER, &correct)
        .json(&serde_json::json!({"protocol":transport::PROTOCOL,"epoch":peer.epoch,"events":[]}))
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    assert_eq!(
        response
            .headers()
            .get(noisefence::central::binding::HEADER)
            .unwrap(),
        correct.as_str()
    );
    let receipt: transport::HistoryReceipt = response.json().await.unwrap();
    assert_eq!(receipt.identity, peer);
    assert!(receipt.receipts.is_empty());
    assert_eq!(
        pg.query_one("SELECT count(*) FROM noisefence.message_versions", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    server.abort();
    f.finish().await;
}
