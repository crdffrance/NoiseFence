#[allow(dead_code)]
mod common;
use noisefence::{
    diagnostics::AnalysisPolicy,
    engine::{Scan, Signal},
    fusion::runtime::{Decision, Outcome},
    reliability::{self, Counts, Options},
    store::Store,
};
use rusqlite::params;
use serde_json::json;

#[test]
fn intervals_never_turn_missing_annotations_or_abstention_into_zero_error() {
    assert!(reliability::interval(0, 0).is_none());
    assert!(reliability::interval(2, 1).is_none());
    let tiny = reliability::interval(0, 10).unwrap();
    assert!(tiny["upper"].as_f64().unwrap() > 0.27);
    let large = reliability::interval(0, 4000).unwrap();
    assert!(large["upper"].as_f64().unwrap() < 0.001);
    let mut counts = Counts::default();
    counts.add(Outcome::Undetermined, true);
    counts.add(Outcome::Unwanted, true);
    counts.add(Outcome::Undetermined, false);
    counts.add(Outcome::Legitimate, false);
    let report = counts.report();
    assert_eq!(report["recall"]["value"], 0.5);
    assert_eq!(report["false_positive_rate"]["total"], 2);
    assert_eq!(report["abstention"]["value"], 0.5);
}
fn recorded(config: &noisefence::config::Config) -> Scan {
    let mut policy = AnalysisPolicy::capture(config);
    policy.threshold = 95.;
    policy.require_corroboration = false;
    let mut scan = Scan {
        complete: true,
        analysis_policy: Some(policy),
        score: noisefence::engine::sigmoid(4.) * 100.,
        reasons: vec![
            Signal {
                id: "model_contribution".into(),
                weight: 2.,
                detail: "PRIVATE FEATURES".into(),
            },
            Signal {
                id: "ip_url".into(),
                weight: 2.,
                detail: "PRIVATE URL".into(),
            },
        ],
        ..Default::default()
    };
    scan.decision = Some(Decision::legacy(&scan, 95.));
    noisefence::decision::apply(&mut scan, false);
    scan
}
#[test]
fn score_ablation_replays_only_reconstructable_observations_and_preserves_malware() {
    let root = tempfile::tempdir().unwrap();
    let cfg = common::config(root.path());
    let mut scan = recorded(&cfg);
    let original = serde_json::to_value(&scan).unwrap();
    assert_eq!(
        reliability::without_weight(&scan, "ip_url"),
        Some(Outcome::Legitimate)
    );
    assert_eq!(serde_json::to_value(&scan).unwrap(), original);
    scan.score = 0.;
    assert_eq!(reliability::without_weight(&scan, "ip_url"), None);
    scan = recorded(&cfg);
    scan.complete = false;
    assert_eq!(reliability::without_weight(&scan, "ip_url"), None);
    scan = recorded(&cfg);
    scan.analysis_policy.as_mut().unwrap().version = "obsolete".into();
    assert_eq!(reliability::without_weight(&scan, "ip_url"), None);
    scan = recorded(&cfg);
    scan.antivirus.status = noisefence::antivirus::AntivirusStatus::Malware;
    noisefence::decision::apply(&mut scan, false);
    assert_eq!(
        reliability::without_weight(&scan, "ip_url"),
        None,
        "AV outcome is not a replayable legacy decision"
    );
}
#[tokio::test]
async fn history_and_api_are_recipient_scoped_count_messages_once_and_hide_private_inputs() {
    use axum::{
        body::Body,
        http::{Request, StatusCode, header},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    let root = tempfile::tempdir().unwrap();
    let cfg = common::config(root.path());
    let store = Store::open(root.path()).unwrap();
    noisefence::api::create_user(
        &store,
        "alice".into(),
        "a long password 123".into(),
        vec!["alice@example.test".into()],
        false,
    )
    .await
    .unwrap();
    let scan = recorded(&cfg);
    let raw = serde_json::to_string(&scan).unwrap();
    store.run(move|db|{
        db.execute("INSERT INTO users(username,password,admin) VALUES('bob','unused',0)",[])?;
        for (id,recipient) in [("a","alice@example.test"),("b","bob@example.test")] {
            db.execute("INSERT INTO messages(id,created,sender,scan,raw_present) VALUES(?1,?2,'PRIVATE SENDER',?3,0)",params![id,noisefence::now()-10,raw])?;
            db.execute("INSERT INTO deliveries(message_id,address,destination,hosts,next_attempt) VALUES(?1,?2,?2,'[]',0)",params![id,recipient])?;
        }
        db.execute("INSERT INTO deliveries(message_id,address,destination,hosts,next_attempt) VALUES('a','alias@example.test','alice@example.test','[]',0)",[])?;
        db.execute("INSERT INTO quality_labels VALUES('alice','a','legitimate',NULL,?1)",[noisefence::now()])?;
        db.execute("INSERT INTO quality_labels VALUES('bob','a','spam',NULL,?1)",[noisefence::now()])?;
        Ok(())
    }).await.unwrap();
    let report = reliability::audit(&store, "alice".into(), Options::default())
        .await
        .unwrap();
    assert_eq!(report["observations"]["messages"], 1);
    assert_eq!(report["quality_labels"]["counts"]["fp"], 1);
    assert_eq!(
        report["symbols"]["legacy:ip_url"]["false_positives_avoided"],
        1
    );
    assert_eq!(report["targeted_feedback"]["labelled"], 0);
    assert!(report["targeted_feedback"]["false_positive_rate"].is_null());
    assert!(!report.to_string().contains("PRIVATE"));
    assert!(!report.to_string().contains("example.test"));
    assert_eq!(
        reliability::audit(
            &store,
            "alice".into(),
            Options {
                domain: "hidden.test".into(),
                ..Default::default()
            }
        )
        .await
        .unwrap()["observations"]["messages"],
        0
    );
    let app = noisefence::api::router(cfg.clone(), store.clone()).unwrap();
    let response = app
        .clone()
        .oneshot(
            Request::get("/api/v1/quality/reliability")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let login = app
        .clone()
        .oneshot(
            Request::post("/api/v1/login")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ORIGIN, &cfg.web.public_origin)
                .body(Body::from(
                    r#"{"username":"alice","password":"a long password 123"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::OK);
    let cookie = login.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let response = app
        .clone()
        .oneshot(
            Request::get("/api/v1/quality/reliability")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let result: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert!(result.get("system").is_none());
    assert_eq!(result["may_activate"], false);
    let response = app
        .oneshot(
            Request::get("/api/v1/quality/reliability?days=500")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    store
        .run(|db| {
            db.execute("UPDATE users SET disabled=1 WHERE username='alice'", [])?;
            Ok(())
        })
        .await
        .unwrap();
    assert!(
        reliability::audit(&store, "alice".into(), Options::default())
            .await
            .is_err()
    );
}
#[tokio::test]
async fn incomplete_observations_and_uncertain_labels_remain_visible_without_metrics() {
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path()).unwrap();
    let mut scan = Scan::default();
    scan.complete = false;
    scan.score = 99.;
    scan.decision = Some(Decision::legacy(&scan, 95.));
    scan.protection = Some(noisefence::protection::Report {
        crdf: noisefence::protection::ProviderReport {
            status: noisefence::protection::Status::Quota,
            ..Default::default()
        },
        virustotal: noisefence::protection::ProviderReport {
            status: noisefence::protection::Status::Unavailable,
            ..Default::default()
        },
        ..Default::default()
    });
    let raw = serde_json::to_string(&scan).unwrap();
    store.run(move|db| {
        db.execute("INSERT INTO users(username,password,admin) VALUES('admin','unused',1)",[])?;
        for n in 0..4 {
            let id=n.to_string();db.execute("INSERT INTO messages(id,created,sender,scan,raw_present) VALUES(?1,?2,'',?3,0)",params![id,noisefence::now()-5,raw])?;
            db.execute("INSERT INTO deliveries(message_id,address,destination,hosts,next_attempt) VALUES(?1,'user@example.test','user@example.test','[]',0)",[&id])?;
            db.execute("INSERT INTO feedback VALUES('admin',?1,0,?2)",params![id,noisefence::now()])?;
            db.execute("INSERT INTO quality_labels VALUES('admin',?1,'uncertain',NULL,?2)",params![id,noisefence::now()])?;
        } Ok(())
    }).await.unwrap();
    let result = reliability::audit(&store, "admin".into(), Options::default())
        .await
        .unwrap();
    assert_eq!(result["observations"]["incomplete"], 4);
    assert_eq!(result["quality_labels"]["labelled"], 0);
    assert_eq!(result["targeted_feedback"]["labelled"], 0);
    assert_eq!(result["unlabelled"], 4);
    assert!(
        result["alerts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["code"] == "detector_degraded" && a["detector"] == "crdf")
    );
}
#[test]
fn signature_dates_are_bounded_uncertain_and_never_prove_the_loaded_set() {
    let now = 1_783_036_800; // 2026-07-03 00:00 UTC
    let value =
        reliability::health::version_report("ClamAV 1.4.3/28000/Thu Jul  2 12:00:00 2026", now);
    assert_eq!(value["status"], "fresh");
    assert_eq!(value["minimum_age_seconds"], 0);
    assert_eq!(value["maximum_age_seconds"], 26 * 3600);
    assert_eq!(value["exact_loaded_set_verified"], false);
    assert_eq!(
        reliability::health::version_report("ClamAV 1.4/28000/Sun Jun 21 12:00:00 2026", now)["status"],
        "stale"
    );
    for text in [
        "COMMAND UNAVAILABLE",
        "ClamAV 1.4/1/Mon Feb 30 00:00:00 2026",
        "ClamAV 1.4/1/Thu Jul 2 12:bad:00:00 2026",
        "ClamAV 1.4/1/Thu Jul 9 12:00:00 2026",
        "ClamAV 1.4/1/Thu Jul 2 12:00:00 2026\nPRIVATE",
    ] {
        assert_eq!(
            reliability::health::version_report(text, now)["status"],
            "unknown"
        );
    }
}
#[tokio::test]
async fn clamd_probe_uses_only_version_and_bounds_oversized_responses() {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::UnixListener,
    };
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("clam.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut command = [0; 9];
        stream.read_exact(&mut command).await.unwrap();
        assert_eq!(&command, b"zVERSION\0");
        let _ = stream.write_all(&vec![b'a'; 514]).await;
    });
    let config: noisefence::antivirus::AntivirusConfig =
        serde_json::from_value(json!({"socket":path})).unwrap();
    let value = reliability::health::check(Some(&config)).await;
    task.await.unwrap();
    assert_eq!(value["status"], "unavailable");
    assert_eq!(reliability::health::check(None).await["status"], "disabled");
}
#[test]
fn proton_checklist_does_not_promote_missing_or_invalid_evidence() {
    let root = tempfile::tempdir().unwrap();
    let cfg = common::config(root.path());
    let checklist = reliability::proton::checklist(&cfg);
    assert_eq!(checklist["activation_requested"], false);
    assert_eq!(checklist["spam"]["status"], "not_configured");
    let path = root.path().join("report.json");
    std::fs::write(&path, b"{\"private\":\"TOKEN\"}").unwrap();
    let result = reliability::proton::inspect(&cfg, Some(&path), "[SPAM]");
    assert_eq!(result["status"], "invalid");
    assert!(!result.to_string().contains("TOKEN"));
}
