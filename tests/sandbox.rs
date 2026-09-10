//! Contract tests against a local fake CAPEv2 service; no VM or real attachment.
//! Path import deliberately lets the owned module compile before lib.rs integration.
#[allow(dead_code)]
#[path = "../src/sandbox.rs"]
mod sandbox;

use axum::{
    Router,
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use sandbox::{Client, Detail, Disposition, OfficeKind, Outcome, Settings, Status};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

const SAMPLE: &[u8] = b"synthetic-contract-fixture-no-office-code-PRIVATE_PAYLOAD";
fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn message_digest() -> String {
    digest(b"synthetic-message")
}
fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

#[derive(Clone, Default)]
struct Fake {
    state: Arc<Mutex<FakeState>>,
    in_flight: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
}
#[derive(Default)]
struct FakeState {
    tasks: HashMap<u64, Value>,
    uploads: Vec<Vec<u8>>,
    requests: Vec<String>,
    lose_submit_reply: bool,
    delay_ms: u64,
    // A stalled response is released only after the client proves its timeout.
    stall_view: Option<Arc<tokio::sync::Notify>>,
    http_error: bool,
    error_json: bool,
    invalid_json: bool,
    response_bytes: usize,
    wrong_sample: bool,
    wrong_report: bool,
    wrong_custom: bool,
    wrong_task_id: bool,
    wrong_version: bool,
    unknown_status: bool,
    report_errors: bool,
    no_machine: bool,
    findings: usize,
    bad_finding: bool,
    multiple_tasks: bool,
    search_empty: bool,
    malscore: Option<Value>,
}

fn field(body: &[u8], name: &str) -> String {
    let body = std::str::from_utf8(body).unwrap();
    body.split(&format!("name=\"{name}\"\r\n\r\n"))
        .nth(1)
        .unwrap()
        .split("\r\n")
        .next()
        .unwrap()
        .into()
}
async fn submit(State(fake): State<Fake>, headers: HeaderMap, body: Bytes) -> Response {
    assert_eq!(headers["accept-encoding"], "identity");
    let content_type = headers["content-type"].to_str().unwrap();
    let boundary = content_type
        .strip_prefix("multipart/form-data; boundary=")
        .unwrap();
    assert!(body.ends_with(format!("\r\n--{boundary}--\r\n").as_bytes()));
    assert_eq!(field(&body, "machine"), "office-vm");
    assert_eq!(field(&body, "route"), "drop");
    assert_eq!(field(&body, "platform"), "windows");
    // CAPE does not parse this field as a boolean: even "0" can enable static mode.
    assert!(
        !std::str::from_utf8(&body)
            .unwrap()
            .contains("name=\"static\"")
    );
    let start = body
        .windows(42)
        .position(|w| w == b"Content-Type: application/octet-stream\r\n\r\n")
        .unwrap()
        + 42;
    let end = body.len() - format!("\r\n--{boundary}--\r\n").len();
    let payload = &body[start..end];
    let (id, lose, multi) = {
        let mut state = fake.state.lock().unwrap();
        let id = state.tasks.len() as u64 + 1;
        let task = json!({"id":id, "custom":field(&body,"custom"), "category":"file", "package":field(&body,"package"), "sample":{"sha256":digest(payload)}, "status":"pending", "errors":[]});
        state.tasks.insert(id, task.clone());
        state.requests.push("submit".into());
        state.uploads.push(payload.to_vec());
        if state.multiple_tasks {
            let mut extra = task;
            extra["id"] = json!(id + 1);
            state.tasks.insert(id + 1, extra);
        }
        (id, state.lose_submit_reply, state.multiple_tasks)
    };
    if lose {
        return (StatusCode::BAD_GATEWAY, "PRIVATE_ERROR").into_response();
    }
    if multi {
        axum::Json(json!({"error":[], "data":{"task_ids":[id,id+1]}})).into_response()
    } else {
        axum::Json(json!({"error":[], "data":{"task_ids":[id]}})).into_response()
    }
}

async fn view(State(fake): State<Fake>, Path(id): Path<u64>) -> Response {
    let active = fake.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
    fake.peak.fetch_max(active, Ordering::SeqCst);
    let (delay, stall) = {
        let state = fake.state.lock().unwrap();
        (state.delay_ms, state.stall_view.clone())
    };
    if let Some(stall) = stall {
        stall.notified().await;
    }
    tokio::time::sleep(Duration::from_millis(delay)).await;
    fake.in_flight.fetch_sub(1, Ordering::SeqCst);
    let mut state = fake.state.lock().unwrap();
    state.requests.push("view".into());
    if state.http_error {
        return (StatusCode::SERVICE_UNAVAILABLE, "PRIVATE_ERROR").into_response();
    }
    if state.error_json {
        return axum::Json(json!({"error":true,"error_value":"PRIVATE_ERROR"})).into_response();
    }
    if state.invalid_json {
        return "PRIVATE_NOT_JSON".into_response();
    }
    if state.response_bytes > 0 {
        return "x".repeat(state.response_bytes).into_response();
    }
    let mut task = state.tasks[&id].clone();
    if state.wrong_sample {
        task["sample"]["sha256"] = json!("a".repeat(64));
    }
    if state.wrong_custom {
        task["custom"] = json!("another-job");
    }
    if state.wrong_task_id {
        task["id"] = json!(id + 1);
    }
    if state.unknown_status {
        task["status"] = json!("recovered");
    }
    axum::Json(json!({"error":false,"data":task})).into_response()
}
async fn search(State(fake): State<Fake>, Path(sha): Path<String>) -> Response {
    let mut state = fake.state.lock().unwrap();
    state.requests.push("search".into());
    let tasks: Vec<_> = if state.search_empty {
        vec![]
    } else {
        state
            .tasks
            .values()
            .filter(|t| t["sample"]["sha256"] == sha)
            .cloned()
            .collect()
    };
    axum::Json(json!({"error":[], "data":tasks})).into_response()
}
async fn report(State(fake): State<Fake>, Path((id, format)): Path<(u64, String)>) -> Response {
    assert!(format == "json" || format == "litereport");
    let mut state = fake.state.lock().unwrap();
    state.requests.push("report".into());
    let task = &state.tasks[&id];
    let signatures: Vec<_> = (0..state.findings).map(|i| json!({"name":if state.bad_finding { "PRIVATE\nCOMMAND".to_string() } else { format!("office_process_{i}") }, "severity":3, "confidence":90, "weight":10000, "categories":["malware"], "description":"PRIVATE_DESCRIPTION", "marks":[{"command":"PRIVATE_COMMAND"}], "data":["PRIVATE_MACRO"]})).collect();
    let mut value = json!({
        "info":{"id":id,"custom":task["custom"],"category":"file","package":task["package"],"version":if state.wrong_version {"wrong"} else {"2.5"},"duration":60,"machine":{"name":"office-vm"},"CAPE_current_commit":"a".repeat(40)},
        "target":{"file":{"sha256": if state.wrong_report { json!("b".repeat(64)) } else { task["sample"]["sha256"].clone() }, "data":"PRIVATE_ATTACHMENT"}},
        "signatures": signatures,
        "behavior":{"processes":[{"command_line":"PRIVATE_COMMAND_LINE"}]},
        "debug":{"errors":if state.report_errors {json!(["PRIVATE_ERROR"])} else {json!([])}}
    });
    if state.no_machine {
        value["info"]["machine"] = Value::Null;
    }
    if let Some(score) = &state.malscore {
        value["malscore"] = score.clone();
    }
    // Backend classifications and individual weights are not gateway decisions.
    value["malstatus"] = json!("Malicious");
    axum::Json(value).into_response()
}

struct Harness {
    _root: tempfile::TempDir,
    settings: Settings,
    fake: Fake,
    server: tokio::task::JoinHandle<()>,
}
impl Harness {
    async fn new() -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let root = tempfile::tempdir().unwrap();
        let fake = Fake::default();
        let app = Router::new()
            .route("/apiv2/tasks/create/file/", post(submit))
            .route("/apiv2/tasks/view/{id}/", get(view))
            .route("/apiv2/tasks/search/sha256/{sha}/", get(search))
            .route("/apiv2/tasks/get/report/{id}/{format}/", get(report))
            .with_state(fake.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let settings = Settings {
            enabled: true,
            state_dir: root.path().join("sandbox"),
            endpoint: format!("http://{address}/apiv2/"),
            machine: "office-vm".into(),
            expected_version: Some("2.5".into()),
            request_timeout_ms: 100,
            analysis_timeout_secs: 1,
            job_timeout_secs: 10,
            poll_interval_ms: 100,
            max_attachment_bytes: 1024,
            max_total_bytes: 4096,
            max_jobs: 20,
            max_response_bytes: 8192,
            ..Default::default()
        };
        Self {
            _root: root,
            settings,
            fake,
            server,
        }
    }
    fn client(&self) -> Client {
        Client::new(self.settings.clone()).unwrap()
    }
    async fn enqueue(&self, client: &Client) -> sandbox::Summary {
        client
            .enqueue(
                &message_digest(),
                SAMPLE,
                OfficeKind::Docm,
                Disposition::ResearchOnly,
            )
            .await
            .unwrap()
    }
    fn status(&self, id: u64, status: &str) {
        self.fake.state.lock().unwrap().tasks.get_mut(&id).unwrap()["status"] = json!(status);
    }
    async fn tick(&self, client: &Client) -> usize {
        tokio::time::sleep(Duration::from_millis(115)).await;
        client.tick().await.unwrap()
    }
}
impl Drop for Harness {
    fn drop(&mut self) {
        self.server.abort();
    }
}

#[tokio::test]
async fn disabled_is_default_and_never_creates_state() {
    let root = tempfile::tempdir().unwrap();
    let settings = Settings {
        state_dir: root.path().join("absent"),
        token_file: Some(root.path().join("missing-token")),
        ..Default::default()
    };
    settings.validate().unwrap();
    let client = Client::new(settings).unwrap();
    assert!(!client.enabled());
    assert_eq!(
        client
            .enqueue("invalid", SAMPLE, OfficeKind::Doc, Disposition::Quarantine)
            .await
            .unwrap()
            .status,
        Status::Disabled
    );
    assert_eq!(client.tick().await.unwrap(), 0);
    assert!(!root.path().join("absent").exists());
}

#[test]
fn settings_restrict_destinations_and_resource_bounds() {
    for endpoint in [
        "https://example.com/apiv2/",
        "https://8.8.8.8/apiv2/",
        "http://10.0.0.1/apiv2/",
        "http://127.0.0.1/",
        "http://127.0.0.1/apiv2/?next=http://example.com",
        "http://user:secret@127.0.0.1/apiv2/",
        "http://[::ffff:8.8.8.8]/apiv2/",
    ] {
        assert!(
            Settings {
                endpoint: endpoint.into(),
                ..Default::default()
            }
            .validate()
            .is_err(),
            "{endpoint}"
        );
    }
    for endpoint in [
        "http://[::1]:8000/apiv2/",
        "https://10.0.0.1/apiv2/",
        "https://[fd00::1]/apiv2/",
    ] {
        Settings {
            endpoint: endpoint.into(),
            ..Default::default()
        }
        .validate()
        .unwrap();
    }
    assert!(
        Settings {
            enabled: true,
            machine: "all".into(),
            ..Default::default()
        }
        .validate()
        .is_err()
    );
    assert!(
        Settings {
            max_parallel: 0,
            ..Default::default()
        }
        .validate()
        .is_err()
    );
    assert!(
        Settings {
            max_response_bytes: usize::MAX,
            ..Default::default()
        }
        .validate()
        .is_err()
    );
    assert!(
        Settings {
            request_timeout_ms: 0,
            ..Default::default()
        }
        .validate()
        .is_err()
    );
}

#[tokio::test]
async fn persisted_enqueue_restart_poll_and_redacted_result() {
    let h = Harness::new().await;
    h.fake.state.lock().unwrap().findings = 2;
    let client = h.client();
    let queued = h.enqueue(&client).await;
    assert_eq!(queued.status, Status::Queued);
    assert!(h.fake.state.lock().unwrap().requests.is_empty());
    let same = h.enqueue(&client).await;
    assert_eq!(queued.job_id, same.job_id);
    drop(client);
    let client = h.client();
    assert_eq!(client.tick().await.unwrap(), 1);
    let submitted = client.get(&queued.job_id).await.unwrap().unwrap();
    assert_eq!(submitted.status, Status::Submitted);
    assert_eq!(submitted.remote_task_id, Some(1));
    assert_eq!(h.fake.state.lock().unwrap().uploads, [SAMPLE]);
    let db = rusqlite::Connection::open(h.settings.state_dir.join("jobs.sqlite3")).unwrap();
    let remaining: Option<Vec<u8>> = db
        .query_row("SELECT payload FROM jobs", [], |r| r.get(0))
        .unwrap();
    assert!(remaining.is_none());
    drop(client);
    let client = h.client();
    h.status(1, "running");
    h.tick(&client).await;
    assert_eq!(
        client.get(&queued.job_id).await.unwrap().unwrap().status,
        Status::Running
    );
    h.status(1, "completed");
    h.tick(&client).await;
    assert_eq!(
        client.get(&queued.job_id).await.unwrap().unwrap().status,
        Status::Reporting
    );
    h.status(1, "reported");
    h.tick(&client).await;
    let complete = client.get(&queued.job_id).await.unwrap().unwrap();
    assert_eq!(complete.status, Status::Complete);
    assert_eq!(complete.outcome, Outcome::Findings);
    assert_eq!(complete.findings.len(), 2);
    assert_eq!(complete.findings[0].id, "office_process_0");
    assert_eq!(complete.provenance.engine_version.as_deref(), Some("2.5"));
    assert!(!complete.provenance.isolation_verified);
    assert!(complete.provenance.report_sha256.is_some());
    complete.validate().unwrap();
    assert!(
        !serde_json::to_string(&complete)
            .unwrap()
            .contains("PRIVATE")
    );
    let persisted: String = db
        .query_row("SELECT summary FROM jobs", [], |r| r.get(0))
        .unwrap();
    assert!(!persisted.contains("PRIVATE"));
    assert_eq!(h.tick(&client).await, 0);
    assert_eq!(h.fake.state.lock().unwrap().uploads.len(), 1);
    assert_eq!(client.list(0, 100).await.unwrap().len(), 1);
    client.remove(&queued.job_id).await.unwrap();
    assert!(client.get(&queued.job_id).await.unwrap().is_none());
}

#[tokio::test]
async fn lost_submission_response_reconciles_after_restart_without_reupload() {
    let h = Harness::new().await;
    h.fake.state.lock().unwrap().lose_submit_reply = true;
    let client = h.client();
    let job = h.enqueue(&client).await;
    client.tick().await.unwrap();
    let uncertain = client.get(&job.job_id).await.unwrap().unwrap();
    assert_eq!(uncertain.status, Status::Uncertain);
    assert!(uncertain.remote_slot_held);
    drop(client);
    let client = h.client();
    h.tick(&client).await;
    let recovered = client.get(&job.job_id).await.unwrap().unwrap();
    assert_eq!(recovered.remote_task_id, Some(1));
    assert_eq!(recovered.status, Status::Submitted);
    assert_eq!(h.fake.state.lock().unwrap().uploads.len(), 1);
}

#[tokio::test]
async fn crash_after_submission_intent_uses_search_never_a_second_post() {
    let h = Harness::new().await;
    let client = h.client();
    let job = h.enqueue(&client).await;
    drop(client);
    let db = rusqlite::Connection::open(h.settings.state_dir.join("jobs.sqlite3")).unwrap();
    let mut job = job;
    job.status = Status::Submitting;
    job.remote_slot_held = true;
    db.execute(
        "UPDATE jobs SET summary=?1",
        [serde_json::to_string(&job).unwrap()],
    )
    .unwrap();
    drop(db);
    let client = h.client();
    client.tick().await.unwrap();
    assert_eq!(
        client.get(&job.job_id).await.unwrap().unwrap().status,
        Status::Uncertain
    );
    assert!(h.fake.state.lock().unwrap().uploads.is_empty());
    assert_eq!(h.fake.state.lock().unwrap().requests, ["search"]);
}

#[tokio::test]
async fn local_spool_digest_is_checked_before_any_upload() {
    let h = Harness::new().await;
    let client = h.client();
    let job = h.enqueue(&client).await;
    let db = rusqlite::Connection::open(h.settings.state_dir.join("jobs.sqlite3")).unwrap();
    db.execute("UPDATE jobs SET payload=?1", [b"modified".to_vec()])
        .unwrap();
    client.tick().await.unwrap();
    let failed = client.get(&job.job_id).await.unwrap().unwrap();
    assert_eq!(failed.status, Status::Failed);
    assert_eq!(failed.detail, Some(Detail::DigestMismatch));
    assert!(!failed.remote_slot_held);
    assert!(h.fake.state.lock().unwrap().requests.is_empty());
}

#[tokio::test]
async fn task_report_identity_and_backend_mismatches_are_inconclusive() {
    for variant in 0..6 {
        let h = Harness::new().await;
        let client = h.client();
        let job = h.enqueue(&client).await;
        client.tick().await.unwrap();
        h.status(1, "reported");
        let expected = {
            let mut state = h.fake.state.lock().unwrap();
            match variant {
                0 => {
                    state.wrong_sample = true;
                    Detail::DigestMismatch
                }
                1 => {
                    state.wrong_report = true;
                    Detail::DigestMismatch
                }
                2 => {
                    state.wrong_custom = true;
                    Detail::TaskMismatch
                }
                3 => {
                    state.wrong_task_id = true;
                    Detail::TaskMismatch
                }
                4 => {
                    state.wrong_version = true;
                    Detail::BackendMismatch
                }
                _ => {
                    state.unknown_status = true;
                    Detail::InvalidResponse
                }
            }
        };
        h.tick(&client).await;
        let result = client.get(&job.job_id).await.unwrap().unwrap();
        assert_eq!(result.status, Status::Failed);
        assert_eq!(result.detail, Some(expected));
        assert_eq!(result.outcome, Outcome::Inconclusive);
        assert!(result.findings.is_empty());
    }
}

#[tokio::test]
async fn remote_failures_deadlines_and_protocol_errors_never_become_clean() {
    for variant in 0..6 {
        let h = Harness::new().await;
        let client = h.client();
        let job = h.enqueue(&client).await;
        client.tick().await.unwrap();
        let release = Arc::new(tokio::sync::Notify::new());
        let expected = {
            let mut s = h.fake.state.lock().unwrap();
            match variant {
                0 => {
                    s.stall_view = Some(release.clone());
                    Detail::RequestTimeout
                }
                1 => {
                    s.http_error = true;
                    Detail::HttpError
                }
                2 => {
                    s.error_json = true;
                    Detail::ApiError
                }
                3 => {
                    s.invalid_json = true;
                    Detail::InvalidResponse
                }
                4 => {
                    s.response_bytes = 9000;
                    Detail::ResponseLimit
                }
                _ => {
                    s.tasks.get_mut(&1).unwrap()["status"] = json!("failed_analysis");
                    Detail::AnalysisFailed
                }
            }
        };
        // A 450 ms wall-clock assertion included poll scheduling and durable
        // SQLite writes and failed on a contended Linux runner. Exercise the
        // actual timeout against a response which cannot arrive on its own.
        tokio::time::timeout(Duration::from_secs(5), h.tick(&client))
            .await
            .expect("sandbox tick did not terminate");
        let result = client.get(&job.job_id).await.unwrap().unwrap();
        assert_eq!(result.detail, Some(expected), "variant {variant}");
        assert_eq!(result.outcome, Outcome::Inconclusive);
        assert!(!serde_json::to_string(&result).unwrap().contains("PRIVATE"));
        release.notify_waiters();
    }
}

#[tokio::test]
async fn transient_poll_error_recovers_without_new_submission() {
    let h = Harness::new().await;
    let client = h.client();
    let job = h.enqueue(&client).await;
    client.tick().await.unwrap();
    h.fake.state.lock().unwrap().http_error = true;
    h.tick(&client).await;
    h.fake.state.lock().unwrap().http_error = false;
    h.status(1, "reported");
    h.tick(&client).await;
    let result = client.get(&job.job_id).await.unwrap().unwrap();
    assert_eq!(result.outcome, Outcome::NoFindings);
    assert_eq!(result.status, Status::Complete);
    assert!(result.detail.is_none());
    assert_eq!(h.fake.state.lock().unwrap().uploads.len(), 1);
}

#[tokio::test]
async fn findings_are_bounded_and_incomplete_execution_is_explicit() {
    for variant in 0..4 {
        let mut h = Harness::new().await;
        h.settings.max_findings = 1;
        let client = h.client();
        let job = h.enqueue(&client).await;
        client.tick().await.unwrap();
        h.status(1, "reported");
        {
            let mut state = h.fake.state.lock().unwrap();
            match variant {
                0 => {
                    state.findings = 2;
                }
                1 => {
                    state.report_errors = true;
                }
                2 => {
                    state.no_machine = true;
                }
                _ => {
                    state.findings = 1;
                    state.bad_finding = true;
                }
            }
        }
        h.tick(&client).await;
        let result = client.get(&job.job_id).await.unwrap().unwrap();
        assert_eq!(result.outcome, Outcome::Inconclusive);
        assert!(result.findings.len() <= 1);
        if variant == 0 {
            assert!(result.findings_truncated);
            assert_eq!(result.detail, Some(Detail::FindingLimit));
        }
        assert!(!serde_json::to_string(&result).unwrap().contains("PRIVATE"));
    }
}

#[tokio::test]
async fn queue_byte_row_and_parallel_limits_survive_restart() {
    let mut h = Harness::new().await;
    h.settings.max_attachment_bytes = 60;
    h.settings.max_total_bytes = 100;
    h.settings.max_jobs = 2;
    let client = h.client();
    assert!(
        client
            .enqueue(
                &message_digest(),
                &[0; 61],
                OfficeKind::Doc,
                Disposition::ResearchOnly
            )
            .await
            .is_err()
    );
    let first = h.enqueue(&client).await;
    assert!(
        client
            .enqueue(
                &digest(b"two"),
                SAMPLE,
                OfficeKind::Docm,
                Disposition::ResearchOnly
            )
            .await
            .is_err()
    );
    client.tick().await.unwrap();
    let second = client
        .enqueue(
            &digest(b"two"),
            SAMPLE,
            OfficeKind::Docm,
            Disposition::ResearchOnly,
        )
        .await
        .unwrap();
    assert!(
        client
            .enqueue(
                &digest(b"three"),
                &[0],
                OfficeKind::Docm,
                Disposition::ResearchOnly
            )
            .await
            .is_err()
    );
    drop(client);
    let client = h.client();
    h.tick(&client).await;
    assert_eq!(h.fake.state.lock().unwrap().uploads.len(), 1);
    assert_eq!(
        client.get(&second.job_id).await.unwrap().unwrap().status,
        Status::Queued
    );
    assert!(client.remove(&first.job_id).await.is_err());
    h.status(1, "reported");
    h.tick(&client).await;
    client.tick().await.unwrap();
    assert_eq!(h.fake.state.lock().unwrap().uploads.len(), 2);
}

#[tokio::test]
async fn concurrent_tick_and_cancelled_wait_do_not_duplicate_or_exceed_parallelism() {
    let mut h = Harness::new().await;
    h.settings.max_parallel = 2;
    h.settings.request_timeout_ms = 1000;
    let client = h.client();
    h.enqueue(&client).await;
    client
        .enqueue(
            &digest(b"other"),
            SAMPLE,
            OfficeKind::Xlsm,
            Disposition::ResearchOnly,
        )
        .await
        .unwrap();
    client.tick().await.unwrap();
    h.fake.state.lock().unwrap().delay_ms = 250;
    tokio::time::sleep(Duration::from_millis(120)).await;
    let c = client.clone();
    let waiting = tokio::spawn(async move { c.tick().await.unwrap() });
    tokio::time::sleep(Duration::from_millis(30)).await;
    waiting.abort();
    assert_eq!(client.tick().await.unwrap(), 0);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(h.fake.peak.load(Ordering::SeqCst), 2);
    assert_eq!(h.fake.state.lock().unwrap().uploads.len(), 2);
}

#[tokio::test]
async fn expiry_keeps_unknown_remote_slot_until_operator_acknowledges() {
    let mut h = Harness::new().await;
    h.settings.job_timeout_secs = 1;
    let client = h.client();
    h.fake.state.lock().unwrap().lose_submit_reply = true;
    h.fake.state.lock().unwrap().search_empty = true;
    let job = client
        .enqueue(
            &message_digest(),
            SAMPLE,
            OfficeKind::Docm,
            Disposition::Quarantine,
        )
        .await
        .unwrap();
    assert!(job.requires_quarantine());
    client.tick().await.unwrap();
    tokio::time::sleep(Duration::from_millis(1050)).await;
    client.tick().await.unwrap();
    let expired = client.get(&job.job_id).await.unwrap().unwrap();
    assert_eq!(expired.status, Status::TimedOut);
    assert_eq!(expired.detail, Some(Detail::JobTimeout));
    assert!(expired.remote_slot_held);
    assert!(expired.requires_quarantine());
    assert!(client.remove(&job.job_id).await.is_err());
    client
        .acknowledge_remote_stopped(&job.job_id)
        .await
        .unwrap();
    client.remove(&job.job_id).await.unwrap();
}

#[tokio::test]
async fn unsubmitted_expiry_discards_bytes_without_network_or_remote_slot() {
    let mut h = Harness::new().await;
    h.settings.job_timeout_secs = 1;
    let client = h.client();
    let job = h.enqueue(&client).await;
    tokio::time::sleep(Duration::from_millis(1050)).await;
    assert_eq!(client.tick().await.unwrap(), 0);
    let expired = client.get(&job.job_id).await.unwrap().unwrap();
    assert_eq!(expired.status, Status::TimedOut);
    assert!(!expired.remote_slot_held);
    assert!(h.fake.state.lock().unwrap().requests.is_empty());
}

#[tokio::test]
async fn policy_binding_and_single_worker_lock_prevent_wrong_backend_reuse() {
    let h = Harness::new().await;
    let client = h.client();
    assert!(Client::new(h.settings.clone()).is_err());
    h.enqueue(&client).await;
    drop(client);
    let mut changed = h.settings.clone();
    changed.instance_id = "different-cape".into();
    assert!(Client::new(changed).is_err());
    let client = h.client();
    assert_eq!(client.list(0, 100).await.unwrap().len(), 1);
}

#[tokio::test]
async fn quarantine_does_not_authorize_release_even_without_findings() {
    let h = Harness::new().await;
    let client = h.client();
    let job = client
        .enqueue(
            &message_digest(),
            SAMPLE,
            OfficeKind::Pptm,
            Disposition::Quarantine,
        )
        .await
        .unwrap();
    client.tick().await.unwrap();
    h.status(1, "reported");
    h.tick(&client).await;
    let result = client.get(&job.job_id).await.unwrap().unwrap();
    assert_eq!(result.outcome, Outcome::NoFindings);
    assert!(result.requires_quarantine());
}

#[tokio::test]
async fn multiple_task_fanout_freezes_all_admission_until_operator_reconciliation() {
    let mut h = Harness::new().await;
    h.settings.max_parallel = 2;
    h.fake.state.lock().unwrap().multiple_tasks = true;
    let client = h.client();
    let first = h.enqueue(&client).await;
    client.tick().await.unwrap();
    let bad = client.get(&first.job_id).await.unwrap().unwrap();
    assert_eq!(bad.status, Status::Failed);
    assert_eq!(bad.detail, Some(Detail::MultipleTasks));
    assert!(bad.remote_fanout && bad.remote_slot_held);
    let second = client
        .enqueue(
            &digest(b"next"),
            SAMPLE,
            OfficeKind::Docm,
            Disposition::ResearchOnly,
        )
        .await
        .unwrap();
    drop(client);
    let client = h.client();
    assert_eq!(h.tick(&client).await, 0);
    assert_eq!(
        client.get(&second.job_id).await.unwrap().unwrap().status,
        Status::Queued
    );
    assert_eq!(h.fake.state.lock().unwrap().uploads.len(), 1);
    // Simulate the operator verifying all tasks stopped before acknowledgement.
    h.fake.state.lock().unwrap().tasks.clear();
    h.fake.state.lock().unwrap().multiple_tasks = false;
    client
        .acknowledge_remote_stopped(&first.job_id)
        .await
        .unwrap();
    client.tick().await.unwrap();
    assert_eq!(h.fake.state.lock().unwrap().uploads.len(), 2);
}

#[tokio::test]
async fn recovery_will_not_adopt_same_digest_from_a_different_job() {
    let h = Harness::new().await;
    h.fake.state.lock().unwrap().lose_submit_reply = true;
    let client = h.client();
    let job = h.enqueue(&client).await;
    client.tick().await.unwrap();
    h.fake.state.lock().unwrap().tasks.get_mut(&1).unwrap()["custom"] =
        json!("unrelated-submission");
    h.tick(&client).await;
    let result = client.get(&job.job_id).await.unwrap().unwrap();
    assert_eq!(result.status, Status::Uncertain);
    assert_eq!(result.remote_task_id, None);
    assert!(result.remote_slot_held);
    assert_eq!(h.fake.state.lock().unwrap().uploads.len(), 1);
}

#[tokio::test]
async fn malformed_chunked_stalled_and_redirect_responses_are_bounded() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // Seed a durable submitted job so this fake peer handles only a GET.
    // The third case's redirect destination is another loopback listener, never public.
    let sentinel = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let redirect = format!(
        "http://{}/must-not-be-called",
        sentinel.local_addr().unwrap()
    );
    for variant in 0..4 {
        let h = Harness::new().await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut settings = h.settings.clone();
        settings.endpoint = format!("http://{}/apiv2/", listener.local_addr().unwrap());
        settings.max_response_bytes = 1024;
        let client = Client::new(settings.clone()).unwrap();
        let mut job = h.enqueue(&client).await;
        drop(client);
        job.status = Status::Submitted;
        job.remote_task_id = Some(1);
        job.remote_slot_held = true;
        let db = rusqlite::Connection::open(settings.state_dir.join("jobs.sqlite3")).unwrap();
        db.execute(
            "UPDATE jobs SET summary=?1, payload=NULL",
            [serde_json::to_string(&job).unwrap()],
        )
        .unwrap();
        drop(db);
        let client = Client::new(settings).unwrap();
        let redirect = redirect.clone();
        let fake = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(stream.read_u8().await.unwrap());
                assert!(request.len() <= 8192);
            }
            assert!(request.starts_with(b"GET /apiv2/tasks/view/1/ HTTP/1.1"));
            let response = match variant {
                0 => format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n800\r\n{}\r\n0\r\n\r\n", "x".repeat(2048)),
                1 => "HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{".into(),
                2 => format!("HTTP/1.1 307 Temporary Redirect\r\nLocation: {redirect}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
                _ => "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}".into(),
            };
            stream.write_all(response.as_bytes()).await.unwrap();
            if variant == 1 {
                tokio::time::sleep(Duration::from_millis(400)).await;
            }
        });
        let start = std::time::Instant::now();
        client.tick().await.unwrap();
        assert!(start.elapsed() < Duration::from_millis(350));
        let result = client.get(&job.job_id).await.unwrap().unwrap();
        assert_eq!(
            result.detail,
            Some(match variant {
                0 => Detail::ResponseLimit,
                1 => Detail::RequestTimeout,
                2 => Detail::HttpError,
                _ => Detail::InvalidResponse,
            })
        );
        assert_eq!(result.outcome, Outcome::Inconclusive);
        if variant == 1 {
            fake.abort();
        } else {
            fake.await.unwrap();
        }
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(20), sentinel.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn private_state_rejects_symlinks_and_world_readable_directories() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let h = Harness::new().await;
    std::fs::create_dir(&h.settings.state_dir).unwrap();
    std::fs::set_permissions(
        &h.settings.state_dir,
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    assert!(Client::new(h.settings.clone()).is_err());
    std::fs::set_permissions(
        &h.settings.state_dir,
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let other = h.settings.state_dir.join("other");
    std::fs::write(&other, b"unchanged").unwrap();
    symlink(&other, h.settings.state_dir.join("jobs.sqlite3")).unwrap();
    assert!(Client::new(h.settings.clone()).is_err());
    assert_eq!(std::fs::read(&other).unwrap(), b"unchanged");
}

#[tokio::test]
async fn cape_score_is_optional_named_backend_metadata_never_a_malware_verdict() {
    for (score, findings) in [
        (None, 0),
        (Some(json!(0)), 1),
        (Some(json!(10.0)), 0),
        (Some(json!(9.5)), 1),
    ] {
        let h = Harness::new().await;
        {
            let mut state = h.fake.state.lock().unwrap();
            state.malscore = score.clone();
            state.findings = findings;
        }
        let client = h.client();
        let job = client
            .enqueue(
                &message_digest(),
                SAMPLE,
                OfficeKind::Docm,
                Disposition::Quarantine,
            )
            .await
            .unwrap();
        client.tick().await.unwrap();
        h.status(1, "reported");
        h.tick(&client).await;
        let result = client.get(&job.job_id).await.unwrap().unwrap();
        assert_eq!(result.status, Status::Complete);
        assert_eq!(result.cape_malscore, score.as_ref().and_then(Value::as_f64));
        assert_eq!(
            result.outcome,
            if findings == 0 {
                Outcome::NoFindings
            } else {
                Outcome::Findings
            }
        );
        assert!(result.requires_quarantine());
        result.validate().unwrap();
        let json = serde_json::to_value(&result).unwrap();
        assert!(json.get("malstatus").is_none());
        assert!(!json.to_string().contains("Malicious"));
        assert!(!json.to_string().contains("malware"));
        if findings > 0 {
            assert!(json["findings"][0].get("weight").is_none());
            assert!(json["findings"][0].get("categories").is_none());
        }
        drop(client);
        let restarted = h.client();
        assert_eq!(
            restarted
                .get(&job.job_id)
                .await
                .unwrap()
                .unwrap()
                .cape_malscore,
            result.cape_malscore
        );
    }
}

#[tokio::test]
async fn malformed_cape_score_is_inconclusive_and_old_summaries_remain_readable() {
    for score in [
        json!(-1),
        json!(10.01),
        json!("PRIVATE_SCORE"),
        json!({"value":5}),
    ] {
        let h = Harness::new().await;
        h.fake.state.lock().unwrap().malscore = Some(score);
        let client = h.client();
        let job = h.enqueue(&client).await;
        client.tick().await.unwrap();
        h.status(1, "reported");
        h.tick(&client).await;
        let result = client.get(&job.job_id).await.unwrap().unwrap();
        assert_eq!(result.outcome, Outcome::Inconclusive);
        assert_eq!(result.detail, Some(Detail::InvalidResponse));
        assert!(result.cape_malscore.is_none());
        assert!(!serde_json::to_string(&result).unwrap().contains("PRIVATE"));
        let mut json = serde_json::to_value(&result).unwrap();
        json.as_object_mut().unwrap().remove("cape_malscore");
        let old: sandbox::Summary = serde_json::from_value(json).unwrap();
        old.validate().unwrap();
        assert!(old.cape_malscore.is_none());
    }
}

#[tokio::test]
async fn actual_client_policy_and_timestamped_enqueue_are_stable_after_restart() {
    let h = Harness::new().await;
    let client = h.client();
    assert_eq!(client.policy_sha256(), Some(h.settings.policy_sha256()));
    let created = now_ms() - 1000;
    let first = client
        .enqueue_created_at(
            &message_digest(),
            SAMPLE,
            OfficeKind::Docm,
            Disposition::ResearchOnly,
            created,
        )
        .await
        .unwrap();
    assert_eq!(first.created_at_ms, created);
    drop(client);
    let restarted = h.client();
    let retry = restarted
        .enqueue_created_at(
            &message_digest(),
            SAMPLE,
            OfficeKind::Docm,
            Disposition::ResearchOnly,
            created,
        )
        .await
        .unwrap();
    assert_eq!(first.job_id, retry.job_id);
    let disabled = Client::new(Settings::default()).unwrap();
    assert_eq!(disabled.policy_sha256(), None);
    assert!(disabled.prune_before(now_ms()).await.is_err());
}

#[tokio::test]
async fn retention_scrubs_payload_digests_results_and_provenance_but_keeps_remote_reservation() {
    let h = Harness::new().await;
    let client = h.client();
    h.fake.state.lock().unwrap().findings = 1;
    let result_job = h.enqueue(&client).await;
    client.tick().await.unwrap();
    h.status(1, "reported");
    h.tick(&client).await;
    let result = client.get(&result_job.job_id).await.unwrap().unwrap();
    let unresolved = client
        .enqueue(
            &digest(b"uncertain"),
            b"SECRET_ATTACHMENT_IN_SPOOL",
            OfficeKind::Docm,
            Disposition::Quarantine,
        )
        .await
        .unwrap();
    let db = rusqlite::Connection::open(h.settings.state_dir.join("jobs.sqlite3")).unwrap();
    // Simulate a crash after sending intent, before payload cleanup.
    let mut uncertain = unresolved.clone();
    uncertain.status = Status::Uncertain;
    uncertain.remote_slot_held = true;
    uncertain.remote_task_id = Some(2);
    db.execute(
        "UPDATE jobs SET summary=?1 WHERE id=?2",
        rusqlite::params![serde_json::to_string(&uncertain).unwrap(), uncertain.job_id],
    )
    .unwrap();
    assert_eq!(client.prune_before(now_ms()).await.unwrap(), 2);
    assert!(client.get(&unresolved.job_id).await.unwrap().is_none());
    assert!(client.get(&result.job_id).await.unwrap().is_none());
    assert!(client.list(0, 100).await.unwrap().is_empty());
    let tombstones = client.tombstones(0, 100).await.unwrap();
    assert_eq!(
        tombstones,
        [sandbox::RemoteReservation {
            job_id: unresolved.job_id.clone(),
            remote_task_id: Some(2),
            remote_fanout: false
        }]
    );
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM jobs", [], |r| r.get::<_, usize>(0))
            .unwrap(),
        0
    );
    let bytes = std::fs::read(h.settings.state_dir.join("jobs.sqlite3")).unwrap();
    for secret in [
        b"SECRET_ATTACHMENT_IN_SPOOL".as_slice(),
        result.message_sha256.as_bytes(),
        result.attachment_sha256.as_bytes(),
        result.provenance.report_sha256.as_ref().unwrap().as_bytes(),
        b"office_process_0",
        h.settings.environment_id.as_bytes(),
        unresolved.attachment_sha256.as_bytes(),
    ] {
        assert!(
            !bytes.windows(secret.len()).any(|window| window == secret),
            "scrubbed bytes survived"
        );
    }
    assert_eq!(client.prune_before(now_ms()).await.unwrap(), 0);
    assert_eq!(client.tombstones(0, 100).await.unwrap().len(), 1);
    assert!(client.remove(&unresolved.job_id).await.is_err());
}

#[tokio::test]
async fn pruning_preserves_capacity_and_fanout_on_restart_and_never_polls_tombstones() {
    for fanout in [false, true] {
        let mut h = Harness::new().await;
        h.settings.max_parallel = if fanout { 2 } else { 1 };
        h.fake.state.lock().unwrap().multiple_tasks = fanout;
        h.fake.state.lock().unwrap().lose_submit_reply = !fanout;
        let client = h.client();
        let job = h.enqueue(&client).await;
        client.tick().await.unwrap();
        let cutoff = now_ms();
        client.prune_before(cutoff).await.unwrap();
        drop(client);
        let client = h.client();
        tokio::time::sleep(Duration::from_millis(10)).await;
        let fresh = client
            .enqueue_created_at(
                &digest(b"new-intent"),
                SAMPLE,
                OfficeKind::Docm,
                Disposition::ResearchOnly,
                now_ms(),
            )
            .await
            .unwrap();
        let requests = h.fake.state.lock().unwrap().requests.len();
        assert_eq!(client.tick().await.unwrap(), 0);
        assert_eq!(h.fake.state.lock().unwrap().requests.len(), requests);
        assert_eq!(
            client.get(&fresh.job_id).await.unwrap().unwrap().status,
            Status::Queued
        );
        assert_eq!(
            client.tombstones(0, 100).await.unwrap()[0].remote_fanout,
            fanout
        );
        // The operator's explicit action alone frees this tombstone, after inspection.
        h.fake.state.lock().unwrap().tasks.clear();
        h.fake.state.lock().unwrap().multiple_tasks = false;
        h.fake.state.lock().unwrap().lose_submit_reply = false;
        client
            .acknowledge_remote_stopped(&job.job_id)
            .await
            .unwrap();
        assert!(client.tombstones(0, 100).await.unwrap().is_empty());
        assert_eq!(client.tick().await.unwrap(), 1);
    }
}

#[tokio::test]
async fn retention_floor_rejects_stale_outbox_replay_and_requires_creation_time_for_new_jobs() {
    let h = Harness::new().await;
    let client = h.client();
    let created = now_ms() - 1000;
    let job = client
        .enqueue_created_at(
            &message_digest(),
            SAMPLE,
            OfficeKind::Docm,
            Disposition::ResearchOnly,
            created,
        )
        .await
        .unwrap();
    let cutoff = now_ms();
    assert_eq!(client.prune_before(cutoff).await.unwrap(), 1);
    drop(client);
    let client = h.client();
    assert!(
        client
            .enqueue_created_at(
                &message_digest(),
                SAMPLE,
                OfficeKind::Docm,
                Disposition::ResearchOnly,
                created
            )
            .await
            .is_err()
    );
    assert!(
        client
            .enqueue(
                &message_digest(),
                SAMPLE,
                OfficeKind::Docm,
                Disposition::ResearchOnly
            )
            .await
            .is_err()
    );
    assert!(
        client
            .enqueue_created_at(
                &message_digest(),
                SAMPLE,
                OfficeKind::Docm,
                Disposition::ResearchOnly,
                cutoff
            )
            .await
            .is_err()
    );
    assert!(
        client
            .enqueue_created_at(
                &message_digest(),
                SAMPLE,
                OfficeKind::Docm,
                Disposition::ResearchOnly,
                now_ms() + 60_000
            )
            .await
            .is_err()
    );
    // A deliberate new outbox intent with a later creation time remains usable.
    tokio::time::sleep(Duration::from_millis(10)).await;
    let fresh = client
        .enqueue_created_at(
            &digest(b"fresh"),
            SAMPLE,
            OfficeKind::Docm,
            Disposition::ResearchOnly,
            now_ms(),
        )
        .await
        .unwrap();
    let same = client
        .enqueue(
            &digest(b"fresh"),
            SAMPLE,
            OfficeKind::Docm,
            Disposition::ResearchOnly,
        )
        .await
        .unwrap();
    assert_eq!(same.job_id, fresh.job_id);
    assert_ne!(same.job_id, job.job_id);
    assert_eq!(client.prune_before(cutoff - 100).await.unwrap(), 0);
    assert!(client.get(&fresh.job_id).await.unwrap().is_some());
    assert!(h.fake.state.lock().unwrap().requests.is_empty());
}

#[tokio::test]
async fn disabled_backend_cleanup_needs_only_store_path_and_maintains_minimum_thirty_day_limit() {
    let h = Harness::new().await;
    let client = h.client();
    let mut job = h.enqueue(&client).await;
    job.created_at_ms = now_ms() - sandbox::MAX_RETENTION_MS - 1000;
    job.remote_slot_held = true;
    job.status = Status::Uncertain;
    let db = rusqlite::Connection::open(h.settings.state_dir.join("jobs.sqlite3")).unwrap();
    db.execute(
        "UPDATE jobs SET summary=?1",
        [serde_json::to_string(&job).unwrap()],
    )
    .unwrap();
    assert!(Client::prune_local(&h.settings.state_dir, 0).await.is_err());
    drop(client);
    // No endpoint/token is consulted, and an older requested cutoff cannot extend retention.
    assert_eq!(
        Client::prune_local(&h.settings.state_dir, 0).await.unwrap(),
        1
    );
    assert_eq!(
        Client::prune_local(&h.settings.state_dir, 0).await.unwrap(),
        0
    );
    assert!(h.fake.state.lock().unwrap().requests.is_empty());
    let client = h.client();
    assert_eq!(client.tombstones(0, 100).await.unwrap().len(), 1);
    assert!(client.get(&job.job_id).await.unwrap().is_none());
    let absent = h._root.path().join("absent-cleanup");
    assert_eq!(Client::prune_local(&absent, now_ms()).await.unwrap(), 0);
    assert!(!absent.exists());
}

#[tokio::test]
async fn pruning_batches_are_bounded_and_future_cutoffs_are_rejected() {
    let mut h = Harness::new().await;
    h.settings.max_jobs = 105;
    let client = h.client();
    for index in 0..105u32 {
        client
            .enqueue(
                &digest(&index.to_be_bytes()),
                b"x",
                OfficeKind::Doc,
                Disposition::ResearchOnly,
            )
            .await
            .unwrap();
    }
    assert!(client.prune_before(now_ms() + 1000).await.is_err());
    assert!(client.prune_before(-1).await.is_err());
    assert_eq!(
        client.prune_before(now_ms()).await.unwrap(),
        sandbox::PRUNE_BATCH_SIZE
    );
    // Remaining old rows cannot be polled or exposed between bounded scrub batches.
    assert!(client.list(0, 100).await.unwrap().is_empty());
    assert_eq!(client.tick().await.unwrap(), 0);
    assert_eq!(client.prune_before(now_ms()).await.unwrap(), 5);
    assert_eq!(client.prune_before(now_ms()).await.unwrap(), 0);
    assert!(client.tombstones(0, 100).await.unwrap().is_empty());
    assert!(h.fake.state.lock().unwrap().requests.is_empty());
}

#[tokio::test]
async fn prune_refuses_inflight_network_pass_and_cannot_resurrect_scrubbed_results() {
    let mut h = Harness::new().await;
    h.settings.request_timeout_ms = 1000;
    let client = h.client();
    let job = h.enqueue(&client).await;
    client.tick().await.unwrap();
    h.fake.state.lock().unwrap().delay_ms = 200;
    tokio::time::sleep(Duration::from_millis(115)).await;
    let worker = client.clone();
    let tick = tokio::spawn(async move { worker.tick().await.unwrap() });
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(client.prune_before(now_ms()).await.is_err());
    tick.await.unwrap();
    assert_eq!(client.prune_before(now_ms()).await.unwrap(), 1);
    assert!(client.get(&job.job_id).await.unwrap().is_none());
    assert_eq!(client.tick().await.unwrap(), 0);
    assert_eq!(client.tombstones(0, 100).await.unwrap().len(), 1);
}
