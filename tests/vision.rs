#[allow(dead_code)]
mod common;
use noisefence::{
    engine::Engine,
    vision::{Client, Settings, Status},
};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const IMAGE: &[u8] = b"From: sender@example.org\r\nTo: alice@example.test\r\nSubject: Image\r\nMIME-Version: 1.0\r\nContent-Type: image/png\r\nContent-Transfer-Encoding: base64\r\n\r\niVBORw0KGgo=\r\n";

async fn fake_worker(
    path: &std::path::Path,
    response: serde_json::Value,
) -> tokio::task::JoinHandle<()> {
    let listener = tokio::net::UnixListener::bind(path).unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let length = stream.read_u32().await.unwrap();
        assert!(length < 1024);
        let mut request = vec![0; length as usize];
        stream.read_exact(&mut request).await.unwrap();
        let request: serde_json::Value = serde_json::from_slice(&request).unwrap();
        assert_eq!(request["parts"][0]["kind"], "image");
        assert_eq!(request["parts"][0]["data"], "iVBORw0KGgo=");
        assert!(request.get("sender").is_none());
        let encoded = serde_json::to_vec(&response).unwrap();
        stream.write_u32(encoded.len() as u32).await.unwrap();
        stream.write_all(&encoded).await.unwrap();
    })
}

fn response() -> serde_json::Value {
    serde_json::json!({"protocol": noisefence::vision::PROTOCOL, "status": "complete",
        "backend_sha256": "a".repeat(64), "errors": [], "pages": [{"part":0,"page":0,
        "text":"Urgent, verify your account password immediately", "codes":[{
        "kind":"QR-Code", "data":"https://trusted.example@actual.example.invalid/login?secret=PRIVATE_TOKEN"}]}]})
}

#[test]
fn worker_pool_configuration_is_bounded_and_distinct() {
    let mut settings = Settings {
        additional_sockets: vec!["/run/vision-2.sock".into()],
        max_parallel: 2,
        ..Default::default()
    };
    settings.validate().unwrap();
    let legacy: Settings = toml::from_str("max_parallel = 4").unwrap();
    legacy.validate().unwrap();
    assert!(legacy.additional_sockets.is_empty());
    for sockets in [
        vec![settings.socket.clone()],
        vec!["relative.sock".into()],
        vec!["/run/../vision.sock".into()],
        vec!["/run/same.sock".into(), "/run/./same.sock".into()],
        (1..=4)
            .map(|i| format!("/run/vision-{i}.sock").into())
            .collect(),
    ] {
        let invalid = Settings {
            additional_sockets: sockets,
            ..settings.clone()
        };
        assert!(invalid.validate().is_err(), "{invalid:?}");
    }
    settings.max_parallel = 3;
    assert!(settings.validate().is_err());
}

#[tokio::test]
async fn pooled_workers_overlap_without_queuing_on_an_occupied_instance() {
    let root = tempfile::tempdir().unwrap();
    let paths: Vec<_> = (0..2)
        .map(|i| root.path().join(format!("worker-{i}.sock")))
        .collect();
    let (ready, mut requests) = tokio::sync::mpsc::channel(4);
    let mut tasks = Vec::new();
    for (index, path) in paths.iter().enumerate() {
        let listener = tokio::net::UnixListener::bind(path).unwrap();
        let ready = ready.clone();
        tasks.push(tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let length = stream.read_u32().await.unwrap();
                assert!(length < 1024);
                let mut raw = vec![0; length as usize];
                stream.read_exact(&mut raw).await.unwrap();
                let (release, wait) = tokio::sync::oneshot::channel();
                ready.send((index, release)).await.unwrap();
                if wait.await.is_err() {
                    break;
                }
                let mut reply = response();
                reply["pages"][0]["text"] = format!("worker-{index}").into();
                let encoded = serde_json::to_vec(&reply).unwrap();
                stream.write_u32(encoded.len() as u32).await.unwrap();
                stream.write_all(&encoded).await.unwrap();
            }
        }));
    }
    let client = Arc::new(
        Client::new(Settings {
            socket: paths[0].clone(),
            additional_sockets: vec![paths[1].clone()],
            max_parallel: 2,
            timeout_ms: 5000,
            ..Default::default()
        })
        .unwrap(),
    );
    let spawn = || {
        let client = client.clone();
        tokio::spawn(async move { client.inspect(IMAGE).await })
    };
    async fn receive(
        receiver: &mut tokio::sync::mpsc::Receiver<(usize, tokio::sync::oneshot::Sender<()>)>,
    ) -> (usize, tokio::sync::oneshot::Sender<()>) {
        tokio::time::timeout(std::time::Duration::from_secs(3), receiver.recv())
            .await
            .unwrap()
            .unwrap()
    }
    let first = spawn();
    let (first_index, first_release) = receive(&mut requests).await;
    let second = spawn();
    let (second_index, second_release) = receive(&mut requests).await;
    assert_ne!(first_index, second_index);
    assert_eq!(client.inspect(IMAGE).await.summary.status, Status::Busy);
    first_release.send(()).unwrap();
    let first_result = first.await.unwrap();
    assert_eq!(first_result.summary.status, Status::Complete);
    assert_eq!(first_result.pages[0].text, format!("worker-{first_index}"));
    // The second instance is still occupied. A new request must use the free
    // first instance, even if the round-robin cursor initially selects the other.
    let third = spawn();
    let (third_index, third_release) = receive(&mut requests).await;
    assert_eq!(third_index, first_index);
    third_release.send(()).unwrap();
    assert_eq!(third.await.unwrap().summary.status, Status::Complete);
    second_release.send(()).unwrap();
    let second_result = second.await.unwrap();
    assert_eq!(second_result.summary.status, Status::Complete);
    assert_eq!(
        second_result.pages[0].text,
        format!("worker-{second_index}")
    );
    for task in tasks {
        task.abort();
        let _ = task.await;
    }
}

#[tokio::test]
async fn failed_pool_exchange_does_not_retry_or_poison_the_next_instance() {
    let root = tempfile::tempdir().unwrap();
    let first = root.path().join("absent.sock");
    let second = root.path().join("healthy.sock");
    let task = fake_worker(&second, response()).await;
    let client = Client::new(Settings {
        socket: first,
        additional_sockets: vec![second],
        max_parallel: 2,
        backend_sha256: Some("a".repeat(64)),
        ..Default::default()
    })
    .unwrap();
    assert_eq!(
        client.inspect(IMAGE).await.summary.status,
        Status::Unavailable
    );
    assert_eq!(client.inspect(IMAGE).await.summary.status, Status::Complete);
    task.await.unwrap();
}

#[tokio::test]
async fn pool_honors_a_smaller_global_limit_and_releases_it_after_cancellation() {
    let root = tempfile::tempdir().unwrap();
    let first = root.path().join("held.sock");
    let second = root.path().join("free.sock");
    let listener = tokio::net::UnixListener::bind(&first).unwrap();
    let (accepted, ready) = tokio::sync::oneshot::channel();
    let held = tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.unwrap();
        accepted.send(()).unwrap();
        std::future::pending::<()>().await;
    });
    let healthy = fake_worker(&second, response()).await;
    let client = Arc::new(
        Client::new(Settings {
            socket: first,
            additional_sockets: vec![second],
            max_parallel: 1,
            timeout_ms: 5000,
            ..Default::default()
        })
        .unwrap(),
    );
    let shared = client.clone();
    let running = tokio::spawn(async move { shared.inspect(IMAGE).await });
    tokio::time::timeout(std::time::Duration::from_secs(3), ready)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(client.inspect(IMAGE).await.summary.status, Status::Busy);
    running.abort();
    assert!(running.await.unwrap_err().is_cancelled());
    assert_eq!(client.inspect(IMAGE).await.summary.status, Status::Complete);
    healthy.await.unwrap();
    held.abort();
    let _ = held.await;
}

#[tokio::test]
async fn smtp_processing_keeps_original_and_only_retains_summary() {
    let root = tempfile::tempdir().unwrap();
    let mut config = (*common::config(root.path())).clone();
    config.vision = Some(Settings {
        socket: root.path().join("vision.sock"),
        ..Default::default()
    });
    let task = fake_worker(&config.vision.as_ref().unwrap().socket, response()).await;
    let engine = Engine::new(Arc::new(config)).unwrap();
    let (scan, delivered) = engine
        .process(
            IMAGE,
            "127.0.0.1".parse().unwrap(),
            "example.org",
            "sender@example.org",
            "vision-test",
        )
        .await
        .unwrap();
    task.await.unwrap();
    assert_eq!(scan.vision.status, Status::Complete);
    assert!(scan.complete);
    assert!(!scan.tagged);
    assert_eq!(scan.vision.qr_codes, 1);
    assert_eq!(scan.vision.link_domains, 1);
    assert!(
        scan.reasons
            .iter()
            .any(|s| s.id == "vision_credential_lure" && s.weight == 0.0)
    );
    let body = |raw: &[u8]| {
        raw.windows(4)
            .position(|v| v == b"\r\n\r\n")
            .map(|i| raw[i + 4..].to_vec())
            .unwrap()
    };
    assert_eq!(body(IMAGE), body(&delivered));
    let persisted = serde_json::to_string(&scan).unwrap();
    assert!(!persisted.contains("PRIVATE_TOKEN"));
    assert!(!persisted.contains("actual.example.invalid"));
    assert!(!persisted.contains("password immediately"));
    let evidence = scan.evidence.unwrap();
    evidence.validate().unwrap();
    assert_eq!(evidence.vision.unwrap().qr_codes, 1);
}

#[tokio::test]
async fn decoded_url_uses_actual_host_and_backend_pin_is_checked() {
    let root = tempfile::tempdir().unwrap();
    let settings = Settings {
        socket: root.path().join("vision.sock"),
        backend_sha256: Some("a".repeat(64)),
        ..Default::default()
    };
    let task = fake_worker(&settings.socket, response()).await;
    let result = Client::new(settings).unwrap().inspect(IMAGE).await;
    task.await.unwrap();
    assert_eq!(result.summary.status, Status::Complete);
    assert_eq!(result.domains(), ["actual.example.invalid"]);
    let settings = Settings {
        socket: root.path().join("wrong.sock"),
        backend_sha256: Some("b".repeat(64)),
        ..Default::default()
    };
    let task = fake_worker(&settings.socket, response()).await;
    let result = Client::new(settings).unwrap().inspect(IMAGE).await;
    task.await.unwrap();
    assert_eq!(result.summary.status, Status::Unavailable);
    assert!(result.pages.is_empty());
}

#[tokio::test]
async fn fabricated_completion_and_injected_error_details_are_rejected() {
    let root = tempfile::tempdir().unwrap();
    for (i, malformed) in [
        serde_json::json!([]),
        serde_json::json!([{"part":5,"page":0,"text":"", "codes":[]}]),
    ]
    .into_iter()
    .enumerate()
    {
        let settings = Settings {
            socket: root.path().join(format!("bad{i}.sock")),
            ..Default::default()
        };
        let mut data = response();
        data["pages"] = malformed;
        let task = fake_worker(&settings.socket, data).await;
        let result = Client::new(settings).unwrap().inspect(IMAGE).await;
        task.await.unwrap();
        assert_eq!(result.summary.status, Status::Unavailable);
    }
    let settings = Settings {
        socket: root.path().join("error.sock"),
        ..Default::default()
    };
    let mut data = response();
    data["status"] = "limited".into();
    data["errors"] = serde_json::json!(["<script>secret</script>"]);
    let task = fake_worker(&settings.socket, data).await;
    let result = Client::new(settings).unwrap().inspect(IMAGE).await;
    task.await.unwrap();
    assert_eq!(result.summary.status, Status::Unavailable);
    assert!(
        !serde_json::to_string(&result.summary)
            .unwrap()
            .contains("script")
    );
}

#[tokio::test]
async fn busy_worker_and_deadline_are_explicit_and_bounded() {
    let root = tempfile::tempdir().unwrap();
    let settings = Settings {
        socket: root.path().join("slow.sock"),
        timeout_ms: 200,
        ..Default::default()
    };
    let listener = tokio::net::UnixListener::bind(&settings.socket).unwrap();
    let (accepted, ready) = tokio::sync::oneshot::channel();
    let worker = tokio::spawn(async move {
        let (_socket, _) = listener.accept().await.unwrap();
        accepted.send(()).unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    });
    let client = Arc::new(Client::new(settings).unwrap());
    let first_client = client.clone();
    let first = tokio::spawn(async move { first_client.inspect(IMAGE).await });
    ready.await.unwrap();
    assert_eq!(client.inspect(IMAGE).await.summary.status, Status::Busy);
    let result = first.await.unwrap();
    assert_eq!(result.summary.status, Status::Unavailable);
    assert_eq!(result.summary.errors, ["timeout"]);
    assert!(result.summary.elapsed_ms < 1000);
    worker.abort();
    let _ = worker.await;
}

#[tokio::test]
async fn unbounded_frame_is_rejected_before_allocation() {
    let root = tempfile::tempdir().unwrap();
    let settings = Settings {
        socket: root.path().join("frame.sock"),
        ..Default::default()
    };
    let listener = tokio::net::UnixListener::bind(&settings.socket).unwrap();
    let worker = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let size = socket.read_u32().await.unwrap() as usize;
        let mut request = vec![0; size];
        socket.read_exact(&mut request).await.unwrap();
        socket.write_u32(u32::MAX).await.unwrap();
    });
    let result = Client::new(settings).unwrap().inspect(IMAGE).await;
    worker.await.unwrap();
    assert_eq!(result.summary.status, Status::Unavailable);
    assert!(result.pages.is_empty());
}
