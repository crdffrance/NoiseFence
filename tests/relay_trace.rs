mod common;

use noisefence::{
    delivery_log::{Attempt, MAX_EVENTS, MAX_TEXT_BYTES},
    relay::{self, DeliveryReport, Outcome},
    smtp::{self, Wire},
    store::Job,
};
use tokio::{io::BufReader, net::TcpListener};

fn job(hosts: Vec<String>) -> Job {
    Job {
        delivery_id: 42,
        message_id: "trace-message-id".into(),
        created: noisefence::now(),
        sender: "private-sender@example.org".into(),
        destination: "private-destination@example.test".into(),
        hosts,
        attempts: 2,
        is_dsn: false,
    }
}

// Only the fake server sees outgoing commands and DATA. It disconnects after
// its final scripted reply, including after accepting a message with 250.
async fn scripted(
    greeting: String,
    steps: Vec<(&'static str, String)>,
) -> (String, tokio::task::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let route = listener.local_addr().unwrap().to_string();
    let task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut io: Wire = BufReader::new(Box::new(socket));
        smtp::reply(&mut io, &greeting).await.unwrap();
        let mut body = Vec::new();
        for (expected, response) in steps {
            if expected == "body" {
                loop {
                    let line = smtp::line(&mut io, 1001, 5).await.unwrap().unwrap();
                    if line == b".\r\n" {
                        break;
                    }
                    body.extend(line);
                }
            } else {
                let line = smtp::line(&mut io, 1024, 5).await.unwrap().unwrap();
                assert!(line.starts_with(expected.as_bytes()), "unexpected command");
            }
            smtp::reply(&mut io, &response).await.unwrap();
        }
        body
    });
    (route, task)
}

fn steps(final_reply: &str) -> Vec<(&'static str, String)> {
    vec![
        (
            "EHLO ",
            "250-sink.test\r\n250-SIZE 50000000\r\n250 8BITMIME\r\n".into(),
        ),
        (
            "MAIL FROM:",
            "250 2.1.0 Sender <PRIVATE-SENDER@example.org> accepted\r\n".into(),
        ),
        (
            "RCPT TO:",
            "250 2.1.5 Recipient private-destination@example.test accepted\r\n".into(),
        ),
        ("DATA\r\n", "354 Send message\r\n".into()),
        ("body", final_reply.into()),
    ]
}

fn assert_safe(report: &DeliveryReport) {
    let json = serde_json::to_string(&report.attempts).unwrap();
    let diagnostics = format!("{json} {:?}", report.outcome).to_lowercase();
    for private in [
        "private-sender@example.org",
        "private-destination@example.test",
        "sender@example.org",
        "alice@example.test",
        "rendez-vous",
        "bonjour",
        "mail from:",
        "rcpt to:",
        "subject:",
    ] {
        assert!(!diagnostics.contains(private), "leaked {private}");
    }
    for attempt in &report.attempts {
        assert!(attempt.events.len() <= MAX_EVENTS);
        assert!(attempt.started > 0);
        assert!(
            attempt
                .events
                .windows(2)
                .all(|w| w[0].elapsed_ms <= w[1].elapsed_ms)
        );
        for event in &attempt.events {
            assert!(event.elapsed_ms <= attempt.elapsed_ms);
            for text in [&event.response, &event.detail].into_iter().flatten() {
                assert!(text.len() <= MAX_TEXT_BYTES);
                assert!(!text.chars().any(char::is_control));
                assert!(!text.contains(['\u{202e}', '\u{2066}', '\u{61c}']));
            }
        }
    }
    let decoded: Vec<Attempt> = serde_json::from_str(&json).unwrap();
    assert_eq!(
        serde_json::to_value(decoded).unwrap(),
        serde_json::to_value(&report.attempts).unwrap()
    );
}

#[tokio::test]
async fn captures_success_and_classifies_451_and_550_without_leaking_content() {
    let root = tempfile::tempdir().unwrap();
    let cfg = common::config(root.path());
    for (reply, code, enhanced, outcome) in [
        (
            "250 2.0.0 queued as remote-123\r\n",
            250,
            "2.0.0",
            "delivered",
        ),
        (
            "451 4.7.1 remote greylist; retry later\r\n",
            451,
            "4.7.1",
            "temporary",
        ),
        (
            "550 5.7.1 remote policy rejected\r\n",
            550,
            "5.7.1",
            "permanent",
        ),
    ] {
        let (route, task) = scripted("220 sink.test ESMTP\r\n".into(), steps(reply)).await;
        let started = noisefence::now();
        let report = relay::deliver_traced(&cfg, &job(vec![route.clone()]), common::MESSAGE).await;
        assert!(matches!(
            (code, &report.outcome),
            (250, Outcome::Delivered) | (451, Outcome::Temporary(_)) | (550, Outcome::Permanent(_))
        ));
        assert_eq!(task.await.unwrap(), common::MESSAGE);
        assert_eq!(report.attempts.len(), 1);
        let attempt = &report.attempts[0];
        assert_eq!(attempt.route, route);
        assert_eq!(attempt.peer.as_deref(), Some("127.0.0.1"));
        assert!((started..=noisefence::now()).contains(&attempt.started));
        assert_eq!(attempt.outcome, outcome);
        assert!(!attempt.truncated);
        let final_reply = attempt
            .events
            .iter()
            .find(|e| e.phase == "data_result")
            .unwrap();
        assert_eq!(final_reply.code, Some(code));
        assert_eq!(final_reply.enhanced_code.as_deref(), Some(enhanced));
        assert_eq!(final_reply.response.as_deref(), Some(reply.trim_end()));
        let ehlo = attempt.events.iter().find(|e| e.phase == "ehlo").unwrap();
        assert_eq!(
            ehlo.response.as_deref(),
            Some("250-sink.test | 250-SIZE 50000000 | 250 8BITMIME")
        );
        let mut phases = vec![
            "dns",
            "connect",
            "greeting",
            "ehlo",
            "mail_from",
            "rcpt_to",
            "data",
            "data_result",
        ];
        if code == 250 {
            phases.push("quit");
        }
        assert_eq!(
            attempt
                .events
                .iter()
                .map(|e| e.phase.as_str())
                .collect::<Vec<_>>(),
            phases
        );
        assert_safe(&report);
    }
}

#[tokio::test]
async fn captures_connection_and_protocol_failures_then_fallback_acceptance() {
    let root = tempfile::tempdir().unwrap();
    let cfg = common::config(root.path());
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closed_route = closed.local_addr().unwrap().to_string();
    drop(closed);
    let (invalid_route, invalid) = scripted(
        "220-partial greeting\r\n250 inconsistent code\r\n".into(),
        vec![],
    )
    .await;
    let (good_route, good) =
        scripted("220 sink.test\r\n".into(), steps("250 2.0.0 accepted\r\n")).await;
    let routes = vec![closed_route, invalid_route, good_route];
    let report = relay::deliver_traced(&cfg, &job(routes.clone()), common::MESSAGE).await;
    assert!(matches!(report.outcome, Outcome::Delivered));
    assert_eq!(
        report.attempts.iter().map(|a| &a.route).collect::<Vec<_>>(),
        routes.iter().collect::<Vec<_>>()
    );
    assert_eq!(
        report
            .attempts
            .iter()
            .map(|a| a.outcome.as_str())
            .collect::<Vec<_>>(),
        ["temporary", "temporary", "delivered"]
    );
    let connection = report.attempts[0].events.last().unwrap();
    assert_eq!(connection.phase, "connect");
    assert!(
        connection
            .detail
            .as_ref()
            .unwrap()
            .to_lowercase()
            .contains("refused")
    );
    let protocol = report.attempts[1].events.last().unwrap();
    assert_eq!(protocol.phase, "greeting");
    assert_eq!(
        protocol.response.as_deref(),
        Some("220-partial greeting | 250 inconsistent code")
    );
    assert!(
        protocol
            .detail
            .as_ref()
            .unwrap()
            .contains("inconsistent multiline reply")
    );
    invalid.await.unwrap();
    assert_eq!(good.await.unwrap(), common::MESSAGE);
    assert_safe(&report);
}

#[tokio::test]
async fn retries_451_on_next_route_but_never_falls_back_after_550_or_final_250() {
    let root = tempfile::tempdir().unwrap();
    let cfg = common::config(root.path());
    let (deferred_route, deferred) =
        scripted("451 4.3.2 Try another route\r\n".into(), vec![]).await;
    let (good_route, good) =
        scripted("220 sink.test\r\n".into(), steps("250 2.0.0 accepted\r\n")).await;
    let report = relay::deliver_traced(
        &cfg,
        &job(vec![deferred_route, good_route]),
        common::MESSAGE,
    )
    .await;
    assert!(matches!(report.outcome, Outcome::Delivered));
    assert_eq!(report.attempts.len(), 2);
    assert_eq!(
        report.attempts[0]
            .events
            .last()
            .unwrap()
            .enhanced_code
            .as_deref(),
        Some("4.3.2")
    );
    deferred.await.unwrap();
    good.await.unwrap();
    assert_safe(&report);

    for code in [250, 550] {
        let unused = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (route, task) = scripted(
            "220 sink.test\r\n".into(),
            steps(&format!("{code} result\r\n")),
        )
        .await;
        let report = relay::deliver_traced(
            &cfg,
            &job(vec![route, unused.local_addr().unwrap().to_string()]),
            common::MESSAGE,
        )
        .await;
        assert_eq!(report.attempts.len(), 1);
        assert!(matches!(
            (code, &report.outcome),
            (250, Outcome::Delivered) | (550, Outcome::Permanent(_))
        ));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), unused.accept())
                .await
                .is_err()
        );
        task.await.unwrap();
        assert_safe(&report);
    }
}

#[tokio::test]
async fn caps_multiline_responses_sanitizes_controls_and_preserves_final_code() {
    let root = tempfile::tempdir().unwrap();
    let cfg = common::config(root.path());
    let mut response = "451-4.7.1 \u{1b}[31mRemote\u{1b}[0m\u{202e}\u{2066}\u{61c}\t busy <private-sender@example.org>\r\n".to_string();
    for _ in 0..20 {
        response.push_str(&format!("451-{}\r\n", "é".repeat(200)));
    }
    response.push_str("451 4.7.1 retry later\r\n");
    let (route, task) = scripted("220 sink.test\r\n".into(), steps(&response)).await;
    let report = relay::deliver_traced(&cfg, &job(vec![route]), common::MESSAGE).await;
    assert!(matches!(report.outcome, Outcome::Temporary(_)));
    assert!(report.attempts[0].truncated);
    let final_reply = report.attempts[0].events.last().unwrap();
    assert_eq!(final_reply.code, Some(451));
    assert_eq!(final_reply.enhanced_code.as_deref(), Some("4.7.1"));
    assert!(
        final_reply
            .response
            .as_ref()
            .unwrap()
            .starts_with("451-4.7.1 Remote  busy <[redacted]>")
    );
    task.await.unwrap();
    assert_safe(&report);
}

#[tokio::test]
async fn tls_certificate_failure_keeps_actual_error_and_prior_replies() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    let root = tempfile::tempdir().unwrap();
    let cfg = common::config(root.path());
    let key = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![key.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(key.signing_key.serialize_der()).into(),
        )
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let route = listener.local_addr().unwrap().to_string();
    let task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut io: Wire = BufReader::new(Box::new(socket));
        smtp::reply(&mut io, "220 localhost\r\n").await.unwrap();
        assert!(
            smtp::line(&mut io, 512, 5)
                .await
                .unwrap()
                .unwrap()
                .starts_with(b"EHLO ")
        );
        smtp::reply(&mut io, "250-localhost\r\n250 STARTTLS\r\n")
            .await
            .unwrap();
        assert_eq!(
            smtp::line(&mut io, 512, 5).await.unwrap().unwrap(),
            b"STARTTLS\r\n"
        );
        smtp::reply(&mut io, "220 2.0.0 Ready for TLS\r\n")
            .await
            .unwrap();
        let _ = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server))
            .accept(io.into_inner())
            .await;
    });
    let report = relay::deliver_traced(&cfg, &job(vec![route]), common::MESSAGE).await;
    let Outcome::Temporary(reason) = &report.outcome else {
        panic!("untrusted TLS must defer");
    };
    assert!(reason.contains("UnknownIssuer"), "{reason}");
    let attempt = &report.attempts[0];
    let tls = attempt.events.last().unwrap();
    assert_eq!(tls.phase, "tls");
    assert!(tls.detail.as_ref().unwrap().contains("UnknownIssuer"));
    assert!(!tls.detail.as_ref().unwrap().contains("Verified TLS;"));
    assert!(
        attempt
            .events
            .iter()
            .any(|e| e.phase == "starttls" && e.code == Some(220))
    );
    assert!(!attempt.events.iter().any(|e| e.phase == "mail_from"));
    task.await.unwrap();
    assert_safe(&report);
}
