mod common;

use noisefence::{
    actions::{Action, Applied},
    challenge::{self, Actor, Policy, Request, ResponseRequest, VerifiedSmtpFrom},
    config::Recipient,
    engine::Scan,
    evidence::{Artifacts, AuthResult, Evidence, Source, State},
    message,
    store::Store,
};
use rusqlite::params;

const ALICE: &str = "alice@example.test";
const BOB: &str = "bob@example.test";
const ALIAS: &str = "sales@example.test";
const FROM: &str = "sender@example.org";

fn policy() -> Policy {
    Policy {
        enabled: true,
        public_origin: "https://filter.example.test".into(),
        notification_from: "postmaster@example.test".into(),
        ..Policy::default()
    }
}
fn actor(name: &str) -> Actor {
    Actor {
        username: name.into(),
        session_hash: message::digest(session_token(name).as_bytes()),
    }
}
fn session_token(name: &str) -> String {
    message::digest(format!("session-{name}").as_bytes())
}
fn body(address: &str) -> Request {
    Request {
        recipient: address.into(),
    }
}
fn response(token: &str) -> ResponseRequest {
    ResponseRequest {
        token: token.into(),
        nonce: String::new(),
        code: String::new(),
    }
}
// Controlled fixture for authorization/queue tests. The public image issuer runs
// normally; only this test database replaces its random answer with a known code.
// No test-only answer, bypass, or plaintext code exists in the production API.
async fn solved(store: &Store, token: &str) -> ResponseRequest {
    let puzzle = challenge::visual::issue(
        store,
        &policy(),
        challenge::visual::Request {
            token: token.into(),
        },
    )
    .await
    .unwrap();
    let nonce = puzzle.nonce.clone();
    let hash = message::digest(token.as_bytes());
    store.run(move |db| {
        db.execute(
            "UPDATE challenge_visual_codes SET answer_hash=?1 WHERE nonce=?2 AND challenge_id IN (SELECT id FROM challenge_requests WHERE token_hash=?3 AND state='pending')",
            params![message::digest(format!("noisefence-visual-code-1\n{hash}\n{nonce}\nABC234").as_bytes()), nonce, hash],
        )?;
        Ok(())
    }).await.unwrap();
    ResponseRequest {
        token: token.into(),
        nonce: puzzle.nonce,
        code: "ABC234".into(),
    }
}

async fn puzzle(store: &Store, token: &str) -> challenge::visual::Puzzle {
    challenge::visual::issue(
        store,
        &policy(),
        challenge::visual::Request {
            token: token.into(),
        },
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn visual_code_is_required_bound_to_its_token_and_consumed_atomically() {
    let f = Fixture::new().await;
    let token = f.issue().await;
    let before = f.count("SELECT COUNT(*) FROM messages").await;
    challenge::submit(&f.store, &policy(), response(&token))
        .await
        .unwrap();
    f.assert_held().await;
    assert_eq!(
        f.count("SELECT COUNT(*) FROM challenge_visual_codes").await,
        0
    );
    let correct = solved(&f.store, &token).await;
    // Neither displaying the code nor an incomplete or incorrect response releases mail.
    f.assert_held().await;
    for wrong in [
        response(&token),
        ResponseRequest {
            code: "ZZZ999".into(),
            ..correct.clone()
        },
        ResponseRequest {
            nonce: "0".repeat(64),
            ..correct.clone()
        },
        ResponseRequest {
            code: "ＡBC234".into(),
            ..correct.clone()
        },
    ] {
        assert_eq!(
            challenge::submit(&f.store, &policy(), wrong).await.unwrap(),
            challenge::Submission::default()
        );
        f.assert_held().await;
    }
    let bob = f.issue_for(&f.id, "bob", BOB).await.unwrap();
    let bob_token = f.token(&bob.id).await;
    let bob_correct = solved(&f.store, &bob_token).await;
    challenge::submit(
        &f.store,
        &policy(),
        ResponseRequest {
            token: bob_token.clone(),
            ..correct.clone()
        },
    )
    .await
    .unwrap();
    f.assert_held().await;
    assert_eq!(
        f.count("SELECT SUM(attempts) FROM challenge_visual_codes")
            .await,
        5
    );

    let normalized = ResponseRequest {
        code: " abc234\t".into(),
        ..correct.clone()
    };
    challenge::submit(&f.store, &policy(), normalized)
        .await
        .unwrap();
    assert_eq!(
        f.states().await,
        vec![
            (ALICE.into(), "pending".into()),
            (BOB.into(), "quarantined".into()),
            (ALIAS.into(), "quarantined".into())
        ]
    );
    challenge::submit(&f.store, &policy(), correct.clone())
        .await
        .unwrap();
    assert_eq!(
        f.count("SELECT COUNT(*) FROM audit WHERE action='quarantine_release'")
            .await,
        1
    );
    assert_eq!(f.count("SELECT COUNT(*) FROM challenge_visual_codes WHERE nonce='' AND answer_hash='' AND expires=0").await, 1);
    challenge::submit(&f.store, &policy(), bob_correct)
        .await
        .unwrap();
    assert_eq!(
        f.count("SELECT COUNT(*) FROM audit WHERE action='quarantine_release'")
            .await,
        2
    );
    assert_eq!(f.count("SELECT COUNT(*) FROM messages").await, before + 1); // Only Bob's explicit notification.
    let debug = format!("{:?}", correct);
    assert!(
        !debug.contains(&token) && !debug.contains("ABC234") && !debug.contains(&correct.nonce)
    );
}

#[tokio::test]
async fn visual_bad_code_does_not_parse_the_spool_and_correct_code_revalidates_the_message() {
    let f = Fixture::new().await;
    let token = f.issue().await;
    let correct = solved(&f.store, &token).await;
    let id = f.id.clone();
    let original = f
        .store
        .run(move |db| {
            let json: String =
                db.query_row("SELECT scan FROM messages WHERE id=?1", [&id], |r| r.get(0))?;
            db.execute("UPDATE messages SET scan='invalid-json' WHERE id=?1", [id])?;
            Ok(json)
        })
        .await
        .unwrap();
    let wrong = ResponseRequest {
        code: "ZZZ999".into(),
        ..correct.clone()
    };
    challenge::submit(&f.store, &policy(), wrong).await.unwrap();
    f.assert_held().await;
    assert_eq!(
        f.count("SELECT attempts FROM challenge_visual_codes").await,
        1
    );
    assert_eq!(
        f.count("SELECT COUNT(*) FROM challenge_requests WHERE state='pending'")
            .await,
        1
    );
    challenge::submit(&f.store, &policy(), correct.clone())
        .await
        .unwrap();
    f.assert_held().await;
    assert_eq!(
        f.count("SELECT attempts FROM challenge_visual_codes").await,
        2
    );
    assert_eq!(
        f.count("SELECT COUNT(*) FROM challenge_requests WHERE state='revoked'")
            .await,
        1
    );
    let id = f.id.clone();
    f.store
        .run(move |db| {
            db.execute(
                "UPDATE messages SET scan=?2 WHERE id=?1",
                params![id, original],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    challenge::submit(&f.store, &policy(), correct)
        .await
        .unwrap();
    // Restoring the fixture scan cannot revive an invalidated link.
    f.assert_held().await;
}

#[tokio::test]
async fn visual_rotation_and_expiry_preserve_attempt_budget_across_restarts() {
    let f = Fixture::new().await;
    let token = f.issue().await;
    let old = solved(&f.store, &token).await;
    let current = solved(&f.store, &token).await;
    assert_ne!(old.nonce, current.nonce);
    challenge::submit(&f.store, &policy(), old).await.unwrap();
    f.assert_held().await;
    assert_eq!(
        f.count("SELECT attempts FROM challenge_visual_codes").await,
        1
    );
    assert_eq!(
        f.count("SELECT issues FROM challenge_visual_codes").await,
        2
    );
    f.sql("UPDATE challenge_visual_codes SET expires=0").await;
    challenge::submit(&f.store, &policy(), current)
        .await
        .unwrap();
    f.assert_held().await;
    f.store.cleanup().await.unwrap();
    assert_eq!(
        f.count("SELECT COUNT(*) FROM challenge_visual_codes WHERE nonce='' AND answer_hash=''")
            .await,
        1
    );
    assert_eq!(
        f.count("SELECT attempts FROM challenge_visual_codes").await,
        1
    );
    let reopened = Store::open(f.root.path()).unwrap();
    let latest = solved(&reopened, &token).await;
    assert_eq!(
        f.count("SELECT issues FROM challenge_visual_codes").await,
        3
    );
    assert_eq!(
        f.count("SELECT attempts FROM challenge_visual_codes").await,
        1
    );
    challenge::submit(&reopened, &policy(), latest)
        .await
        .unwrap();
    assert_eq!(
        f.count("SELECT COUNT(*) FROM audit WHERE action='quarantine_release'")
            .await,
        1
    );
}

#[tokio::test]
async fn visual_attempt_limit_is_shared_by_workers_and_cannot_be_reset() {
    let f = Fixture::new().await;
    let token = f.issue().await;
    let correct = solved(&f.store, &token).await;
    let other = Store::open(f.root.path()).unwrap();
    let wrong = ResponseRequest {
        code: "ZZZ999".into(),
        ..correct.clone()
    };
    for _ in 0..6 {
        challenge::submit(&f.store, &policy(), wrong.clone())
            .await
            .unwrap();
    }
    let cfg = policy();
    let (a, b, c, d) = tokio::join!(
        challenge::submit(&f.store, &cfg, wrong.clone()),
        challenge::submit(&other, &cfg, wrong.clone()),
        challenge::submit(&f.store, &cfg, wrong.clone()),
        challenge::submit(&other, &cfg, wrong),
    );
    for result in [a, b, c, d] {
        assert_eq!(result.unwrap(), challenge::Submission::default());
    }
    assert_eq!(
        f.count("SELECT attempts FROM challenge_visual_codes").await,
        challenge::visual::MAX_ATTEMPTS
    );
    let reopened = Store::open(f.root.path()).unwrap();
    for _ in 0..12 {
        let _ = puzzle(&reopened, &token).await;
    }
    assert_eq!(
        f.count("SELECT issues FROM challenge_visual_codes").await,
        1
    );
    assert_eq!(f.count("SELECT COUNT(*) FROM challenge_visual_codes WHERE nonce='' AND answer_hash='' AND expires=0").await, 1);
    challenge::submit(&reopened, &policy(), correct)
        .await
        .unwrap();
    f.assert_held().await;
}

#[tokio::test]
async fn visual_issue_budget_does_not_expand_rows_or_revoke_last_valid_picture() {
    let f = Fixture::new().await;
    let token = f.issue().await;
    let mut correct = solved(&f.store, &token).await;
    for _ in 1..challenge::visual::MAX_ISSUES {
        correct = solved(&f.store, &token).await;
    }
    let reopened = Store::open(f.root.path()).unwrap();
    let other = Store::open(f.root.path()).unwrap();
    let (a, b) = tokio::join!(puzzle(&reopened, &token), puzzle(&other, &token));
    assert_ne!(a.nonce, correct.nonce);
    assert_ne!(b.nonce, correct.nonce);
    for n in 0..16 {
        let _ = puzzle(&f.store, &format!("{n:064x}")).await;
    }
    assert_eq!(
        f.count("SELECT COUNT(*) FROM challenge_visual_codes").await,
        1
    );
    assert_eq!(
        f.count("SELECT issues FROM challenge_visual_codes").await,
        challenge::visual::MAX_ISSUES
    );
    assert_eq!(f.count("SELECT COUNT(*) FROM messages").await, 2);
    challenge::submit(&reopened, &policy(), correct)
        .await
        .unwrap();
    assert_eq!(
        f.count("SELECT COUNT(*) FROM audit WHERE action='quarantine_release'")
            .await,
        1
    );
}

#[tokio::test]
async fn visual_expiration_cannot_extend_the_parent_link_and_retention_cascades() {
    for close in [false, true] {
        let f = Fixture::new().await;
        let token = f.issue().await;
        let time = noisefence::now();
        f.sql(&format!(
            "UPDATE challenge_requests SET expires={}",
            time + 60
        ))
        .await;
        let correct = solved(&f.store, &token).await;
        assert_eq!(
            f.count("SELECT expires FROM challenge_visual_codes").await,
            time + 60
        );
        if close {
            assert!(
                challenge::revoke(&f.store, actor("alice"), f.id.clone(), body(ALICE))
                    .await
                    .unwrap()
            );
        } else {
            f.sql(&format!(
                "UPDATE challenge_requests SET created=created-120,expires={}",
                noisefence::now()
            ))
            .await;
        }
        f.store.cleanup().await.unwrap();
        challenge::submit(&f.store, &policy(), correct)
            .await
            .unwrap();
        f.assert_held().await;
        assert_eq!(f.count("SELECT COUNT(*) FROM challenge_visual_codes WHERE nonce='' AND answer_hash='' AND expires=0").await, 1);
        f.sql(&format!(
            "UPDATE challenge_requests SET created={}",
            time - challenge::RETENTION_SECONDS
        ))
        .await;
        f.store.cleanup().await.unwrap();
        assert_eq!(
            f.count("SELECT COUNT(*) FROM challenge_visual_codes").await,
            0
        );
        assert_eq!(f.count("SELECT COUNT(*) FROM challenge_requests").await, 0);
        assert!(f.store.raw_path(&f.id).exists());
    }
}

#[tokio::test]
async fn visual_public_route_enforces_origin_body_limits_and_has_no_delivery_side_effects() {
    use axum::{
        body::Body,
        http::{Request as HttpRequest, StatusCode},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    let f = Fixture::new().await;
    let token = f.issue().await;
    let state = std::sync::Arc::new(std::sync::RwLock::new(policy()));
    let current = state.clone();
    let app = challenge::public_router(f.store.clone(), move || current.read().unwrap().clone());
    let valid = serde_json::json!({"token":token}).to_string();
    for (method, path, origins, body, expected) in [
        (
            "GET",
            "/challenge/puzzle",
            vec![],
            String::new(),
            StatusCode::METHOD_NOT_ALLOWED,
        ),
        (
            "POST",
            "/challenge/puzzle",
            vec![],
            valid.clone(),
            StatusCode::FORBIDDEN,
        ),
        (
            "POST",
            "/challenge/puzzle",
            vec!["https://evil.test"],
            valid.clone(),
            StatusCode::FORBIDDEN,
        ),
        (
            "POST",
            "/challenge/puzzle",
            vec!["https://filter.example.test", "https://filter.example.test"],
            valid.clone(),
            StatusCode::FORBIDDEN,
        ),
        (
            "POST",
            "/challenge/puzzle?token=untrusted",
            vec!["https://filter.example.test"],
            valid.clone(),
            StatusCode::FORBIDDEN,
        ),
        (
            "POST",
            "/challenge/puzzle",
            vec!["https://filter.example.test"],
            "x".repeat(2048),
            StatusCode::BAD_REQUEST,
        ),
        (
            "POST",
            "/challenge/puzzle",
            vec!["https://filter.example.test"],
            "{}".into(),
            StatusCode::BAD_REQUEST,
        ),
        (
            "POST",
            "/challenge/puzzle",
            vec!["https://filter.example.test"],
            serde_json::json!({"token":token,"recipient":BOB}).to_string(),
            StatusCode::BAD_REQUEST,
        ),
    ] {
        let mut request = HttpRequest::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json");
        for origin in origins {
            request = request.header("origin", origin);
        }
        let result = app
            .clone()
            .oneshot(request.body(Body::from(body)).unwrap())
            .await
            .unwrap();
        assert_eq!(result.status(), expected);
        assert_eq!(
            f.count("SELECT COUNT(*) FROM challenge_visual_codes").await,
            0
        );
    }
    for bearer in ["invalid".to_string(), "0".repeat(64), token.clone()] {
        let reply = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri(challenge::visual::PATH)
                    .header("origin", "https://filter.example.test")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::json!({"token":bearer}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(reply.status(), StatusCode::OK);
        for (name, value) in [
            ("cache-control", "no-store"),
            ("referrer-policy", "no-referrer"),
            ("x-content-type-options", "nosniff"),
        ] {
            assert_eq!(reply.headers()[name], value);
        }
        let bytes = reply.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            body.as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            ["image", "nonce"]
        );
        assert_eq!(body["nonce"].as_str().unwrap().len(), 64);
        assert!(!String::from_utf8_lossy(&bytes).contains(&token));
        f.assert_held().await;
    }
    assert_eq!(
        f.count("SELECT issues FROM challenge_visual_codes").await,
        1
    );
    assert_eq!(f.count("SELECT COUNT(*) FROM messages").await, 2);
    state.write().unwrap().enabled = false;
    let reply = app
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri(challenge::visual::PATH)
                .header("origin", "https://filter.example.test")
                .header("content-type", "application/json")
                .body(Body::from(valid))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(reply.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        f.count("SELECT issues FROM challenge_visual_codes").await,
        1
    );
}
fn proof(raw: &[u8], domain: &str) -> Option<VerifiedSmtpFrom> {
    // Synthetic verifier fixture only; no live SMTP or DNS verification is invoked.
    VerifiedSmtpFrom::from_dmarc(
        raw,
        &mail_auth::DmarcOutput::default()
            .with_domain(domain)
            .with_spf_result(mail_auth::DmarcResult::Pass),
    )
}

async fn console_post(
    app: &axum::Router,
    path: &str,
    user: &str,
    csrf: &str,
    origin: &str,
    body: serde_json::Value,
) -> (axum::http::StatusCode, serde_json::Value) {
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    let reply = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(path)
                .header(
                    "cookie",
                    format!("noisefence_session={}", session_token(user)),
                )
                .header("origin", origin)
                .header("x-csrf-token", csrf)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = reply.status();
    let raw = reply.into_body().collect().await.unwrap().to_bytes();
    let value = serde_json::from_slice(&raw).unwrap_or(serde_json::Value::Null);
    (status, value)
}

async fn stats(app: &axum::Router) -> serde_json::Value {
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    let reply = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/api/v1/stats")
                .header(
                    "cookie",
                    format!("noisefence_session={}", session_token("alice")),
                )
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(reply.status(), axum::http::StatusCode::OK);
    serde_json::from_slice(&reply.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

struct Fixture {
    root: tempfile::TempDir,
    store: Store,
    id: String,
}
impl Fixture {
    async fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let store = Store::open(root.path()).unwrap();
        store.run(|db| {
            db.execute_batch(challenge::SCHEMA_SQL)?;
            db.execute_batch(challenge::SCHEMA_SQL)?; // Additive initialization is repeatable.
            for (name,admin) in [("alice",false),("bob",false),("admin",true),("stranger",false)] {
                db.execute("INSERT INTO users(username,password,admin) VALUES(?1,?2,?3)",params![name,format!("salted-password-{name}"),admin])?;
                let who = actor(name);
                db.execute("INSERT INTO sessions(token_hash,username,csrf,expires) VALUES(?1,?2,'csrf',?3)",params![who.session_hash,name,noisefence::now()+3600])?;
            }
            db.execute("INSERT INTO grants VALUES('alice',?1)",[ALICE])?;
            db.execute("INSERT INTO grants VALUES('bob',?1)",[BOB])?;
            Ok(())
        }).await.unwrap();
        let mut f = Self {
            root,
            store,
            id: String::new(),
        };
        f.id = f.mail(common::MESSAGE, true).await;
        f
    }
    async fn mail(&self, raw: &[u8], register: bool) -> String {
        let cfg = common::config(self.root.path());
        let mut evidence = Evidence::new(&cfg, Artifacts::new(&cfg, None, None, false), false);
        evidence.source = Source::SmtpSession;
        evidence.analysis_complete = true;
        evidence.authentication.state = State::Complete;
        evidence.authentication.dmarc_state = State::Complete;
        evidence.authentication.dmarc_spf = Some(AuthResult::Pass);
        let scan = Scan {
            complete: true,
            raw_sha256: Some(message::digest(raw)),
            evidence: Some(evidence),
            action: Some(Applied {
                requested: Action::Quarantine,
                effective: Action::Quarantine,
                reason: "category".into(),
                quarantine_days: 14,
            }),
            ..Scan::default()
        };
        let id = uuid::Uuid::new_v4().to_string();
        let recipients = [(ALICE, ALICE), (BOB, BOB), (ALIAS, ALICE)]
            .into_iter()
            .map(|(address, destination)| Recipient {
                address: address.into(),
                destination: destination.into(),
                hosts: vec!["mx.example.test".into()],
            })
            .collect();
        self.store
            .enqueue(
                id.clone(),
                "bounce@bounces.example.net".into(),
                recipients,
                scan,
                raw.to_vec(),
            )
            .await
            .unwrap();
        if register {
            assert!(
                challenge::record_smtp_identity(
                    &self.store,
                    id.clone(),
                    proof(raw, "example.org").unwrap()
                )
                .await
                .unwrap()
            );
        }
        id
    }
    async fn prepare(&self, name: &str, id: &str, address: &str) -> Option<challenge::Prepared> {
        challenge::prepare(
            &self.store,
            &policy(),
            actor(name),
            id.into(),
            body(address),
        )
        .await
        .unwrap()
    }
    async fn issue_for(&self, id: &str, name: &str, address: &str) -> Option<challenge::Receipt> {
        let p = self.prepare(name, id, address).await?;
        challenge::request(
            &self.store,
            &policy(),
            actor(name),
            p,
            vec!["mx.example.org".into()],
        )
        .await
        .unwrap()
    }
    async fn issue(&self) -> String {
        let receipt = self.issue_for(&self.id, "alice", ALICE).await.unwrap();
        self.token(&receipt.id).await
    }
    async fn token(&self, request: &str) -> String {
        let id = request.to_string();
        let notification = self
            .store
            .run(move |db| {
                Ok(db.query_row(
                    "SELECT notification_id FROM challenge_requests WHERE id=?1",
                    [id],
                    |r| r.get::<_, String>(0),
                )?)
            })
            .await
            .unwrap();
        let raw = std::fs::read(self.store.raw_path(&notification)).unwrap();
        let parsed = mail_parser::MessageParser::default().parse(&raw).unwrap();
        let text = parsed.body_text(0).unwrap();
        text.lines()
            .find_map(|l| l.strip_prefix("https://filter.example.test/challenge#"))
            .unwrap()
            .into()
    }
    async fn sql(&self, sql: &str) {
        let sql = sql.to_string();
        self.store
            .run(move |db| {
                db.execute_batch(&sql)?;
                Ok(())
            })
            .await
            .unwrap();
    }
    async fn count(&self, sql: &str) -> i64 {
        let sql = sql.to_string();
        self.store
            .run(move |db| Ok(db.query_row(&sql, [], |r| r.get(0))?))
            .await
            .unwrap()
    }
    async fn states(&self) -> Vec<(String, String)> {
        let id = self.id.clone();
        self.store
            .run(move |db| {
                let mut q = db.prepare(
                    "SELECT address,status FROM deliveries WHERE message_id=?1 ORDER BY address",
                )?;
                Ok(q.query_map([id], |r| Ok((r.get(0)?, r.get(1)?)))?
                    .collect::<rusqlite::Result<_>>()?)
            })
            .await
            .unwrap()
    }
    async fn assert_held(&self) {
        assert!(self.states().await.iter().all(|(_, s)| s == "quarantined"));
        assert_eq!(
            self.count("SELECT COUNT(*) FROM audit WHERE action='quarantine_release'")
                .await,
            0
        );
    }
}

#[tokio::test]
async fn default_disabled_and_no_incoming_or_page_side_effects() {
    let f = Fixture::new().await;
    assert!(!Policy::default().enabled);
    assert!(
        challenge::prepare(
            &f.store,
            &Policy::default(),
            actor("admin"),
            f.id.clone(),
            body(ALICE)
        )
        .await
        .unwrap()
        .is_none()
    );
    assert_eq!(
        challenge::submit(&f.store, &Policy::default(), response(&"a".repeat(64)))
            .await
            .unwrap(),
        challenge::Submission::default()
    );
    let _ = challenge::page();
    assert_eq!(f.count("SELECT COUNT(*) FROM challenge_requests").await, 0);
    assert!(f.store.claim().await.unwrap().is_none());
    f.assert_held().await;
}

#[test]
fn configuration_request_and_proof_fail_closed() {
    for origin in [
        "http://filter.example.test",
        "https://filter.example.test/",
        "https://filter.example.test/path",
        "https://filter.example.test#x",
        "https://filter.example.test?token=x",
        "https://user:pass@filter.example.test",
    ] {
        assert!(
            Policy {
                public_origin: origin.into(),
                ..policy()
            }
            .validate()
            .is_err()
        );
    }
    for from in [
        "postmaster@example.test\r\nBcc: victim@example.org",
        "",
        "bad",
    ] {
        assert!(
            Policy {
                notification_from: from.into(),
                ..policy()
            }
            .validate()
            .is_err()
        );
    }
    for ttl_seconds in [0, 59, 86401, u32::MAX] {
        assert!(
            Policy {
                ttl_seconds,
                ..policy()
            }
            .validate()
            .is_err()
        );
    }
    assert!(
        serde_json::from_str::<Request>(
            r#"{"recipient":"alice@example.test","hosts":["attacker.test"]}"#
        )
        .is_err()
    );
    assert!(
        serde_json::from_str::<ResponseRequest>(r#"{"token":"a","recipient":"bob@example.test"}"#)
            .is_err()
    );
    assert!(!format!("{:?}", response("never-log-this")).contains("never-log-this"));
    assert!(proof(common::MESSAGE, "example.org").is_some());
    assert!(proof(common::MESSAGE, "EXAMPLE.ORG").is_some());
    for domain in ["org", "sub.example.org", "example.org.", "evil.example"] {
        assert!(proof(common::MESSAGE, domain).is_none());
    }
    assert!(
        VerifiedSmtpFrom::from_dmarc(
            common::MESSAGE,
            &mail_auth::DmarcOutput::default().with_domain("example.org")
        )
        .is_none()
    );
}

#[tokio::test]
async fn proof_record_binds_original_and_queued_octets_and_shares_enqueue_transaction() {
    let f = Fixture::new().await;
    f.sql("DELETE FROM challenge_smtp_identity").await;
    let mut evidence = proof(common::MESSAGE, "example.org").unwrap();
    let clone = evidence.clone();
    assert!(!format!("{clone:?}").contains(FROM));
    assert!(!format!("{clone:?}").contains("example.org"));
    let id = f.id.clone();
    f.store
        .run(move |db| {
            let tx = db.transaction()?;
            let scan: String =
                tx.query_row("SELECT scan FROM messages WHERE id=?1", [&id], |r| r.get(0))?;
            let scan: Scan = serde_json::from_str(&scan)?;
            assert!(!evidence.record(&tx, &id, &scan)?); // Not yet bound to queued bytes.
            assert!(!evidence.bind_queued(b"From: other@example.org\r\n\r\nHi\r\n"));
            assert!(!evidence.record(&tx, &id, &scan)?);
            assert!(evidence.bind_queued(common::MESSAGE));
            let mut changed_scan = scan.clone();
            changed_scan.subject = "different stored scan".into();
            assert!(!evidence.record(&tx, &id, &changed_scan)?);
            assert!(!evidence.record(&tx, &uuid::Uuid::new_v4().to_string(), &scan)?);
            assert!(evidence.record(&tx, &id, &scan)?);
            assert!(!evidence.record(&tx, &id, &scan)?); // Immutable/idempotent identity.
            tx.rollback()?;
            assert_eq!(
                db.query_row("SELECT COUNT(*) FROM challenge_smtp_identity", [], |r| r
                    .get::<_, i64>(0))?,
                0
            );
            Ok(())
        })
        .await
        .unwrap();
    // Trusted rewriting can change trace headers without changing From or original digest.
    let queued = message::rewrite(
        common::MESSAGE,
        false,
        "Received: by local.test; Thu, 10 Sep 2026 00:00:00 +0000\r\n",
    )
    .unwrap();
    std::fs::write(f.store.raw_path(&f.id), &queued).unwrap();
    assert!(
        challenge::record_smtp_identity(
            &f.store,
            f.id.clone(),
            proof(common::MESSAGE, "example.org").unwrap()
        )
        .await
        .unwrap()
    );
    assert!(f.prepare("alice", &f.id, ALICE).await.is_some());
}

#[tokio::test]
async fn notification_and_hash_are_durable_private_and_single_recipient() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new().await;
    let p = f.prepare("alice", &f.id, ALICE).await.unwrap();
    assert_eq!(p.mailbox(), FROM);
    assert_eq!(p.domain(), "example.org");
    let receipt = challenge::request(
        &f.store,
        &policy(),
        actor("alice"),
        p,
        vec!["mx.example.org".into()],
    )
    .await
    .unwrap()
    .unwrap();
    let token = f.token(&receipt.id).await;
    assert_eq!(token.len(), 64);
    assert!(!serde_json::to_string(&receipt).unwrap().contains(&token));
    f.assert_held().await;
    let reopened = Store::open(f.root.path()).unwrap();
    reopened.recover().await.unwrap();
    let job = reopened.claim().await.unwrap().unwrap();
    assert_eq!(job.sender, "");
    assert!(job.is_dsn);
    assert_eq!(job.destination, FROM);
    assert_eq!(job.hosts, ["mx.example.org"]);
    let raw = std::fs::read(reopened.raw_path(&job.message_id)).unwrap();
    message::validate(&raw).unwrap();
    assert_eq!(
        std::fs::metadata(reopened.raw_path(&job.message_id))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let mail = String::from_utf8(raw).unwrap();
    assert!(mail.is_ascii(), "French accents must not require 8BITMIME");
    let parsed = mail_parser::MessageParser::default()
        .parse(mail.as_bytes())
        .unwrap();
    let text = parsed.body_text(0).unwrap();
    assert!(text.contains("ne prouve") || text.contains("pas que vous êtes humain"));
    for header in [
        "Auto-Submitted: auto-generated\r\n",
        "X-Auto-Response-Suppress: All\r\n",
        "To: <sender@example.org>\r\n",
        "X-NoiseFence-Challenge: 1\r\n",
        "Content-Type: text/plain; charset=utf-8\r\n",
        "Content-Transfer-Encoding: base64\r\n",
    ] {
        assert!(mail.contains(header));
    }
    for private in [
        ALICE,
        BOB,
        ALIAS,
        "Rendez-vous",
        "bounce@bounces.example.net",
    ] {
        assert!(!mail.contains(private));
        assert!(!text.contains(private));
    }
    assert!(text.contains(&format!("/challenge#{token}\r\n")));
    assert!(!mail.contains("?token="));
    assert!(!text.contains("?token="));
    let expected = message::digest(token.as_bytes());
    f.store
        .run(move |db| {
            assert_eq!(
                db.query_row("SELECT token_hash FROM challenge_requests", [], |r| r
                    .get::<_, String>(0))?,
                expected
            );
            Ok(())
        })
        .await
        .unwrap();
    for file in ["state.sqlite3", "state.sqlite3-wal"] {
        if let Ok(bytes) = std::fs::read(f.root.path().join(file)) {
            assert!(!bytes.windows(token.len()).any(|w| w == token.as_bytes()));
        }
    }
}

#[tokio::test]
async fn correct_response_releases_only_selected_delivery_and_retains_semantics() {
    let f = Fixture::new().await;
    let token = f.issue().await;
    f.sql(
        "UPDATE deliveries SET attempts=3,error='old failure' WHERE address='alice@example.test'",
    )
    .await;
    let before = std::fs::read(f.store.raw_path(&f.id)).unwrap();
    let started = noisefence::now();
    let answer = challenge::submit(&f.store, &policy(), solved(&f.store, &token).await)
        .await
        .unwrap();
    assert_eq!(answer, challenge::Submission::default());
    assert_eq!(
        f.states().await,
        vec![
            (ALICE.into(), "pending".into()),
            (BOB.into(), "quarantined".into()),
            (ALIAS.into(), "quarantined".into())
        ]
    );
    assert_eq!(std::fs::read(f.store.raw_path(&f.id)).unwrap(), before);
    let id = f.id.clone();
    f.store.run(move |db| {
        let (action,released,attempts,error,scan,sender):(String,i64,i64,Option<String>,String,String) = db.query_row("SELECT p.action,p.released_at,d.attempts,d.error,m.scan,m.sender FROM deliveries d JOIN delivery_policy p ON p.delivery_id=d.id JOIN messages m ON m.id=d.message_id WHERE m.id=?1 AND d.address=?2",params![id,ALICE],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?)))?;
        assert_eq!(action,"quarantine"); assert!(released>=started); assert_eq!(attempts,3); assert!(error.is_none());
        assert_eq!(serde_json::from_str::<Scan>(&scan)?.action.unwrap().effective,Action::Quarantine);
        assert_eq!(sender,"bounce@bounces.example.net");
        assert_eq!(db.query_row("SELECT COUNT(*) FROM audit WHERE username='alice' AND action IN ('challenge_complete','quarantine_release')",[],|r|r.get::<_,i64>(0))?,2);
        assert_eq!(db.query_row("SELECT COUNT(*) FROM feedback",[],|r|r.get::<_,i64>(0))?,0);
        Ok(())
    }).await.unwrap();
    assert_eq!(
        challenge::submit(&f.store, &policy(), solved(&f.store, &token).await)
            .await
            .unwrap(),
        answer
    );
    assert_eq!(
        challenge::submit(&f.store, &policy(), response(&"0".repeat(64)))
            .await
            .unwrap(),
        answer
    );
    assert_eq!(
        f.count("SELECT COUNT(*) FROM audit WHERE action='quarantine_release'")
            .await,
        1
    );
}

#[tokio::test]
async fn admin_and_alias_grants_work_but_hidden_recipients_and_sessions_do_not() {
    let f = Fixture::new().await;
    assert!(f.prepare("alice", &f.id, ALIAS).await.is_some());
    assert!(f.prepare("alice", &f.id, BOB).await.is_none());
    assert!(f.prepare("stranger", &f.id, ALICE).await.is_none());
    assert!(f.prepare("admin", &f.id, BOB).await.is_some());
    let forged = Actor {
        username: "admin".into(),
        session_hash: actor("alice").session_hash,
    };
    assert!(
        challenge::prepare(&f.store, &policy(), forged, f.id.clone(), body(BOB))
            .await
            .unwrap()
            .is_none()
    );
    f.sql("UPDATE sessions SET expires=0 WHERE username='alice'")
        .await;
    assert!(f.prepare("alice", &f.id, ALICE).await.is_none());
    f.sql("UPDATE users SET disabled=1 WHERE username='admin'")
        .await;
    assert!(f.prepare("admin", &f.id, BOB).await.is_none());
    f.assert_held().await;
}

#[tokio::test]
async fn authorization_and_route_binding_are_rechecked_after_async_preparation() {
    for mutation in [
        "DELETE FROM grants WHERE username='alice'",
        "DELETE FROM sessions WHERE username='alice'",
        "UPDATE users SET disabled=1 WHERE username='alice'",
        "UPDATE deliveries SET destination='new@example.test' WHERE address='alice@example.test'",
        "UPDATE delivery_policy SET held_until=0",
    ] {
        let f = Fixture::new().await;
        let p = f.prepare("alice", &f.id, ALICE).await.unwrap();
        f.sql(mutation).await;
        assert!(
            challenge::request(
                &f.store,
                &policy(),
                actor("alice"),
                p,
                vec!["mx.example.org".into()]
            )
            .await
            .unwrap()
            .is_none(),
            "{mutation}"
        );
        assert_eq!(f.count("SELECT COUNT(*) FROM challenge_requests").await, 0);
        assert_eq!(f.count("SELECT COUNT(*) FROM messages").await, 1);
    }
    let f = Fixture::new().await;
    for hosts in [
        vec![],
        vec![".".into()],
        vec!["mx.example.org\r\nRCPT TO:<victim@example.org>".into()],
    ] {
        let p = f.prepare("alice", &f.id, ALICE).await.unwrap();
        assert!(
            challenge::request(&f.store, &policy(), actor("alice"), p, hosts)
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn revocation_replay_expiry_and_current_privileges_fail_closed() {
    for mutation in [
        "DELETE FROM grants WHERE username='alice'",
        "UPDATE users SET disabled=1 WHERE username='alice'",
        "UPDATE users SET password='new-salted-password' WHERE username='alice'",
        "INSERT INTO console_user_versions VALUES('alice',1)",
        "DELETE FROM users WHERE username='alice'",
        "UPDATE deliveries SET destination='changed@example.test' WHERE address='alice@example.test'",
        "UPDATE deliveries SET status='discarded' WHERE address='alice@example.test'",
        "UPDATE deliveries SET status='pending' WHERE address='alice@example.test'",
        "UPDATE delivery_policy SET held_until=0",
        "UPDATE messages SET raw_present=0 WHERE is_dsn=0",
        "UPDATE messages SET scan=json_set(scan,'$.antivirus.status','malware') WHERE is_dsn=0",
        "UPDATE messages SET scan=json_set(scan,'$.signatures.status','malware') WHERE is_dsn=0",
        "UPDATE messages SET scan=json_set(scan,'$.evidence.antivirus',json('{\"status\":\"malware\",\"signature\":null,\"elapsed_ms\":0}')) WHERE is_dsn=0",
        "UPDATE messages SET scan=json_set(scan,'$.evidence.source','supplied_envelope') WHERE is_dsn=0",
        "UPDATE messages SET scan=json_set(scan,'$.evidence.authentication.dmarc_spf','fail') WHERE is_dsn=0",
        "UPDATE challenge_requests SET created=created-3600,expires=created-1",
    ] {
        let f = Fixture::new().await;
        let token = f.issue().await;
        f.sql(mutation).await;
        assert_eq!(
            challenge::submit(&f.store, &policy(), solved(&f.store, &token).await)
                .await
                .unwrap(),
            challenge::Submission::default(),
            "{mutation}"
        );
        assert_eq!(
            f.count("SELECT COUNT(*) FROM audit WHERE action='quarantine_release'")
                .await,
            0,
            "{mutation}"
        );
        assert!(
            f.states()
                .await
                .iter()
                .filter(|(a, _)| a != ALICE)
                .all(|(_, s)| s == "quarantined")
        );
    }
    let f = Fixture::new().await;
    let token = f.issue().await;
    assert!(
        !challenge::revoke(&f.store, actor("stranger"), f.id.clone(), body(ALICE))
            .await
            .unwrap()
    );
    assert!(
        challenge::revoke(&f.store, actor("admin"), f.id.clone(), body(ALICE))
            .await
            .unwrap()
    );
    assert!(
        !challenge::revoke(&f.store, actor("admin"), f.id.clone(), body(ALICE))
            .await
            .unwrap()
    );
    assert!(f.store.claim().await.unwrap().is_none());
    challenge::submit(&f.store, &policy(), solved(&f.store, &token).await)
        .await
        .unwrap();
    f.assert_held().await;
}

#[tokio::test]
async fn known_token_losing_grant_is_permanently_revoked_but_session_logout_is_not_reauthorization()
{
    let f = Fixture::new().await;
    let token = f.issue().await;
    f.sql("DELETE FROM grants WHERE username='alice'").await;
    challenge::submit(&f.store, &policy(), solved(&f.store, &token).await)
        .await
        .unwrap();
    f.sql("INSERT INTO grants VALUES('alice','alice@example.test')")
        .await;
    challenge::submit(&f.store, &policy(), solved(&f.store, &token).await)
        .await
        .unwrap();
    f.assert_held().await;
    let f = Fixture::new().await;
    let token = f.issue().await;
    f.sql("DELETE FROM sessions WHERE username='alice'").await;
    challenge::submit(&f.store, &policy(), solved(&f.store, &token).await)
        .await
        .unwrap();
    assert_eq!(
        f.count("SELECT COUNT(*) FROM audit WHERE action='quarantine_release'")
            .await,
        1
    );
}

#[tokio::test]
async fn missing_changed_and_expired_payloads_never_release() {
    for remove in [false, true] {
        let f = Fixture::new().await;
        let token = f.issue().await;
        if remove {
            std::fs::remove_file(f.store.raw_path(&f.id)).unwrap();
        } else {
            std::fs::write(
                f.store.raw_path(&f.id),
                [common::MESSAGE, b"Changed payload\r\n"].concat(),
            )
            .unwrap();
        }
        challenge::submit(&f.store, &policy(), solved(&f.store, &token).await)
            .await
            .unwrap();
        f.assert_held().await;
    }
    let f = Fixture::new().await;
    f.sql(&format!(
        "UPDATE delivery_policy SET held_until={}",
        noisefence::now() + 120
    ))
    .await;
    let receipt = f.issue_for(&f.id, "alice", ALICE).await.unwrap();
    assert!(receipt.expires_at <= noisefence::now() + 120);
    let token = f.token(&receipt.id).await;
    f.sql("UPDATE delivery_policy SET held_until=0").await;
    f.store.cleanup().await.unwrap();
    challenge::submit(&f.store, &policy(), solved(&f.store, &token).await)
        .await
        .unwrap();
    assert!(f.states().await.iter().all(|(_, s)| s == "expired"));
    assert_eq!(
        f.count("SELECT COUNT(*) FROM audit WHERE action='quarantine_release'")
            .await,
        0
    );
}

#[tokio::test]
async fn historical_spoofed_untrusted_or_incomplete_authentication_is_ineligible() {
    let f = Fixture::new().await;
    let id = f.mail(common::MESSAGE, false).await;
    assert!(f.prepare("admin", &id, ALICE).await.is_none());
    for mutation in [
        "UPDATE messages SET sender=''",
        "UPDATE messages SET is_dsn=1",
        "UPDATE messages SET scan=json_set(scan,'$.complete',json('false'))",
        "UPDATE messages SET scan=json_set(scan,'$.raw_sha256','wrong')",
        "UPDATE messages SET scan=json_set(scan,'$.evidence.source','content_only')",
        "UPDATE messages SET scan=json_set(scan,'$.evidence.source','supplied_envelope')",
        "UPDATE messages SET scan=json_set(scan,'$.evidence.authentication.state','unavailable')",
        "UPDATE messages SET scan=json_set(scan,'$.evidence.authentication.dmarc_state','unavailable')",
        "UPDATE messages SET scan=json_set(scan,'$.evidence.authentication.dmarc_spf','none')",
        "UPDATE messages SET scan=json_set(scan,'$.antivirus.status','malware')",
        "UPDATE messages SET scan=json_set(scan,'$.signatures.status','malware')",
    ] {
        let f = Fixture::new().await;
        f.sql("DELETE FROM challenge_smtp_identity").await;
        f.sql(mutation).await;
        assert!(
            !challenge::record_smtp_identity(
                &f.store,
                f.id.clone(),
                proof(common::MESSAGE, "example.org").unwrap()
            )
            .await
            .unwrap(),
            "{mutation}"
        );
        assert!(f.prepare("admin", &f.id, ALICE).await.is_none());
    }
}

#[tokio::test]
async fn automated_list_report_and_ambiguous_from_mail_cannot_be_challenged() {
    for extra in [
        "Auto-Submitted: auto-replied\r\n",
        "Auto-Submitted: auto-generated\r\n",
        "Auto-Submitted: unknown\r\n",
        "Auto-Submitted:\r\n auto-generated\r\n",
        "List-Id: <list.example.org>\r\n",
        "List-Unsubscribe: <mailto:list@example.org>\r\n",
        "Precedence: bulk\r\n",
        "X-Auto-Response-Suppress: All\r\n",
        "X-NoiseFence-Challenge: 1\r\n",
        "Content-Type: multipart/report; report-type=delivery-status\r\n",
    ] {
        let raw = [extra.as_bytes(), common::MESSAGE].concat();
        assert!(proof(&raw, "example.org").is_none(), "{extra}");
    }
    for from in [
        "",
        "From: a@example.org, b@example.org\r\n",
        "From: a@example.org\r\nFrom: b@example.org\r\n",
        "From: a@sub.example.org\r\n",
        "From: Group: a@example.org;\r\n",
    ] {
        let raw = format!("{from}Subject: test\r\n\r\nhello\r\n");
        assert!(proof(raw.as_bytes(), "example.org").is_none(), "{from}");
    }
    let spoofed = [
        b"Authentication-Results: trusted.test; dmarc=pass header.from=example.org\r\n".as_slice(),
        common::MESSAGE,
    ]
    .concat();
    let f = Fixture::new().await;
    let id = f.mail(&spoofed, false).await;
    assert!(f.prepare("admin", &id, ALICE).await.is_none());
    assert!(
        proof(
            &[b"Auto-Submitted: no\r\n".as_slice(), common::MESSAGE].concat(),
            "example.org"
        )
        .is_some()
    );
}

#[tokio::test]
async fn durable_rate_limits_survive_revocation_and_reopening() {
    let f = Fixture::new().await;
    let _ = f.issue().await;
    assert!(f.issue_for(&f.id, "admin", ALICE).await.is_none());
    challenge::revoke(&f.store, actor("admin"), f.id.clone(), body(ALICE))
        .await
        .unwrap();
    let reopened = Store::open(f.root.path()).unwrap();
    let p = challenge::prepare(
        &reopened,
        &policy(),
        actor("admin"),
        f.id.clone(),
        body(ALICE),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        challenge::request(
            &reopened,
            &policy(),
            actor("admin"),
            p,
            vec!["mx.example.org".into()]
        )
        .await
        .unwrap()
        .is_none()
    );
    for _ in 0..2 {
        let id = f.mail(common::MESSAGE, true).await;
        assert!(f.issue_for(&id, "admin", ALICE).await.is_some());
    }
    let id = f.mail(common::MESSAGE, true).await;
    assert!(f.issue_for(&id, "admin", ALICE).await.is_none());
    assert_eq!(f.count("SELECT COUNT(*) FROM challenge_requests").await, 3);
    // Metadata cleanup must not restore the mailbox budget, even when the original
    // delivery and its foreign-keyed challenge record have disappeared.
    f.sql(&format!("DELETE FROM messages WHERE id='{}'", f.id))
        .await;
    assert_eq!(f.count("SELECT COUNT(*) FROM challenge_requests").await, 2);
    assert_eq!(
        f.count("SELECT COUNT(*) FROM challenge_rate_events").await,
        3
    );
    assert!(f.issue_for(&id, "admin", ALICE).await.is_none());
}

#[tokio::test]
async fn expiry_boundary_never_releases_and_later_reissue_cannot_revive_old_token() {
    let f = Fixture::new().await;
    let old = f.issue().await;
    f.sql(&format!(
        "UPDATE challenge_requests SET created=created-60,expires={}",
        noisefence::now()
    ))
    .await;
    challenge::submit(&f.store, &policy(), solved(&f.store, &old).await)
        .await
        .unwrap();
    f.assert_held().await;
    assert!(f.issue_for(&f.id, "admin", ALICE).await.is_none());
    // Move only test history beyond both expiration and the strict 24h rate window.
    f.sql(&format!("UPDATE challenge_requests SET created={},expires={}; UPDATE challenge_rate_events SET created={}",noisefence::now()-90000,noisefence::now()-86401,noisefence::now()-90000)).await;
    let receipt = f.issue_for(&f.id, "alice", ALICE).await.unwrap();
    let current = f.token(&receipt.id).await;
    assert_ne!(current, old);
    challenge::submit(&f.store, &policy(), solved(&f.store, &old).await)
        .await
        .unwrap();
    f.assert_held().await;
    challenge::submit(&f.store, &policy(), solved(&f.store, &current).await)
        .await
        .unwrap();
    assert_eq!(
        f.count("SELECT COUNT(*) FROM audit WHERE action='quarantine_release'")
            .await,
        1
    );
    assert_eq!(
        f.count("SELECT COUNT(*) FROM challenge_requests WHERE state='revoked'")
            .await,
        1
    );
    assert_eq!(
        f.count("SELECT COUNT(*) FROM challenge_requests WHERE state='consumed'")
            .await,
        1
    );
}

#[tokio::test]
async fn per_user_and_global_budgets_apply_across_distinct_mailboxes() {
    for (limit, username) in [(20, "alice"), (100, "admin")] {
        let f = Fixture::new().await;
        let _ = f.issue().await;
        // Seed durable history locally, keeping the target case independent of the
        // mailbox/per-delivery cap. No notifications are sent by fixture history.
        f.store.run(move |db| {
            for n in 1..limit {
                let requester = if limit == 100 { format!("prior-user-{n}") } else { "alice".into() };
                db.execute("INSERT INTO challenge_rate_events(id,delivery_key,mailbox_key,requested_by,created) SELECT ?1,?2,?3,?4,created FROM challenge_rate_events LIMIT 1",params![format!("history-{n}"),message::digest(format!("delivery-{n}").as_bytes()),message::digest(format!("different-{n}@example.org").as_bytes()),requester])?;
            }
            Ok(())
        }).await.unwrap();
        let raw = String::from_utf8(common::MESSAGE.to_vec())
            .unwrap()
            .replace(FROM, "another@example.org");
        let id = f.mail(raw.as_bytes(), true).await;
        assert!(f.issue_for(&id, username, ALICE).await.is_none());
    }
}

#[tokio::test]
async fn separate_sqlite_connections_cannot_issue_or_consume_twice() {
    let f = Fixture::new().await;
    let other = Store::open(f.root.path()).unwrap();
    let p1 = f.prepare("alice", &f.id, ALICE).await.unwrap();
    let p2 = f.prepare("alice", &f.id, ALICE).await.unwrap();
    let cfg = policy();
    let (a, b) = tokio::join!(
        challenge::request(
            &f.store,
            &cfg,
            actor("alice"),
            p1,
            vec!["mx.example.org".into()]
        ),
        challenge::request(
            &other,
            &cfg,
            actor("alice"),
            p2,
            vec!["mx.example.org".into()]
        )
    );
    let (a, b) = (a.unwrap(), b.unwrap());
    assert_eq!(usize::from(a.is_some()) + usize::from(b.is_some()), 1);
    let receipt = a.or(b).unwrap();
    let token = f.token(&receipt.id).await;
    let solved = solved(&f.store, &token).await;
    let (a, b) = tokio::join!(
        challenge::submit(&f.store, &cfg, solved.clone()),
        challenge::submit(&other, &cfg, solved)
    );
    assert_eq!(a.unwrap(), b.unwrap());
    assert_eq!(
        f.count("SELECT COUNT(*) FROM audit WHERE action='quarantine_release'")
            .await,
        1
    );
    assert_eq!(
        f.count("SELECT COUNT(*) FROM challenge_requests WHERE state='consumed'")
            .await,
        1
    );
}

#[tokio::test]
async fn sqlite_failure_rolls_back_queue_hash_audit_and_consumption() {
    let f = Fixture::new().await;
    f.sql("CREATE TRIGGER reject_request BEFORE INSERT ON audit WHEN NEW.action='challenge_request' BEGIN SELECT RAISE(ABORT,'fixture storage failure'); END").await;
    let p = f.prepare("alice", &f.id, ALICE).await.unwrap();
    assert!(
        challenge::request(
            &f.store,
            &policy(),
            actor("alice"),
            p,
            vec!["mx.example.org".into()]
        )
        .await
        .is_err()
    );
    assert_eq!(f.count("SELECT COUNT(*) FROM messages").await, 1);
    assert_eq!(f.count("SELECT COUNT(*) FROM challenge_requests").await, 0);
    assert_eq!(
        std::fs::read_dir(f.root.path().join("spool"))
            .unwrap()
            .count(),
        1
    );
    f.sql("DROP TRIGGER reject_request").await;
    let token = f.issue().await;
    let answer = solved(&f.store, &token).await;
    f.sql("CREATE TRIGGER reject_release BEFORE INSERT ON audit WHEN NEW.action='quarantine_release' BEGIN SELECT RAISE(ABORT,'fixture storage failure'); END").await;
    assert!(
        challenge::submit(&f.store, &policy(), answer.clone())
            .await
            .is_err()
    );
    f.assert_held().await;
    assert_eq!(
        f.count("SELECT COUNT(*) FROM challenge_requests WHERE state='pending'")
            .await,
        1
    );
    assert_eq!(
        f.count("SELECT COUNT(*) FROM audit WHERE action='challenge_complete'")
            .await,
        0
    );
    assert_eq!(
        f.count("SELECT attempts FROM challenge_visual_codes").await,
        0
    );
    assert_eq!(
        f.count("SELECT COUNT(*) FROM challenge_visual_codes WHERE nonce<>'' AND answer_hash<>''")
            .await,
        1
    );
    f.sql("DROP TRIGGER reject_release").await;
    challenge::submit(&f.store, &policy(), answer)
        .await
        .unwrap();
    assert_eq!(
        f.count("SELECT COUNT(*) FROM audit WHERE action='quarantine_release'")
            .await,
        1
    );
}

#[tokio::test]
async fn public_http_requires_body_post_origin_and_current_policy_and_is_generic() {
    use axum::{
        body::Body,
        http::{Request as HttpRequest, StatusCode},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    let f = Fixture::new().await;
    let token = f.issue().await;
    let state = std::sync::Arc::new(std::sync::RwLock::new(policy()));
    let current = state.clone();
    let app = challenge::public_router(f.store.clone(), move || current.read().unwrap().clone());
    let page = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .uri("/challenge")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(page.status(), StatusCode::OK);
    for (name, value) in [
        ("cache-control", "no-store"),
        ("referrer-policy", "no-referrer"),
        ("x-frame-options", "DENY"),
    ] {
        assert_eq!(page.headers()[name], value);
    }
    let csp = page.headers()["content-security-policy"]
        .to_str()
        .unwrap()
        .to_owned();
    let html = String::from_utf8(
        page.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(!html.contains(&token));
    assert!(!html.contains("localStorage"));
    assert!(html.find("history.replaceState").unwrap() < html.find("fetch(").unwrap());
    use base64::Engine as _;
    use sha2::Digest as _;
    for name in ["script", "style"] {
        let content = html
            .split_once(&format!("<{name}>"))
            .unwrap()
            .1
            .split_once(&format!("</{name}>"))
            .unwrap()
            .0;
        let hash = base64::engine::general_purpose::STANDARD
            .encode(sha2::Sha256::digest(content.as_bytes()));
        assert!(csp.contains(&format!("{name}-src 'sha256-{hash}'")));
    }
    assert!(csp.contains("img-src data:") && csp.contains("connect-src 'self'"));
    assert!(!csp.contains("unsafe-inline") && !csp.contains("unsafe-eval"));
    f.assert_held().await;
    let proof = solved(&f.store, &token).await;
    let good = serde_json::json!({"token":token,"nonce":proof.nonce,"code":proof.code}).to_string();
    let expected = serde_json::to_vec(&challenge::Submission::default()).unwrap();
    for (origin, path, json) in [
        (
            "https://filter.example.test",
            "/challenge/submit",
            serde_json::json!({"token":token}).to_string(),
        ),
        ("https://evil.example", "/challenge/submit", good.clone()),
        ("", "/challenge/submit", good.clone()),
        (
            "https://filter.example.test",
            "/challenge/submit?ignored=1",
            good.clone(),
        ),
        (
            "https://filter.example.test",
            "/challenge/submit",
            "bad json".into(),
        ),
        (
            "https://filter.example.test",
            "/challenge/submit",
            "x".repeat(2048),
        ),
        (
            "https://filter.example.test",
            "/challenge/submit",
            r#"{"token":"invalid"}"#.into(),
        ),
    ] {
        let reply = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri(path)
                    .header("origin", origin)
                    .header("content-type", "application/json")
                    .body(Body::from(json))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(reply.status(), StatusCode::OK);
        assert_eq!(
            reply.into_body().collect().await.unwrap().to_bytes(),
            expected
        );
        f.assert_held().await;
    }
    let duplicate_origin = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri(challenge::SUBMIT_PATH)
                .header("origin", "https://filter.example.test")
                .header("origin", "https://filter.example.test")
                .header("content-type", "application/json")
                .body(Body::from(good.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(duplicate_origin.status(), StatusCode::OK);
    f.assert_held().await;
    for enabled in [false, true, true] {
        state.write().unwrap().enabled = enabled;
        if !enabled {
            let page = app
                .clone()
                .oneshot(
                    HttpRequest::builder()
                        .uri(challenge::PAGE_PATH)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(page.status(), StatusCode::NOT_FOUND);
        }
        let reply = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri(challenge::SUBMIT_PATH)
                    .header("origin", "https://filter.example.test")
                    .header("content-type", "application/json")
                    .body(Body::from(good.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(reply.status(), StatusCode::OK);
        assert_eq!(
            reply.into_body().collect().await.unwrap().to_bytes(),
            expected
        );
        if !enabled {
            f.assert_held().await;
        }
    }
    assert_eq!(
        f.count("SELECT COUNT(*) FROM audit WHERE action='quarantine_release'")
            .await,
        1
    );
}

#[tokio::test]
async fn queued_notification_uses_null_smtp_mail_from_on_loopback_protocol() {
    use noisefence::{
        relay::{self, Outcome},
        smtp::{self, Wire},
    };
    use tokio::{io::BufReader, net::TcpListener};
    let f = Fixture::new().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let route = listener.local_addr().unwrap().to_string();
    let p = f.prepare("alice", &f.id, ALICE).await.unwrap();
    let receipt = challenge::request(&f.store, &policy(), actor("alice"), p, vec![route])
        .await
        .unwrap()
        .unwrap();
    let token = f.token(&receipt.id).await;
    let job = f.store.claim().await.unwrap().unwrap();
    let raw = std::fs::read(f.store.raw_path(&job.message_id)).unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut wire: Wire = BufReader::new(Box::new(stream));
        smtp::reply(&mut wire, "220 local.test\r\n").await.unwrap();
        for (expected, reply) in [
            ("EHLO ", "250 local.test\r\n"),
            ("MAIL FROM:<>", "250 OK\r\n"),
            ("RCPT TO:<sender@example.org>", "250 OK\r\n"),
            ("DATA\r\n", "354 Send\r\n"),
        ] {
            let command = smtp::line(&mut wire, 1024, 5).await.unwrap().unwrap();
            assert!(command.starts_with(expected.as_bytes()));
            smtp::reply(&mut wire, reply).await.unwrap();
        }
        let mut body = Vec::new();
        loop {
            let line = smtp::line(&mut wire, 1001, 5).await.unwrap().unwrap();
            if line == b".\r\n" {
                break;
            }
            body.extend(line);
        }
        smtp::reply(&mut wire, "250 accepted\r\n").await.unwrap();
        body
    });
    let report = relay::deliver_traced(&common::config(f.root.path()), &job, &raw).await;
    assert!(matches!(report.outcome, Outcome::Delivered));
    assert_eq!(server.await.unwrap(), raw);
    assert!(
        !serde_json::to_string(&report.attempts)
            .unwrap()
            .contains(&token)
    );
    f.assert_held().await;
}

#[tokio::test]
async fn parent_enqueue_persists_only_current_smtp_proof_with_final_bytes() {
    let f = Fixture::new().await;
    let id = f.id.clone();
    let scan = f
        .store
        .run(move |db| {
            let json: String =
                db.query_row("SELECT scan FROM messages WHERE id=?1", [id], |r| r.get(0))?;
            Ok(serde_json::from_str::<Scan>(&json)?)
        })
        .await
        .unwrap();
    for source in [
        Source::SmtpSession,
        Source::SuppliedEnvelope,
        Source::ContentOnly,
    ] {
        let mut scan = scan.clone();
        scan.evidence.as_mut().unwrap().source = source;
        scan.challenge_identity = proof(common::MESSAGE, "example.org");
        assert!(
            !serde_json::to_string(&scan)
                .unwrap()
                .contains("challenge_identity")
        );
        let id = uuid::Uuid::new_v4().to_string();
        let raw = message::rewrite(
            common::MESSAGE,
            false,
            "Received: by filter.example.test; Thu, 10 Sep 2026 00:00:00 +0000\r\n",
        )
        .unwrap();
        f.store
            .enqueue(
                id.clone(),
                "bounce@bounces.example.net".into(),
                vec![Recipient {
                    address: ALICE.into(),
                    destination: ALICE.into(),
                    hosts: vec!["mx.example.test".into()],
                }],
                scan,
                raw,
            )
            .await
            .unwrap();
        assert_eq!(
            f.prepare("alice", &id, ALICE).await.is_some(),
            source == Source::SmtpSession
        );
    }
}

#[tokio::test]
async fn parent_api_preflight_is_authorized_side_effect_free_and_preserves_public_csp() {
    use axum::{
        body::Body,
        http::{Request as HttpRequest, StatusCode},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    let f = Fixture::new().await;
    let mut cfg = (*common::config(f.root.path())).clone();
    cfg.web.public_origin = policy().public_origin;
    cfg.web.secure_cookies = true;
    cfg.challenge = Some(policy());
    // A configured route prevents even DNS queries in this API test. Only queue it.
    cfg.domains.push(noisefence::config::Domain {
        name: "example.org".into(),
        next_hops: vec!["mx.example.test".into()],
        accept_all_recipients: false,
        recipients: vec![FROM.into()],
        aliases: Default::default(),
    });
    cfg.validate().unwrap();
    let app = noisefence::api::router(std::sync::Arc::new(cfg.clone()), f.store.clone()).unwrap();
    let page = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .uri(challenge::PAGE_PATH)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let csp = page.headers()["content-security-policy"].to_str().unwrap();
    assert!(csp.contains("script-src 'sha256-"));
    assert!(!csp.contains("unsafe-inline"));
    assert_eq!(page.status(), StatusCode::OK);
    assert_eq!(stats(&app).await["challenge_enabled"], true);
    let prepare_path = format!("/api/v1/messages/{}/challenge/prepare", f.id);
    for suffix in ["/prepare", "", "/revoke"] {
        let path = format!("/api/v1/messages/{}/challenge{suffix}", f.id);
        for (user, csrf, origin, status) in [
            (
                "nonexistent",
                "csrf",
                cfg.web.public_origin.as_str(),
                StatusCode::UNAUTHORIZED,
            ),
            (
                "alice",
                "wrong",
                cfg.web.public_origin.as_str(),
                StatusCode::FORBIDDEN,
            ),
            (
                "alice",
                "csrf",
                "https://foreign.example",
                StatusCode::FORBIDDEN,
            ),
        ] {
            let (actual, _) = console_post(
                &app,
                &path,
                user,
                csrf,
                origin,
                serde_json::json!({"recipient":ALICE}),
            )
            .await;
            assert_eq!(actual, status, "{suffix}");
        }
        let (status, json) = console_post(
            &app,
            &path,
            "bob",
            "csrf",
            &cfg.web.public_origin,
            serde_json::json!({"recipient":ALICE}),
        )
        .await;
        if suffix == "/revoke" {
            assert_eq!(status, StatusCode::OK);
            assert_eq!(json, serde_json::json!({"revoked":false}));
        } else {
            assert_eq!(status, StatusCode::CONFLICT);
        }
        let (status, _) = console_post(
            &app,
            &path,
            "alice",
            "csrf",
            &cfg.web.public_origin,
            serde_json::json!({"recipient":ALICE,"mailbox":"victim@example.org"}),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        f.sql("UPDATE sessions SET expires=0 WHERE username='alice'")
            .await;
        let (status, _) = console_post(
            &app,
            &path,
            "alice",
            "csrf",
            &cfg.web.public_origin,
            serde_json::json!({"recipient":ALICE}),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        f.sql(&format!(
            "UPDATE sessions SET expires={} WHERE username='alice'",
            noisefence::now() + 3600
        ))
        .await;
        assert_eq!(f.count("SELECT COUNT(*) FROM messages").await, 1);
        assert_eq!(f.count("SELECT COUNT(*) FROM challenge_requests").await, 0);
    }
    for (user, csrf, status) in [
        ("alice", "wrong", StatusCode::FORBIDDEN),
        ("bob", "csrf", StatusCode::CONFLICT),
        ("alice", "csrf", StatusCode::OK),
    ] {
        let reply = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri(&prepare_path)
                    .header(
                        "cookie",
                        format!("noisefence_session={}", session_token(user)),
                    )
                    .header("origin", &cfg.web.public_origin)
                    .header("x-csrf-token", csrf)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({"recipient":ALICE}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(reply.status(), status);
        if status == StatusCode::OK {
            let json: serde_json::Value =
                serde_json::from_slice(&reply.into_body().collect().await.unwrap().to_bytes())
                    .unwrap();
            assert_eq!(json, serde_json::json!({"mailbox":FROM}));
        }
        assert_eq!(f.count("SELECT COUNT(*) FROM messages").await, 1);
        assert_eq!(f.count("SELECT COUNT(*) FROM challenge_requests").await, 0);
    }
    let reply = app
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri(format!("/api/v1/messages/{}/challenge", f.id))
                .header(
                    "cookie",
                    format!("noisefence_session={}", session_token("alice")),
                )
                .header("origin", &cfg.web.public_origin)
                .header("x-csrf-token", "csrf")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"recipient":ALICE}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(reply.status(), StatusCode::OK);
    let receipt: serde_json::Value =
        serde_json::from_slice(&reply.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(receipt.as_object().unwrap().len(), 2);
    assert!(receipt.get("id").is_some() && receipt.get("expires_at").is_some());
    let token = f.token(receipt["id"].as_str().unwrap()).await;
    assert_eq!(f.count("SELECT COUNT(*) FROM challenge_requests").await, 1);
    f.assert_held().await;
    for setting in [None, Some(Policy::default())] {
        cfg.challenge = setting;
        let app =
            noisefence::api::router(std::sync::Arc::new(cfg.clone()), f.store.clone()).unwrap();
        let page = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri(challenge::PAGE_PATH)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(page.status(), StatusCode::NOT_FOUND);
        assert_eq!(stats(&app).await["challenge_enabled"], false);
        let reply = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .method("POST")
                    .uri(&prepare_path)
                    .header(
                        "cookie",
                        format!("noisefence_session={}", session_token("alice")),
                    )
                    .header("origin", &cfg.web.public_origin)
                    .header("x-csrf-token", "csrf")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({"recipient":ALICE}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(!reply.status().is_success());
        assert_eq!(f.count("SELECT COUNT(*) FROM challenge_requests").await, 1);
    }
    let disabled_app =
        noisefence::api::router(std::sync::Arc::new(cfg.clone()), f.store.clone()).unwrap();
    let revoke_path = format!("/api/v1/messages/{}/challenge/revoke", f.id);
    let (status, result) = console_post(
        &disabled_app,
        &revoke_path,
        "admin",
        "csrf",
        &cfg.web.public_origin,
        serde_json::json!({"recipient":ALICE}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(result, serde_json::json!({"revoked":true}));
    assert!(f.store.claim().await.unwrap().is_none());
    challenge::submit(&f.store, &policy(), solved(&f.store, &token).await)
        .await
        .unwrap();
    f.assert_held().await;
}

#[tokio::test]
async fn retention_purges_aged_metadata_even_while_original_deliveries_and_raw_remain() {
    for status in ["pending", "quarantined"] {
        for state in ["pending", "consumed", "revoked"] {
            let f = Fixture::new().await;
            let _token = f.issue().await;
            let time = noisefence::now();
            let id = f.id.clone();
            let audit_count = f.count("SELECT COUNT(*) FROM audit").await;
            f.store.run(move |db| {
                db.execute("UPDATE messages SET created=?2 WHERE id=?1",params![id,time-challenge::RETENTION_SECONDS-86400])?;
                db.execute("UPDATE deliveries SET status=?2 WHERE message_id=?1",params![id,status])?;
                db.execute("UPDATE challenge_requests SET created=?1,expires=?2,state=?3",params![time-challenge::RETENTION_SECONDS,time-challenge::RETENTION_SECONDS+3600,state])?;
                db.execute("UPDATE challenge_rate_events SET created=?1",[time-86400])?;
                db.execute("INSERT INTO challenge_rate_events(id,delivery_key,mailbox_key,requested_by,created) VALUES('recent-rate','delivery','mailbox','alice',?1)",[time-86399])?;
                // The helper composes with the transaction owned by Store.cleanup.
                let tx = db.transaction()?;
                assert_eq!(challenge::prune(&tx,time)?,3);
                tx.rollback()?;
                assert_eq!(db.query_row("SELECT COUNT(*) FROM challenge_requests",[],|r|r.get::<_,i64>(0))?,1);
                assert_eq!(challenge::prune(db,time)?,3);
                assert_eq!(challenge::prune(db,time)?,0);
                Ok(())
            }).await.unwrap();
            assert_eq!(f.count("SELECT COUNT(*) FROM challenge_requests").await, 0);
            assert_eq!(
                f.count("SELECT COUNT(*) FROM challenge_smtp_identity")
                    .await,
                0
            );
            assert_eq!(
                f.count("SELECT COUNT(*) FROM challenge_rate_events").await,
                1
            );
            assert_eq!(f.count("SELECT COUNT(*) FROM messages").await, 2);
            assert_eq!(f.count("SELECT COUNT(*) FROM audit").await, audit_count);
            assert!(f.states().await.iter().all(|(_, s)| s == status));
            assert_eq!(
                std::fs::read(f.store.raw_path(&f.id)).unwrap(),
                common::MESSAGE
            );
        }
    }
}

#[tokio::test]
async fn retention_preserves_an_existing_live_request_on_old_mail_and_its_shared_identity() {
    let f = Fixture::new().await;
    let token = f.issue().await;
    let time = noisefence::now();
    let id = f.id.clone();
    f.store.run(move |db| {
        // Models an already-issued link predating the identity lifetime cap.
        db.execute("UPDATE messages SET created=?2 WHERE id=?1",params![id,time-challenge::RETENTION_SECONDS-86400])?;
        db.execute("INSERT INTO challenge_requests(id,delivery_id,requested_by,account_stamp,destination,mailbox,raw_sha256,token_hash,created,expires,state,notification_id) SELECT 'old-request',delivery_id,requested_by,account_stamp,destination,mailbox,raw_sha256,?1,?2,?3,'consumed',notification_id FROM challenge_requests LIMIT 1",params![message::digest(b"old-token"),time-challenge::RETENTION_SECONDS,time-challenge::RETENTION_SECONDS+3600])?;
        assert_eq!(challenge::prune(db,time)?,1);
        assert_eq!(db.query_row("SELECT COUNT(*) FROM challenge_smtp_identity",[],|r|r.get::<_,i64>(0))?,1);
        assert_eq!(db.query_row("SELECT COUNT(*) FROM challenge_requests WHERE state='pending'",[],|r|r.get::<_,i64>(0))?,1);
        Ok(())
    }).await.unwrap();
    // Existing bearer works; expired provenance cannot authorize a fresh request or backfill.
    assert!(f.prepare("alice", &f.id, ALIAS).await.is_none());
    assert!(
        !challenge::record_smtp_identity(
            &f.store,
            f.id.clone(),
            proof(common::MESSAGE, "example.org").unwrap()
        )
        .await
        .unwrap()
    );
    challenge::submit(&f.store, &policy(), solved(&f.store, &token).await)
        .await
        .unwrap();
    assert_eq!(
        f.count("SELECT COUNT(*) FROM audit WHERE action='quarantine_release'")
            .await,
        1
    );
    f.store
        .run(move |db| {
            assert_eq!(challenge::prune(db, time)?, 1);
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(
        f.count("SELECT COUNT(*) FROM challenge_smtp_identity")
            .await,
        0
    );
    assert_eq!(
        f.count("SELECT COUNT(*) FROM challenge_requests WHERE state='consumed'")
            .await,
        1
    );
}

#[tokio::test]
async fn retention_caps_new_link_at_identity_deadline_without_expiring_it_early() {
    let f = Fixture::new().await;
    let time = noisefence::now();
    f.sql(&format!(
        "UPDATE messages SET created={} WHERE id='{}'",
        time - challenge::RETENTION_SECONDS + 120,
        f.id
    ))
    .await;
    let receipt = f.issue_for(&f.id, "alice", ALICE).await.unwrap();
    assert_eq!(receipt.expires_at, time + 120);
    let token = f.token(&receipt.id).await;
    f.store
        .run(move |db| {
            assert_eq!(challenge::prune(db, time + 119)?, 0);
            Ok(())
        })
        .await
        .unwrap();
    challenge::submit(&f.store, &policy(), solved(&f.store, &token).await)
        .await
        .unwrap();
    assert_eq!(
        f.count("SELECT COUNT(*) FROM audit WHERE action='quarantine_release'")
            .await,
        1
    );
    f.store
        .run(move |db| {
            assert_eq!(challenge::prune(db, time + 120)?, 1);
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(
        f.count("SELECT COUNT(*) FROM challenge_smtp_identity")
            .await,
        0
    );
    assert_eq!(f.count("SELECT COUNT(*) FROM challenge_requests").await, 1);

    let f = Fixture::new().await;
    let prepared = f.prepare("alice", &f.id, ALICE).await.unwrap();
    f.sql(&format!(
        "UPDATE messages SET created={} WHERE id='{}'",
        noisefence::now() - challenge::RETENTION_SECONDS,
        f.id
    ))
    .await;
    assert!(f.prepare("alice", &f.id, ALICE).await.is_none());
    assert!(
        challenge::request(
            &f.store,
            &policy(),
            actor("alice"),
            prepared,
            vec!["mx.example.org".into()]
        )
        .await
        .unwrap()
        .is_none()
    );
    assert_eq!(f.count("SELECT COUNT(*) FROM challenge_requests").await, 0);
}

#[tokio::test]
async fn retention_store_cleanup_purges_metadata_without_waiting_for_raw_removal() {
    let f = Fixture::new().await;
    let _ = f.issue().await;
    let time = noisefence::now();
    let id = f.id.clone();
    f.store
        .run(move |db| {
            db.execute(
                "UPDATE messages SET created=?2 WHERE id=?1",
                params![id, time - challenge::RETENTION_SECONDS - 1],
            )?;
            db.execute(
                "UPDATE challenge_requests SET created=?1,expires=?2",
                params![
                    time - challenge::RETENTION_SECONDS - 1,
                    time - challenge::RETENTION_SECONDS + 3600
                ],
            )?;
            db.execute(
                "UPDATE challenge_rate_events SET created=?1",
                [time - 86400 - 1],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    // No policy setting or worker is needed for periodic retention enforcement.
    f.store.cleanup().await.unwrap();
    assert_eq!(f.count("SELECT COUNT(*) FROM challenge_requests").await, 0);
    assert_eq!(
        f.count("SELECT COUNT(*) FROM challenge_smtp_identity")
            .await,
        0
    );
    assert_eq!(
        f.count("SELECT COUNT(*) FROM challenge_rate_events").await,
        0
    );
    assert_eq!(f.count("SELECT COUNT(*) FROM messages").await, 2);
    assert!(f.store.raw_path(&f.id).is_file());
    f.assert_held().await;
}

#[tokio::test]
async fn retention_uses_request_creation_not_expiration_or_message_deletion_for_thirty_day_bound() {
    let f = Fixture::new().await;
    let _ = f.issue().await;
    let time = noisefence::now();
    f.store
        .run(move |db| {
            db.execute(
                "UPDATE challenge_requests SET created=?1,expires=?2",
                params![time - challenge::RETENTION_SECONDS + 1, time - 1],
            )?;
            assert_eq!(challenge::prune(db, time)?, 0); // 29 days, 23:59:59 old.
            assert_eq!(challenge::prune(db, time + 1)?, 1); // Exactly 30 days; message stays.
            assert_eq!(
                db.query_row("SELECT COUNT(*) FROM messages", [], |r| r.get::<_, i64>(0))?,
                2
            );
            Ok(())
        })
        .await
        .unwrap();
}
