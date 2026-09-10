//! Real authentication and relay preparation, with DNS/LLM on loopback only.
use super::*;
use crate::{
    config::Recipient,
    sender_history::{self, ManualEntry, ManualSender, Mode},
    store::Store,
};
use mail_auth::hickory_resolver::{
    config::{NameServerConfig, ResolverConfig, ResolverOpts},
    proto::{
        op::{Message, OpCode, ResponseCode},
        rr::{RData, Record, rdata::TXT},
    },
};
use std::sync::atomic::{AtomicUsize, Ordering};
const ALICE: &str = "alice@example.test";
const BOB: &str = "bob@example.test";
const SENDER: &str = "sender@example.org";
struct Task(tokio::task::JoinHandle<()>);
impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}
async fn dns() -> (MessageAuthenticator, Task) {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut buf = [0; 4096];
        loop {
            let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
            let request = Message::from_vec(&buf[..n]).unwrap();
            let q = request.queries[0].clone();
            let mut response = Message::response(request.id, OpCode::Query);
            response.metadata.recursion_available = true;
            response.metadata.authoritative = true;
            response.add_query(q.clone());
            let value = match q.name().to_ascii().as_str() {
                "example.org." => Some("v=spf1 ip4:192.0.2.1 ip4:127.0.0.1 -all"),
                "_dmarc.example.org." => Some("v=DMARC1; p=reject"),
                _ => None,
            };
            if let Some(value) = value {
                response.add_answer(Record::from_rdata(
                    q.name().clone(),
                    60,
                    RData::TXT(TXT::new(vec![value.into()])),
                ));
            } else {
                response.metadata.response_code = ResponseCode::NXDomain;
            }
            socket
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    let mut ns = NameServerConfig::udp(address.ip());
    ns.connections[0].port = address.port();
    let mut opts = ResolverOpts::default();
    opts.attempts = 1;
    opts.timeout = Duration::from_millis(100);
    (
        MessageAuthenticator::new(ResolverConfig::from_name_servers(vec![ns]), opts).unwrap(),
        Task(server),
    )
}
fn raw(n: usize) -> Vec<u8> {
    format!("From: Sender <{SENDER}>\r\nTo: {ALICE}\r\nSubject: Rendez-vous numero {n}\r\nDate: {}\r\nMessage-ID: <history-{n}@example.org>\r\n\r\nBonjour, voici les informations pour notre rendez-vous de travail numero {n}. Merci pour votre reponse.\r\n",mail_parser::DateTime::from_timestamp(crate::now()).to_rfc822()).into_bytes()
}
struct Fixture {
    root: tempfile::TempDir,
    engine: Engine,
    store: Store,
    _dns: Task,
}
impl Fixture {
    async fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let store = Store::open(root.path()).unwrap();
        store.run(|db| { db.execute_batch("INSERT INTO users(username,password,admin) VALUES('alice','unused',0),('bob','unused',0); INSERT INTO grants(username,address) VALUES('alice','alice@example.test'),('bob','bob@example.test');")?; Ok(()) }).await.unwrap();
        let mut config: Config =
            toml::from_str(include_str!("../../config/development.toml")).unwrap();
        config.data_dir = root.path().into();
        config.filter.authentication = true;
        config.filter.threshold = 60.0;
        config.filter.require_corroboration = false;
        config.sender_history = Some(sender_history::Config {
            mode: Mode::Adaptive,
            trusted_threshold: Some(95.0),
            manual: vec![ManualEntry {
                recipient: ALICE.into(),
                destination: ALICE.into(),
                sender: ManualSender::Exact(SENDER.into()),
            }],
        });
        let mut engine = Engine::new(Arc::new(config.clone())).unwrap();
        // The fixture has no Proton promotion receipt and sends no external mail.
        // Supply the public test key to exercise the real rewrite/seal path.
        config.filter.mode = crate::config::Mode::Tag;
        config.filter.arc_domain = Some("example.test".into());
        config.filter.arc_selector = Some("test".into());
        engine.arc_key = Some(include_str!("../../tests/fixtures/public-test-key.txt").into());
        engine.config = Arc::new(config);
        engine.model = Some(Model {
            version: "history-test".into(),
            algorithm: Algorithm::default(),
            feature_version: crate::features::VERSION,
            bias: 3.0f64.ln(),
            weights: vec![0.0; crate::features::DIMENSION],
            idf: vec![],
            trained_at: crate::now(),
            examples: 0,
        });
        engine.evidence_artifacts =
            crate::evidence::Artifacts::new(&engine.config, Some("a".repeat(64)), None, false);
        let (auth, _dns) = dns().await;
        engine.authenticator = auth;
        Self {
            root,
            engine,
            store,
            _dns,
        }
    }
    fn recipients(&self, addresses: &[&str]) -> Vec<Recipient> {
        addresses
            .iter()
            .map(|a| self.engine.config.recipient(a).unwrap())
            .collect()
    }
    async fn analyze(&self, n: usize, addresses: &[&str]) -> (Scan, Vec<u8>) {
        self.engine
            .process_smtp(
                &raw(n),
                "192.0.2.1".parse().unwrap(),
                "outbound.example.org",
                SENDER,
                &format!("history-{n}"),
                &self.recipients(addresses),
            )
            .await
            .unwrap()
    }
    async fn llm(&mut self, delay: Duration) -> (Arc<AtomicUsize>, Task) {
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app=axum::Router::new().route("/classify",axum::routing::post(move |axum::Json(_input):axum::Json<serde_json::Value>| { let count=count.clone(); async move {
            count.fetch_add(1,Ordering::SeqCst); tokio::time::sleep(delay).await;
            axum::Json(serde_json::json!({"model":"test-model","choices":[{"finish_reason":"stop","message":{"content":serde_json::json!({"category":"spam","spam_probability":0.95,"confidence":0.95,"explanation":"Observation de test"}).to_string(),"tool_calls":[],"function_call":null}}],"usage":{"prompt_tokens":10,"completion_tokens":20}}))
        }}));
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let settings = crate::llm::LlmConfig {
            project_id: uuid::Uuid::new_v4().to_string(),
            model: "test-model".into(),
            api_key_env: "UNUSED_LOCAL_TEST".into(),
            monthly_budget_micro_eur: 20_000_000,
            input_micro_eur_per_million: 1,
            output_micro_eur_per_million: 1,
            pricing_checked_at: crate::now(),
            timeout_ms: 2500,
            max_text_bytes: 12000,
            max_output_tokens: 256,
            score_low: 20.0,
            score_high: 98.0,
            max_parallel: 4,
        };
        self.engine.llm = Some(Arc::new(crate::llm::Client::loopback_fixture(
            settings.clone(),
            self.root.path(),
            address,
        )));
        Arc::make_mut(&mut self.engine.config).llm = Some(settings);
        self.engine.evidence_artifacts =
            crate::evidence::Artifacts::new(&self.engine.config, Some("a".repeat(64)), None, true);
        (calls, Task(server))
    }
}
fn applied(scan: &Scan) -> Option<&sender_history::Applied> {
    scan.sender_history_projection
        .as_ref()?
        .shared_report()?
        .applied
        .as_ref()
}
#[tokio::test]
async fn smtp_mixed_recipients_get_distinct_scans_wire_and_private_durable_reports() {
    let f = Fixture::new().await;
    let (scan, wire) = f.analyze(1, &[ALICE, BOB]).await;
    assert!(scan.complete, "{:?}", scan.reasons);
    assert_eq!(scan.delivery_variants.len(), 1, "scan={scan:?}");
    let child = &scan.delivery_variants[0];
    assert_eq!(child.recipients[0].address, ALICE);
    assert_eq!(scan.score, child.scan.score);
    assert!(scan.tagged);
    assert!(!child.scan.tagged);
    assert!(applied(&scan).is_none());
    assert_eq!(applied(&child.scan).unwrap().threshold, 95.0);
    assert_eq!(scan.analysis_policy.as_ref().unwrap().threshold, 60.0);
    assert_eq!(child.scan.analysis_policy.as_ref().unwrap().threshold, 95.0);
    assert!(String::from_utf8_lossy(&wire).contains("Subject: [SPAM]"));
    assert!(!String::from_utf8_lossy(&child.raw).contains("Subject: [SPAM]"));
    assert!(String::from_utf8_lossy(&child.raw).contains("ARC-Seal:"));
    assert_eq!(
        message::fields(&wire).unwrap().1,
        message::fields(&child.raw).unwrap().1
    );
    let child_id = child.id.clone();
    f.store
        .enqueue(
            "history-1".into(),
            SENDER.into(),
            f.recipients(&[ALICE, BOB]),
            scan,
            wire,
        )
        .await
        .unwrap();
    assert!(
        f.store
            .diagnostics("alice".into(), "history-1".into())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        f.store
            .diagnostics("bob".into(), child_id.clone())
            .await
            .unwrap()
            .is_none()
    );
    let own = f
        .store
        .diagnostics("alice".into(), child_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(own.recipients.len(), 1);
    assert!(
        own.recipients[0]
            .sender_history
            .as_ref()
            .unwrap()
            .applied
            .is_some()
    );
    f.store.recover().await.unwrap();
}
#[tokio::test]
async fn all_trusted_omit_real_optional_llm_but_mixed_message_still_calls_it_once() {
    let mut f = Fixture::new().await;
    let (calls, _server) = f.llm(Duration::from_millis(20)).await;
    for n in 10..13 {
        let (scan, _) = f.analyze(n, &[ALICE]).await;
        assert!(scan.delivery_variants.is_empty());
        assert!(applied(&scan).unwrap().optional_llm_omitted);
        assert_eq!(scan.llm.status, crate::llm::LlmStatus::NotNeeded);
        assert!(scan.llm.verdict.is_none());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let (mixed, _) = f.analyze(14, &[ALICE, BOB]).await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(mixed.llm.status, crate::llm::LlmStatus::Complete);
    assert!(mixed.llm.verdict.is_some());
    let trusted = &mixed.delivery_variants[0].scan;
    assert!(applied(trusted).unwrap().optional_llm_omitted);
    assert!(trusted.llm.verdict.is_none());
    assert!(!trusted.reasons.iter().any(|r| r.id == "llm_advisory"));
}
#[tokio::test]
async fn supplied_or_failed_authentication_and_high_risk_never_use_history() {
    let mut f = Fixture::new().await;
    let data = raw(20);
    let rcpt = f.recipients(&[ALICE]);
    let (offline, _) = f
        .engine
        .process(
            &data,
            "192.0.2.1".parse().unwrap(),
            "outbound.example.org",
            SENDER,
            "offline",
        )
        .await
        .unwrap();
    assert!(applied(&offline).is_none());
    let (failed, _) = f
        .engine
        .process_smtp(
            &data,
            "192.0.2.2".parse().unwrap(),
            "outbound.example.org",
            SENDER,
            "failed",
            &rcpt,
        )
        .await
        .unwrap();
    assert!(applied(&failed).is_none());
    assert!(failed.delivery_variants.is_empty());
    f.engine.model.as_mut().unwrap().bias = 10.0;
    let (high, _) = f.analyze(21, &[ALICE]).await;
    assert!(applied(&high).is_none());
    assert!(high.tagged);
}
#[tokio::test]
async fn feedback_or_access_change_between_analysis_and_enqueue_rejects_entire_batch() {
    for mutation in [
        "DELETE FROM grants WHERE username='alice'",
        "UPDATE users SET password='changed' WHERE username='alice'",
    ] {
        let f = Fixture::new().await;
        let (scan, wire) = f.analyze(30, &[ALICE, BOB]).await;
        assert_eq!(scan.delivery_variants.len(), 1);
        f.store
            .run(move |db| {
                db.execute_batch(mutation)?;
                Ok(())
            })
            .await
            .unwrap();
        let result = f
            .store
            .enqueue(
                "history-30".into(),
                SENDER.into(),
                f.recipients(&[ALICE, BOB]),
                scan,
                wire,
            )
            .await;
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("sender history changed")
        );
        let count: i64 = f
            .store
            .run(|db| Ok(db.query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))?))
            .await
            .unwrap();
        assert_eq!(count, 0);
        assert_eq!(
            std::fs::read_dir(f.root.path().join("spool"))
                .unwrap()
                .count(),
            0
        );
    }
}
#[tokio::test]
async fn unrelated_new_mail_does_not_invalidate_a_trust_snapshot() {
    let f = Fixture::new().await;
    let (trusted, wire) = f.analyze(40, &[ALICE]).await;
    assert!(applied(&trusted).is_some());
    let (other, other_wire) = f.analyze(41, &[BOB]).await;
    f.store
        .enqueue(
            "history-41".into(),
            SENDER.into(),
            f.recipients(&[BOB]),
            other,
            other_wire,
        )
        .await
        .unwrap();
    f.store
        .enqueue(
            "history-40".into(),
            SENDER.into(),
            f.recipients(&[ALICE]),
            trusted,
            wire,
        )
        .await
        .unwrap();
}
#[tokio::test]
async fn cached_authenticated_correspondents_accelerate_distinct_messages() {
    let mut f = Fixture::new().await;
    let (calls, _server) = f.llm(Duration::from_millis(120)).await;
    // Warm DNS, not a message classification cache; every subsequent raw differs.
    f.analyze(50, &[ALICE]).await;
    let mut fast = Vec::new();
    let mut ordinary = Vec::new();
    for i in 0..12 {
        let begin = Instant::now();
        let (s, _) = f.analyze(100 + i, &[ALICE]).await;
        fast.push(begin.elapsed().as_micros() as u64);
        assert!(applied(&s).is_some());
        let begin = Instant::now();
        let (s, _) = f.analyze(200 + i, &[BOB]).await;
        ordinary.push(begin.elapsed().as_micros() as u64);
        assert_eq!(s.llm.status, crate::llm::LlmStatus::Complete);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 12);
    let result = serde_json::json!({"scenario":"loopback DNS and optional LLM delayed 120 ms; distinct synthetic messages", "samples_per_group":12,"trusted_us":fast,"ordinary_us":ordinary,"llm_calls":12,"external_messages":0});
    if let Ok(path) = std::env::var("NOISEFENCE_HISTORY_BENCHMARK") {
        std::fs::write(path, serde_json::to_vec_pretty(&result).unwrap()).unwrap();
    }
    eprintln!("{result}");
}

#[tokio::test]
async fn learned_relation_changes_the_result_and_saves_calls_until_human_revocation() {
    let mut f = Fixture::new().await;
    let texts = [
        "Reunion technique lundi pour discuter ensemble de la documentation du projet logiciel. Les collegues presenteront leurs travaux pendant la matinée et nous preparerons le calendrier des prochaines etapes.",
        "Pour cette recette familiale, melanger les pommes coupees et la farine puis verser du lait dans le saladier. Cuire doucement au four chaud jusqu'a obtenir une belle tarte doree. Servir apres refroidissement.",
        "Les observations astronomiques montrent les etoiles de la constellation et les planetes autour du soleil. Ce soir nous utiliserons le telescope pour observer les crateres lunaires et les nebuleuses lointaines dans le ciel.",
    ];
    for (i, text) in texts.iter().enumerate() {
        let original = raw(300 + i);
        let end = original.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let data = [&original[..end], text.as_bytes(), b"\r\n"].concat();
        let id = format!("learned-{i}");
        let (scan, wire) = f
            .engine
            .process_smtp(
                &data,
                "192.0.2.1".parse().unwrap(),
                "outbound.example.org",
                SENDER,
                &id,
                &f.recipients(&[ALICE]),
            )
            .await
            .unwrap();
        assert!(scan.complete);
        f.store
            .enqueue(
                id.clone(),
                SENDER.into(),
                f.recipients(&[ALICE]),
                scan,
                wire,
            )
            .await
            .unwrap();
        let received = crate::now() - (5 - 2 * i as i64) * 86400;
        let key = id.clone();
        f.store
            .run(move |db| {
                let tx = db.transaction()?;
                tx.execute(
                    "UPDATE messages SET created=?2 WHERE id=?1",
                    rusqlite::params![key, received],
                )?;
                tx.execute(
                    "UPDATE sender_history_receipts SET received=?2 WHERE message_id=?1",
                    rusqlite::params![key, received],
                )?;
                tx.commit()?;
                Ok(())
            })
            .await
            .unwrap();
        f.store.feedback("alice".into(), id, false).await.unwrap();
    }
    let history = Arc::make_mut(&mut f.engine.config)
        .sender_history
        .as_mut()
        .unwrap();
    history.manual.clear();
    f.engine.sender_history = Some(Arc::new(sender_history::History::new(
        f.root.path(),
        history.clone(),
    )));
    let (calls, _server) = f.llm(Duration::from_millis(20)).await;
    let (current, wire) = f.analyze(310, &[ALICE]).await;
    let report = current
        .sender_history_projection
        .as_ref()
        .unwrap()
        .shared_report()
        .unwrap();
    assert!(report.learned_candidate, "{report:?}");
    assert_eq!(report.manual_match, sender_history::ManualMatch::None);
    assert!(applied(&current).unwrap().optional_llm_omitted);
    assert!(!current.tagged);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    // Change the human label after the live read, before the durable acceptance.
    f.store
        .feedback("alice".into(), "learned-0".into(), true)
        .await
        .unwrap();
    assert!(
        f.store
            .enqueue(
                "history-310".into(),
                SENDER.into(),
                f.recipients(&[ALICE]),
                current,
                wire
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("sender history changed")
    );
    let (next, _) = f.analyze(311, &[ALICE]).await;
    assert!(applied(&next).is_none());
    assert!(next.tagged);
    assert!(
        next.sender_history_projection
            .as_ref()
            .unwrap()
            .shared_report()
            .unwrap()
            .contradicted
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn adverse_observations_prevent_adaptation_even_without_numerical_weight() {
    let f = Fixture::new().await;
    let (mut scan, _) = f.analyze(400, &[ALICE]).await;
    let projection = scan.sender_history_projection.clone().unwrap();
    scan.reasons
        .retain(|r| r.id != sender_history::adaptive::REASON);
    assert_eq!(
        sender_history::adaptive::selected(&scan, &f.engine.config, &projection, false),
        vec![0]
    );
    for kind in 0..6 {
        let mut altered = scan.clone();
        match kind {
            0 => altered.signatures.status = crate::antivirus::AntivirusStatus::Suspicious,
            1 => altered.vision.credential_request = true,
            2 => altered.vision.status = crate::vision::Status::Limited,
            3 => altered.smtp_policy.candidate_weight = 0.1,
            4 => altered.features_complete = Some(false),
            _ => {
                altered.protection = Some(crate::protection::Report {
                    local_status: crate::protection::Status::Unavailable,
                    ..Default::default()
                });
            }
        }
        assert!(
            sender_history::adaptive::selected(&altered, &f.engine.config, &projection, false)
                .is_empty(),
            "kind {kind}"
        );
    }
}

#[tokio::test]
async fn incomplete_url_resolution_prevents_trust_shortcuts() {
    let f = Fixture::new().await;
    let (mut scan, _) = f.analyze(401, &[ALICE]).await;
    let projection = scan.sender_history_projection.clone().unwrap();
    scan.reasons
        .retain(|r| r.id != sender_history::adaptive::REASON);
    let mut config = (*f.engine.config).clone();
    config.protection = Some(crate::protection::Settings::default());
    config.protection.as_mut().unwrap().policy.follow_urls = true;
    scan.protection = Some(crate::protection::Report::default());
    assert!(sender_history::adaptive::selected(&scan, &config, &projection, false).is_empty());
    scan.protection.as_mut().unwrap().url_resolution = Some(crate::protection::redirects::Report {
        version: "url-resolution-1".into(),
        settings_sha256: "test-settings".into(),
        chains: vec![],
        omitted: 0,
        elapsed_ms: 0,
    });
    assert_eq!(
        sender_history::adaptive::selected(&scan, &config, &projection, false),
        vec![0]
    );
    scan.protection
        .as_mut()
        .unwrap()
        .url_resolution
        .as_mut()
        .unwrap()
        .omitted = 1;
    assert!(sender_history::adaptive::selected(&scan, &config, &projection, false).is_empty());
    let resolution = scan
        .protection
        .as_mut()
        .unwrap()
        .url_resolution
        .as_mut()
        .unwrap();
    resolution.omitted = 0;
    resolution.chains.push(crate::protection::redirects::Chain {
        source_sha256: "synthetic-url".into(),
        hops: vec![],
        complete: false,
        detail: Some(crate::protection::redirects::Detail::Deadline),
    });
    assert!(sender_history::adaptive::selected(&scan, &config, &projection, false).is_empty());
}

#[tokio::test]
async fn snapshot_deadlines_follow_the_recipient_and_future_votes() {
    for related in [false, true] {
        let f = Fixture::new().await;
        let target = if related { ALICE } else { BOB };
        let (scan, wire) = f.analyze(500, &[target]).await;
        f.store
            .enqueue(
                "history-500".into(),
                SENDER.into(),
                f.recipients(&[target]),
                scan,
                wire,
            )
            .await
            .unwrap();
        let user = if related { "alice" } else { "bob" };
        f.store
            .feedback(user.into(), "history-500".into(), true)
            .await
            .unwrap();
        let time = crate::now();
        f.store
            .run(move |db| {
                db.execute(
                    "UPDATE feedback SET created=?1 WHERE message_id='history-500'",
                    [time + 2],
                )?;
                Ok(())
            })
            .await
            .unwrap();
        let (scan, _) = f.analyze(501, &[ALICE]).await;
        let epoch = scan
            .sender_history_projection
            .as_ref()
            .unwrap()
            .active_epoch()
            .expect("future vote must not count yet");
        f.store
            .run(move |db| {
                let tx = db.transaction()?;
                assert_eq!(epoch.validate(&tx, time + 3).is_err(), related);
                Ok(())
            })
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn an_unrelated_receipt_expiring_soon_does_not_shorten_adaptive_processing() {
    let f = Fixture::new().await;
    let (scan, wire) = f.analyze(510, &[BOB]).await;
    f.store
        .enqueue(
            "history-510".into(),
            SENDER.into(),
            f.recipients(&[BOB]),
            scan,
            wire,
        )
        .await
        .unwrap();
    let time = crate::now();
    f.store
        .run(move |db| {
            db.execute(
                "UPDATE sender_history_receipts SET received=?1 WHERE message_id='history-510'",
                [time - 30 * 86400 + 2],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    let (scan, _) = f.analyze(511, &[ALICE]).await;
    let epoch = scan
        .sender_history_projection
        .as_ref()
        .unwrap()
        .active_epoch()
        .unwrap();
    f.store
        .run(move |db| {
            let tx = db.transaction()?;
            epoch.validate(&tx, time + 3)
        })
        .await
        .unwrap();
}

#[test]
fn adaptive_configuration_requires_an_explicit_cutoff_and_authentication() {
    let base: Config = toml::from_str(include_str!("../../config/development.toml")).unwrap();
    let mut config = base.clone();
    config.sender_history = Some(sender_history::Config {
        mode: Mode::Adaptive,
        trusted_threshold: Some(98.0),
        manual: vec![],
    });
    assert!(config.validate().is_err());
    config.filter.authentication = true;
    config.validate().unwrap();
    for cutoff in [None, Some(95.0), Some(100.0), Some(f64::NAN)] {
        config.sender_history.as_mut().unwrap().trusted_threshold = cutoff;
        assert!(config.validate().is_err());
    }
    // Existing advisory configurations keep exactly their historical JSON shape.
    let settings: sender_history::Config = toml::from_str("mode = 'candidate_credit'").unwrap();
    assert_eq!(
        serde_json::to_value(settings).unwrap(),
        serde_json::json!({"mode":"candidate_credit","manual":[]})
    );
}

#[tokio::test]
async fn real_smtp_acknowledges_the_whole_batch_or_returns_451_for_a_second_variant_failure() {
    use tokio::io::{AsyncWriteExt, BufReader};
    for fail in [false, true] {
        let f = Fixture::new().await;
        if fail {
            f.store.run(|db| {db.execute_batch("CREATE TRIGGER fail_second_variant BEFORE INSERT ON deliveries WHEN NEW.address='alice@example.test' BEGIN SELECT RAISE(ABORT,'fixture second variant failure'); END;")?;Ok(())}).await.unwrap();
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop, rx) = tokio::sync::watch::channel(false);
        let state = crate::smtp::State {
            config: f.engine.config.clone(),
            store: f.store.clone(),
            engine: Arc::new(f.engine),
            processing: Arc::new(tokio::sync::Semaphore::new(2)),
        };
        let server = tokio::spawn(crate::smtp::serve(listener, state, rx));
        let exchange = async {
            let mut io: crate::smtp::Wire = BufReader::new(Box::new(
                tokio::net::TcpStream::connect(address).await.unwrap(),
            ));
            assert_eq!(crate::relay::response(&mut io).await.unwrap().code, 220);
            for (cmd, code) in [
                ("EHLO outbound.example.org\r\n", 250),
                ("MAIL FROM:<sender@example.org>\r\n", 250),
                ("RCPT TO:<alice@example.test>\r\n", 250),
                ("RCPT TO:<bob@example.test>\r\n", 250),
                ("DATA\r\n", 354),
            ] {
                crate::smtp::reply(&mut io, cmd).await.unwrap();
                assert_eq!(crate::relay::response(&mut io).await.unwrap().code, code);
            }
            io.write_all(&raw(600)).await.unwrap();
            io.write_all(b".\r\n").await.unwrap();
            io.flush().await.unwrap();
            let reply = crate::relay::response(&mut io).await.unwrap();
            assert_eq!(reply.code, if fail { 451 } else { 250 });
            let variants: Vec<(String, bool)> = f
                .store
                .run(|db| {
                    let mut q = db.prepare("SELECT id,scan FROM messages ORDER BY id")?;
                    q.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
                        .map(|row| {
                            let (id, json) = row?;
                            let scan: Scan = serde_json::from_str(&json)?;
                            Ok((id, scan.tagged))
                        })
                        .collect::<Result<Vec<_>>>()
                })
                .await
                .unwrap();
            assert_eq!(variants.len(), if fail { 0 } else { 2 });
            if !fail {
                assert_eq!(variants.iter().filter(|(_, tag)| *tag).count(), 1);
                for (id, _) in &variants {
                    assert!(f.store.raw_path(id).is_file());
                }
            }
            crate::smtp::reply(&mut io, "QUIT\r\n").await.unwrap();
            assert_eq!(crate::relay::response(&mut io).await.unwrap().code, 221);
        };
        let result = tokio::time::timeout(Duration::from_secs(10), exchange).await;
        stop.send(true).unwrap();
        server.await.unwrap().unwrap();
        result.unwrap();
        let reopened = Store::open(f.root.path()).unwrap();
        reopened.recover().await.unwrap();
        if fail {
            assert_eq!(
                std::fs::read_dir(f.root.path().join("spool"))
                    .unwrap()
                    .count(),
                0
            );
        }
    }
}

#[tokio::test]
async fn another_recipient_feedback_on_a_shared_message_does_not_invalidate_our_variant() {
    let mut f = Fixture::new().await;
    Arc::make_mut(&mut f.engine.config)
        .sender_history
        .as_mut()
        .unwrap()
        .mode = Mode::Observation;
    f.engine.sender_history = Some(Arc::new(sender_history::History::new(
        f.root.path(),
        f.engine.config.sender_history.clone().unwrap(),
    )));
    let (legacy, wire) = f.analyze(700, &[ALICE, BOB]).await;
    assert!(legacy.delivery_variants.is_empty());
    f.store
        .enqueue(
            "history-700".into(),
            SENDER.into(),
            f.recipients(&[ALICE, BOB]),
            legacy,
            wire,
        )
        .await
        .unwrap();
    Arc::make_mut(&mut f.engine.config)
        .sender_history
        .as_mut()
        .unwrap()
        .mode = Mode::Adaptive;
    f.engine.sender_history = Some(Arc::new(sender_history::History::new(
        f.root.path(),
        f.engine.config.sender_history.clone().unwrap(),
    )));
    let (mixed, wire) = f.analyze(701, &[ALICE, BOB]).await;
    assert_eq!(mixed.delivery_variants.len(), 1);
    let other = Store::open(f.root.path()).unwrap();
    for _ in 0..10 {
        other
            .feedback("bob".into(), "history-700".into(), true)
            .await
            .unwrap();
    }
    f.store
        .enqueue(
            "history-701".into(),
            SENDER.into(),
            f.recipients(&[ALICE, BOB]),
            mixed,
            wire,
        )
        .await
        .unwrap();
    // Promotion now makes that same human vote authoritative for Alice too.
    let (before_promotion, wire) = f.analyze(702, &[ALICE]).await;
    assert!(applied(&before_promotion).is_some());
    other
        .run(|db| {
            db.execute("UPDATE users SET admin=1 WHERE username='bob'", [])?;
            Ok(())
        })
        .await
        .unwrap();
    assert!(
        f.store
            .enqueue(
                "history-702".into(),
                SENDER.into(),
                f.recipients(&[ALICE]),
                before_promotion,
                wire
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("sender history changed")
    );
    let (after, _) = f.analyze(703, &[ALICE]).await;
    assert!(applied(&after).is_none());
    assert!(
        after
            .sender_history_projection
            .as_ref()
            .unwrap()
            .shared_report()
            .unwrap()
            .contradicted
    );
}
