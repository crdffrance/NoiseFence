mod common;
use mail_auth::{
    MessageAuthenticator,
    hickory_resolver::{
        config::{NameServerConfig, ResolverConfig, ResolverOpts},
        proto::{
            op::{Message, OpCode, ResponseCode},
            rr::{RData, Record, rdata::TXT},
        },
    },
};
use noisefence::{
    engine::{Algorithm, Engine, Model},
    evidence::{AuthResult, Source, State},
    features,
};
use std::{sync::Arc, time::Duration};

struct Dns(tokio::task::JoinHandle<()>);
impl Drop for Dns {
    fn drop(&mut self) {
        self.0.abort();
    }
}
async fn resolver(temporary_dmarc: bool, drop_spf: bool) -> (MessageAuthenticator, Dns) {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut buf = [0; 4096];
        loop {
            let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
            let request = Message::from_vec(&buf[..n]).unwrap();
            let query = request.queries[0].clone();
            let name = query.name().to_ascii().to_lowercase();
            if drop_spf && name == "example.org." {
                continue;
            }
            let mut reply = Message::response(request.id, OpCode::Query);
            reply.metadata.recursion_desired = request.recursion_desired;
            reply.metadata.recursion_available = true;
            reply.metadata.authoritative = true;
            reply.add_query(query.clone());
            let text = match name.as_str() {
                "example.org." => Some("v=spf1 ip4:192.0.2.1 -all"),
                "_dmarc.example.org." if temporary_dmarc => {
                    reply.metadata.response_code = ResponseCode::ServFail;
                    None
                }
                "_dmarc.example.org." => Some("v=DMARC1; p=reject"),
                "test._domainkey.example.org." => {
                    Some(include_str!("fixtures/public-test-key.dns").trim())
                }
                _ => {
                    reply.metadata.response_code = ResponseCode::NXDomain;
                    None
                }
            };
            if let Some(text) = text {
                reply.add_answer(Record::from_rdata(
                    query.name().clone(),
                    30,
                    RData::TXT(TXT::new(
                        text.as_bytes()
                            .chunks(200)
                            .map(|chunk| std::str::from_utf8(chunk).unwrap().to_owned())
                            .collect(),
                    )),
                ));
            }
            socket
                .send_to(&reply.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    let mut nameserver = NameServerConfig::udp(address.ip());
    nameserver.connections[0].port = address.port();
    let mut options = ResolverOpts::default();
    options.attempts = 1;
    options.timeout = if drop_spf {
        Duration::from_secs(20)
    } else {
        Duration::from_millis(100)
    };
    options.cache_size = 0;
    (
        MessageAuthenticator::new(ResolverConfig::from_name_servers(vec![nameserver]), options)
            .unwrap(),
        Dns(server),
    )
}
fn signed() -> Vec<u8> {
    use mail_auth::{
        common::{
            crypto::{RsaKey, Sha256},
            headers::HeaderWriter,
        },
        dkim::DkimSigner,
    };
    let key =
        rustls_pemfile::private_key(&mut include_bytes!("fixtures/public-test-key.txt").as_slice())
            .unwrap()
            .unwrap();
    let signature = DkimSigner::from_key(RsaKey::<Sha256>::from_key_der(key).unwrap())
        .domain("example.org")
        .selector("test")
        .headers(["From", "To", "Subject", "Date", "Message-ID"])
        .sign(common::MESSAGE)
        .unwrap();
    [signature.to_header().as_bytes(), common::MESSAGE].concat()
}

#[tokio::test]
async fn verified_authentication_preserves_alignment_and_partial_results_on_dns_failure() {
    for (ip, temporary) in [
        ("192.0.2.1", false),
        ("192.0.2.2", false),
        ("192.0.2.1", true),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut config = (*common::config(dir.path())).clone();
        config.filter.authentication = true;
        let mut engine = Engine::new(Arc::new(config)).unwrap();
        let (authenticator, _server) = resolver(temporary, false).await;
        engine.authenticator = authenticator;
        let signed = signed();
        let forged = [
            b"Authentication-Results: gateway.example.test; spf=pass; dkim=fail\r\nX-NoiseFence-Evidence: forged-observation\r\n".as_slice(),
            &signed,
        ].concat();
        let (scan, raw) = engine
            .process(
                &forged,
                ip.parse().unwrap(),
                "outbound.example.org",
                "sender@example.org",
                "evidence-fixture",
            )
            .await
            .unwrap();
        let evidence = scan.evidence.as_ref().unwrap();
        evidence.validate().unwrap();
        noisefence::fusion::features(evidence).unwrap();
        assert!(!String::from_utf8_lossy(&raw).contains("forged-observation"));
        let auth = &evidence.authentication;
        assert_eq!(evidence.source, Source::SuppliedEnvelope);
        assert_eq!(auth.arc_state, State::Complete);
        assert_eq!(auth.arc, Some(AuthResult::None));
        assert_eq!(
            auth.spf,
            Some(if ip == "192.0.2.1" {
                AuthResult::Pass
            } else {
                AuthResult::Fail
            })
        );
        assert_eq!(auth.dkim, Some(vec![AuthResult::Pass]));
        assert_eq!(auth.spf_state, State::Complete);
        assert_eq!(auth.dkim_state, State::Complete);
        if temporary {
            assert_eq!(auth.state, State::Unavailable);
            assert_eq!(auth.dmarc_state, State::Unavailable);
            assert!(!scan.complete && !scan.tagged);
            assert!(
                auth.dmarc_spf == Some(AuthResult::TempError)
                    || auth.dmarc_dkim == Some(AuthResult::TempError)
            );
            assert!(!String::from_utf8_lossy(&raw).contains("[SPAM]"));
        } else {
            assert_eq!(auth.state, State::Complete);
            assert!(scan.complete);
            assert_eq!(auth.dmarc_dkim, Some(AuthResult::Pass));
            assert!(!scan.reasons.iter().any(|r| r.id == "dmarc_fail"));
        }
        let serialized = serde_json::to_string(evidence).unwrap();
        for private in [
            "sender@example.org",
            "outbound.example.org",
            "192.0.2.1",
            "Rendez-vous",
        ] {
            assert!(!serialized.contains(private));
        }
    }
}

#[tokio::test]
async fn total_deadline_retains_attempted_state_and_cannot_enable_tagging() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = (*common::config(dir.path())).clone();
    config.filter.authentication = true;
    config.filter.mode = noisefence::config::Mode::Tag;
    config.filter.threshold = 0.;
    let mut engine = Engine::new(Arc::new(config)).unwrap();
    let (authenticator, _server) = resolver(false, true).await;
    engine.authenticator = authenticator;
    let started = std::time::Instant::now();
    let (scan, raw) = engine
        .process(
            common::MESSAGE,
            "192.0.2.1".parse().unwrap(),
            "outbound.example.org",
            "sender@example.org",
            "timeout-fixture",
        )
        .await
        .unwrap();
    assert!(started.elapsed() < Duration::from_secs(8));
    let evidence = scan.evidence.as_ref().unwrap();
    assert_eq!(evidence.authentication.state, State::Unavailable);
    assert!(evidence.authentication.spf.is_none());
    assert_eq!(evidence.authentication.spf_state, State::Unavailable);
    assert_eq!(evidence.authentication.dkim_state, State::Complete);
    assert_eq!(evidence.authentication.dkim, Some(vec![]));
    assert_eq!(evidence.authentication.dmarc_state, State::NotRun);
    assert_eq!(evidence.authentication.arc_state, State::Complete);
    assert!(!scan.complete && !scan.tagged && !evidence.analysis_complete);
    assert!(!String::from_utf8_lossy(&raw).contains("[SPAM]"));
}

#[test]
fn content_only_diagnostics_do_not_run_configured_checks_and_bind_loaded_model_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = (*common::config(dir.path())).clone();
    config.filter.authentication = true;
    config.smtp_policy = Some(Default::default());
    let path = dir.path().join("model.json");
    let model = Model {
        version: "model-identity-fixture".into(),
        algorithm: Algorithm::Logistic,
        feature_version: features::VERSION,
        bias: -2.,
        weights: vec![0.; features::DIMENSION],
        idf: vec![1.; features::DIMENSION],
        trained_at: 0,
        examples: 1,
    };
    let bytes = serde_json::to_vec(&model).unwrap();
    std::fs::write(&path, &bytes).unwrap();
    config.filter.model = Some(path.clone());
    let engine = Engine::new(Arc::new(config)).unwrap();
    std::fs::write(&path, b"changed after engine initialization").unwrap();
    let scan = engine.offline(common::MESSAGE);
    let evidence = scan.evidence.unwrap();
    assert_eq!(evidence.source, Source::ContentOnly);
    assert_eq!(evidence.authentication.state, State::NotRun);
    assert_eq!(evidence.smtp_policy_state, State::NotRun);
    assert_eq!(evidence.lexical_logit, Some(-2.));
    assert_eq!(
        evidence.artifacts.lexical_model_sha256,
        Some(noisefence::message::digest(&bytes))
    );
    evidence.validate().unwrap();
}

#[test]
fn optional_local_evidence_preserves_historical_v1_and_refreshes_only_pinned_binding() {
    use noisefence::{
        evidence::{Artifacts, Evidence},
        fusion::{
            self,
            local::{Binding, LocalEvidence},
        },
        heuristics, research_engines,
    };
    let dir = tempfile::tempdir().unwrap();
    let mut config = (*common::config(dir.path())).clone();
    config.heuristics = Some(heuristics::Settings::default());
    let mut e = Evidence::new(&config, Artifacts::new(&config, None, None, false), false);
    e.source = Source::SmtpSession;
    e.validate().unwrap();
    let old_json = serde_json::to_value(&e).unwrap();
    assert!(old_json.get("local").is_none());
    let mut old: Evidence = serde_json::from_value(old_json.clone()).unwrap();
    assert!(old.local.is_none());
    let v1 = fusion::features(&old).unwrap();
    let mut scan = noisefence::engine::Scan::default();
    research_engines::Runtime::new(&config)
        .unwrap()
        .offline(common::MESSAGE)
        .apply(&mut scan);
    old.refresh(&scan);
    assert!(
        old.local.is_none(),
        "refresh must not backfill historical bindings"
    );
    assert_eq!(fusion::features(&old).unwrap(), v1);
    let binding = Binding::from_config(&config).unwrap();
    e.local = Some(LocalEvidence::capture(&binding, &scan));
    e.refresh(&scan);
    e.validate().unwrap();
    assert_eq!(e.local.as_ref().unwrap().binding, binding);
    assert_eq!(fusion::features(&e).unwrap(), v1);
    let mut changed_config = config.clone();
    changed_config.heuristics.as_mut().unwrap().rules[0]
        .pattern
        .push_str("different");
    research_engines::Runtime::new(&changed_config)
        .unwrap()
        .offline(common::MESSAGE)
        .apply(&mut scan);
    e.refresh(&scan);
    assert_eq!(e.local.as_ref().unwrap().binding, binding);
    assert!(!e.local.as_ref().unwrap().tag_eligible());
    assert_eq!(fusion::features(&e).unwrap(), v1);
    e.local.as_mut().unwrap().heuristics.rule_hits[0] = true;
    assert!(
        e.validate().is_err(),
        "incomplete local payload cannot remain positive"
    );
    assert_eq!(
        fusion::features(&e).unwrap(),
        v1,
        "v1 ignores validity of the additive local block"
    );
    assert!(
        fusion::features_for(&e, 2).is_err(),
        "v2 must validate its local payload"
    );
}

#[test]
fn engine_captures_local_observations_before_evidence_and_keeps_content_only_source() {
    use noisefence::{content_inspection, fusion::local::State as LocalState, heuristics};
    let dir = tempfile::tempdir().unwrap();
    let mut config = (*common::config(dir.path())).clone();
    config.heuristics = Some(heuristics::Settings::default());
    config.content_inspection = Some(content_inspection::Settings::default());
    let engine = Engine::new(Arc::new(config)).unwrap();
    let scan = engine.offline(common::MESSAGE);
    let e = scan.evidence.unwrap();
    assert_eq!(e.source, Source::ContentOnly);
    e.validate().unwrap();
    let local = e.local.as_ref().expect("engine capture");
    assert_eq!(local.heuristics.state, LocalState::Complete);
    assert_eq!(local.structure.state, LocalState::Complete);
    assert_eq!(local.values().unwrap().len(), 109);
    assert!(!noisefence::fusion::eligible_for(&e, 2));
}
