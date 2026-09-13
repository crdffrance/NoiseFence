use noisefence::{
    antivirus::AntivirusStatus,
    delivery_log::{Attempt, Event},
    engine::{Engine, Scan},
    evidence::{AuthResult, Source, State},
    fusion::runtime::Decision,
    llm::{Category, LlmStatus, Verdict},
};

pub fn scan(config: std::sync::Arc<noisefence::config::Config>) -> Scan {
    let mut scan = Engine::new(config).unwrap().offline(crate::common::MESSAGE);
    scan.complete = true;
    scan.score = 99.93;
    scan.decision = Some(Decision::legacy(&scan, 95.));
    scan.signatures.status = AntivirusStatus::Suspicious;
    scan.signatures.signature = Some("Sanesecurity.Phishing.Fake.Coin.FIXTURE.UNOFFICIAL".into());
    scan.llm.status = LlmStatus::Complete;
    scan.llm.verdict = Some(Verdict {
        category: Category::Phishing,
        spam_probability: 0.95,
        confidence: 0.9,
        explanation: "Synthetic test observation, no model or provider call".into(),
    });
    let e = scan.evidence.as_mut().unwrap();
    e.source = Source::SmtpSession;
    e.authentication = noisefence::evidence::Authentication {
        state: State::Complete,
        spf_state: State::Complete,
        spf: Some(AuthResult::SoftFail),
        dkim_state: State::Complete,
        dkim: Some(vec![]),
        dmarc_state: State::Complete,
        dmarc_spf: Some(AuthResult::None),
        dmarc_dkim: Some(AuthResult::None),
        arc_state: State::Complete,
        arc: Some(AuthResult::None),
        arc_can_seal: Some(true),
    };
    scan
}

pub fn rejection() -> Attempt {
    Attempt {
        route: "mail.example.test".into(),
        peer: Some("192.0.2.1".into()),
        started: noisefence::now(),
        elapsed_ms: 123,
        outcome: "permanent".into(),
        truncated: false,
        events: vec![
            Event {
                phase: "tls".into(),
                elapsed_ms: 10,
                code: None,
                enhanced_code: None,
                response: None,
                detail: Some("Verified TLS; synthetic fixture".into()),
            },
            Event {
                phase: "data_result".into(),
                elapsed_ms: 123,
                code: Some(554),
                enhanced_code: Some("5.7.1".into()),
                response: Some("554 5.7.1 rejected by rspamd filter".into()),
                detail: None,
            },
        ],
    }
}
