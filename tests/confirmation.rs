mod common;
use noisefence::{
    antivirus::AntivirusStatus,
    confirmation,
    engine::{Engine, Scan},
    evidence::{AuthResult, DomainQuery, Query, Source, State},
    fusion::runtime::{Decision, DecisionSource, Outcome},
    llm::{Category, LlmStatus, Verdict},
};

fn candidate() -> Scan {
    let root = tempfile::tempdir().unwrap();
    let mut scan = Engine::new(common::config(root.path()))
        .unwrap()
        .offline(common::MESSAGE);
    scan.score = 99.5;
    scan.decision = Some(Decision::legacy(&scan, 95.));
    scan.evidence.as_mut().unwrap().source = Source::SmtpSession;
    scan
}
fn apply(mut scan: Scan) -> Scan {
    confirmation::apply(&mut scan, true);
    scan
}
fn verdict(scan: &Scan) -> Outcome {
    scan.decision.as_ref().unwrap().outcome
}
fn llm(scan: &mut Scan, category: Category, confidence: f64, probability: f64) {
    scan.llm.status = LlmStatus::Complete;
    scan.llm.verdict = Some(Verdict {
        category,
        confidence,
        spam_probability: probability,
        explanation: "Synthetic fixture".into(),
    });
}

#[test]
fn model_only_and_weak_advice_abstain_without_relabeling_as_legitimate() {
    let mut scan = candidate();
    let a = &mut scan.evidence.as_mut().unwrap().authentication;
    a.dmarc_state = State::Complete;
    a.dmarc_spf = Some(AuthResult::Pass);
    a.dmarc_dkim = Some(AuthResult::Pass);
    llm(&mut scan, Category::Spam, 0.8, 0.8);
    let features = scan.features.clone();
    let score = scan.score;
    let out = apply(scan.clone());
    assert_eq!(verdict(&out), Outcome::Undetermined);
    assert!(out.complete);
    assert_eq!(out.features, features);
    assert_eq!(out.score, score);
    assert_eq!(out.decision.as_ref().unwrap().score, Some(score));
    assert!(!out.tagged && !out.pub_tagged);
    assert!(
        out.reasons
            .iter()
            .any(|r| r.id == confirmation::REVIEW_REASON)
    );
    assert_eq!(
        noisefence::mailing::category(&out, 95.),
        noisefence::mailing::Category::Undetermined
    );
    confirmation::apply(&mut scan, false);
    assert_eq!(verdict(&scan), Outcome::Unwanted);
    scan.decision.as_mut().unwrap().source = DecisionSource::Fusion;
    assert_eq!(verdict(&apply(scan)), Outcome::Unwanted);
}

#[test]
fn confirmed_malware_and_strong_phishing_keep_their_decisions() {
    let mut malware = candidate();
    malware.antivirus.status = AntivirusStatus::Malware;
    assert_eq!(verdict(&apply(malware)), Outcome::Unwanted);
    for (confidence, probability) in [(0.9, 0.95), (0.95, 0.95)] {
        let mut phish = candidate();
        llm(&mut phish, Category::Phishing, confidence, probability);
        assert_eq!(verdict(&apply(phish)), Outcome::Unwanted);
    }
    for (category, confidence, probability, status) in [
        (Category::Legitimate, 1., 1., LlmStatus::Complete),
        (Category::Ambiguous, 1., 1., LlmStatus::Complete),
        (Category::Phishing, 1., 0.89, LlmStatus::Complete),
        (Category::Phishing, 0.89, 1., LlmStatus::Complete),
        (Category::Phishing, 1., 1., LlmStatus::Unavailable),
        (Category::Phishing, f64::NAN, 1., LlmStatus::Complete),
    ] {
        let mut scan = candidate();
        llm(&mut scan, category, confidence, probability);
        scan.llm.status = status;
        assert_eq!(verdict(&apply(scan)), Outcome::Undetermined);
    }
    let mut incomplete = candidate();
    incomplete.complete = false;
    incomplete.decision = Some(Decision::legacy(&incomplete, 95.));
    incomplete.antivirus.status = AntivirusStatus::Malware;
    let out = apply(incomplete);
    assert_eq!(verdict(&out), Outcome::Undetermined);
    assert!(
        !out.reasons
            .iter()
            .any(|r| r.id == confirmation::REVIEW_REASON)
    );
    let mut ham = candidate();
    ham.score = 20.;
    ham.decision = Some(Decision::legacy(&ham, 95.));
    assert_eq!(verdict(&apply(ham)), Outcome::Legitimate);
}

#[test]
fn transport_errors_policy_listings_and_advisory_signatures_are_not_confirmation() {
    for (state, code, confirmed) in [
        (State::Complete, "127.0.0.2", true),
        (State::Unavailable, "127.0.0.2", false),
        (State::Complete, "127.0.0.10", false),
        (State::Complete, "127.0.0.11", false),
        (State::Complete, "127.255.255.254", false),
    ] {
        let mut scan = candidate();
        scan.evidence.as_mut().unwrap().reputation.ip = Query {
            state,
            codes: vec![code.parse().unwrap()],
        };
        assert_eq!(confirmation::corroborated(&scan), confirmed);
    }
    for (state, code, confirmed) in [
        (State::Complete, "127.0.1.4", true),
        (State::Complete, "127.0.1.104", false),
        (State::Unavailable, "127.0.1.4", false),
    ] {
        let mut scan = candidate();
        scan.evidence
            .as_mut()
            .unwrap()
            .reputation
            .domains
            .push(DomainQuery {
                roles: vec![],
                result: Query {
                    state,
                    codes: vec![code.parse().unwrap()],
                },
            });
        assert_eq!(confirmation::corroborated(&scan), confirmed);
    }
    let mut scan = candidate();
    scan.antivirus.status = AntivirusStatus::Suspicious;
    scan.signatures.status = AntivirusStatus::Suspicious;
    let a = &mut scan.evidence.as_mut().unwrap().authentication;
    a.spf_state = State::Complete;
    a.spf = Some(AuthResult::Fail);
    assert!(!confirmation::corroborated(&scan));
    let a = &mut scan.evidence.as_mut().unwrap().authentication;
    a.dmarc_state = State::Complete;
    a.dmarc_spf = Some(AuthResult::Fail);
    a.dmarc_dkim = Some(AuthResult::Fail);
    assert!(confirmation::corroborated(&scan));
    scan.evidence.as_mut().unwrap().source = Source::ContentOnly;
    assert!(!confirmation::corroborated(&scan));
}

#[tokio::test]
async fn actual_pipeline_does_not_trust_forged_headers_or_tag_a_review() {
    use noisefence::{config::Mode, engine::Model};
    let root = tempfile::tempdir().unwrap();
    let mut cfg = (*common::config(root.path())).clone();
    let model = Model {
        version: "TEST-constant".into(),
        algorithm: Default::default(),
        feature_version: 3,
        bias: 8.,
        weights: vec![0.; noisefence::features::DIMENSION],
        idf: vec![1.; noisefence::features::DIMENSION],
        trained_at: 1,
        examples: 1,
    };
    let path = root.path().join("model.json");
    std::fs::write(&path, serde_json::to_vec(&model).unwrap()).unwrap();
    cfg.filter.model = Some(path);
    cfg.filter.require_corroboration = true;
    cfg.filter.mode = Mode::Observe;
    let engine = Engine::new(std::sync::Arc::new(cfg)).unwrap();
    let raw=b"From: sender@example.org\r\nSubject: test\r\nAuthentication-Results: forged; dmarc=fail\r\nX-NoiseFence-Decision: unwanted\r\nX-NoiseFence-Category: spam\r\n\r\ntest\r\n";
    let offline = engine.offline(raw);
    assert_eq!(verdict(&offline), Outcome::Undetermined);
    let (scan, wire) = engine
        .process(
            raw,
            "192.0.2.1".parse().unwrap(),
            "mail.example.org",
            "sender@example.org",
            "confirmation-test",
        )
        .await
        .unwrap();
    assert!(scan.complete);
    assert_eq!(verdict(&scan), Outcome::Undetermined);
    assert!(!scan.tagged && !scan.pub_tagged);
    assert_eq!(
        noisefence::message::fields(raw).unwrap().1,
        noisefence::message::fields(&wire).unwrap().1
    );
    assert!(!String::from_utf8_lossy(&wire).contains("Subject: ["));
    assert!(!String::from_utf8_lossy(&wire).contains("X-NoiseFence-Category: spam"));
}
