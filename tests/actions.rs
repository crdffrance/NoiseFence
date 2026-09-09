mod common;
use noisefence::{
    actions::{self, Action, Policy},
    config::Mode,
    engine::{Engine, Scan},
    fusion::runtime::Decision,
};
use std::{collections::BTreeMap, sync::Arc};

#[test]
fn actions_respect_category_observation_and_incomplete_checks() {
    let root = tempfile::tempdir().unwrap();
    let mut cfg = (*common::config(root.path())).clone();
    cfg.mailing = Some(Default::default());
    for mode in [Mode::Observe, Mode::Enforce, Mode::Tag] {
        cfg.filter.mode = mode;
        for action in [Action::Deliver, Action::Tag, Action::Quarantine] {
            cfg.actions = Some(Policy {
                spam: action,
                publicity: Action::Deliver,
                malware: action,
                quarantine_days: 7,
            });
            for complete in [false, true] {
                for malware in [false, true] {
                    let mut scan = Scan {
                        score: 99.,
                        complete,
                        ..Default::default()
                    };
                    scan.decision = Some(Decision::legacy(&scan, 95.));
                    if malware {
                        scan.antivirus.status = noisefence::antivirus::AntivirusStatus::Malware;
                        noisefence::decision::apply(&mut scan, true);
                    }
                    let evaluated = actions::evaluate(&scan, &cfg);
                    let expected = if mode == Mode::Observe
                        || (!complete && !(malware && action == Action::Quarantine))
                    {
                        Action::Deliver
                    } else {
                        action
                    };
                    assert_eq!(evaluated.effective, expected);
                    assert_eq!(
                        noisefence::decision::subject_tag(&scan, &cfg).is_some(),
                        expected == Action::Tag
                    );
                }
            }
        }
    }
    cfg.filter.mode = Mode::Enforce;
    cfg.actions = Some(Policy {
        spam: Action::Quarantine,
        publicity: Action::Tag,
        malware: Action::Quarantine,
        quarantine_days: 7,
    });
    let raw = b"Subject: Offres exclusives\r\nList-Unsubscribe: <https://example.org/unsubscribe>\r\n\r\nProfitez de nos offres exclusives. Achetez maintenant avec 50% de reduction.\r\n";
    let mut scan = noisefence::engine::extract(raw, 10000);
    scan.mailing = Some(noisefence::mailing::inspect(
        raw,
        &Default::default(),
        10000,
    ));
    scan.decision = Some(Decision::legacy(&scan, 95.));
    assert_eq!(actions::evaluate(&scan, &cfg).effective, Action::Tag);
    assert_eq!(
        noisefence::decision::subject_tag(&scan, &cfg),
        Some(noisefence::message::SubjectTag::Publicity)
    );
    scan.score = 99.;
    scan.decision = Some(Decision::legacy(&scan, 95.));
    assert_eq!(actions::evaluate(&scan, &cfg).effective, Action::Quarantine);
    assert!(noisefence::decision::subject_tag(&scan, &cfg).is_none());
}

#[test]
fn quarantine_activation_requires_no_subject_rewriting_but_tagging_still_has_gates() {
    let root = tempfile::tempdir().unwrap();
    let mut cfg = (*common::config(root.path())).clone();
    cfg.filter.mode = Mode::Enforce;
    cfg.actions = Some(Policy {
        spam: Action::Quarantine,
        publicity: Action::Deliver,
        malware: Action::Quarantine,
        quarantine_days: 14,
    });
    cfg.validate().unwrap();
    cfg.actions.as_mut().unwrap().spam = Action::Tag;
    assert!(cfg.validate().unwrap_err().to_string().contains("ARC"));
    cfg.filter.mode = Mode::Observe;
    cfg.validate().unwrap();
    for days in [0, 31, u16::MAX] {
        cfg.actions.as_mut().unwrap().quarantine_days = days;
        assert!(cfg.validate().is_err());
    }
    cfg.actions.as_mut().unwrap().quarantine_days = 1;
    for (id, weight) in [
        ("antivirus", 0.),
        ("llm_advisory", 0.),
        ("urgency", -1.),
        ("urgency", 3.1),
        ("urgency", f64::NAN),
    ] {
        cfg.filter.rule_weights = BTreeMap::from([(id.into(), weight)]);
        assert!(cfg.validate().is_err());
    }
}

#[tokio::test]
async fn custom_rules_change_actual_scores_without_rewriting_model_features_or_compounding() {
    let root = tempfile::tempdir().unwrap();
    let cfg = common::config(root.path());
    assert!(
        Engine::new(cfg.clone())
            .unwrap()
            .offline(common::MESSAGE)
            .complete
    );
    let raw = b"From: sender@example.org\r\nSubject: urgent verify your account\r\n\r\nBonjour\r\n";
    let baseline = Engine::new(cfg.clone()).unwrap().offline(raw);
    let mut changed = (*cfg).clone();
    changed.filter.rule_weights =
        BTreeMap::from([("urgency".into(), 0.), ("credential_request".into(), 0.)]);
    let engine = Engine::new(Arc::new(changed)).unwrap();
    let offline = engine.offline(raw);
    assert!(offline.score < baseline.score);
    assert_eq!(offline.features, baseline.features);
    let (online, _) = engine
        .process(
            raw,
            "192.0.2.1".parse().unwrap(),
            "example.org",
            "sender@example.org",
            "fixture",
        )
        .await
        .unwrap();
    assert_eq!(online.score, offline.score);
    assert!(
        online
            .reasons
            .iter()
            .filter(|r| matches!(r.id.as_str(), "urgency" | "credential_request"))
            .all(|r| r.weight == 0.)
    );
    let mut repeated = online.clone();
    let weights = BTreeMap::from([("urgency".into(), 0.3)]);
    noisefence::rules::apply(&mut repeated, &weights);
    let once = serde_json::to_value(&repeated).unwrap();
    noisefence::rules::apply(&mut repeated, &weights);
    assert_eq!(serde_json::to_value(repeated).unwrap(), once);
}
