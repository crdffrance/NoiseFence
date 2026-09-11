mod common;
use noisefence::native_filter::{
    self as native, Runtime, Settings, Status, input,
    rules::{self, Family, Symbol},
};
use std::sync::Arc;

fn mail(subject: &str, body: &str) -> Vec<u8> {
    format!("From: sender@example.org\r\nSubject: {subject}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{body}").into_bytes()
}
fn symbol(id: &str, family: Family, weight: f64) -> Symbol {
    Symbol {
        id: id.into(),
        label: id.into(),
        family,
        weight,
        absorbed_by: vec![],
    }
}
#[test]
fn native_features_ignore_old_filter_headers_and_mime_encoding() {
    use base64::Engine;
    let subject = "Réunion été";
    let body = "Bonjour merci de confirmer la réunion prévue demain avec notre équipe.";
    let a = input::extract(&mail(subject, body), 10000).unwrap();
    let b = format!(
        "From: changed@example.net\r\nX-Spam-Flag: YES\r\nX-Rspamd-Score: 999\r\nSubject: [SPAM] [PUB] =?UTF-8?B?{}?=\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n{}",
        base64::engine::general_purpose::STANDARD.encode(subject),
        base64::engine::general_purpose::STANDARD.encode(body)
    );
    let b = input::extract(b.as_bytes(), 10000).unwrap();
    assert_eq!(a.subject, b.subject);
    assert_eq!(a.features.osb, b.features.osb);
    assert_eq!(a.features.text, b.features.text);
    assert_eq!(a.features.fingerprint, b.features.fingerprint);
}
#[test]
fn views_and_multi_pattern_matches_equal_individual_regexes() {
    let patterns = rules::default_patterns();
    let matcher = rules::Matcher::compile(&patterns).unwrap();
    for raw in [
        mail("urgent", "Bonjour merci"),
        mail(
            "normal",
            "URGENT verify your account. Enter your seed phrase immediately.",
        ),
        mail("normal", "Vous pouvez vous désabonner de cette lettre."),
    ] {
        let input = input::extract(&raw, 10000).unwrap();
        let expected: std::collections::BTreeSet<_> = patterns
            .iter()
            .filter(|r| {
                let text = match r.target {
                    rules::Target::Subject => &input.subject,
                    rules::Target::Body => &input.body,
                    rules::Target::Html => &input.html,
                };
                regex::Regex::new(&r.pattern).unwrap().is_match(text)
            })
            .map(|r| r.id.clone())
            .collect();
        let actual = matcher.inspect(&input).into_iter().map(|s| s.id).collect();
        assert_eq!(expected, actual);
    }
    let html=b"Subject: form\r\nContent-Type: text/html\r\n\r\n<style>urgent verify your account</style><p>Bonjour</p><form action='/'>texte</form>";
    let results = matcher.inspect(&input::extract(html, 10000).unwrap());
    assert!(results.iter().any(|r| r.id == "NF_FORM"));
    assert!(!results.iter().any(|r| r.id == "NF_CREDENTIALS"));
}
#[test]
fn caps_and_composites_absorb_correlated_symbols_once() {
    let config = Settings::default();
    let composites = rules::Composites::compile(&config.composites, &config.patterns).unwrap();
    let mut symbols = vec![
        symbol("spf_fail", Family::Authentication, 1.),
        symbol("dmarc_fail", Family::Authentication, 2.),
        symbol("NF_LEXICAL", Family::Lexical, 100.),
    ];
    symbols.extend(symbols.clone());
    let result = composites.apply(symbols, &config.caps);
    assert_eq!(result.families[&Family::Lexical].effective, 1.5);
    assert_eq!(result.families[&Family::Authentication].effective, 1.0);
    assert_eq!(result.total, 2.5);
    assert_eq!(result.symbols.len(), 4);
    assert!(
        result
            .symbols
            .iter()
            .filter(|s| s.id == "spf_fail" || s.id == "dmarc_fail")
            .all(|s| s.absorbed_by == ["NF_AUTH_FAILURE"])
    );
    let mut config = config;
    config.composites.reverse();
    let other = rules::Composites::compile(&config.composites, &config.patterns).unwrap();
    assert_eq!(
        serde_json::to_value(&result).unwrap(),
        serde_json::to_value(other.apply(result.symbols.clone(), &config.caps)).unwrap()
    );
}
#[test]
fn configuration_rejects_cycles_unknown_symbols_collisions_and_excessive_resources() {
    let mut config = Settings::default();
    config.composites[0].all = vec![config.composites[0].id.clone()];
    config.composites[0].replace.clear();
    assert!(config.validate().is_err());
    let mut config = Settings::default();
    config.composites[0].none.push("missing_check".into());
    assert!(config.validate().is_err());
    let mut config = Settings::default();
    config.patterns[0].id = "NF_BAYES".into();
    assert!(config.validate().is_err());
    let mut config = Settings::default();
    config.patterns[0].pattern = r"(a+)\1".into();
    assert!(config.validate().is_err());
    let mut config = Settings::default();
    config.caps.insert(
        Family::Lexical,
        rules::Bounds {
            min: -1.,
            max: f64::NAN,
        },
    );
    assert!(config.validate().is_err());
    let config = Settings {
        max_parallel: 0,
        ..Default::default()
    };
    assert!(config.validate().is_err());
    assert!(toml::from_str::<Settings>("mode='enforce'").is_err());
    let mut config = Settings::default();
    config.composites[0].none = vec!["domain_reputation".into()];
    assert!(config.validate().is_err()); // unavailable DNS is not a negative test
}
#[test]
fn minhash_distinguishes_structure_from_content_and_bounds_short_inputs() {
    let text = (0..80)
        .map(|i| format!("distinctword{i}"))
        .collect::<Vec<_>>()
        .join(" ");
    // Digits are deliberately volatile; use alphabetic names for distinct shingles.
    let text = format!(
        "{text} The careful engineer reviews every delivery trace before deciding whether a message really belongs in spam or in a legitimate mailbox with existing authenticated conversation history."
    );
    let a = input::extract(&mail("first", &text), 10000).unwrap();
    let b = input::extract(&mail("second", &format!("{text} Additional note.")), 10000).unwrap();
    assert!(input::similarity(&a.features.text, &b.features.text).unwrap() > 0.8);
    let short = input::extract(&mail("", "ok"), 10000).unwrap();
    assert!(input::similarity(&short.features.text, &a.features.text).is_none());
    let a=input::extract(b"Content-Type: text/html\r\n\r\n<table><tr><td><a href='https://good.example/'>Bonjour</a></td></tr></table>",10000).unwrap();
    let b=input::extract(b"Content-Type: text/html\r\n\r\n<table><tr><td><a href='https://evil.example/'>Different fraudulent message</a></td></tr></table>",10000).unwrap();
    assert_eq!(a.features.html, b.features.html);
    assert_ne!(a.features.text, b.features.text);
}
#[tokio::test]
async fn observations_preserve_score_decision_and_delivered_body() {
    let root = tempfile::tempdir().unwrap();
    let cfg = common::config(root.path());
    let baseline = noisefence::engine::Engine::new(cfg.clone()).unwrap();
    let mut configured = (*cfg).clone();
    configured.native_filter = Some(Settings::default());
    configured.validate().unwrap();
    let engine = noisefence::engine::Engine::new(Arc::new(configured)).unwrap();
    let message = mail(
        "urgent",
        "Urgent verify your account and enter your seed phrase immediately.",
    );
    let a = baseline.offline(&message);
    let b = engine.offline(&message);
    assert_eq!(a.score, b.score);
    assert_eq!(
        serde_json::to_value(a.decision).unwrap(),
        serde_json::to_value(&b.decision).unwrap()
    );
    let observed = b.native_filter.unwrap();
    assert!(!observed.report.affects_delivery);
    assert!(!observed.report.calibrated);
    assert!(
        observed
            .report
            .score
            .unwrap()
            .symbols
            .iter()
            .any(|s| s.id == "NF_WALLET_URGENCY")
    );
    let (scan, wire) = engine
        .process(
            &message,
            "192.0.2.1".parse().unwrap(),
            "sender.example.org",
            "sender@example.org",
            "native-fixture",
        )
        .await
        .unwrap();
    assert!(!scan.tagged);
    assert!(
        wire.ends_with(&message[message.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4..])
    );
    assert_eq!(
        scan.native_filter.as_ref().unwrap().report.status,
        Status::Complete
    );
    let diagnostic = serde_json::to_value(noisefence::diagnostics::Analysis::from(scan)).unwrap();
    assert!(!diagnostic.to_string().contains("\"osb\""));
    assert!(!diagnostic.to_string().contains("seed phrase"));
    assert!(!diagnostic.to_string().contains("\"local_symbols\""));
}
#[tokio::test]
async fn oversized_messages_fail_open_without_creating_features() {
    let runtime = Runtime::new(Settings {
        max_bytes: 1024,
        ..Default::default()
    })
    .unwrap();
    let result = runtime.inspect(&vec![b'a'; 1025], &[]).await;
    assert_eq!(result.report.status, Status::Limited);
    assert!(result.features.is_none());
    assert!(result.report.score.is_none());
    let mut features = input::extract(common::MESSAGE, 10000).unwrap().features;
    features.osb = vec![1, 1];
    assert!(features.validate().is_err());
}

fn training_example(index: usize, spam: bool, observed_at: i64) -> native::bayes::Example {
    let mut features = input::extract(common::MESSAGE, 10000).unwrap().features;
    // Synthetic fixtures deliberately isolate the training/evaluation contract.
    features.fingerprint = noisefence::message::digest(format!("campaign-{index}").as_bytes());
    features.osb = if spam {
        (100..130).collect()
    } else {
        (200..230).collect()
    };
    features.text = vec![];
    features.text_shingles = 0;
    native::bayes::Example {
        scope: "example.test".into(),
        id: noisefence::message::digest(format!("row-{index}").as_bytes()),
        observed_at,
        labelled_at: observed_at + 1,
        spam,
        features,
    }
}
#[test]
fn osb_model_is_bound_to_scope_protocol_and_expiration() {
    let rows: Vec<_> = (0..12)
        .map(|i| training_example(i, i % 2 == 0, 100 + i as i64))
        .collect();
    let model = native::bayes::Model::fit(&rows, "fixture-1", "a".repeat(64)).unwrap();
    let spam = model.predict(&rows[0].features, &["example.test".into()], model.created);
    let ham = model.predict(&rows[1].features, &["example.test".into()], model.created);
    assert!(spam.raw_log_odds.unwrap() > 0.);
    assert!(ham.raw_log_odds.unwrap() < 0.);
    assert!(!spam.calibrated);
    assert!(
        model
            .predict(&rows[0].features, &["other.test".into()], model.created)
            .raw_log_odds
            .is_none()
    );
    assert_eq!(
        model
            .predict(&rows[0].features, &["example.test".into()], model.expires)
            .status,
        "expired"
    );
    let mut invalid = model.clone();
    let mut expired = model.clone();
    expired.created = noisefence::now() - 31 * 86400;
    expired.expires = expired.created + 30 * 86400;
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("expired-model.json");
    std::fs::write(&path, serde_json::to_vec(&expired).unwrap()).unwrap();
    let runtime = Runtime::new(Settings {
        bayes_model: Some(path),
        ..Default::default()
    })
    .unwrap();
    let observation = runtime.offline(common::MESSAGE, &["example.test".into()]);
    assert_eq!(observation.report.status, Status::Complete);
    assert_eq!(observation.report.bayes.status, "expired");
    assert!(observation.report.bayes.raw_log_odds.is_none());
    invalid.counts[0].1 = 100;
    assert!(invalid.validate().is_err());
    let mut rows = rows;
    rows.push(rows[0].clone());
    assert!(native::bayes::Model::fit(&rows, "duplicate", "a".repeat(64)).is_err());
}
#[test]
fn osb_training_uses_chronological_campaigns_and_freezes_validation_threshold() {
    use std::io::Write;
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("samples.jsonl");
    let mut file = std::fs::File::create(&path).unwrap();
    for i in 0..36 {
        serde_json::to_writer(
            &mut file,
            &training_example(i, i % 2 == 0, 100 + (i / 12) as i64 * 100 + i as i64 % 12),
        )
        .unwrap();
        writeln!(&mut file).unwrap();
    }
    let output = root.path().join("candidate");
    let report = native::learning::train(&path, &output, "osb-test", 200, 300).unwrap();
    assert_eq!(report.train, 12);
    assert_eq!(report.test.false_positive, 0);
    assert_eq!(report.test.true_positive, 6);
    assert!(!report.may_activate);
    assert!(report.test.false_positive_rate_ci95[1] > 0.001);
    assert!(native::learning::train(&path, &output, "osb-test", 200, 300).is_err());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(output.join("model.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    let input = root.path().join("independent.jsonl");
    let mut file = std::fs::File::create(&input).unwrap();
    // Freeze the fixture in the past to evaluate genuinely later observations.
    let model_path = output.join("model.json");
    let mut model: native::bayes::Model =
        serde_json::from_slice(&std::fs::read(&model_path).unwrap()).unwrap();
    model.created -= 60;
    model.expires -= 60;
    let model_bytes = serde_json::to_vec_pretty(&model).unwrap();
    std::fs::write(&model_path, &model_bytes).unwrap();
    let report_path = output.join("report.json");
    let mut metadata: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&report_path).unwrap()).unwrap();
    metadata["model_sha256"] = noisefence::message::digest(&model_bytes).into();
    std::fs::write(&report_path, serde_json::to_vec_pretty(&metadata).unwrap()).unwrap();
    let now = noisefence::now();
    for i in 36..48 {
        serde_json::to_writer(&mut file, &training_example(i, i % 2 == 0, now - 10)).unwrap();
        writeln!(&mut file).unwrap();
    }
    let result = native::learning::evaluate(
        &input,
        &output.join("model.json"),
        &output.join("manifest.json"),
        &output.join("report.json"),
        &root.path().join("evaluation.json"),
    )
    .unwrap();
    assert!(result.independent);
    assert!(!result.may_activate);
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(output.join("report.json")).unwrap()).unwrap();
    value["model_sha256"] = "bad".into();
    std::fs::write(
        output.join("report.json"),
        serde_json::to_vec(&value).unwrap(),
    )
    .unwrap();
    assert!(
        native::learning::evaluate(
            &input,
            &output.join("model.json"),
            &output.join("manifest.json"),
            &output.join("report.json"),
            &root.path().join("bad-evaluation.json")
        )
        .is_err()
    );
}

async fn seed(store: &noisefence::store::Store, id: &str, raw: &[u8], spam: bool, created: i64) {
    let runtime = Runtime::new(Settings::default()).unwrap();
    let observation = runtime.offline(raw, &[]);
    let mut scan = noisefence::features::extract(raw, 100000);
    scan.native_filter = Some(observation);
    let id = id.to_owned();
    let json = serde_json::to_string(&scan).unwrap();
    store.run(move|db|{
        db.execute("INSERT OR IGNORE INTO users(username,password,admin) VALUES('reviewer','unused',1)",[])?;
        db.execute("INSERT INTO messages(id,created,sender,scan) VALUES(?1,?2,'private@example.org',?3)",rusqlite::params![id,created,json])?;
        db.execute("INSERT INTO deliveries(message_id,address,destination,hosts,next_attempt) VALUES(?1,'alice@example.test','alice@example.test','[]',0)",[&id])?;
        db.execute("INSERT INTO feedback(username,message_id,spam,created) VALUES('reviewer',?1,?2,?3)",rusqlite::params![id,spam,created+1])?;Ok(())
    }).await.unwrap();
}
#[tokio::test]
async fn fuzzy_memory_and_export_recheck_scope_conflicts_expiration_and_access() {
    let root = tempfile::tempdir().unwrap();
    let store = noisefence::store::Store::open(root.path()).unwrap();
    let body = "Bonjour voici une invitation détaillée pour notre prochaine réunion concernant les changements du projet et les décisions nécessaires afin de préparer ensemble le calendrier des travaux ainsi que les réponses aux questions ouvertes parmi tous les participants disponibles cette semaine.";
    let raw = mail("invitation", body);
    let runtime = Runtime::new(Settings::default()).unwrap();
    let observation = runtime.offline(&raw, &[]);
    let features = observation.features.unwrap();
    assert!(features.text_shingles >= 24);
    let now = noisefence::now();
    seed(&store, "a", &mail("original a", body), true, now - 100).await;
    seed(&store, "b", &mail("original b", body), true, now - 90).await;
    let result = native::memory::inspect(
        root.path(),
        &features,
        &["example.test".into()],
        "different",
    )
    .await;
    assert!(result.corroborated_spam);
    assert_eq!(result.spam_examples, 2);
    let result =
        native::memory::inspect(root.path(), &features, &["other.test".into()], "different").await;
    assert_eq!(result.spam_examples, 0);
    assert_eq!(
        native::memory::inspect(
            root.path(),
            &features,
            &["example.test".into(), "other.test".into()],
            "different"
        )
        .await
        .status,
        Status::NotRun
    );
    let export = native::learning::export(
        &store,
        "reviewer".into(),
        "example.test".into(),
        &root.path().join("export.jsonl"),
    )
    .await
    .unwrap();
    assert_eq!(export.exported, 2);
    store
        .run(|db| {
            db.execute("UPDATE feedback SET spam=0 WHERE message_id='a'", [])?;
            Ok(())
        })
        .await
        .unwrap();
    let result = native::memory::inspect(
        root.path(),
        &features,
        &["example.test".into()],
        "different",
    )
    .await;
    assert!(result.conflict);
    assert!(!result.corroborated_spam);
    store
        .run(|db| {
            db.execute("UPDATE users SET disabled=1 WHERE username='reviewer'", [])?;
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(
        native::memory::inspect(
            root.path(),
            &features,
            &["example.test".into()],
            "different"
        )
        .await
        .spam_examples,
        0
    );
    assert!(
        native::learning::export(
            &store,
            "reviewer".into(),
            "example.test".into(),
            &root.path().join("denied.jsonl")
        )
        .await
        .is_err()
    );
    store
        .run(|db| {
            db.execute(
                "UPDATE users SET disabled=0,admin=0 WHERE username='reviewer'",
                [],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(
        native::memory::inspect(
            root.path(),
            &features,
            &["example.test".into()],
            "different"
        )
        .await
        .matches,
        0
    );
    store
        .run(|db| {
            db.execute("UPDATE users SET admin=1 WHERE username='reviewer'", [])?;
            db.execute(
                "UPDATE messages SET created=?1",
                [noisefence::now() - 31 * 86400],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(
        native::memory::inspect(
            root.path(),
            &features,
            &["example.test".into()],
            "different"
        )
        .await
        .matches,
        0
    );
}

#[test]
fn training_excludes_conflicting_and_near_duplicate_campaigns_across_time_boundaries() {
    use std::io::Write;
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("data.jsonl");
    let mut rows: Vec<_> = (0..36)
        .map(|i| training_example(i, i % 2 == 0, 100 + (i / 12) as i64 * 100 + i as i64 % 12))
        .collect();
    let mut a = training_example(90, true, 150);
    let mut b = training_example(91, true, 250);
    a.features.text = vec![7; 32];
    a.features.text_shingles = 50;
    b.features.text = vec![7; 32];
    b.features.text[0] = 9;
    b.features.text_shingles = 50;
    rows.extend([a, b]);
    let a = training_example(92, false, 150);
    let mut b = training_example(93, true, 151);
    b.features.fingerprint = a.features.fingerprint.clone();
    rows.extend([a, b]);
    let mut file = std::fs::File::create(&path).unwrap();
    for row in &rows {
        serde_json::to_writer(&mut file, row).unwrap();
        writeln!(file).unwrap();
    }
    let report = native::learning::train(
        &path,
        &root.path().join("candidate"),
        "boundary-test",
        200,
        300,
    )
    .unwrap();
    assert_eq!(report.excluded_boundary, 2);
    assert_eq!(report.excluded_conflict, 2);
    assert_eq!(report.train, 12);
    let future = training_example(100, true, noisefence::now() + 100);
    assert!(future.validate().is_err());
}

#[tokio::test]
async fn concurrent_benchmark_reports_completed_work_and_matching_parity() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("fixture.eml");
    std::fs::write(&path, common::MESSAGE).unwrap();
    let report = native::benchmark::run(&path, 8, 2).await.unwrap();
    assert_eq!(report.messages, 8);
    assert_eq!(report.unavailable, 0);
    assert!(report.identical_matches);
    assert!(report.p95_ms.is_finite() && report.messages_per_second > 0.);
    assert!(native::benchmark::run(&path, 0, 2).await.is_err());
}

#[test]
fn arbitrary_mime_inputs_keep_feature_shapes_bounded() {
    let mut state = 19u64;
    for length in [0, 1, 100, 1024, 4096, 16384] {
        for _ in 0..10 {
            let raw: Vec<u8> = (0..length)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    state as u8
                })
                .collect();
            if let Ok(input) = input::extract(&raw, 16384) {
                input.features.validate().unwrap();
                assert!(input.body.chars().count() <= 32000);
            }
        }
    }
}

#[tokio::test]
async fn short_bursts_wait_for_cpu_capacity_under_one_shared_deadline() {
    let runtime = Runtime::new(Settings {
        max_parallel: 1,
        ..Default::default()
    })
    .unwrap();
    let raw = mail(
        "Burst",
        &"Bonjour merci pour votre participation à cette réunion. ".repeat(1000),
    );
    let (a, b, c, d) = tokio::join!(
        runtime.inspect(&raw, &[]),
        runtime.inspect(&raw, &[]),
        runtime.inspect(&raw, &[]),
        runtime.inspect(&raw, &[])
    );
    assert!(
        [a, b, c, d]
            .iter()
            .all(|o| o.report.status == Status::Complete)
    );
}
