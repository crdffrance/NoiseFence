#[allow(dead_code)]
mod common;
#[path = "common/postgres.rs"]
mod postgres;
use noisefence::{
    central::outbox,
    engine::{SemanticResult, SemanticStatus},
    features,
    learning::{self, SemanticProtocol},
    store::Store,
};
use std::os::unix::fs::PermissionsExt;

#[tokio::test]
#[ignore = "requires disposable PostgreSQL and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn streaming_learning_exports_preserve_population_counters_privacy_and_atomicity() {
    let f = postgres::Fixture::new().await;
    let pg = f.connect().await;
    let root = tempfile::tempdir().unwrap();
    let local = Store::open(root.path()).unwrap();
    let identity = local.run(|db| outbox::initialize(db, "mx1")).await.unwrap();
    f.central.register_source(&identity).await.unwrap();
    for user in ["alice", "peer", "revoked", "disabled"] {
        pg.execute(
            "INSERT INTO noisefence.users(username,password) VALUES($1,'unused')",
            &[&user],
        )
        .await
        .unwrap();
        let address = format!("{user}@example.test");
        pg.execute(
            "INSERT INTO noisefence.grants VALUES($1,$2)",
            &[&user, &address],
        )
        .await
        .unwrap();
        local
            .run(move |db| {
                db.execute(
                    "INSERT INTO users(username,password) VALUES(?1,'unused')",
                    [user],
                )?;
                db.execute(
                    "INSERT INTO grants VALUES(?1,?2)",
                    rusqlite::params![user, address],
                )?;
                Ok(())
            })
            .await
            .unwrap();
    }
    let time = noisefence::now() - 100;
    let mut ids = Vec::new();
    pg.execute(
        "INSERT INTO noisefence.users(username,password,admin) VALUES('admin','unused',true)",
        &[],
    )
    .await
    .unwrap();
    local
        .run(|db| {
            db.execute(
                "INSERT INTO users(username,password,admin) VALUES('admin','unused',1)",
                [],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    let native = noisefence::native_filter::Runtime::new(Default::default()).unwrap();
    let reserved_hash = noisefence::message::digest(b"campaign-6");
    for n in 0..24 {
        let id = uuid::Uuid::from_u128(100 + n).to_string();
        ids.push(id.clone());
        let mut scan = features::extract(common::MESSAGE, 10000);
        scan.native_filter = Some(native.offline(common::MESSAGE, &["example.test".into()]));
        scan.fingerprint = noisefence::message::digest(format!("campaign-{n}").as_bytes());
        scan.campaign_simhash = Some(scan.fingerprint[..16].into());
        let mut vector = vec![0.; learning::DIMENSION];
        vector[0] = 1.;
        scan.semantic = SemanticResult {
            status: SemanticStatus::Complete,
            encoder: learning::ENCODER_ID.into(),
            protocol: Some(SemanticProtocol::pinned()),
            features: vector,
            ..Default::default()
        };
        match n {
            2 => scan.features.clear(),
            3 => scan.feature_version = 999,
            4 => scan.campaign_simhash = None,
            7 => {
                scan.campaign_simhash = Some(format!(
                    "{:016x}",
                    u64::from_str_radix(&reserved_hash[..16], 16).unwrap() ^ 1
                ))
            }
            12 => scan.semantic.protocol = None,
            _ => {}
        }
        let created = if n == 11 { time - 31 * 86400 } else { time };
        let is_dsn = n == 10;
        let user = if n == 8 {
            "revoked"
        } else if n == 9 {
            "disabled"
        } else {
            "alice"
        };
        let mut votes = vec![(user, n != 0, if n == 0 { "publicity" } else { "spam" })];
        if n == 0 || n == 5 {
            votes.push(("peer", false, "legitimate"));
        }
        let copy = votes.clone();
        let key = id.clone();
        local.run(move |db| {
            db.execute("INSERT INTO messages(id,created,sender,scan,is_dsn) VALUES(?1,?2,'private@example.org',?3,?4)",rusqlite::params![key,created,serde_json::to_string(&scan)?,is_dsn])?;
            for (user,spam,category) in copy {
                let recipient=format!("{user}@example.test");
                db.execute("INSERT INTO deliveries(message_id,address,destination,hosts,next_attempt) VALUES(?1,?2,?2,'[]',0)",rusqlite::params![key,recipient])?;
                db.execute("INSERT INTO feedback(username,message_id,spam,created) VALUES(?1,?2,?3,?4)",rusqlite::params![user,key,spam,time])?;
                db.execute("INSERT INTO feedback_categories(username,message_id,category) VALUES(?1,?2,?3)",rusqlite::params![user,key,category])?;
            }Ok(())
        }).await.unwrap();
        while f.central.synchronize_once(&local).await.unwrap() > 0 {}
        for (user, spam, category) in votes {
            pg.execute("INSERT INTO noisefence.feedback(username,message_id,spam,category,created) VALUES($1,$2,$3,$4,$5)",&[&user,&id,&spam,&category,&time]).await.unwrap();
        }
    }
    let reserved = ids[6].clone();
    pg.execute(
        "INSERT INTO noisefence.quality_reserved VALUES($1,$2,'independent')",
        &[&reserved, &time],
    )
    .await
    .unwrap();
    pg.batch_execute("DELETE FROM noisefence.grants WHERE username='revoked'; UPDATE noisefence.users SET disabled=true WHERE username='disabled'").await.unwrap();
    local.run(move |db| {
        db.execute("INSERT INTO quality_reserved VALUES(?1,?2,'independent')",rusqlite::params![reserved,time])?;
        db.execute_batch("DELETE FROM grants WHERE username='revoked'; UPDATE users SET disabled=1 WHERE username='disabled'")?;Ok(())
    }).await.unwrap();
    let central = local
        .clone()
        .with_management(f.central.clone())
        .await
        .unwrap();
    let population_since = time - 1;
    let population_until = noisefence::now() + 1;
    for invalid_capture in [i64::MIN, i64::MAX, 0] {
        assert!(
            f.central
                .population_export(
                    &root.path().join("invalid-capture.jsonl"),
                    population_since,
                    population_until,
                    invalid_capture
                )
                .await
                .is_err()
        );
    }
    let population_legacy = root.path().join("population-legacy.jsonl");
    let population_central = root.path().join("population-central.jsonl");
    let a = noisefence::population::export(
        &local,
        &population_legacy,
        population_since,
        population_until,
    )
    .await
    .unwrap();
    let b = noisefence::population::export(
        &central,
        &population_central,
        population_since,
        population_until,
    )
    .await
    .unwrap();
    assert_eq!(a, b);
    assert_eq!(b.considered, 23);
    assert_eq!(b.exported, 22);
    assert_eq!(b.automatic_dsn, 1);
    assert_eq!(b.ignored_feedback, 2);
    assert_eq!(b.unlabelled, 2);
    assert_eq!(b.conflicting_labels, 1);
    assert_population_equal(&population_legacy, &population_central);
    let frozen = std::fs::read(&population_central).unwrap();
    assert!(
        noisefence::population::export(
            &central,
            &population_central,
            population_since,
            population_until
        )
        .await
        .is_err()
    );
    assert_eq!(frozen, std::fs::read(&population_central).unwrap());
    let output = root.path().join("central.jsonl");
    let reference = root.path().join("legacy.jsonl");
    for semantic in [false, true] {
        let a = learning::export(&local, &reference, semantic)
            .await
            .unwrap();
        let b = learning::export(&central, &output, semantic).await.unwrap();
        assert_eq!(
            serde_json::to_value(&a).unwrap(),
            serde_json::to_value(&b).unwrap()
        );
        assert_eq!(b.considered, 19);
        assert_eq!(b.conflicting, 1);
        assert_eq!(b.conflicting_categories, 1);
        assert_eq!(b.protected_campaigns, 1);
        assert_eq!(b.exported, if semantic { 13 } else { 14 });
        assert_eq!(
            std::fs::read(&output).unwrap(),
            std::fs::read(&reference).unwrap()
        );
        let text = std::fs::read_to_string(&output).unwrap();
        for private in ["private@example.org", "alice@example.test", "Rendez-vous"] {
            assert!(!text.contains(private));
        }
        assert_eq!(
            std::fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let old_native = root.path().join("native-legacy.jsonl");
    let new_native = root.path().join("native-central.jsonl");
    let a = noisefence::native_filter::learning::export(
        &local,
        "admin".into(),
        "example.test".into(),
        &old_native,
    )
    .await
    .unwrap();
    let b = noisefence::native_filter::learning::export(
        &central,
        "admin".into(),
        "example.test".into(),
        &new_native,
    )
    .await
    .unwrap();
    assert_eq!(
        serde_json::to_value(&a).unwrap(),
        serde_json::to_value(&b).unwrap()
    );
    assert_eq!(b.exported, 17);
    assert_eq!(b.protected_campaigns, 1);
    assert_eq!(b.conflicting_labels, 1);
    assert_eq!(
        std::fs::read(old_native).unwrap(),
        std::fs::read(new_native).unwrap()
    );
    assert!(
        noisefence::native_filter::learning::export(
            &central,
            "alice".into(),
            "example.test".into(),
            &root.path().join("denied-native.jsonl")
        )
        .await
        .is_err()
    );
    let old_corpus = root.path().join("corpus-legacy.jsonl");
    let new_corpus = root.path().join("corpus-central.jsonl");
    let a = noisefence::corpus::export_feedback(&local, &old_corpus)
        .await
        .unwrap();
    let b = noisefence::corpus::export_feedback(&central, &new_corpus)
        .await
        .unwrap();
    assert_eq!(a, b);
    assert_eq!(b, 16);
    assert_eq!(
        std::fs::read(old_corpus).unwrap(),
        std::fs::read(&new_corpus).unwrap()
    );
    assert_eq!(
        std::fs::metadata(&new_corpus).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let before = std::fs::read(&output).unwrap();
    // Invalid late data must not replace the previous complete export.
    pg.execute("UPDATE noisefence.messages SET scan=jsonb_set(scan,'{features}','[[1,0.5]]'::jsonb) WHERE id=$1",&[&ids[23]]).await.unwrap();
    assert!(learning::export(&central, &output, false).await.is_err());
    assert_eq!(before, std::fs::read(&output).unwrap());
    assert!(!std::fs::read_dir(root.path()).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".partial")
    }));
    let before_corpus = std::fs::read(&new_corpus).unwrap();
    pg.execute(
        "UPDATE noisefence.messages SET scan=jsonb_set(scan,'{subject}','123'::jsonb) WHERE id=$1",
        &[&ids[23]],
    )
    .await
    .unwrap();
    assert!(
        noisefence::corpus::export_feedback(&central, &new_corpus)
            .await
            .is_err()
    );
    assert_eq!(before_corpus, std::fs::read(&new_corpus).unwrap());
    f.suspend().await;
    assert!(learning::export(&central, &output, false).await.is_err());
    assert_eq!(before, std::fs::read(&output).unwrap());
    assert!(learning::export(&local, &reference, false).await.is_ok());
    f.resume().await;
    let id = ids[23].clone();
    local.run(move |db|{db.execute("UPDATE messages SET scan=json_set(scan,'$.subject',123,'$.features',json('[[1,0.5]]')) WHERE id=?1",[id])?;Ok(())}).await.unwrap();
    let old_invalid = root.path().join("population-invalid-legacy.jsonl");
    let new_invalid = root.path().join("population-invalid-central.jsonl");
    let a =
        noisefence::population::export(&local, &old_invalid, population_since, population_until)
            .await
            .unwrap();
    let b =
        noisefence::population::export(&central, &new_invalid, population_since, population_until)
            .await
            .unwrap();
    assert_eq!(a, b);
    assert_eq!(b.invalid_scan, 1);
    assert_population_equal(&old_invalid, &new_invalid);

    drop(pg);
    f.finish().await;
}

fn assert_population_equal(a: &std::path::Path, b: &std::path::Path) {
    let parse = |p: &std::path::Path| {
        let mut rows: Vec<serde_json::Value> = std::fs::read_to_string(p)
            .unwrap()
            .lines()
            .map(|s| serde_json::from_str(s).unwrap())
            .collect();
        rows[0].as_object_mut().unwrap().remove("captured_at");
        rows
    };
    assert_eq!(parse(a), parse(b));
    let text = std::fs::read_to_string(b).unwrap();
    for private in [
        "private@example.org",
        "alice@example.test",
        "Rendez-vous",
        "\"features\"",
    ] {
        assert!(!text.contains(private));
    }
    assert_eq!(
        std::fs::metadata(b).unwrap().permissions().mode() & 0o777,
        0o600
    );
}
