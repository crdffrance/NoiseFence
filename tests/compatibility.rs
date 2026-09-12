#[path = "../build_support.rs"]
mod build_support;

#[test]
fn only_application_release_metadata_is_normalized() {
    let cargo =
        "[package]\nname = \"noisefence\"\nversion = \"0.4.15\"\n[dependencies]\nregex = \"1\"\n";
    assert_eq!(
        build_support::normalize_manifest(cargo, false),
        build_support::normalize_manifest(&cargo.replace("0.4.15", "9.0.0"), false)
    );
    assert_ne!(
        build_support::normalize_manifest(cargo, false),
        build_support::normalize_manifest(&cargo.replace("regex = \"1\"", "regex = \"2\""), false)
    );
    let lock = "[[package]]\nname = \"noisefence\"\nversion = \"0.4.15\"\n[[package]]\nname = \"regex\"\nversion = \"1.0.0\"\nchecksum = \"abc\"\n";
    assert_eq!(
        build_support::normalize_manifest(lock, true),
        build_support::normalize_manifest(&lock.replace("0.4.15", "0.4.16"), true)
    );
    assert_ne!(
        build_support::normalize_manifest(lock, true),
        build_support::normalize_manifest(&lock.replace("1.0.0", "2.0.0"), true)
    );
    assert_ne!(
        build_support::normalize_manifest(lock, true),
        build_support::normalize_manifest(&lock.replace("abc", "def"), true)
    );
}

#[test]
fn compatibility_binds_every_rust_source_runtime_data_and_build_context() {
    use std::{fs, path::Path};
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let inputs = build_support::inputs(root).unwrap();
    assert!(inputs.contains(&root.join("src/engine.rs")));
    assert!(inputs.contains(&root.join("src/native_filter/rules.rs")));
    assert!(inputs.contains(&root.join("src/control-schema.sql")));
    assert!(inputs.contains(&root.join("deploy/vision-worker.py")));
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("engine.rs");
    fs::write(&path, b"old detector").unwrap();
    let a = build_support::fingerprint(
        temporary.path(),
        std::slice::from_ref(&path),
        "release/target-a",
    )
    .unwrap();
    let b = build_support::fingerprint(
        temporary.path(),
        std::slice::from_ref(&path),
        "release/target-b",
    )
    .unwrap();
    assert_ne!(a, b);
    fs::write(&path, b"new detector").unwrap();
    assert_ne!(
        a,
        build_support::fingerprint(temporary.path(), &[path], "release/target-a").unwrap()
    );
    assert!(noisefence::compatibility::valid_hash(
        noisefence::compatibility::DETECTOR_BUILD_SHA256
    ));
}

#[test]
fn artifact_equivalence_never_overrides_detector_model_or_policy_changes() {
    let config: noisefence::config::Config =
        toml::from_str(include_str!("../config/development.toml")).unwrap();
    let a = noisefence::evidence::Artifacts::new(&config, None, None, false);
    let mut b = a.clone();
    b.application = format!("9.0.0-nf1.{}", a.compatibility_hash().unwrap());
    b.dependency_lock_sha256 = "1".repeat(64);
    assert!(a.equivalent(&b));
    b.policy_sha256 = "2".repeat(64);
    assert!(!a.equivalent(&b));
    b = a.clone();
    b.lexical_model_sha256 = Some("3".repeat(64));
    assert!(!a.equivalent(&b));
    b = a.clone();
    b.application = format!("9.0.0-nf1.{}", "4".repeat(64));
    assert!(!a.equivalent(&b));
    b = a.clone();
    b.application = "0.4.15".into();
    let mut legacy = b.clone();
    legacy.application = "legacy-other".into();
    assert!(!legacy.equivalent(&b));
    assert!(!a.equivalent(&b));
}

#[test]
fn new_artifacts_keep_the_strict_previous_json_shape_for_queued_mail_rollback() {
    let config: noisefence::config::Config =
        toml::from_str(include_str!("../config/development.toml")).unwrap();
    let a = noisefence::evidence::Artifacts::new(&config, None, None, false);
    let object = serde_json::to_value(&a).unwrap();
    let expected = std::collections::BTreeSet::from([
        "application",
        "dependency_lock_sha256",
        "policy_sha256",
        "lexical_model_sha256",
        "semantic_model_sha256",
        "semantic_protocol",
        "llm_prompt_sha256",
        "antivirus_database_sha256",
        "signatures_database_sha256",
        "llm_model_revision",
    ]);
    assert_eq!(
        object
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>(),
        expected
    );
    assert!(
        a.application
            .starts_with(concat!(env!("CARGO_PKG_VERSION"), "-nf1."))
    );
    assert_eq!(
        a.compatibility_hash(),
        Some(noisefence::compatibility::DETECTOR_BUILD_SHA256)
    );
    for invalid in [
        "release-nf1.bad".to_string(),
        format!("-nf1.{}", "a".repeat(64)),
    ] {
        let mut changed = a.clone();
        changed.application = invalid;
        assert!(changed.compatibility_hash().is_none());
        assert!(!changed.equivalent(&a));
    }
}
