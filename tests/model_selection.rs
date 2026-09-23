#[allow(dead_code)]
mod common;
use noisefence::{cluster::artifacts, control::Settings};
use serde_json::json;

#[test]
fn model_identity_is_bound_to_logical_slots_and_bytes_not_capture_order() {
    let root = tempfile::tempdir().unwrap();
    let mut config = (*common::config(root.path())).clone();
    let path = root.path().join("source.json");
    std::fs::write(&path, b"synthetic artifact bytes").unwrap();
    config.filter.model = Some(path);
    let p = artifacts::capture(&config, Settings::from_config(&config), 0).unwrap();
    let before = artifacts::model_digest(&p.bundle).unwrap();
    let mut renamed = p.bundle.clone();
    let file = renamed.files.remove("model-0.json").unwrap();
    renamed.files.insert("model-4.json".into(), file);
    renamed.shared["filter"]["model"] = json!("model-4.json");
    renamed.digest = renamed.hash().unwrap();
    assert_eq!(artifacts::model_digest(&renamed).unwrap(), before);
    let mut changed = renamed.clone();
    changed.files.get_mut("model-4.json").unwrap().sha256 = "a".repeat(64);
    changed.digest = changed.hash().unwrap();
    assert_ne!(artifacts::model_digest(&changed).unwrap(), before);
    let mut extra = renamed.clone();
    extra.shared["fusion"] = json!({"validation_report":"model-4.json"});
    extra.digest = extra.hash().unwrap();
    assert_ne!(
        artifacts::model_digest(&extra).unwrap(),
        before,
        "Validation evidence is part of the selected artifact identity"
    );
}
#[test]
fn rebase_uses_only_manifest_slots_and_rejects_original_or_unlisted_paths() {
    let root = tempfile::tempdir().unwrap();
    let mut config = (*common::config(root.path())).clone();
    let path = root.path().join("source.json");
    std::fs::write(&path, b"fixture").unwrap();
    config.filter.model = Some(path.clone());
    let p = artifacts::capture(&config, Settings::from_config(&config), 0).unwrap();
    artifacts::freeze(root.path(), &p, 0).unwrap();
    std::fs::remove_file(path).unwrap();
    let pinned = artifacts::model_base(&config, &p.bundle).unwrap();
    assert!(pinned.filter.model.as_ref().unwrap().is_file());
    artifacts::require_installed_models(&pinned, &p.bundle, false).unwrap();
    assert!(artifacts::require_installed_models(&config, &p.bundle, false).is_err());
    let mut injected = p.bundle.clone();
    injected.shared["filter"]["model"] = json!("../../secret");
    injected.digest = injected.hash().unwrap();
    assert!(artifacts::model_base(&config, &injected).is_err());
    assert!(artifacts::model_manifest(&injected).is_err());
}
#[test]
fn disabled_quality_candidate_does_not_reappear_from_installation_defaults() {
    let root = tempfile::tempdir().unwrap();
    let mut config = (*common::config(root.path())).clone();
    config.quality = Some(noisefence::quality::Settings {
        candidate: Some(root.path().join("old.json")),
    });
    let mut disabled = config.clone();
    disabled.quality.as_mut().unwrap().candidate = None;
    let p = artifacts::capture(&disabled, Settings::from_config(&disabled), 1).unwrap();
    let pinned = artifacts::model_base(&config, &p.bundle).unwrap();
    assert!(pinned.quality.unwrap().candidate.is_none());
}
