#[allow(dead_code)]
mod common;
use noisefence::{cluster::artifacts, control::Settings, engine, model_catalog as catalog};
use std::{fs, sync::Arc};
#[path = "common/fusion.rs"]
mod fusion_fixture;

fn source(root: &std::path::Path, bias: f64) -> artifacts::Publication {
    let mut config = (*common::config(root)).clone();
    let path = root.join("source-model.json");
    let model = engine::Model {
        version: "catalog-fixture".into(),
        algorithm: engine::Algorithm::Logistic,
        feature_version: 1,
        bias,
        weights: vec![0.; engine::FEATURE_COUNT],
        idf: vec![],
        trained_at: noisefence::now(),
        examples: 2,
    };
    fs::write(&path, serde_json::to_vec(&model).unwrap()).unwrap();
    config.filter.model = Some(path);
    artifacts::capture(&config, Settings::from_config(&config), 1).unwrap()
}

#[test]
fn retained_models_survive_pruning_source_loss_and_keep_current_policy_and_keys() {
    let root = tempfile::tempdir().unwrap();
    let publication = source(root.path(), -4.);
    let entry = catalog::retain(root.path(), &publication, "Baseline".into(), 0).unwrap();
    assert_eq!(
        catalog::retain(root.path(), &publication, "Same files".into(), 0)
            .unwrap()
            .id,
        entry.id
    );
    assert_eq!(catalog::list(root.path()).unwrap().len(), 1);
    artifacts::freeze(root.path(), &publication, 0).unwrap();
    let next = source(root.path(), -8.);
    artifacts::freeze(root.path(), &next, 0).unwrap();
    artifacts::prune_retained(root.path(), &[&next.bundle]).unwrap();
    fs::remove_file(next.config.filter.model.as_ref().unwrap()).unwrap();
    let mut base = next.config.clone();
    let keys = noisefence::credentials::Snapshot::from_map(
        [("crdf".into(), "synthetic-current-credential".into())].into(),
    )
    .unwrap();
    base.credential_generation = Some(keys.fingerprint());
    base.provider_credentials = Some(Arc::new(keys));
    let mut settings = Settings::from_config(&base);
    settings.filters.threshold = 91.;
    settings.preferences.enabled = true;
    base.console_only = true;
    let restored = entry.effective(&base, &settings).unwrap();
    assert_eq!(restored.filter.threshold, 91.);
    assert!(restored.preferences.enabled);
    assert!(restored.console_only);
    assert_eq!(restored.credential_generation, base.credential_generation);
    assert_eq!(
        restored.provider_credentials.unwrap().fingerprint(),
        base.provider_credentials.unwrap().fingerprint()
    );
    assert_eq!(
        engine::Model::load(restored.filter.model.as_ref().unwrap())
            .unwrap()
            .bias,
        -4.
    );
    let raw = serde_json::to_string(&entry).unwrap();
    for secret in [
        "synthetic-current-credential",
        "example.test",
        "source-model.json",
        "provider_credentials",
        "domains",
    ] {
        assert!(!raw.contains(secret), "{secret}");
    }
    assert_eq!(
        entry.qualification(root.path())["whole_pipeline"],
        "not_evaluated"
    );
    catalog::remove(root.path(), &entry.id).unwrap();
    assert!(catalog::list(root.path()).unwrap().is_empty());
    assert!(artifacts::directory(root.path(), &next.bundle).is_dir());
}

#[test]
fn corruption_unsafe_paths_source_changes_and_capacity_are_refused() {
    let root = tempfile::tempdir().unwrap();
    let publication = source(root.path(), -4.);
    fs::write(
        publication.config.filter.model.as_ref().unwrap(),
        b"changed",
    )
    .unwrap();
    assert!(catalog::retain(root.path(), &publication, "Changed".into(), 0).is_err());
    assert!(catalog::list(root.path()).unwrap().is_empty());
    assert!(
        fs::read_dir(root.path().join("cluster/model-catalog"))
            .unwrap()
            .next()
            .is_none()
    );
    let publication = source(root.path(), -4.);
    let entry = catalog::retain(root.path(), &publication, "Valid".into(), 0).unwrap();
    let dir = root.path().join("cluster/model-catalog").join(&entry.id);
    let file = dir.join(&entry.files["/filter/model"].sha256);
    fs::write(&file, b"corrupt").unwrap();
    assert!(entry.verify(root.path()).is_err());
    assert!(
        entry
            .effective(&publication.config, &publication.bundle.settings)
            .is_err()
    );
    fs::remove_file(&file).unwrap();
    std::os::unix::fs::symlink(publication.config.filter.model.as_ref().unwrap(), &file).unwrap();
    assert!(entry.verify(root.path()).is_err());
    for id in ["../source-model.json", "", "/tmp", &"a".repeat(65)] {
        assert!(catalog::load(root.path(), id).is_err());
        assert!(catalog::remove(root.path(), id).is_err());
    }
    catalog::remove(root.path(), &entry.id).unwrap();
    for i in 0..catalog::MAX_SETS {
        let publication = source(root.path(), i as f64);
        catalog::retain(root.path(), &publication, format!("Set {i}"), 0).unwrap();
    }
    let overflow = source(root.path(), 100.);
    assert!(catalog::retain(root.path(), &overflow, "Overflow".into(), 0).is_err());
    assert_eq!(catalog::list(root.path()).unwrap().len(), catalog::MAX_SETS);
}

#[test]
fn report_contract_checks_are_model_bound_and_never_whole_pipeline_qualification() {
    let root = tempfile::tempdir().unwrap();
    let mut config = (*common::config(root.path())).clone();
    let (_, mut report) =
        fusion_fixture::install(&mut config, noisefence::fusion::runtime::Mode::Observe);
    let publication = artifacts::capture(&config, Settings::from_config(&config), 1).unwrap();
    let valid = catalog::retain(
        root.path(),
        &publication,
        "Synthetic report contract".into(),
        0,
    )
    .unwrap();
    let status = valid.qualification(root.path());
    assert_eq!(status["whole_pipeline"], "not_evaluated");
    assert_eq!(status["fusion_validation"], "report_contract_valid");
    report.model_sha256 = noisefence::message::digest(b"another model");
    fs::write(
        config
            .fusion
            .as_ref()
            .unwrap()
            .validation_report
            .as_ref()
            .unwrap(),
        serde_json::to_vec(&report).unwrap(),
    )
    .unwrap();
    let publication = artifacts::capture(&config, Settings::from_config(&config), 2).unwrap();
    let invalid =
        catalog::retain(root.path(), &publication, "Mismatched report".into(), 0).unwrap();
    assert_eq!(
        invalid.qualification(root.path())["fusion_validation"],
        "invalid_or_stale"
    );
    assert_ne!(invalid.id, valid.id);
}
