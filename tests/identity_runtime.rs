mod common;
use noisefence::{
    cluster::artifacts,
    control,
    identity::{directory, runtime},
};
use serde_json::json;

fn document(generation: u64) -> runtime::Document {
    let mut source: directory::Snapshot =
        serde_json::from_str(include_str!("fixtures/identity/directory.json")).unwrap();
    source.generation = generation;
    source.completed_at = noisefence::now();
    runtime::Document {
        schema: runtime::SCHEMA.into(),
        sources: vec![source],
    }
}
fn prepare(config: &mut noisefence::config::Config, generation: u64) -> runtime::Selection {
    let bytes = serde_json::to_vec(&document(generation)).unwrap();
    let mut selection = runtime::prepare(&config.data_dir, &bytes, noisefence::now(), 0).unwrap();
    selection.reviewed_from = config.identity.as_ref().map(|s| s.sha256.clone());
    config.identity = selection
        .apply(&config.data_dir, config.identity.as_ref())
        .unwrap();
    selection
}
#[test]
fn directory_moves_with_policy_but_never_changes_model_identity() {
    let root = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    let mut config = (*common::config(root.path())).clone();
    let original = artifacts::capture(&config, control::Settings::from_config(&config), 0).unwrap();
    let original_model_hash = artifacts::model_digest(&original.bundle).unwrap();
    prepare(&mut config, 1);
    let publication =
        artifacts::capture(&config, control::Settings::from_config(&config), 1).unwrap();
    assert_eq!(
        artifacts::model_digest(&publication.bundle).unwrap(),
        original_model_hash
    );
    assert_ne!(publication.bundle.digest, original.bundle.digest);
    assert_eq!(
        publication.bundle.shared["identity"]["catalog"],
        "identity-directory.json"
    );
    assert!(
        publication
            .bundle
            .files
            .contains_key("identity-directory.json")
    );
    assert!(publication.bundle.for_build("0.32.0-rc.2").is_err());
    assert!(publication.bundle.for_build("0.32.0-rc.3").is_err());
    assert!(
        publication
            .bundle
            .for_build(env!("CARGO_PKG_VERSION"))
            .is_ok()
    );
    artifacts::freeze(other.path(), &publication, 0).unwrap();
    let mut worker = (*common::config(other.path())).clone();
    let materialized = artifacts::materialize(&worker, &publication.bundle, true).unwrap();
    let installed = materialized.identity.as_ref().unwrap();
    assert_eq!(installed.sha256, config.identity.as_ref().unwrap().sha256);
    assert!(
        installed
            .catalog
            .starts_with(other.path().join("cluster/models"))
    );
    let loaded = runtime::Loaded::load(installed, noisefence::now()).unwrap();
    assert_eq!(
        loaded
            .inspect(
                common::MESSAGE,
                "alice@example.test",
                None,
                noisefence::now()
            )
            .observation
            .status,
        "complete"
    );
    // Legacy/disabled shared policy must not fall back to worker-local files.
    worker.identity = config.identity.clone();
    assert!(
        artifacts::materialize(&worker, &original.bundle, false)
            .unwrap()
            .identity
            .is_none()
    );
    std::fs::write(&installed.catalog, b"tampered").unwrap();
    assert!(artifacts::materialize(&worker, &publication.bundle, true).is_err());
    assert!(runtime::Loaded::load(installed, noisefence::now()).is_err());
}
#[test]
fn settings_save_keeps_frozen_directory_after_source_upload_is_removed() {
    let root = tempfile::tempdir().unwrap();
    let mut config = (*common::config(root.path())).clone();
    prepare(&mut config, 1);
    let publication =
        artifacts::capture(&config, control::Settings::from_config(&config), 1).unwrap();
    artifacts::freeze(root.path(), &publication, 0).unwrap();
    let installed = artifacts::materialize(&config, &publication.bundle, true).unwrap();
    std::fs::remove_file(&config.identity.as_ref().unwrap().catalog).unwrap();
    let settings = control::Settings::from_config(&installed);
    let effective = settings.effective(&installed).unwrap();
    assert_eq!(effective.identity, installed.identity);
    let mut disabled = settings;
    disabled.identity_directory = Some(runtime::Selection {
        sha256: None,
        reviewed_from: installed.identity.as_ref().map(|s| s.sha256.clone()),
    });
    let disabled_config = disabled.effective(&installed).unwrap();
    assert!(disabled_config.identity.is_none());
    let off = artifacts::capture(&disabled_config, disabled, 2).unwrap();
    off.bundle.validate().unwrap();
    assert!(!off.bundle.files.contains_key("identity-directory.json"));
}
#[test]
fn manifest_rejects_directory_selection_disagreement_and_extra_files() {
    let root = tempfile::tempdir().unwrap();
    let mut config = (*common::config(root.path())).clone();
    prepare(&mut config, 1);
    let publication =
        artifacts::capture(&config, control::Settings::from_config(&config), 1).unwrap();
    let mut mismatched = publication.bundle.clone();
    mismatched
        .settings
        .identity_directory
        .as_mut()
        .unwrap()
        .sha256 = Some("a".repeat(64));
    mismatched.digest = mismatched.hash().unwrap();
    assert!(mismatched.validate().is_err());
    let mut path = publication.bundle.clone();
    path.shared["identity"]["catalog"] = json!("../../secret");
    path.digest = path.hash().unwrap();
    assert!(path.validate().is_err());
    let mut orphan = publication.bundle;
    orphan.shared.as_object_mut().unwrap().remove("identity");
    orphan.settings.identity_directory = None;
    orphan.digest = orphan.hash().unwrap();
    assert!(orphan.validate().is_err());
}
#[test]
fn invalid_candidate_never_replaces_the_loaded_directory() {
    let root = tempfile::tempdir().unwrap();
    let mut config = (*common::config(root.path())).clone();
    prepare(&mut config, 1);
    let current = config.identity.as_ref().unwrap().clone();
    let publication =
        artifacts::capture(&config, control::Settings::from_config(&config), 1).unwrap();
    let original = artifacts::model_digest(&publication.bundle).unwrap();
    let selection = prepare(&mut config, 2);
    let next = artifacts::capture(&config, control::Settings::from_config(&config), 2).unwrap();
    assert_eq!(artifacts::model_digest(&next.bundle).unwrap(), original);
    assert_ne!(
        next.bundle.files["identity-directory.json"].sha256,
        publication.bundle.files["identity-directory.json"].sha256
    );
    assert_ne!(selection.sha256.as_ref(), Some(&current.sha256));
    std::fs::write(&config.identity.as_ref().unwrap().catalog, b"{}").unwrap();
    assert!(artifacts::capture(&config, control::Settings::from_config(&config), 2).is_err());
    assert!(runtime::Loaded::load(&current, noisefence::now()).is_ok());
}

#[test]
fn review_binds_both_snapshots_and_source_generations_cannot_roll_back() {
    let root = tempfile::tempdir().unwrap();
    let mut config = (*common::config(root.path())).clone();
    prepare(&mut config, 3);
    let current = config.identity.as_ref().unwrap();
    let candidate = serde_json::to_vec(&document(4)).unwrap();
    let mut selection = runtime::prepare(root.path(), &candidate, noisefence::now(), 0).unwrap();
    assert!(selection.apply(root.path(), Some(current)).is_err());
    selection.reviewed_from = Some("b".repeat(64));
    assert!(selection.apply(root.path(), Some(current)).is_err());
    selection.reviewed_from = Some(current.sha256.clone());
    assert!(selection.apply(root.path(), Some(current)).is_ok());
    let rollback = serde_json::to_vec(&document(2)).unwrap();
    let mut selection = runtime::prepare(root.path(), &rollback, noisefence::now(), 0).unwrap();
    selection.reviewed_from = Some(current.sha256.clone());
    assert!(selection.apply(root.path(), Some(current)).is_err());
    let mut changed_authority = document(4);
    changed_authority.sources[0].source.authority = "another-tenant".into();
    let mut selection = runtime::prepare(
        root.path(),
        &serde_json::to_vec(&changed_authority).unwrap(),
        noisefence::now(),
        0,
    )
    .unwrap();
    selection.reviewed_from = Some(current.sha256.clone());
    assert!(selection.apply(root.path(), Some(current)).is_err());
    let empty = runtime::Document {
        schema: runtime::SCHEMA.into(),
        sources: vec![],
    };
    let mut selection = runtime::prepare(
        root.path(),
        &serde_json::to_vec(&empty).unwrap(),
        noisefence::now(),
        0,
    )
    .unwrap();
    assert!(selection.apply(root.path(), Some(current)).is_err());
    selection.reviewed_from = Some(current.sha256.clone());
    assert!(selection.apply(root.path(), Some(current)).is_ok());
}

#[tokio::test]
async fn committed_directory_reopens_without_replaying_review_against_installation_defaults() {
    use noisefence::{control::Controller, store::Store};
    let root = tempfile::tempdir().unwrap();
    let base = common::config(root.path());
    let store = Store::open(root.path()).unwrap();
    store
        .run(|db| {
            db.execute("INSERT INTO users VALUES('admin','unused',1,0)", [])?;
            Ok(())
        })
        .await
        .unwrap();
    let controller = Controller::load(base.clone(), store.clone()).await.unwrap();
    let first = runtime::prepare(
        root.path(),
        &serde_json::to_vec(&document(1)).unwrap(),
        noisefence::now(),
        0,
    )
    .unwrap();
    let mut settings = controller.snapshot().settings.clone();
    settings.identity_directory = Some(first.clone());
    let revision = controller.apply(0, settings, "admin".into()).await.unwrap();
    let mut second = runtime::prepare(
        root.path(),
        &serde_json::to_vec(&document(2)).unwrap(),
        noisefence::now(),
        0,
    )
    .unwrap();
    let mut settings = controller.snapshot().settings.clone();
    settings.identity_directory = Some(second.clone());
    assert!(controller.effective_settings(&settings).await.is_err());
    assert!(
        controller
            .apply(revision, settings.clone(), "admin".into())
            .await
            .is_err()
    );
    second.reviewed_from = first.sha256.clone();
    settings.identity_directory = Some(second.clone());
    let revision = controller
        .apply(revision, settings, "admin".into())
        .await
        .unwrap();
    drop(controller);
    let controller = Controller::load(base.clone(), store.clone()).await.unwrap();
    assert_eq!(controller.snapshot().revision, revision);
    assert_eq!(
        controller
            .snapshot()
            .config
            .identity
            .as_ref()
            .unwrap()
            .sha256,
        second.sha256.clone().unwrap()
    );
    assert_eq!(
        control::effective_from_disk(base).unwrap().identity,
        controller.snapshot().config.identity
    );
    let mut settings = controller.snapshot().settings.clone();
    settings.identity_directory = None;
    assert!(controller.effective_settings(&settings).await.is_err());
    settings.identity_directory = Some(runtime::Selection {
        sha256: None,
        reviewed_from: second.sha256,
    });
    controller
        .apply(revision, settings, "admin".into())
        .await
        .unwrap();
    assert!(controller.snapshot().config.identity.is_none());
}

#[test]
fn identity_policy_is_shared_reviewed_and_cannot_fall_back_to_worker_defaults() {
    use noisefence::identity::correlation::{Mode, Settings};
    let root = tempfile::tempdir().unwrap();
    let mut config = (*common::config(root.path())).clone();
    let legacy = artifacts::capture(&config, control::Settings::from_config(&config), 0).unwrap();
    config.identity_policy = Some(Settings {
        mode: Mode::Contribute,
        maximum_weight: 0.75,
    });
    let settings = control::Settings::from_config(&config);
    let publication = artifacts::capture(&config, settings.clone(), 1).unwrap();
    assert_ne!(publication.bundle.digest, legacy.bundle.digest);
    assert_eq!(
        artifacts::model_digest(&publication.bundle).unwrap(),
        artifacts::model_digest(&legacy.bundle).unwrap()
    );
    assert!(publication.bundle.for_build("0.32.0-rc.2").is_err());
    assert!(publication.bundle.for_build("0.32.0-rc.3").is_err());
    assert_eq!(
        artifacts::materialize(&config, &publication.bundle, false)
            .unwrap()
            .identity_policy,
        config.identity_policy
    );
    assert!(
        artifacts::materialize(&config, &legacy.bundle, false)
            .unwrap()
            .identity_policy
            .is_none()
    );
    let mut invalid = settings.clone();
    invalid.identity_policy.as_mut().unwrap().maximum_weight = 2.;
    assert!(invalid.effective(&config).is_err());
    let mut mismatch = publication.bundle.clone();
    mismatch.shared["identity_policy"]["maximum_weight"] = json!(0.5);
    mismatch.digest = mismatch.hash().unwrap();
    assert!(mismatch.validate().is_err());
    let mut bad = publication.bundle.clone();
    bad.shared["identity_policy"]["maximum_weight"] = json!(1.5);
    bad.settings
        .identity_policy
        .as_mut()
        .unwrap()
        .maximum_weight = 1.5;
    bad.digest = bad.hash().unwrap();
    assert!(bad.validate().is_err());
}

#[test]
fn legacy_build_labels_cannot_authorize_new_identity_fields() {
    for kind in 0..3 {
        let root = tempfile::tempdir().unwrap();
        let mut config = (*common::config(root.path())).clone();
        match kind {
            0 => {
                prepare(&mut config, 1);
            }
            1 => config.identity_policy = Some(Default::default()),
            _ => {
                config.contact_learning = Some(noisefence::identity::learning::Settings {
                    enabled: false,
                    ..Default::default()
                })
            }
        }
        let bundle = artifacts::capture(&config, control::Settings::from_config(&config), 1)
            .unwrap()
            .bundle;
        bundle.validate().unwrap();
        for old in ["0.32.0-rc.2", "0.32.0-rc.3"] {
            assert!(bundle.for_build(old).is_err());
            let mut relabelled = bundle.clone();
            relabelled.build = old.into();
            relabelled.digest = relabelled.hash().unwrap();
            assert!(
                relabelled.validate().is_err(),
                "legacy label {old} must not authorize field {kind}"
            );
        }
    }
}
