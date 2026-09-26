#[allow(dead_code)]
mod common;
use noisefence::{
    cluster::protocol,
    credentials::{self, Snapshot},
    management,
};
use std::{collections::BTreeMap, sync::Arc};

#[test]
fn one_resident_snapshot_survives_source_changes_and_never_serializes_secrets() {
    let root = tempfile::tempdir().unwrap();
    let mut config = (*common::config(root.path())).clone();
    config.filter.spamhaus_key_env = Some("UNUSED_TEST_ENV".into());
    management::save_key(root.path(), "spamhaus", "syntheticOldDqsCredential123456").unwrap();
    noisefence::protection::save_key(
        root.path(),
        noisefence::protection::Provider::Crdf,
        "synthetic-old-crdf-credential-123456",
    )
    .unwrap();
    let base = Arc::new(config);
    let pinned = credentials::pin(base.clone()).unwrap();
    let before = protocol::secrets(&pinned).unwrap();
    management::save_key(root.path(), "spamhaus", "syntheticNewDqsCredential123456").unwrap();
    noisefence::protection::save_key(
        root.path(),
        noisefence::protection::Provider::Crdf,
        "synthetic-new-crdf-credential-123456",
    )
    .unwrap();
    let fresh = credentials::pin(base).unwrap();
    assert_ne!(protocol::secrets(&fresh).unwrap(), before);
    assert_eq!(protocol::secrets(&pinned).unwrap(), before);
    assert_eq!(
        management::dqs_key(&pinned).unwrap().as_deref(),
        Some("syntheticOldDqsCredential123456")
    );
    assert!(Arc::ptr_eq(
        &pinned,
        &credentials::pin(pinned.clone()).unwrap()
    ));
    let debug = format!("{pinned:?}");
    let json = serde_json::to_string(&*pinned).unwrap();
    for key in before.values() {
        assert!(!debug.contains(key));
        assert!(!json.contains(key));
    }
    assert!(!json.contains("provider_credentials"));
    assert!(debug.contains("REDACTED"));
}

#[test]
fn explicitly_absent_keys_do_not_fall_back_to_mutable_files() {
    let root = tempfile::tempdir().unwrap();
    let mut config = (*common::config(root.path())).clone();
    config.filter.spamhaus_key_env = Some("UNUSED_TEST_ENV".into());
    management::save_key(root.path(), "spamhaus", "syntheticDqsCredential123456789").unwrap();
    config.provider_credentials = Some(Arc::new(Snapshot::default()));
    assert_eq!(management::dqs_key(&config).unwrap(), None);
    assert!(protocol::secrets(&config).unwrap().is_empty());
    assert!(
        Snapshot::capture(&config)
            .unwrap()
            .get("spamhaus")
            .is_none()
    );
}

#[test]
fn authenticated_credential_sets_are_bounded_and_validate_before_installation() {
    for (name, key) in [
        ("unknown", "synthetic-credential-123456"),
        ("spamhaus", "synthetic-credential-123456"),
        ("crdf", "short"),
        ("scaleway", "synthetic\r\nheader-credential"),
    ] {
        let error = Snapshot::from_map(BTreeMap::from([(name.into(), key.into())])).unwrap_err();
        assert!(!error.to_string().contains(key));
    }
    let a = Snapshot::from_map(BTreeMap::from([(
        "crdf".into(),
        "synthetic-credential-123456".into(),
    )]))
    .unwrap();
    let b = Snapshot::from_map(BTreeMap::from([(
        "crdf".into(),
        "synthetic-credential-654321".into(),
    )]))
    .unwrap();
    assert_ne!(a.fingerprint(), b.fingerprint());
    assert_ne!(a.fingerprint(), Snapshot::default().fingerprint());
    assert_eq!(a.clone().fingerprint(), a.fingerprint());
}

#[test]
fn generations_are_private_immutable_and_retained_for_recovery() {
    use noisefence::credentials::generations;
    use std::{collections::BTreeSet, os::unix::fs::PermissionsExt};
    let root = tempfile::tempdir().unwrap();
    let old = Snapshot::from_map(BTreeMap::from([(
        "crdf".into(),
        "synthetic-generation-old-key-12345".into(),
    )]))
    .unwrap();
    let new = old
        .replacing(
            "crdf".into(),
            Some("synthetic-generation-new-key-67890".into()),
        )
        .unwrap();
    let a = generations::freeze(root.path(), &old).unwrap();
    let b = generations::freeze(root.path(), &new).unwrap();
    let folder = root.path().join("cluster/credentials");
    assert_eq!(
        std::fs::metadata(&folder).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::metadata(folder.join(format!("{a}.json")))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(generations::freeze(root.path(), &old).unwrap(), a);
    generations::retain(root.path(), &BTreeSet::from([a.clone(), b.clone()])).unwrap();
    assert_eq!(generations::load(root.path(), &a).unwrap().fingerprint(), a);
    generations::retain(root.path(), &BTreeSet::from([a.clone()])).unwrap();
    assert!(generations::load(root.path(), &b).is_err());
    let path = folder.join(format!("{a}.json"));
    std::fs::write(&path, b"{}").unwrap();
    assert!(generations::freeze(root.path(), &old).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"{}");
}

#[test]
fn invalid_generation_or_permissions_cannot_replace_a_bound_configuration() {
    use noisefence::{cluster::artifacts, control::Settings, credentials::generations};
    use std::os::unix::fs::{PermissionsExt, symlink};
    let root = tempfile::tempdir().unwrap();
    let config = credentials::pin(common::config(root.path())).unwrap();
    let publication = artifacts::bind_credentials(
        artifacts::capture(&config, Settings::from_config(&config), 0).unwrap(),
    )
    .unwrap();
    artifacts::freeze(root.path(), &publication, 0).unwrap();
    let hash = publication.bundle.credential_generation.as_ref().unwrap();
    let path = root.path().join(format!("cluster/credentials/{hash}.json"));
    let restored = artifacts::materialize(&config, &publication.bundle, true).unwrap();
    assert_eq!(restored.credential_generation.as_ref(), Some(hash));
    let original = std::fs::read(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(artifacts::materialize(&config, &publication.bundle, true).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&path, vec![b'x'; 4097]).unwrap();
    assert!(generations::load(root.path(), hash).is_err());
    std::fs::write(&path, &original).unwrap();
    let external = root.path().join("external");
    std::fs::rename(&path, &external).unwrap();
    symlink(&external, &path).unwrap();
    assert!(generations::load(root.path(), hash).is_err());
    assert!(artifacts::materialize(&config, &publication.bundle, true).is_err());
}

#[test]
fn bound_bundle_retains_keys_after_source_replacement_and_cannot_forge_their_digest() {
    use noisefence::{cluster::artifacts, control::Settings};
    let root = tempfile::tempdir().unwrap();
    let mut config = (*common::config(root.path())).clone();
    config.filter.spamhaus_key_env = Some("UNUSED_TEST_ENV".into());
    management::save_key(root.path(), "spamhaus", "syntheticOldDqsGeneration123456").unwrap();
    let pinned = credentials::pin(Arc::new(config.clone())).unwrap();
    let legacy = artifacts::capture(&pinned, Settings::from_config(&pinned), 0).unwrap();
    let before = legacy.bundle.digest.clone();
    let bound = artifacts::bind_credentials(legacy).unwrap();
    artifacts::freeze(root.path(), &bound, 0).unwrap();
    assert_ne!(before, bound.bundle.digest);
    assert_eq!(
        artifacts::without_credential_binding(&bound.bundle).unwrap(),
        before
    );
    management::save_key(root.path(), "spamhaus", "syntheticNewDqsGeneration678901").unwrap();
    let restored = artifacts::materialize(&config, &bound.bundle, true).unwrap();
    assert_eq!(
        management::dqs_key(&restored).unwrap().as_deref(),
        Some("syntheticOldDqsGeneration123456")
    );
    assert!(
        !serde_json::to_string(&bound.bundle)
            .unwrap()
            .contains("syntheticOldDqs")
    );
    assert!(bound.bundle.files.is_empty());
    let mut forged = restored;
    forged.credential_generation = Some("a".repeat(64));
    assert!(artifacts::capture(&forged, Settings::from_config(&forged), 1).is_err());
}
