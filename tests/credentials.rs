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
