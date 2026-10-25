use super::*;
use crate::identity::{
    connections::{self, PROTOCOL},
    directory::{Provider, Source},
};
use std::collections::BTreeSet;
fn meta(key: &Key) -> Metadata {
    Metadata {
        protocol: PROTOCOL.into(),
        source: Source {
            id: "synthetic".into(),
            label: "Synthetic directory".into(),
            provider: Provider::Entra,
            authority: "11111111-1111-4111-8111-111111111111".into(),
            scopes: BTreeSet::from(["example.test".into()]),
            stale_after_seconds: 86400,
        },
        generation: uuid::Uuid::new_v4().to_string(),
        supersedes: None,
        authority: "sqlite".into(),
        key_id: key.id(),
        owner: "admin".into(),
        owner_version: 0,
        created: 1000,
        expires: 2000,
    }
}
fn credential() -> Credential {
    Credential::EntraApplication {
        client_id: "22222222-2222-4222-8222-222222222222".into(),
        client_secret: "synthetic-never-live-directory-secret".into(),
    }
}
#[test]
fn encryption_is_randomized_and_survives_key_reload() {
    let root = tempfile::tempdir().unwrap();
    let key = Key::initialize(root.path()).unwrap();
    let metadata = meta(&key);
    let first = key.seal(metadata.clone(), &credential()).unwrap();
    let second = key.seal(metadata, &credential()).unwrap();
    assert_ne!(first.sealed, second.sealed);
    assert!(
        !first
            .encode()
            .unwrap()
            .contains("synthetic-never-live-directory-secret")
    );
    let reloaded = Key::load(root.path()).unwrap();
    assert_eq!(key.id(), reloaded.id());
    let Credential::EntraApplication {
        client_id,
        client_secret,
    } = reloaded.open(&first, 1500).unwrap()
    else {
        panic!("Expected synthetic application credential");
    };
    assert_eq!(client_id, "22222222-2222-4222-8222-222222222222");
    assert_eq!(client_secret, "synthetic-never-live-directory-secret");
    assert_eq!(key.id(), Key::initialize(root.path()).unwrap().id());
    assert_eq!(
        fs::read_dir(root.path().join("directory-vault"))
            .unwrap()
            .count(),
        1
    );
}
#[test]
fn every_authority_and_lease_field_is_authenticated() {
    let key = Key([7; 32]);
    let original = key.seal(meta(&key), &credential()).unwrap();
    let mut variants = Vec::new();
    macro_rules! change {
        ($field:ident, $value:expr) => {{
            let mut r = original.clone();
            r.metadata.$field = $value;
            variants.push(r);
        }};
    }
    change!(owner, "other-admin".into());
    change!(owner_version, 1);
    change!(generation, uuid::Uuid::new_v4().to_string());
    change!(supersedes, Some(uuid::Uuid::new_v4().to_string()));
    change!(authority, "postgres:other".into());
    change!(created, 1001);
    change!(expires, 2001);
    let mut source = original.metadata.source.clone();
    source.id = "other-source".into();
    change!(source, source);
    let mut source = original.metadata.source.clone();
    source.authority = "33333333-3333-4333-8333-333333333333".into();
    change!(source, source);
    let mut source = original.metadata.source.clone();
    source.scopes.insert("other.test".into());
    change!(source, source);
    let mut corrupt = original.clone();
    corrupt.sealed.as_mut().unwrap()[15] ^= 1;
    variants.push(corrupt);
    for r in variants {
        assert!(key.open(&r, 1500).is_err());
    }
    assert!(Key([8; 32]).open(&original, 1500).is_err());
}
#[test]
fn credential_limits_provider_expiry_and_revocation_are_enforced() {
    let key = Key([7; 32]);
    let metadata = meta(&key);
    let record = key.seal(metadata.clone(), &credential()).unwrap();
    assert!(key.open(&record, 999).is_err());
    assert!(key.open(&record, 2000).is_err());
    let revoked = connections::revoke(record.clone(), &metadata.generation, 1500).unwrap();
    assert!(key.open(&revoked, 1501).is_err());
    assert!(revoked.sealed.is_none());
    assert!(
        key.seal(
            metadata.clone(),
            &Credential::GoogleAccessToken {
                access_token: "synthetic".into()
            }
        )
        .is_err()
    );
    let mut too_long = metadata.clone();
    too_long.expires = too_long.created + 90 * 86400 + 1;
    assert!(key.seal(too_long, &credential()).is_err());
    for (provider, authority, credential) in [
        (
            Provider::Google,
            "C01234567",
            Credential::GoogleAccessToken {
                access_token: "synthetic-token".into(),
            },
        ),
        (
            Provider::Okta,
            "example.okta.com",
            Credential::OktaAccessToken {
                access_token: "synthetic-token".into(),
            },
        ),
    ] {
        let mut m = metadata.clone();
        m.source.provider = provider;
        m.source.authority = authority.into();
        m.expires = m.created + 3600;
        let r = key.seal(m.clone(), &credential).unwrap();
        assert!(key.open(&r, 1500).is_ok());
        m.expires += 1;
        assert!(key.seal(m, &credential).is_err());
    }
    let invalid = Credential::EntraApplication {
        client_id: "22222222-2222-4222-8222-222222222222".into(),
        client_secret: "SECRET\nINJECTION".into(),
    };
    let error = key.seal(metadata, &invalid).err().unwrap().to_string();
    assert!(!error.contains("SECRET"));
}
#[test]
fn malformed_records_and_status_never_expose_credential_material() {
    let key = Key([7; 32]);
    let r = key.seal(meta(&key), &credential()).unwrap();
    assert!(Record::decode(&r.encode().unwrap(), "other", "sqlite").is_err());
    let view = serde_json::to_value(r.view(1500, true)).unwrap();
    assert!(view.get("sealed").is_none());
    assert!(view.get("credential").is_none());
    assert_eq!(r.view(999, true).status, "not_yet_valid");
    assert_eq!(r.view(2000, true).status, "expired");
    assert_eq!(r.view(1500, false).status, "authorization_changed");
    let mut value = serde_json::to_value(&r).unwrap();
    value["unexpected"] = "value".into();
    assert!(Record::decode(&value.to_string(), "synthetic", "sqlite").is_err());
    let mut bad = r;
    bad.sealed = Some(vec![0; 12]);
    assert!(key.open(&bad, 1500).is_err());
}
#[test]
fn key_loss_is_never_repaired_implicitly_with_existing_connections() {
    let root = tempfile::tempdir().unwrap();
    assert!(Key::load(root.path()).is_err());
    assert!(!root.path().join("directory-vault").exists());
    assert!(Key::load_or_initialize(root.path(), true).is_err());
    let key = Key::load_or_initialize(root.path(), false).unwrap();
    let path = root.path().join("directory-vault/key");
    fs::remove_file(&path).unwrap();
    assert!(Key::load_or_initialize(root.path(), true).is_err());
    assert!(!path.exists());
    let replacement = Key::initialize(root.path()).unwrap();
    assert_ne!(key.id(), replacement.id());
    fs::write(&path, b"short").unwrap();
    assert!(Key::load_or_initialize(root.path(), false).is_err());
    assert_eq!(fs::read(&path).unwrap(), b"short");
}
#[test]
fn vault_rejects_shared_permissions_symlinks_and_multiple_links() {
    let root = tempfile::tempdir().unwrap();
    Key::initialize(root.path()).unwrap();
    let dir = root.path().join("directory-vault");
    let path = dir.join("key");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Key::load(root.path()).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(Key::load(root.path()).is_err());
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    fs::hard_link(&path, dir.join("copy")).unwrap();
    assert!(Key::load(root.path()).is_err());
    fs::remove_file(dir.join("copy")).unwrap();
    assert!(Key::load(root.path()).is_ok());
    fs::rename(&path, dir.join("real")).unwrap();
    std::os::unix::fs::symlink("real", &path).unwrap();
    assert!(Key::load(root.path()).is_err());
    assert!(Key::load_or_initialize(root.path(), false).is_err());
    let parent = tempfile::tempdir().unwrap();
    let link = parent.path().join("root");
    std::os::unix::fs::symlink(root.path(), &link).unwrap();
    assert!(Key::initialize(&link).is_err());
}
