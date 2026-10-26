use super::*;
use std::os::unix::fs::symlink;
#[test]
fn durable_private_key_is_shared_explicitly_and_never_exported() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    let key = Key::install(first.path(), None).unwrap();
    let again = Key::install(first.path(), None).unwrap();
    assert_eq!(key.id(), again.id());
    let peer = Key::install(
        second.path(),
        Some(&first.path().join("contact-memory/key")),
    )
    .unwrap();
    assert_eq!(key.id(), peer.id());
    assert_eq!(
        key.token("contact", &["a", "b"]),
        peer.token("contact", &["a", "b"])
    );
    assert_ne!(
        key.token("contact", &["ab", "c"]),
        key.token("contact", &["a", "bc"])
    );
    assert_ne!(
        key.token("reply", &["a", "b"]),
        key.token("contact", &["a", "b"])
    );
    assert_ne!(
        key.token("contact", &["a", "b"]),
        crate::message::digest(b"a:b")
    );
    assert!(Key::matching(first.path(), Some(key.id())).is_ok());
    assert!(Key::matching(first.path(), Some(&"0".repeat(64))).is_err());
    assert!(Key::matching(first.path(), None).is_err());
    assert_eq!(
        fs::read_dir(first.path().join("contact-memory"))
            .unwrap()
            .count(),
        2
    );
}
#[test]
fn key_loss_requires_exact_restore_and_never_creates_another_epoch() {
    let root = tempfile::tempdir().unwrap();
    let backup = tempfile::tempdir().unwrap();
    let foreign = tempfile::tempdir().unwrap();
    assert!(Key::load(root.path()).is_err());
    assert!(!root.path().join("contact-memory").exists());
    let original = Key::install(root.path(), None).unwrap();
    Key::install(backup.path(), Some(&root.path().join("contact-memory/key"))).unwrap();
    Key::install(foreign.path(), None).unwrap();
    assert!(
        Key::install(
            root.path(),
            Some(&foreign.path().join("contact-memory/key"))
        )
        .is_err()
    );
    assert_eq!(Key::load(root.path()).unwrap().id(), original.id());
    fs::remove_file(root.path().join("contact-memory/key")).unwrap();
    assert!(Key::install(root.path(), None).is_err());
    assert!(!root.path().join("contact-memory/key").exists());
    assert!(
        Key::install(
            root.path(),
            Some(&foreign.path().join("contact-memory/key"))
        )
        .is_err()
    );
    assert!(!root.path().join("contact-memory/key").exists());
    let restored =
        Key::install(root.path(), Some(&backup.path().join("contact-memory/key"))).unwrap();
    assert_eq!(restored.id(), original.id());
    assert_eq!(
        restored.token("contact", &["sender"]),
        original.token("contact", &["sender"])
    );
}
#[test]
fn permissions_links_fifos_and_corruption_are_refused() {
    let root = tempfile::tempdir().unwrap();
    Key::install(root.path(), None).unwrap();
    let dir = root.path().join("contact-memory");
    let path = dir.join("key");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Key::load(root.path()).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let alias = dir.join("alias");
    fs::hard_link(&path, &alias).unwrap();
    assert!(Key::load(root.path()).is_err());
    fs::remove_file(&alias).unwrap();
    fs::rename(&path, &alias).unwrap();
    symlink(&alias, &path).unwrap();
    assert!(Key::load(root.path()).is_err());
    fs::remove_file(&path).unwrap();
    fs::rename(&alias, &path).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(Key::load(root.path()).is_err());
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(&path, [1u8; 32]).unwrap();
    assert!(Key::load(root.path()).is_err());
    assert!(Key::install(root.path(), None).is_err());
    fs::remove_file(&path).unwrap();
    let name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: null-terminated pathname, creating a disposable test-only FIFO.
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    assert!(Key::load(root.path()).is_err());
}
