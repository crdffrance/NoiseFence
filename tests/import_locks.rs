use noisefence::{central::import::SourceLocks, store::Store};
use std::{
    fs::OpenOptions,
    os::{fd::AsRawFd, unix::fs::symlink},
};
#[test]
fn offline_locks_exclude_daemon_and_worker_and_release_after_errors() {
    let root = tempfile::tempdir().unwrap();
    let store = Store::open(root.path()).unwrap();
    let daemon = store.daemon_lock().unwrap();
    assert!(SourceLocks::acquire(root.path()).is_err());
    drop(daemon);
    let held = SourceLocks::acquire(root.path()).unwrap();
    held.verify().unwrap();
    assert!(store.daemon_lock().is_err());
    let worker = OpenOptions::new()
        .read(true)
        .write(true)
        .open(root.path().join("calibration/worker.lock"))
        .unwrap();
    // SAFETY: this test owns the live file descriptors passed to flock.
    assert_ne!(
        unsafe { libc::flock(worker.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    drop(held);
    assert_eq!(
        unsafe { libc::flock(worker.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    assert!(SourceLocks::acquire(root.path()).is_err());
    assert!(
        store.daemon_lock().is_ok(),
        "partial acquisition released daemon lock"
    );
    drop(worker);
    assert!(SourceLocks::acquire(root.path()).is_ok());
}
#[test]
fn locks_reject_symlinks_and_detect_path_replacement() {
    let root = tempfile::tempdir().unwrap();
    Store::open(root.path()).unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let original = elsewhere.path().join("untouched");
    std::fs::write(&original, b"preserve").unwrap();
    symlink(&original, root.path().join("daemon.lock")).unwrap();
    assert!(SourceLocks::acquire(root.path()).is_err());
    assert_eq!(std::fs::read(&original).unwrap(), b"preserve");
    std::fs::remove_file(root.path().join("daemon.lock")).unwrap();
    let held = SourceLocks::acquire(root.path()).unwrap();
    std::fs::rename(
        root.path().join("daemon.lock"),
        root.path().join("old.lock"),
    )
    .unwrap();
    std::fs::write(root.path().join("daemon.lock"), b"").unwrap();
    assert!(held.verify().is_err());
    drop(held);
    std::fs::remove_file(root.path().join("calibration/worker.lock")).unwrap();
    std::fs::remove_dir(root.path().join("calibration")).unwrap();
    symlink(elsewhere.path(), root.path().join("calibration")).unwrap();
    assert!(SourceLocks::acquire(root.path()).is_err());
    assert!(!elsewhere.path().join("worker.lock").exists());
}

#[test]
fn retained_guard_detects_calibration_directory_substitution() {
    let root = tempfile::tempdir().unwrap();
    Store::open(root.path()).unwrap();
    let held = SourceLocks::acquire(root.path()).unwrap();
    std::fs::rename(
        root.path().join("calibration"),
        root.path().join("previous-calibration"),
    )
    .unwrap();
    symlink(
        root.path().join("previous-calibration"),
        root.path().join("calibration"),
    )
    .unwrap();
    assert!(held.verify().is_err());
}
