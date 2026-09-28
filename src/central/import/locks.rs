//! Process locks held by the offline importer for the complete cutover window.
use anyhow::{Context, Result, ensure};
use std::{
    fs::{File, OpenOptions},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
};

pub struct SourceLocks {
    root: PathBuf,
    identity: (u64, u64),
    calibration_identity: (u64, u64),
    _files: Vec<File>,
}
impl SourceLocks {
    /// Run as the installation owner. File locks are also respected by the
    /// daemon and Python calibration worker; an import must acquire both.
    /// This does not stop services or acquire locks on a remote host.
    pub fn acquire(root: &Path) -> Result<Self> {
        ensure!(root.is_absolute(), "Offline source path must be absolute");
        let metadata = std::fs::symlink_metadata(root)?;
        // SAFETY: geteuid only reads the calling process's effective identity.
        let uid = unsafe { libc::geteuid() };
        ensure!(
            metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == uid
                && metadata.permissions().mode() & 0o022 == 0,
            "Run offline import as the owner of a non-writable-by-others source directory"
        );
        let daemon = lock(&root.join("daemon.lock"), uid)?;
        let calibration = root.join("calibration");
        match std::fs::create_dir(&calibration) {
            Ok(()) => {
                std::fs::set_permissions(&calibration, std::fs::Permissions::from_mode(0o700))?
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
        let learning = std::fs::symlink_metadata(&calibration)?;
        ensure!(
            learning.is_dir()
                && !learning.file_type().is_symlink()
                && learning.uid() == uid
                && learning.permissions().mode() & 0o022 == 0,
            "Unsafe calibration lock directory"
        );
        let worker = lock(&calibration.join("worker.lock"), uid)?;
        let held = Self {
            root: root.into(),
            identity: (metadata.dev(), metadata.ino()),
            calibration_identity: (learning.dev(), learning.ino()),
            _files: vec![daemon, worker],
        };
        held.verify()?;
        Ok(held)
    }
    /// Recheck before copying and selecting the source backend. Keeping this
    /// object alive retains both locks, including while waiting for PostgreSQL.
    pub fn verify(&self) -> Result<()> {
        let metadata = std::fs::symlink_metadata(&self.root)?;
        ensure!(
            metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && (metadata.dev(), metadata.ino()) == self.identity,
            "Offline source directory was replaced"
        );
        let calibration = std::fs::symlink_metadata(self.root.join("calibration"))?;
        ensure!(
            calibration.is_dir()
                && !calibration.file_type().is_symlink()
                && (calibration.dev(), calibration.ino()) == self.calibration_identity,
            "Offline calibration directory was replaced"
        );
        for (path, file) in [
            self.root.join("daemon.lock"),
            self.root.join("calibration/worker.lock"),
        ]
        .iter()
        .zip(&self._files)
        {
            let current = std::fs::symlink_metadata(path)?;
            let locked = file.metadata()?;
            ensure!(
                current.is_file()
                    && !current.file_type().is_symlink()
                    && (current.dev(), current.ino()) == (locked.dev(), locked.ino()),
                "Offline source lock file was replaced"
            );
        }
        Ok(())
    }

    /// Bind a reused guard to the exact source it protects.
    pub(crate) fn verify_for(&self, root: &Path) -> Result<()> {
        ensure!(self.root == root, "Offline lock belongs to another source");
        self.verify()
    }
}
fn lock(path: &Path, uid: u32) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .context("Cannot open offline source lock")?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.nlink() == 1
            && metadata.uid() == uid
            && metadata.permissions().mode() & 0o022 == 0,
        "Unsafe offline source lock"
    );
    // SAFETY: the file owns this descriptor for the lifetime of the guard.
    ensure!(
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "Stop the source daemon and calibration worker before importing"
    );
    Ok(file)
}
