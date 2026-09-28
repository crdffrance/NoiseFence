//! Original-source export with process locks and a continuous write reservation.
use super::{SourceLocks, SpoolSnapshot, installation, offline::open_source};
use crate::{
    central::{outbox, selection::Selection},
    cluster::activation::Journal,
    config::Config,
};
use anyhow::{Context, Result, ensure};
use rusqlite::{
    Connection, OpenFlags, Transaction, TransactionBehavior,
    backup::{Backup, StepResult},
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::Read,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

#[derive(Serialize)]
pub struct Receipt {
    pub journal: outbox::Status,
    pub sha256: String,
    pub bytes: u64,
}

/// Only available inside `with_source`. No raw connection is exposed, so the
/// caller cannot release its write reservation before making a selection.
pub struct FrozenSource<'a> {
    tx: Option<Transaction<'a>>,
    guard: &'a SourceLocks,
    config: &'a Config,
    file_identity: (u64, u64),
    export: Export,
    pub receipt: Receipt,
    existing: Option<Selection>,
}
impl FrozenSource<'_> {
    /// Private SQLite metadata export; contains credentials and must remain on
    /// authorized hosts. No raw message body directory is copied.
    pub fn export_path(&self) -> &Path {
        &self.export.path
    }

    pub fn existing_selection(&self) -> Option<&Selection> {
        self.existing.as_ref()
    }

    pub fn verify(&self) -> Result<()> {
        self.guard.verify()?;
        let info = std::fs::symlink_metadata(self.config.data_dir.join("state.sqlite3"))?;
        ensure!(
            info.is_file()
                && !info.file_type().is_symlink()
                && info.nlink() == 1
                && (info.dev(), info.ino()) == self.file_identity,
            "Frozen source database was replaced"
        );
        Ok(())
    }

    /// Revalidate installed artifacts and commit the selected authority while
    /// retaining process locks until the enclosing callback returns. Call only
    /// inside the verified PostgreSQL activation transaction. A committed
    /// selection is never rolled back to the legacy backend on a later error.
    pub fn select(&mut self, authority: &Journal, proposed: &Selection) -> Result<Selection> {
        self.verify()?;
        let tx = self
            .tx
            .as_ref()
            .context("Source selection was already committed")?;
        let actual = match &self.existing {
            Some(existing) => installation::selected(tx, self.config, authority, existing)?,
            None => installation::candidate(tx, self.config, authority, &proposed.database)?,
        };
        ensure!(
            &actual == proposed,
            "Selection differs from the frozen installation"
        );
        ensure!(
            outbox::status(tx)?.sequence == self.receipt.journal.sequence
                && actual.node == self.receipt.journal.identity,
            "Frozen journal changed"
        );
        actual.install(tx)?;
        self.tx
            .take()
            .context("Frozen transaction missing")?
            .commit()?;
        self.verify()?;
        Ok(actual)
    }
}

/// Stop service/CLI writers first. Prepare the ORIGINAL journal durably, then
/// hold a SQLite write reservation through export and the caller's protocol.
/// The callback must have an external lifetime bound (e.g. a supervised session).
/// On failure before selection, only prepared journal generations persist.
/// Temporary exports are removed on return; process death requires operator
/// cleanup of the private `management-export-*` directory. Never start services
/// automatically after a partial selection.
pub fn with_source<T>(
    config: &Config,
    export_parent: &Path,
    run: impl FnOnce(&mut FrozenSource<'_>) -> Result<T>,
) -> Result<T> {
    hold(config, export_parent, None, true, run)
}

/// Resume only the exact durable local selection. Never reseeds its journal.
pub fn with_selected_source<T>(
    config: &Config,
    export_parent: &Path,
    selected: &Selection,
    run: impl FnOnce(&mut FrozenSource<'_>) -> Result<T>,
) -> Result<T> {
    selected.validate()?;
    hold(config, export_parent, Some(selected), false, run)
}

/// Reacquire an unselected peer after an interrupted multi-source cutover.
/// Its already exported journal must remain identical to the inactive import.
pub fn with_seeded_source<T>(
    config: &Config,
    export_parent: &Path,
    run: impl FnOnce(&mut FrozenSource<'_>) -> Result<T>,
) -> Result<T> {
    hold(config, export_parent, None, false, run)
}

fn hold<T>(
    config: &Config,
    export_parent: &Path,
    existing: Option<&Selection>,
    reseed: bool,
    run: impl FnOnce(&mut FrozenSource<'_>) -> Result<T>,
) -> Result<T> {
    Export::validate_parent(export_parent)?;
    let mut source = open_source(config, existing)?;
    if reseed {
        outbox::initialize(&mut source.db, &source.source.node_id)?;
        let mut tx = source
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        SpoolSnapshot::capture(&mut tx)?;
        tx.commit()?;
    }
    source.verify()?;
    let tx = source
        .db
        .transaction_with_behavior(TransactionBehavior::Immediate)?;
    // Detect missing journal coverage if a legacy CLI wrote in the small gap
    // between durable preparation and the final reservation.
    match existing {
        Some(selected) => SpoolSnapshot::read_selected(&tx, selected)?,
        None => SpoolSnapshot::read_seeded(&tx)?,
    };
    let journal = outbox::status(&tx)?;
    let export = Export::copy(&config.data_dir.join("state.sqlite3"), export_parent)?;
    let (sha256, bytes) = export.digest()?;
    let mut frozen = FrozenSource {
        tx: Some(tx),
        guard: &source.guard,
        config,
        file_identity: source.file_identity,
        export,
        existing: existing.cloned(),
        receipt: Receipt {
            journal,
            sha256,
            bytes,
        },
    };
    frozen.verify()?;
    let result = run(&mut frozen)?;
    frozen.verify()?;
    Ok(result)
}

struct Export {
    path: PathBuf,
    root: PathBuf,
}
impl Export {
    fn validate_parent(parent: &Path) -> Result<()> {
        let info = std::fs::symlink_metadata(parent)?;
        // SAFETY: geteuid only reads process identity.
        ensure!(
            parent.is_absolute()
                && parent.canonicalize()? == parent
                && info.is_dir()
                && !info.file_type().is_symlink()
                && info.uid() == unsafe { libc::geteuid() }
                && info.mode() & 0o077 == 0,
            "Export parent must be a private physical directory owned by this user"
        );
        Ok(())
    }
    fn copy(source: &Path, parent: &Path) -> Result<Self> {
        Self::validate_parent(parent)?;
        let root = parent.join(format!("management-export-{}", uuid::Uuid::new_v4()));
        std::fs::DirBuilder::new().mode(0o700).create(&root)?;
        let export = Self {
            path: root.join("state.sqlite3"),
            root,
        };
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&export.path)?;
        let mut dest = Connection::open_with_flags(
            &export.path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        dest.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;")?;
        // A distinct read-only connection sees the committed preparation while
        // the original connection excludes writers. Backing up the connection
        // holding the write transaction itself would return SQLITE_LOCKED.
        let reader = Connection::open_with_flags(
            source,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        let deadline = Instant::now() + Duration::from_secs(120);
        {
            let backup = Backup::new(&reader, &mut dest)?;
            loop {
                ensure!(
                    Instant::now() < deadline,
                    "Frozen export exceeded its deadline"
                );
                match backup.step(256)? {
                    StepResult::Done => break,
                    StepResult::More => {}
                    _ => anyhow::bail!("Frozen export could not acquire its read snapshot"),
                }
            }
        }
        drop(dest);
        file.sync_all()?;
        File::open(&export.root)?.sync_all()?;
        File::open(parent)?.sync_all()?;
        Ok(export)
    }
    fn digest(&self) -> Result<(String, u64)> {
        let mut file = File::open(&self.path)?;
        let mut hasher = Sha256::new();
        let mut block = [0u8; 65536];
        let mut bytes = 0;
        loop {
            let n = file.read(&mut block)?;
            if n == 0 {
                break;
            }
            hasher.update(&block[..n]);
            bytes += n as u64;
        }
        Ok((format!("{:x}", hasher.finalize()), bytes))
    }
}
impl Drop for Export {
    fn drop(&mut self) {
        for suffix in ["", "-journal", "-wal", "-shm"] {
            let _ = std::fs::remove_file(self.root.join(format!("state.sqlite3{suffix}")));
        }
        let _ = std::fs::remove_dir(&self.root);
    }
}
