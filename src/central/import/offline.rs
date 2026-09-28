//! Operator entry point for an inactive management copy from local offline spools.
use super::{
    AccountsSnapshot, DeliveryIdentities, PolicySnapshot, PreparedImport, QualitySnapshot,
    ReconciledSpools, SourceLocks, SpoolSnapshot, StagedImport,
};
use crate::{
    central::{Central, Settings, outbox},
    cluster::Role,
};
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OpenFlags, TransactionBehavior};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::OpenOptions,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub database: Settings,
    pub sources: Vec<Source>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub node_id: String,
    pub role: Role,
    pub data_dir: PathBuf,
    /// Required by installation preflight, optional for a copy-only rehearsal.
    pub config: Option<PathBuf>,
}
impl Plan {
    pub fn read(path: &Path) -> Result<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        let info = file.metadata()?;
        ensure!(
            info.is_file() && info.len() <= 65536,
            "Import plan must be a regular file of at most 64 KiB"
        );
        let mut raw = String::new();
        (&mut file).take(65537).read_to_string(&mut raw)?;
        ensure!(raw.len() <= 65536, "Import plan exceeds bounds");
        let plan: Self = toml::from_str(&raw)?;
        plan.validate()?;
        Ok(plan)
    }
    fn validate(&self) -> Result<()> {
        self.database.validate()?;
        ensure!(
            (1..=64).contains(&self.sources.len())
                && self
                    .sources
                    .iter()
                    .filter(|s| s.role == Role::Coordinator)
                    .count()
                    == 1,
            "Import requires one coordinator and at most 63 workers"
        );
        let mut nodes = BTreeSet::new();
        let mut paths = BTreeSet::new();
        for source in &self.sources {
            ensure!(
                crate::cluster::valid_id(&source.node_id)
                    && source.data_dir.is_absolute()
                    && nodes.insert(&source.node_id)
                    && paths.insert(&source.data_dir),
                "Invalid or duplicate import source"
            );
        }
        Ok(())
    }
}
pub(super) struct LockedSource {
    pub(super) source: Source,
    pub(super) guard: SourceLocks,
    pub(super) db: Connection,
    pub(super) file_identity: (u64, u64),
}
impl LockedSource {
    pub(super) fn verify(&self) -> Result<()> {
        self.guard.verify()?;
        let file = std::fs::symlink_metadata(self.source.data_dir.join("state.sqlite3"))?;
        ensure!(
            file.is_file()
                && !file.file_type().is_symlink()
                && file.nlink() == 1
                && (file.dev(), file.ino()) == self.file_identity,
            "Offline database file was replaced"
        );
        Ok(())
    }
}
struct Capture {
    sources: Vec<LockedSource>,
    prepared: PreparedImport,
}
fn capture(
    sources: Vec<Source>,
    reseed: bool,
    binding: Option<&crate::central::binding::Binding>,
) -> Result<Capture> {
    // Acquire ALL process locks before initializing even one source journal.
    let guards = sources
        .iter()
        .map(|s| SourceLocks::acquire(&s.data_dir))
        .collect::<Result<Vec<_>>>()?;
    let mut locked = Vec::new();
    let mut total_rows = 0i64;
    let mut total_bytes = 0i64;
    let mut files = BTreeSet::new();
    for (source, guard) in sources.into_iter().zip(guards) {
        let path = source.data_dir.join("state.sqlite3");
        let info = std::fs::symlink_metadata(&path)?;
        ensure!(
            info.is_file()
                && !info.file_type().is_symlink()
                && info.nlink() == 1
                && files.insert((info.dev(), info.ino())),
            "Unsafe or duplicate source database"
        );
        let db = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        db.busy_timeout(std::time::Duration::from_secs(2))?;
        db.execute_batch("PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL;")?;
        let selected = crate::central::selection::Selection::read(&db)?;
        let version = db.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))?;
        match selected {
            Some(ref selected) => {
                ensure!(
                    !reseed && version == 7 && binding == Some(&selected.database),
                    "Recovery source belongs to another management authority"
                );
                selected.verify_key(&source.data_dir)?;
            }
            None => ensure!(
                version == 6,
                "Import requires existing coordinated format-six storage"
            ),
        }
        let node: String = db.query_row(
            "SELECT value FROM cluster_state WHERE key='node_id'",
            [],
            |r| r.get(0),
        )?;
        let role: String = db.query_row(
            "SELECT value FROM cluster_state WHERE key='role'",
            [],
            |r| r.get(0),
        )?;
        let expected = match source.role {
            Role::Coordinator => "coordinator",
            Role::Worker => "worker",
        };
        ensure!(
            node == source.node_id && role == expected,
            "Source identity differs from import plan"
        );
        let (rows,bytes):(i64,i64)=db.query_row("SELECT (SELECT count(*) FROM messages)+(SELECT count(*) FROM delivery_attempts),coalesce((SELECT sum(length(CAST(scan AS BLOB))) FROM messages),0)+coalesce((SELECT sum(length(CAST(trace AS BLOB))) FROM delivery_attempts),0)",[],|r|Ok((r.get(0)?,r.get(1)?)))?;
        total_rows = total_rows
            .checked_add(rows)
            .context("Source row count overflow")?;
        total_bytes = total_bytes
            .checked_add(bytes)
            .context("Source size overflow")?;
        ensure!(
            total_rows <= 200_000 && total_bytes <= 512 * 1024 * 1024,
            "Combined offline sources exceed the in-memory import limits"
        );
        let item = LockedSource {
            source,
            guard,
            db,
            file_identity: (info.dev(), info.ino()),
        };
        item.verify()?;
        locked.push(item);
    }
    let coordinator = locked
        .iter()
        .position(|s| s.source.role == Role::Coordinator)
        .context("Coordinator missing")?;
    // Read-only: missing encryption material must fail BEFORE source mutations.
    let key = crate::mfa::Key::read_existing(&locked[coordinator].source.data_dir)?;
    let mut epochs = BTreeMap::new();
    for source in &mut locked {
        let identity = if reseed {
            outbox::initialize(&mut source.db, &source.source.node_id)?
        } else {
            outbox::identity(&source.db)?
        };
        ensure!(
            identity.node == source.source.node_id,
            "Source journal identity differs from plan"
        );
        epochs.insert(identity.node, identity.epoch);
    }
    // Simultaneous SQLite write reservations also exclude ordinary local CLI
    // writers that do not use daemon.lock while the snapshots are captured.
    let mut transactions = locked
        .iter_mut()
        .map(|s| {
            s.db.transaction_with_behavior(TransactionBehavior::Immediate)
        })
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let policy = PolicySnapshot::capture(&transactions[coordinator], epochs)?;
    for (index, tx) in transactions.iter().enumerate() {
        if index != coordinator
            && let Some(local) = crate::cluster::activation::participant::Local::read(tx)?
        {
            ensure!(
                local.authority().owner() == policy.journal.owner(),
                "Worker cached policy belongs to another coordinator"
            );
        }
    }
    let accounts = AccountsSnapshot::capture(&transactions[coordinator], Some(&key))?;
    let deliveries = DeliveryIdentities::capture(&transactions[coordinator])?;
    let quality = QualitySnapshot::capture(&transactions[coordinator])?;
    let mut spools = Vec::new();
    for tx in &mut transactions {
        spools.push(if reseed {
            SpoolSnapshot::capture(tx)?
        } else if let Some(selected) = crate::central::selection::Selection::read(tx)? {
            SpoolSnapshot::read_selected(tx, &selected)?
        } else {
            SpoolSnapshot::read_seeded(tx)?
        });
    }
    let prepared = PreparedImport::new(
        accounts,
        deliveries,
        quality,
        policy,
        ReconciledSpools::verify(spools)?,
    )?;
    for tx in transactions {
        tx.commit()?;
    }
    for source in &locked {
        source.verify()?;
    }
    Ok(Capture {
        sources: locked,
        prepared,
    })
}
/// Copies into an unused database. The returned receipt stays inactive. This
/// local command neither acquires remote locks nor installs backend selection.
/// On clones, initialized epochs belong to those clones, not to live MX spools.
pub async fn stage(plan: Plan) -> Result<StagedImport> {
    stage_with_reseed(plan, true).await
}

/// Import a previously prepared, complete source journal unchanged. The caller
/// must freeze the original sources before exporting them; this flag alone does
/// not prove that local copies still match a live or remote source.
pub async fn stage_seeded(plan: Plan) -> Result<StagedImport> {
    stage_with_reseed(plan, false).await
}

async fn stage_with_reseed(plan: Plan, reseed: bool) -> Result<StagedImport> {
    plan.validate()?;
    let central = Central::new(&plan.database)?;
    let Capture { sources, prepared } =
        tokio::task::spawn_blocking(move || capture(plan.sources, reseed, None))
            .await
            .context("Offline capture task failed")??;
    central.migrate().await?;
    let receipt = central.stage_import(prepared).await?;
    for source in &sources {
        source.verify()?;
    }
    // Guards/connections live through the final receipt. Dropping them releases
    // only the local locks; no mail service is started and no config is changed.
    Ok(receipt)
}

/// Reacquires local locks and compares every captured management source with
/// the inactive import receipt, then checks destination row parity. This does
/// not validate artifacts or activate it.
pub async fn verify_sources(plan: Plan, binding: crate::central::binding::Binding) -> Result<()> {
    plan.validate()?;
    binding.validate()?;
    let central = Central::new(&plan.database)?;
    let check_binding = binding.clone();
    let Capture { sources, prepared } =
        tokio::task::spawn_blocking(move || capture(plan.sources, false, Some(&check_binding)))
            .await
            .context("Offline verification task failed")??;
    central.verify_import_sources(&binding, &prepared).await?;
    for source in &sources {
        source.verify()?;
    }
    Ok(())
}

/// Check source/destination parity and the installed runtime on every supplied
/// local source. Returned selections are proposals only; no backend is changed.
pub async fn prepare_selections(
    plan: Plan,
    binding: crate::central::binding::Binding,
) -> Result<Vec<crate::central::selection::Selection>> {
    plan.validate()?;
    binding.validate()?;
    let central = Central::new(&plan.database)?;
    let check_binding = binding.clone();
    let (capture, selections) =
        tokio::task::spawn_blocking(move || installation_capture(plan.sources, &check_binding))
            .await
            .context("Installation preflight task failed")??;
    central
        .verify_import_sources(&binding, &capture.prepared)
        .await?;
    for source in &capture.sources {
        source.verify()?;
    }
    Ok(selections)
}

fn installation_capture(
    sources: Vec<Source>,
    binding: &crate::central::binding::Binding,
) -> Result<(Capture, Vec<crate::central::selection::Selection>)> {
    let mut capture = capture(sources, false, Some(binding))?;
    let mut selections = Vec::new();
    for source in &mut capture.sources {
        let path = source
            .source
            .config
            .as_ref()
            .context("Every source needs an installation config path for preflight")?;
        ensure!(
            path.is_absolute(),
            "Installation config path must be absolute"
        );
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        let info = file.metadata()?;
        ensure!(
            info.is_file() && info.len() <= 1024 * 1024,
            "Installation config must be a regular file of at most 1 MiB"
        );
        let mut raw = String::new();
        (&mut file).take(1024 * 1024 + 1).read_to_string(&mut raw)?;
        ensure!(
            raw.len() <= 1024 * 1024,
            "Installation config exceeds bounds"
        );
        let config: crate::config::Config =
            toml::from_str(&raw).map_err(|_| anyhow::anyhow!("Invalid installation config"))?;
        ensure!(
            config.data_dir.canonicalize()? == source.source.data_dir.canonicalize()?,
            "Installation config names another data directory"
        );
        let tx = source
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        selections.push(match crate::central::selection::Selection::read(&tx)? {
            Some(selected) => super::installation::selected(
                &tx,
                &config,
                &capture.prepared.policy.journal,
                &selected,
            )?,
            None => super::installation::candidate(
                &tx,
                &config,
                &capture.prepared.policy.journal,
                binding,
            )?,
        });
        tx.rollback()?;
        source.verify()?;
    }
    Ok((capture, selections))
}

/// Activate an imported authority through a local supervisor that still holds
/// all original source sessions. Import sources here are verified private copies.
/// The supervisor must commit each original selection inside this barrier and
/// retain the source sessions until this function returns successfully.
pub async fn activate(
    plan: Plan,
    binding: crate::central::binding::Binding,
    commit_socket: &Path,
) -> Result<()> {
    plan.validate()?;
    binding.validate()?;
    let central = Central::new(&plan.database)?;
    let check_binding = binding.clone();
    let (capture, selections) =
        tokio::task::spawn_blocking(move || installation_capture(plan.sources, &check_binding))
            .await
            .context("Activation source preflight task failed")??;
    let mut channel = super::session::CommitChannel::connect(commit_socket).await?;
    central
        .activate_import(&binding, &capture.prepared, &selections, || {
            for source in &capture.sources {
                source.verify()?;
            }
            channel.commit(&binding, &capture.prepared.policy.journal, &selections)
        })
        .await?;
    for source in &capture.sources {
        source.verify()?;
    }
    Ok(())
}

/// Establish the real local spool epoch before an offline export. Does not
/// select PostgreSQL or create a replacement spool. Stop local writers first.
pub fn initialize_source(config: &crate::config::Config) -> Result<outbox::Identity> {
    let mut source = open_original(config)?;
    let identity = outbox::initialize(&mut source.db, &source.source.node_id)?;
    source.verify()?;
    Ok(identity)
}

pub(super) fn open_original(config: &crate::config::Config) -> Result<LockedSource> {
    open_source(config, None)
}

pub(super) fn open_source(
    config: &crate::config::Config,
    selected: Option<&crate::central::selection::Selection>,
) -> Result<LockedSource> {
    config.validate()?;
    ensure!(
        selected.is_some() || config.management.is_none(),
        "Source already configures central management"
    );
    let cluster = config
        .cluster
        .as_ref()
        .context("Source needs an explicit cluster identity")?;
    let guard = SourceLocks::acquire(&config.data_dir)?;
    let path = config.data_dir.join("state.sqlite3");
    let info = std::fs::symlink_metadata(&path)?;
    ensure!(
        info.is_file() && !info.file_type().is_symlink() && info.nlink() == 1,
        "Unsafe source database"
    );
    let db = Connection::open_with_flags(
        &path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    db.busy_timeout(std::time::Duration::from_secs(2))?;
    db.execute_batch("PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL;")?;
    ensure!(
        db.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))?
            == if selected.is_some() { 7 } else { 6 },
        "Source format differs from the requested migration mode"
    );
    let node: String = db.query_row(
        "SELECT value FROM cluster_state WHERE key='node_id'",
        [],
        |r| r.get(0),
    )?;
    let role: String = db.query_row(
        "SELECT value FROM cluster_state WHERE key='role'",
        [],
        |r| r.get(0),
    )?;
    ensure!(
        node == cluster.node_id
            && role
                == match cluster.role {
                    Role::Coordinator => "coordinator",
                    Role::Worker => "worker",
                },
        "Source identity differs from installation"
    );
    ensure!(
        crate::central::selection::Selection::read(&db)?.as_ref() == selected,
        "Source selection differs from the requested recovery authority"
    );
    if let Some(selected) = selected {
        selected.verify_key(&config.data_dir)?;
    }
    let source = LockedSource {
        source: Source {
            node_id: node.clone(),
            role: cluster.role,
            data_dir: config.data_dir.clone(),
            config: None,
        },
        guard,
        db,
        file_identity: (info.dev(), info.ino()),
    };
    source.verify()?;
    Ok(source)
}
