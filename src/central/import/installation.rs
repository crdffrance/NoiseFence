//! Offline installation checks; candidate selections are not activation receipts.
use crate::{
    central::{
        binding::Binding,
        outbox,
        selection::{Selection, key_digest},
    },
    cluster::{
        Role,
        activation::{Journal, participant::Local},
        artifacts,
    },
    config::Config,
};
use anyhow::{Context, Result, ensure};
use rusqlite::Transaction;

/// Caller holds source process locks and a consistent SQLite transaction.
/// Verify the installed immutable runtime, without model loading, network
/// requests, secret output, generated replacement keys or database selection.
pub fn candidate(
    tx: &Transaction<'_>,
    config: &Config,
    authority: &Journal,
    binding: &Binding,
) -> Result<Selection> {
    check(tx, config, authority, binding, None)
}

/// Revalidate a partially committed source without replacing its authority.
pub fn selected(
    tx: &Transaction<'_>,
    config: &Config,
    authority: &Journal,
    expected: &Selection,
) -> Result<Selection> {
    let actual = check(tx, config, authority, &expected.database, Some(expected))?;
    ensure!(
        &actual == expected,
        "Selected installation changed during recovery"
    );
    Ok(actual)
}

fn check(
    tx: &Transaction<'_>,
    config: &Config,
    authority: &Journal,
    binding: &Binding,
    expected: Option<&Selection>,
) -> Result<Selection> {
    binding.validate()?;
    authority.validate()?;
    config.validate()?;
    ensure!(
        expected.is_some() || config.management.is_none(),
        "Installation already configures central management"
    );
    let cluster = config
        .cluster
        .as_ref()
        .context("Installation has no cluster identity")?;
    ensure!(
        tx.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))?
            == if expected.is_some() { 7 } else { 6 },
        "Installation format differs from the requested selection mode"
    );
    ensure!(
        Selection::read(tx)?.as_ref() == expected,
        "Installation selection differs from the requested authority"
    );
    let identity = outbox::identity(tx)?;
    ensure!(
        identity.node == cluster.node_id,
        "Installation node differs from captured source"
    );
    let role: String = tx.query_row(
        "SELECT value FROM cluster_state WHERE key='role'",
        [],
        |r| r.get(0),
    )?;
    let expected = match cluster.role {
        Role::Coordinator => "coordinator",
        Role::Worker => "worker",
    };
    ensure!(
        role == expected,
        "Installation role differs from captured source"
    );
    let local =
        Local::read(tx)?.context("Complete coordinated policy enrollment before migration")?;
    ensure!(
        authority.released()
            && local.authority().released()
            && local.authority().owner() == authority.owner()
            && local.installed_epoch() == &authority.current_epoch()
            && local.installed().digest == authority.current().digest,
        "Installed policy differs from the frozen coordinator authority"
    );
    // Versioned credentials are mandatory for a reproducible runtime. Never
    // silently fall back to mutable key files or process environment variables.
    ensure!(
        local.installed().credential_generation.is_some(),
        "Bind installed provider credentials before migration"
    );
    let effective = artifacts::materialize(config, local.installed(), true)?;
    let credentials = crate::credentials::Snapshot::capture(&effective)?;
    ensure!(
        Some(credentials.fingerprint()).as_ref()
            == local.installed().credential_generation.as_ref(),
        "Installed provider credentials differ from policy binding"
    );
    Selection::new(
        binding.clone(),
        identity,
        cluster.role,
        authority.current_epoch(),
        if cluster.role == Role::Coordinator {
            Some(key_digest(&config.data_dir)?)
        } else {
            None
        },
    )
}
