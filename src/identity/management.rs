//! Administrator-owned manual source preparation. This module performs no IdP
//! requests and never modifies routing, users, grants or the installed policy.
use super::{directory::*, runtime};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Draft {
    pub source: Source,
    pub people: Vec<Person>,
    pub groups: Vec<Group>,
    pub memberships: BTreeSet<Membership>,
    pub delegations: BTreeSet<Delegation>,
}
impl From<Snapshot> for Draft {
    fn from(s: Snapshot) -> Self {
        Self {
            source: s.source,
            people: s.people,
            groups: s.groups,
            memberships: s.memberships,
            delegations: s.delegations,
        }
    }
}
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Edit {
    UpsertManual { draft: Box<Draft> },
    Remove { source_id: String },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SourceStatus {
    pub source: Source,
    pub generation: u64,
    pub completed_at: i64,
    pub fresh: bool,
    pub people: usize,
    pub groups: usize,
    pub protected_people: usize,
    pub protected_groups: usize,
    pub memberships: usize,
    pub delegations: usize,
}
impl SourceStatus {
    pub fn new(s: &Snapshot, now: i64) -> Self {
        Self {
            source: s.source.clone(),
            generation: s.generation,
            completed_at: s.completed_at,
            fresh: s.fresh(now),
            people: s.people.len(),
            groups: s.groups.len(),
            protected_people: s
                .people
                .iter()
                .filter(|p| !p.protected_roles.is_empty())
                .count(),
            protected_groups: s.groups.iter().filter(|g| g.protected).count(),
            memberships: s.memberships.len(),
            delegations: s.delegations.len(),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Counts {
    pub added: usize,
    pub removed: usize,
    pub changed: usize,
}
fn counts<T: PartialEq>(before: BTreeMap<&str, &T>, after: BTreeMap<&str, &T>) -> Counts {
    Counts {
        added: after.keys().filter(|id| !before.contains_key(*id)).count(),
        removed: before.keys().filter(|id| !after.contains_key(*id)).count(),
        changed: after
            .iter()
            .filter(|(id, next)| before.get(*id).is_some_and(|old| old != *next))
            .count(),
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Review {
    pub operation: String,
    pub source_id: String,
    pub source_label: String,
    pub people: Counts,
    pub groups: Counts,
    pub membership_changes: usize,
    pub delegation_changes: usize,
    pub removed_or_disabled: usize,
    pub protected_identity_changes: usize,
    pub source_configuration_changed: bool,
    pub requires_attention: bool,
    pub before: Option<SourceStatus>,
    pub after: Option<SourceStatus>,
}

/// Validation details contain only data-contract errors, never local file paths
/// or provider response bodies. Operational failures keep a separate API message.
#[derive(Debug)]
pub struct InvalidEdit(pub String);
impl std::fmt::Display for InvalidEdit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Directory data is invalid: {}", self.0)
    }
}
impl std::error::Error for InvalidEdit {}

pub struct Candidate {
    pub document: runtime::Document,
    pub review: Review,
}

pub fn preview(
    previous: &runtime::Document,
    edit: Edit,
    scopes: &BTreeSet<String>,
    now: i64,
) -> Result<Candidate> {
    previous.validate(now)?;
    let id = match &edit {
        Edit::UpsertManual { draft } => &draft.source.id,
        Edit::Remove { source_id } => source_id,
    };
    ensure!(super::text(id, 100), "Invalid source identifier");
    let old = previous.sources.iter().find(|s| &s.source.id == id);
    let source_id = id.to_owned();
    let new = match edit {
        Edit::UpsertManual { draft } => {
            ensure!(
                draft.source.provider == Provider::Manual,
                "Use a manual source; provider data cannot be uploaded as a verified synchronization"
            );
            ensure!(
                old.is_none_or(|s| s.source.provider == Provider::Manual
                    && s.source.authority == draft.source.authority),
                "Provider or authority changes require a new source ID"
            );
            ensure!(
                draft.source.scopes.iter().all(|s| scopes.contains(s)),
                "Source scopes must be configured receiving domains"
            );
            let next = Snapshot {
                schema: SCHEMA.into(),
                source: draft.source,
                generation: old.map_or(Ok(1), |s| {
                    s.generation
                        .checked_add(1)
                        .ok_or_else(|| anyhow::anyhow!("Source generation exhausted"))
                })?,
                completed_at: now,
                people: draft.people,
                groups: draft.groups,
                memberships: draft.memberships,
                delegations: draft.delegations,
            };
            next.validate(now)?;
            Some(next)
        }
        Edit::Remove { .. } => {
            ensure!(old.is_some(), "Directory source not found");
            None
        }
    };
    finish(previous, old, new, source_id, now)
}

/// Only called with the result of a server-owned connector, never request JSON.
pub fn preview_collected(
    previous: &runtime::Document,
    collected: Snapshot,
    scopes: &BTreeSet<String>,
    now: i64,
) -> Result<Candidate> {
    previous.validate(now)?;
    collected.validate(now)?;
    ensure!(
        collected.source.provider != Provider::Manual,
        "Expected a provider snapshot"
    );
    ensure!(
        collected.source.scopes.iter().all(|s| scopes.contains(s)),
        "Source scopes must be configured receiving domains"
    );
    let old = previous
        .sources
        .iter()
        .find(|s| s.source.id == collected.source.id);
    ensure!(
        old.is_none_or(|s| s.source == collected.source),
        "Source configuration changed during synchronization"
    );
    let selection = super::protection::Selection {
        source: collected.source.clone(),
        roles: old
            .map(|s| {
                s.people
                    .iter()
                    .filter(|p| !p.protected_roles.is_empty())
                    .map(|p| (p.id.clone(), p.protected_roles.clone()))
                    .collect()
            })
            .unwrap_or_default(),
        groups: old
            .map(|s| {
                s.groups
                    .iter()
                    .filter(|g| g.protected)
                    .map(|g| g.id.clone())
                    .collect()
            })
            .unwrap_or_default(),
        delegations: old.map(|s| s.delegations.clone()).unwrap_or_default(),
    };
    let next = selection.apply(&collected, now)?;
    let id = next.source.id.clone();
    finish(previous, old, Some(next), id, now)
}

fn finish(
    previous: &runtime::Document,
    old: Option<&Snapshot>,
    new: Option<Snapshot>,
    source_id: String,
    now: i64,
) -> Result<Candidate> {
    let before_people = old
        .map(|s| s.people.iter().map(|p| (p.id.as_str(), p)).collect())
        .unwrap_or_default();
    let after_people = new
        .as_ref()
        .map(|s| s.people.iter().map(|p| (p.id.as_str(), p)).collect())
        .unwrap_or_default();
    let before_groups = old
        .map(|s| s.groups.iter().map(|p| (p.id.as_str(), p)).collect())
        .unwrap_or_default();
    let after_groups = new
        .as_ref()
        .map(|s| s.groups.iter().map(|p| (p.id.as_str(), p)).collect())
        .unwrap_or_default();
    let empty_members = BTreeSet::new();
    let empty_delegations = BTreeSet::new();
    let membership_changes = old
        .map_or(&empty_members, |s| &s.memberships)
        .symmetric_difference(new.as_ref().map_or(&empty_members, |s| &s.memberships))
        .count();
    let delegation_changes = old
        .map_or(&empty_delegations, |s| &s.delegations)
        .symmetric_difference(new.as_ref().map_or(&empty_delegations, |s| &s.delegations))
        .count();
    let configuration_changed =
        old.is_some_and(|s| new.as_ref().is_none_or(|n| s.source != n.source));
    // Source configuration changes are reviewed in this explicit operation. The
    // source diff still computes protected object/membership/delegation changes.
    let diff = if let (Some(old), Some(new)) = (old, new.as_ref()) {
        let mut comparable = old.clone();
        comparable.source = new.source.clone();
        Some(changes(Some(&comparable), new, now)?)
    } else {
        None
    };
    let removed_or_disabled = diff.as_ref().map_or_else(
        || {
            if new.is_none() {
                old.map_or(0, |s| {
                    s.people
                        .iter()
                        .filter(|p| p.activity == Activity::Active)
                        .count()
                        + s.groups
                            .iter()
                            .filter(|g| g.activity == Activity::Active)
                            .count()
                })
            } else {
                0
            }
        },
        |d| d.removed_or_disabled,
    );
    let protected_identity_changes = diff.as_ref().map_or_else(
        || {
            if new.is_none() {
                old.map_or(0, |s| {
                    s.people
                        .iter()
                        .filter(|p| !p.protected_roles.is_empty())
                        .count()
                        + s.groups.iter().filter(|g| g.protected).count()
                })
            } else {
                0
            }
        },
        |d| d.protected_identity_changes,
    );
    let review = Review {
        operation: if new.is_none() {
            "remove"
        } else if old.is_some() {
            "update"
        } else {
            "create"
        }
        .into(),
        source_id: source_id.clone(),
        source_label: new.as_ref().or(old).unwrap().source.label.clone(),
        people: counts(before_people, after_people),
        groups: counts(before_groups, after_groups),
        membership_changes,
        delegation_changes,
        removed_or_disabled,
        protected_identity_changes,
        source_configuration_changed: configuration_changed,
        requires_attention: new.is_none()
            || configuration_changed
            || diff.as_ref().is_some_and(|d| d.requires_review),
        before: old.map(|s| SourceStatus::new(s, now)),
        after: new.as_ref().map(|s| SourceStatus::new(s, now)),
    };
    let mut document = previous.clone();
    document.sources.retain(|s| s.source.id != source_id);
    document.sources.extend(new);
    document
        .sources
        .sort_by(|a, b| a.source.id.cmp(&b.source.id));
    document.validate(now)?;
    runtime::validate_transition(previous, &document)?;
    Ok(Candidate { document, review })
}
