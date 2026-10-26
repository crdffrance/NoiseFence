//! Administrator-owned protection choices are kept separate from provider
//! records. A refresh cannot assign roles, remove them or invent delegation.
use super::directory::{
    Delegation, MAX_GROUPS, MAX_MEMBERSHIPS, MAX_PEOPLE, Role, Snapshot, Source,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    /// Bind to the complete administrator-selected source authority and scope.
    pub source: Source,
    pub roles: BTreeMap<String, BTreeSet<Role>>,
    pub groups: BTreeSet<String>,
    pub delegations: BTreeSet<Delegation>,
}
impl Selection {
    pub fn apply(&self, collected: &Snapshot, now: i64) -> Result<Snapshot> {
        collected.validate(now)?;
        ensure!(
            self.source == collected.source,
            "Identity protection belongs to another source revision"
        );
        ensure!(
            self.roles.len() <= MAX_PEOPLE
                && self.groups.len() <= MAX_GROUPS
                && self.delegations.len() <= MAX_MEMBERSHIPS,
            "Identity protection selection exceeds limits"
        );
        let mut snapshot = collected.clone();
        let mut missing_people: BTreeSet<_> = self.roles.keys().collect();
        for person in &mut snapshot.people {
            person.protected_roles = self.roles.get(&person.id).cloned().unwrap_or_default();
            missing_people.remove(&person.id);
        }
        let mut missing_groups = self.groups.clone();
        for group in &mut snapshot.groups {
            group.protected = self.groups.contains(&group.id);
            missing_groups.remove(&group.id);
        }
        // Administrative review must resolve missing selections explicitly.
        // Do not silently unprotect a departed/renamed or transiently absent ID.
        ensure!(
            missing_people.is_empty() && missing_groups.is_empty(),
            "Protected identities are absent; review the source and protection selection"
        );
        snapshot.delegations = self.delegations.clone();
        snapshot.validate(now)?;
        Ok(snapshot)
    }
}
/// A bounded administrator edit, never a replacement for provider-owned data.
/// The selected catalog revision supplies the source authority and all identities.
pub const MAX_PATCH_CHANGES: usize = 100;
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersonPatch {
    pub id: String,
    pub roles: BTreeSet<Role>,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupPatch {
    pub id: String,
    pub protected: bool,
}
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Patch {
    #[serde(default)]
    pub people: Vec<PersonPatch>,
    #[serde(default)]
    pub groups: Vec<GroupPatch>,
    #[serde(default)]
    pub add_delegations: Vec<Delegation>,
    #[serde(default)]
    pub remove_delegations: Vec<Delegation>,
}
impl Patch {
    pub fn apply(&self, installed: &Snapshot, now: i64) -> Result<Snapshot> {
        installed.validate(now)?;
        let count = self.people.len()
            + self.groups.len()
            + self.add_delegations.len()
            + self.remove_delegations.len();
        ensure!(
            (1..=MAX_PATCH_CHANGES).contains(&count),
            "Review between 1 and 100 protection changes at a time"
        );
        let mut next = installed.clone();
        let mut seen = BTreeSet::new();
        for patch in &self.people {
            ensure!(seen.insert(&patch.id), "Repeated person protection edit");
            let person = next
                .people
                .iter_mut()
                .find(|p| p.id == patch.id)
                .ok_or_else(|| anyhow::anyhow!("Protection identity not found in this source"))?;
            person.protected_roles = patch.roles.clone();
        }
        seen.clear();
        for patch in &self.groups {
            ensure!(seen.insert(&patch.id), "Repeated group protection edit");
            let group = next
                .groups
                .iter_mut()
                .find(|g| g.id == patch.id)
                .ok_or_else(|| anyhow::anyhow!("Protection group not found in this source"))?;
            group.protected = patch.protected;
        }
        let mut delegations = BTreeSet::new();
        for removed in &self.remove_delegations {
            ensure!(
                delegations.insert(removed) && next.delegations.remove(removed),
                "Delegation removal is repeated or does not match an installed assignment"
            );
        }
        for added in &self.add_delegations {
            ensure!(
                delegations.insert(added) && next.delegations.insert(added.clone()),
                "Delegation addition is repeated or conflicts with another change"
            );
        }
        next.validate(now)?;
        ensure!(next != *installed, "No protection changes to review");
        next.generation = installed
            .generation
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("Source generation exhausted"))?;
        // Local choices must never renew stale provider data or impersonate a sync.
        debug_assert_eq!(next.completed_at, installed.completed_at);
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const NOW: i64 = 1800000010;
    fn fixture() -> Snapshot {
        Snapshot::decode(
            include_bytes!("../../tests/fixtures/identity/directory.json"),
            NOW,
        )
        .unwrap()
    }
    fn selection(snapshot: &Snapshot) -> Selection {
        Selection {
            source: snapshot.source.clone(),
            roles: BTreeMap::from([("person-alice".into(), BTreeSet::from([Role::Executive]))]),
            groups: BTreeSet::from(["group-finance".into()]),
            delegations: BTreeSet::new(),
        }
    }
    #[test]
    fn provider_claims_cannot_assign_or_clear_local_protection() {
        let mut raw = fixture();
        raw.people[0].protected_roles = BTreeSet::from([Role::Supplier]);
        raw.groups[0].protected = false;
        let local = selection(&raw);
        let prepared = local.apply(&raw, NOW).unwrap();
        assert_eq!(
            prepared.people[0].protected_roles,
            BTreeSet::from([Role::Executive])
        );
        assert!(prepared.groups[0].protected);
        assert_eq!(
            raw.people[0].protected_roles,
            BTreeSet::from([Role::Supplier])
        );
        let empty = Selection {
            roles: BTreeMap::new(),
            groups: BTreeSet::new(),
            ..local
        };
        let prepared = empty.apply(&raw, NOW).unwrap();
        assert!(prepared.people[0].protected_roles.is_empty());
        assert!(!prepared.groups[0].protected);
    }
    #[test]
    fn a_missing_protected_id_or_changed_authority_requires_review() {
        let raw = fixture();
        let local = selection(&raw);
        let mut changed = raw.clone();
        changed.people[0].id = "replacement".into();
        changed.memberships.clear();
        assert!(local.apply(&changed, NOW).is_err());
        changed = raw.clone();
        changed.source.scopes.insert("other.test".into());
        assert!(local.apply(&changed, NOW).is_err());
    }
    #[test]
    fn delegation_is_explicit_and_must_match_real_directory_addresses() {
        let raw = fixture();
        let mut local = selection(&raw);
        local.delegations.insert(Delegation {
            owner: "person-alice".into(),
            delegate: "unknown".into(),
            address: "alice@example.test".into(),
        });
        assert!(local.apply(&raw, NOW).is_err());
    }
}
