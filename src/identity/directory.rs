//! Complete, validated source snapshots. A failed/partial sync is never an empty
//! directory. Administrative source scope cannot be supplied by an IdP payload.
use super::{mailbox, name_key, scope, text};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, RwLock},
};

pub const SCHEMA: &str = "identity-directory-1";
pub const MAX_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_PEOPLE: usize = 20_000;
pub const MAX_GROUPS: usize = 5_000;
pub const MAX_MEMBERSHIPS: usize = 100_000;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    Manual,
    Entra,
    Google,
    Okta,
    ActiveDirectory,
    AwsIdentityStore,
    Scim,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub id: String,
    pub provider: Provider,
    pub label: String,
    /// A provider tenant/directory ID, not an email domain guessed from users.
    pub authority: String,
    /// Recipient domain scopes explicitly assigned by an administrator.
    pub scopes: BTreeSet<String>,
    pub stale_after_seconds: u32,
}
impl Source {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            text(&self.id, 100) && text(&self.label, 200) && text(&self.authority, 256),
            "Invalid directory source"
        );
        ensure!(
            !self.scopes.is_empty()
                && self.scopes.len() <= 100
                && self.scopes.iter().all(|s| scope(s)),
            "Invalid directory scope"
        );
        ensure!(
            (300..=30 * 86400).contains(&self.stale_after_seconds),
            "Invalid directory freshness limit"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Person,
    SharedMailbox,
    Supplier,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Activity {
    Active,
    Inactive,
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Executive,
    Finance,
    Helpdesk,
    Legal,
    Supplier,
    Custom,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Person {
    /// Immutable provider ID within this source, never display name/email.
    pub id: String,
    pub display_name: String,
    pub kind: Kind,
    pub activity: Activity,
    /// Explicit address/alias assignments; no inference from login names.
    pub addresses: BTreeSet<String>,
    pub protected_roles: BTreeSet<Role>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Group {
    pub id: String,
    pub display_name: String,
    pub activity: Activity,
    /// Optional explicit addresses. An empty set is an ordinary identity group,
    /// not a mailing list and never a reason to accept an SMTP recipient.
    pub addresses: BTreeSet<String>,
    pub protected: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
pub enum Member {
    Person(String),
    Group(String),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct Membership {
    pub group: String,
    pub member: Member,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct Delegation {
    pub owner: String,
    pub delegate: String,
    /// One explicitly delegated sending address belonging to the owner.
    pub address: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub schema: String,
    pub source: Source,
    pub generation: u64,
    pub completed_at: i64,
    pub people: Vec<Person>,
    pub groups: Vec<Group>,
    pub memberships: BTreeSet<Membership>,
    pub delegations: BTreeSet<Delegation>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct Key {
    pub kind: EntityKind,
    pub source: String,
    pub id: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum EntityKind {
    Person,
    Group,
}

fn addresses(values: &BTreeSet<String>) -> Result<()> {
    ensure!(values.len() <= 32, "Too many identity aliases");
    for value in values {
        ensure!(mailbox(value)? == *value, "Noncanonical identity mailbox");
    }
    Ok(())
}

impl Snapshot {
    pub fn decode(bytes: &[u8], now: i64) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_BYTES,
            "Directory snapshot exceeds size limit"
        );
        let snapshot: Self = serde_json::from_slice(bytes)?;
        snapshot.validate(now)?;
        Ok(snapshot)
    }
    pub fn validate(&self, now: i64) -> Result<()> {
        self.source.validate()?;
        ensure!(
            self.schema == SCHEMA && self.generation > 0 && self.generation <= i64::MAX as u64,
            "Unsupported directory snapshot"
        );
        ensure!(
            self.completed_at > 0 && self.completed_at <= now.saturating_add(60),
            "Invalid directory completion time"
        );
        ensure!(
            self.people.len() <= MAX_PEOPLE
                && self.groups.len() <= MAX_GROUPS
                && self.memberships.len() <= MAX_MEMBERSHIPS
                && self.delegations.len() <= MAX_MEMBERSHIPS,
            "Directory complexity limit exceeded"
        );
        let mut people = BTreeMap::new();
        for person in &self.people {
            ensure!(
                text(&person.id, 256) && name_key(&person.display_name).is_some(),
                "Invalid directory person"
            );
            addresses(&person.addresses)?;
            ensure!(
                people.insert(&person.id, person).is_none(),
                "Duplicate directory person ID"
            );
        }
        let mut groups = BTreeMap::new();
        for group in &self.groups {
            ensure!(
                text(&group.id, 256) && name_key(&group.display_name).is_some(),
                "Invalid directory group"
            );
            addresses(&group.addresses)?;
            ensure!(
                groups.insert(&group.id, group).is_none(),
                "Duplicate directory group ID"
            );
        }
        for member in &self.memberships {
            ensure!(
                groups.contains_key(&member.group),
                "Unknown membership group"
            );
            ensure!(
                match &member.member {
                    Member::Person(id) => people.contains_key(id),
                    Member::Group(id) => groups.contains_key(id) && id != &member.group,
                },
                "Unknown or self-referential group member"
            );
        }
        // Kahn's algorithm bounds cycle detection without attacker-sized recursion.
        let mut incoming: BTreeMap<&str, usize> =
            groups.keys().map(|id| (id.as_str(), 0)).collect();
        let mut edges: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for member in &self.memberships {
            if let Member::Group(child) = &member.member {
                *incoming.get_mut(child.as_str()).expect("validated group") += 1;
                edges.entry(&member.group).or_default().push(child);
            }
        }
        let mut pending: Vec<_> = incoming
            .iter()
            .filter_map(|(id, n)| (*n == 0).then_some(*id))
            .collect();
        let mut visited = 0;
        while let Some(id) = pending.pop() {
            visited += 1;
            for child in edges.get(id).into_iter().flatten() {
                let count = incoming.get_mut(child).expect("validated group");
                *count -= 1;
                if *count == 0 {
                    pending.push(child);
                }
            }
        }
        ensure!(visited == groups.len(), "Cyclic directory groups");
        for delegation in &self.delegations {
            let owner = people.get(&delegation.owner);
            ensure!(
                delegation.owner != delegation.delegate
                    && people.contains_key(&delegation.delegate)
                    && owner.is_some_and(|p| p.addresses.contains(&delegation.address)),
                "Invalid directory delegation"
            );
        }
        ensure!(
            serde_json::to_vec(self)?.len() <= MAX_BYTES,
            "Directory snapshot exceeds size limit"
        );
        Ok(())
    }
    pub fn fresh(&self, now: i64) -> bool {
        self.completed_at > 0
            && self.completed_at <= now
            && now.saturating_sub(self.completed_at) <= i64::from(self.source.stale_after_seconds)
    }
    /// Canonical digest is bound to identity content, source scope and generation.
    pub fn digest(&self) -> Result<String> {
        let mut canonical = self.clone();
        canonical.people.sort_by(|a, b| a.id.cmp(&b.id));
        canonical.groups.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(crate::message::digest(&serde_json::to_vec(&canonical)?))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Changes {
    pub previous_digest: Option<String>,
    pub candidate_digest: String,
    pub removed_or_disabled: usize,
    pub protected_identity_changes: usize,
    pub requires_review: bool,
}
/// Review is bound to exact previous and candidate snapshots, not a reusable
/// “allow deletion” flag. The caller must authenticate the reviewing admin.
pub fn changes(previous: Option<&Snapshot>, candidate: &Snapshot, now: i64) -> Result<Changes> {
    candidate.validate(now)?;
    let mut result = Changes {
        previous_digest: None,
        candidate_digest: candidate.digest()?,
        removed_or_disabled: 0,
        protected_identity_changes: 0,
        requires_review: false,
    };
    let Some(old) = previous else {
        return Ok(result);
    };
    old.validate(now)?;
    ensure!(
        old.source == candidate.source,
        "Source configuration changed; a separate source revision is required"
    );
    ensure!(
        candidate.generation > old.generation && candidate.completed_at >= old.completed_at,
        "Directory generation rollback"
    );
    result.previous_digest = Some(old.digest()?);
    let next_people: BTreeMap<_, _> = candidate.people.iter().map(|p| (&p.id, p)).collect();
    let next_groups: BTreeMap<_, _> = candidate.groups.iter().map(|g| (&g.id, g)).collect();
    let mut active = 0usize;
    for person in &old.people {
        let next = next_people.get(&person.id);
        if person.activity == Activity::Active {
            active += 1;
            result.removed_or_disabled +=
                usize::from(!next.is_some_and(|p| p.activity == Activity::Active));
        }
        if !person.protected_roles.is_empty() && next.is_none_or(|p| *p != person) {
            result.protected_identity_changes += 1;
        }
    }
    for group in &old.groups {
        let next = next_groups.get(&group.id);
        if group.activity == Activity::Active {
            active += 1;
            result.removed_or_disabled +=
                usize::from(!next.is_some_and(|g| g.activity == Activity::Active));
        }
        if group.protected && next.is_none_or(|g| *g != group) {
            result.protected_identity_changes += 1;
        }
    }
    // Index edges once: source updates must not multiply every protected
    // identity by the entire membership/delegation directory.
    fn memberships(snapshot: &Snapshot) -> BTreeMap<&str, BTreeSet<&Member>> {
        let mut result: BTreeMap<&str, BTreeSet<&Member>> = BTreeMap::new();
        for edge in &snapshot.memberships {
            result.entry(&edge.group).or_default().insert(&edge.member);
        }
        result
    }
    fn delegations(snapshot: &Snapshot) -> BTreeMap<&str, BTreeSet<&Delegation>> {
        let mut result: BTreeMap<&str, BTreeSet<&Delegation>> = BTreeMap::new();
        for edge in &snapshot.delegations {
            result.entry(&edge.owner).or_default().insert(edge);
        }
        result
    }
    let before_memberships = memberships(old);
    let after_memberships = memberships(candidate);
    for group in old.groups.iter().filter(|g| g.protected) {
        if before_memberships.get(group.id.as_str()) != after_memberships.get(group.id.as_str()) {
            result.protected_identity_changes += 1;
        }
    }
    let before_delegations = delegations(old);
    let after_delegations = delegations(candidate);
    for person in old.people.iter().filter(|p| !p.protected_roles.is_empty()) {
        if before_delegations.get(person.id.as_str()) != after_delegations.get(person.id.as_str()) {
            result.protected_identity_changes += 1;
        }
    }
    result.requires_review = result.protected_identity_changes > 0
        || (result.removed_or_disabled > 0 && result.removed_or_disabled * 5 >= active);
    Ok(result)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Match {
    None,
    Unique(Key),
    Ambiguous,
}

/// An immutable index for a single source. Callers must pass the actual tenant
/// recipient scope, not the untrusted From domain. No data is exposed cross-tenant.
pub struct Index {
    snapshot: Snapshot,
    people_by_id: BTreeMap<String, usize>,
    by_address: BTreeMap<String, BTreeSet<String>>,
    by_name: BTreeMap<String, BTreeSet<String>>,
    group_by_name: BTreeMap<String, BTreeSet<String>>,
}
impl Index {
    pub fn new(snapshot: Snapshot, now: i64) -> Result<Self> {
        snapshot.validate(now)?;
        let mut value = Self {
            snapshot,
            people_by_id: BTreeMap::new(),
            by_address: BTreeMap::new(),
            by_name: BTreeMap::new(),
            group_by_name: BTreeMap::new(),
        };
        for (i, person) in value.snapshot.people.iter().enumerate() {
            value.people_by_id.insert(person.id.clone(), i);
            if person.activity != Activity::Active {
                continue;
            }
            for address in &person.addresses {
                value
                    .by_address
                    .entry(address.clone())
                    .or_default()
                    .insert(person.id.clone());
            }
            value
                .by_name
                .entry(name_key(&person.display_name).expect("validated name"))
                .or_default()
                .insert(person.id.clone());
        }
        for group in &value.snapshot.groups {
            if group.activity == Activity::Active && group.protected {
                value
                    .group_by_name
                    .entry(name_key(&group.display_name).expect("validated name"))
                    .or_default()
                    .insert(group.id.clone());
            }
        }
        Ok(value)
    }
    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }
    pub fn eligible(&self, recipient_scope: &str, now: i64) -> bool {
        self.snapshot.source.scopes.contains(recipient_scope) && self.snapshot.fresh(now)
    }
    fn lookup(&self, entries: Option<&BTreeSet<String>>, recipient_scope: &str, now: i64) -> Match {
        if !self.eligible(recipient_scope, now) {
            return Match::None;
        }
        match entries {
            Some(ids) if ids.len() == 1 => Match::Unique(Key {
                kind: EntityKind::Person,
                source: self.snapshot.source.id.clone(),
                id: ids.first().unwrap().clone(),
            }),
            Some(ids) if ids.len() > 1 => Match::Ambiguous,
            _ => Match::None,
        }
    }
    pub fn address(&self, address: &str, recipient_scope: &str, now: i64) -> Match {
        let address = mailbox(address).ok();
        self.lookup(
            address.as_ref().and_then(|a| self.by_address.get(a)),
            recipient_scope,
            now,
        )
    }
    pub fn name(&self, name: &str, recipient_scope: &str, now: i64) -> Match {
        self.lookup(
            name_key(name).as_ref().and_then(|n| self.by_name.get(n)),
            recipient_scope,
            now,
        )
    }
    pub fn person(&self, key: &Key, recipient_scope: &str, now: i64) -> Option<&Person> {
        if key.kind != EntityKind::Person
            || key.source != self.snapshot.source.id
            || !self.eligible(recipient_scope, now)
        {
            return None;
        }
        self.people_by_id
            .get(&key.id)
            .map(|i| &self.snapshot.people[*i])
            .filter(|p| p.activity == Activity::Active)
    }
    pub fn group_name(&self, name: &str, recipient_scope: &str, now: i64) -> Match {
        match self.lookup(
            name_key(name)
                .as_ref()
                .and_then(|n| self.group_by_name.get(n)),
            recipient_scope,
            now,
        ) {
            Match::Unique(mut key) => {
                key.kind = EntityKind::Group;
                Match::Unique(key)
            }
            other => other,
        }
    }
    pub fn group(&self, key: &Key, recipient_scope: &str, now: i64) -> Option<&Group> {
        if key.kind != EntityKind::Group
            || key.source != self.snapshot.source.id
            || !self.eligible(recipient_scope, now)
        {
            return None;
        }
        self.snapshot
            .groups
            .iter()
            .find(|g| g.id == key.id && g.activity == Activity::Active)
    }
    /// This only describes a directory assignment. Email authentication and
    /// permission for the concrete address still have to be independently checked.
    pub fn delegated(
        &self,
        owner: &Key,
        delegate: &Key,
        address: &str,
        recipient_scope: &str,
        now: i64,
    ) -> bool {
        self.person(owner, recipient_scope, now).is_some()
            && self.person(delegate, recipient_scope, now).is_some()
            && self.snapshot.delegations.contains(&Delegation {
                owner: owner.id.clone(),
                delegate: delegate.id.clone(),
                address: address.into(),
            })
    }
}

/// Request-scoped Arc clones see one generation. Errors leave the last-good
/// index intact. Persistence and cluster authorization must precede publication.
#[derive(Default)]
pub struct Resident {
    index: RwLock<Option<Arc<Index>>>,
}
impl Resident {
    pub fn snapshot(&self) -> Option<Arc<Index>> {
        self.index.read().unwrap_or_else(|p| p.into_inner()).clone()
    }
    pub fn publish(
        &self,
        candidate: Snapshot,
        now: i64,
        reviewed: Option<(&str, &str)>,
    ) -> Result<Changes> {
        let prepared = Arc::new(Index::new(candidate, now)?);
        let mut active = self
            .index
            .write()
            .map_err(|_| anyhow::anyhow!("Directory publication unavailable"))?;
        let change = changes(
            active.as_ref().map(|i| i.snapshot()),
            prepared.snapshot(),
            now,
        )?;
        if change.requires_review {
            ensure!(
                reviewed
                    == change
                        .previous_digest
                        .as_deref()
                        .map(|previous| (previous, change.candidate_digest.as_str())),
                "Directory change requires administrator review"
            );
        }
        *active = Some(prepared);
        Ok(change)
    }
}

/// Multiple source indexes; overlapping names/addresses remain ambiguous until
/// an administrator explicitly resolves them. No implicit identity merge.
pub struct Catalog {
    indexes: Vec<Index>,
}
impl Catalog {
    pub fn new(snapshots: Vec<Snapshot>, now: i64) -> Result<Self> {
        ensure!(snapshots.len() <= 16, "Too many directory sources");
        let mut ids = BTreeSet::new();
        let mut indexes = Vec::new();
        let mut size = 0usize;
        for snapshot in snapshots {
            ensure!(
                ids.insert(snapshot.source.id.clone()),
                "Duplicate directory source"
            );
            snapshot.validate(now)?;
            size = size
                .checked_add(serde_json::to_vec(&snapshot)?.len())
                .ok_or_else(|| anyhow::anyhow!("Directory size overflow"))?;
            ensure!(size <= 64 * 1024 * 1024, "Combined directory exceeds limit");
            indexes.push(Index::new(snapshot, now)?);
        }
        Ok(Self { indexes })
    }
    pub fn coverage(&self, recipient_scope: &str, now: i64) -> (usize, usize) {
        let applicable: Vec<_> = self
            .indexes
            .iter()
            .filter(|i| i.snapshot.source.scopes.contains(recipient_scope))
            .collect();
        (
            applicable.iter().filter(|i| i.snapshot.fresh(now)).count(),
            applicable.len(),
        )
    }
    fn merge(&self, lookup: impl Fn(&Index) -> Match) -> Match {
        let mut matched = None;
        for index in &self.indexes {
            match lookup(index) {
                Match::None => (),
                Match::Ambiguous => return Match::Ambiguous,
                Match::Unique(key) => {
                    if matched.is_some() {
                        return Match::Ambiguous;
                    }
                    matched = Some(key);
                }
            }
        }
        matched.map_or(Match::None, Match::Unique)
    }
    pub fn address(&self, value: &str, scope: &str, now: i64) -> Match {
        self.merge(|i| i.address(value, scope, now))
    }
    pub fn name(&self, value: &str, scope: &str, now: i64) -> Match {
        self.merge(|i| i.name(value, scope, now))
    }
    pub fn group_name(&self, value: &str, scope: &str, now: i64) -> Match {
        self.merge(|i| i.group_name(value, scope, now))
    }
    pub fn person(&self, key: &Key, scope: &str, now: i64) -> Option<&Person> {
        self.indexes.iter().find_map(|i| i.person(key, scope, now))
    }
    pub fn group(&self, key: &Key, scope: &str, now: i64) -> Option<&Group> {
        self.indexes.iter().find_map(|i| i.group(key, scope, now))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const NOW: i64 = 1_800_000_000;
    fn fixture() -> Snapshot {
        Snapshot {
            schema: SCHEMA.into(),
            source: Source {
                id: "manual-a".into(),
                provider: Provider::Manual,
                label: "People".into(),
                authority: "local-admin".into(),
                scopes: BTreeSet::from(["example.test".into()]),
                stale_after_seconds: 86400,
            },
            generation: 1,
            completed_at: NOW - 10,
            people: vec![Person {
                id: "alice-id".into(),
                display_name: "Alice Martin".into(),
                kind: Kind::Person,
                activity: Activity::Active,
                addresses: BTreeSet::from([
                    "Alice@example.test".into(),
                    "a.martin@example.test".into(),
                ]),
                protected_roles: BTreeSet::from([Role::Finance]),
            }],
            groups: vec![],
            memberships: BTreeSet::new(),
            delegations: BTreeSet::new(),
        }
    }
    #[test]
    fn tenant_isolation_freshness_aliases_and_homonyms() {
        let snapshot = fixture();
        let index = Index::new(snapshot.clone(), NOW).unwrap();
        assert!(matches!(
            index.name("  ALICE   MARTIN ", "example.test", NOW),
            Match::Unique(_)
        ));
        assert_eq!(index.name("Alice Martin", "other.test", NOW), Match::None);
        assert_eq!(
            index.address("Alice@example.test", "example.test", NOW + 86401),
            Match::None
        );
        assert!(matches!(
            index.address("a.martin@EXAMPLE.TEST", "example.test", NOW),
            Match::Unique(_)
        ));
        assert_eq!(
            index.address("alice@example.test", "example.test", NOW),
            Match::None
        );
        assert_eq!(
            index.address("Alice+tag@example.test", "example.test", NOW),
            Match::None
        );
        let mut snapshot = snapshot;
        let mut homonym = snapshot.people[0].clone();
        homonym.id = "alice-id-2".into();
        homonym.addresses = BTreeSet::from(["other-alice@example.test".into()]);
        snapshot.people.push(homonym);
        let index = Index::new(snapshot, NOW).unwrap();
        assert_eq!(
            index.name("Alice Martin", "example.test", NOW),
            Match::Ambiguous
        );
    }
    #[test]
    fn source_scoped_keys_and_duplicate_mailbox_conflicts() {
        let mut a = fixture();
        let mut p = a.people[0].clone();
        p.id = "another".into();
        a.people.push(p);
        assert_eq!(
            Index::new(a, NOW)
                .unwrap()
                .address("Alice@example.test", "example.test", NOW),
            Match::Ambiguous
        );
        let original = Index::new(fixture(), NOW).unwrap();
        let Match::Unique(key) = original.address("Alice@example.test", "example.test", NOW) else {
            panic!("missing identity")
        };
        let mut b = fixture();
        b.source.id = "another-source".into();
        assert!(
            Index::new(b, NOW)
                .unwrap()
                .person(&key, "example.test", NOW)
                .is_none()
        );
    }
    #[test]
    fn incomplete_invalid_and_rollback_syncs_preserve_old_generation() {
        let resident = Resident::default();
        resident.publish(fixture(), NOW, None).unwrap();
        let captured = resident.snapshot().unwrap();
        let mut broken = fixture();
        broken.generation = 2;
        broken.people.push(broken.people[0].clone());
        assert!(resident.publish(broken, NOW, None).is_err());
        assert!(resident.publish(fixture(), NOW, None).is_err());
        let mut future = fixture();
        future.completed_at = NOW + 61;
        assert!(resident.publish(future, NOW, None).is_err());
        assert_eq!(resident.snapshot().unwrap().snapshot().generation, 1);
        let mut next = fixture();
        next.generation = 2;
        next.completed_at = NOW;
        resident.publish(next, NOW, None).unwrap();
        assert_eq!(captured.snapshot().generation, 1);
        assert_eq!(resident.snapshot().unwrap().snapshot().generation, 2);
    }
    #[test]
    fn destructive_review_is_bound_to_exact_old_and_new_bytes() {
        let resident = Resident::default();
        let old = fixture();
        resident.publish(old.clone(), NOW, None).unwrap();
        let mut deletion = old.clone();
        deletion.generation = 2;
        deletion.people.clear();
        let change = changes(Some(&old), &deletion, NOW).unwrap();
        assert!(change.requires_review);
        assert_eq!(change.removed_or_disabled, 1);
        assert!(resident.publish(deletion.clone(), NOW, None).is_err());
        assert!(
            resident
                .publish(
                    deletion.clone(),
                    NOW,
                    Some(("wrong", &change.candidate_digest))
                )
                .is_err()
        );
        let reviewed = (
            change.previous_digest.as_deref().unwrap(),
            change.candidate_digest.as_str(),
        );
        let mut different = deletion.clone();
        different.generation = 3;
        assert!(resident.publish(different, NOW, Some(reviewed)).is_err());
        resident.publish(deletion, NOW, Some(reviewed)).unwrap();
        assert!(resident.snapshot().unwrap().snapshot().people.is_empty());
    }
    #[test]
    fn changing_protected_addresses_or_disabling_identity_requires_review() {
        let old = fixture();
        let mut changed = old.clone();
        changed.generation = 2;
        changed.people[0].addresses = BTreeSet::from(["attacker@external.test".into()]);
        assert!(changes(Some(&old), &changed, NOW).unwrap().requires_review);
        changed = old.clone();
        changed.generation = 2;
        changed.people[0].activity = Activity::Inactive;
        assert!(changes(Some(&old), &changed, NOW).unwrap().requires_review);
        changed.source.scopes.insert("other.test".into());
        assert!(changes(Some(&old), &changed, NOW).is_err());
    }
    #[test]
    fn groups_are_not_mailboxes_and_cycles_or_dangling_members_fail() {
        let mut data = fixture();
        for id in ["finance", "staff"] {
            data.groups.push(Group {
                id: id.into(),
                display_name: id.into(),
                activity: Activity::Active,
                addresses: BTreeSet::new(),
                protected: true,
            });
        }
        data.memberships.insert(Membership {
            group: "staff".into(),
            member: Member::Group("finance".into()),
        });
        data.memberships.insert(Membership {
            group: "finance".into(),
            member: Member::Person("alice-id".into()),
        });
        data.validate(NOW).unwrap();
        assert_eq!(
            Index::new(data.clone(), NOW).unwrap().address(
                "finance@example.test",
                "example.test",
                NOW
            ),
            Match::None
        );
        data.memberships.insert(Membership {
            group: "finance".into(),
            member: Member::Group("staff".into()),
        });
        assert!(data.validate(NOW).is_err());
        data.memberships.clear();
        data.memberships.insert(Membership {
            group: "finance".into(),
            member: Member::Person("missing".into()),
        });
        assert!(data.validate(NOW).is_err());
    }
    #[test]
    fn delegation_requires_explicit_owner_address_and_active_participants() {
        let mut data = fixture();
        let mut delegate = data.people[0].clone();
        delegate.id = "assistant".into();
        delegate.addresses = BTreeSet::from(["assistant@example.test".into()]);
        data.people.push(delegate);
        let grant = Delegation {
            owner: "alice-id".into(),
            delegate: "assistant".into(),
            address: "Alice@example.test".into(),
        };
        data.delegations.insert(grant);
        let owner = Key {
            kind: EntityKind::Person,
            source: "manual-a".into(),
            id: "alice-id".into(),
        };
        let assistant = Key {
            kind: EntityKind::Person,
            source: "manual-a".into(),
            id: "assistant".into(),
        };
        let index = Index::new(data.clone(), NOW).unwrap();
        assert!(index.delegated(
            &owner,
            &assistant,
            "Alice@example.test",
            "example.test",
            NOW
        ));
        assert!(!index.delegated(
            &owner,
            &assistant,
            "a.martin@example.test",
            "example.test",
            NOW
        ));
        data.people[1].activity = Activity::Inactive;
        assert!(!Index::new(data, NOW).unwrap().delegated(
            &owner,
            &assistant,
            "Alice@example.test",
            "example.test",
            NOW
        ));
    }
    #[test]
    fn digest_order_limits_and_untrusted_text() {
        let mut a = fixture();
        let mut p = a.people[0].clone();
        p.id = "b".into();
        a.people.push(p);
        let mut b = a.clone();
        b.people.reverse();
        assert_eq!(a.digest().unwrap(), b.digest().unwrap());
        b.people[0].display_name = "Alice\u{202e}injected".into();
        assert!(b.validate(NOW).is_err());
        assert!(Snapshot::decode(&vec![b' '; MAX_BYTES + 1], NOW).is_err());
        assert!(mailbox("foo@example.test\r\nX-Fake: pass").is_err());
        assert_eq!(
            mailbox("User@ÉXAMPLE.test").unwrap(),
            "User@xn--xample-9ua.test"
        );
    }
}
