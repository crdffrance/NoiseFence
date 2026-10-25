//! Preparing a candidate is not activation or proof that a remote directory
//! completed provisioning. A caller must explicitly attest the staged inventory,
//! freeze its revision in the selected authority, then use normal policy review.
use super::{Error, INVALID, LIMIT, Resource, ResourceType, Result, resource};
use crate::identity::directory::{self, Member, Membership, Provider, Snapshot, Source};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
const MAX_STAGED_BYTES: usize = 64 * 1024 * 1024;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Revision {
    pub source_id: String,
    pub source_sha256: String,
    pub enrollment: String,
    pub sequence: u64,
}
pub(super) fn source_digest(source: &Source) -> Result<String> {
    source.validate().map_err(|_| INVALID)?;
    if source.provider != Provider::Scim {
        return Err(INVALID);
    }
    Ok(crate::message::digest(
        &serde_json::to_vec(source).map_err(|_| INVALID)?,
    ))
}
impl Revision {
    pub fn new(source: &Source, enrollment: String, sequence: u64) -> Result<Self> {
        let result = Self {
            source_id: source.id.clone(),
            source_sha256: source_digest(source)?,
            enrollment,
            sequence,
        };
        result.validate(source)?;
        Ok(result)
    }
    pub fn validate(&self, source: &Source) -> Result<()> {
        if self.source_id != source.id
            || self.source_sha256 != source_digest(source)?
            || !resource::id(&self.enrollment)
            || self.sequence > i64::MAX as u64
        {
            return Err(INVALID);
        }
        Ok(())
    }
    pub fn next(&self) -> Result<Self> {
        let mut next = self.clone();
        next.sequence = self
            .sequence
            .checked_add(1)
            .filter(|v| *v <= i64::MAX as u64)
            .ok_or(LIMIT)?;
        Ok(next)
    }
}
/// Administrator-confirmed inventory, bound to one enrollment and resource
/// sequence. The digest identifies what was viewed; sequence guards mutations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attestation {
    pub revision: Revision,
    pub inventory_sha256: String,
    pub verified_at: i64,
}
impl Attestation {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            crate::compatibility::valid_hash(&self.inventory_sha256)
                && crate::compatibility::valid_hash(&self.revision.source_sha256)
                && resource::id(&self.revision.enrollment)
                && self.revision.sequence <= i64::MAX as u64
                && self.verified_at > 0,
            "Invalid inventory attestation"
        );
        Ok(())
    }
    pub fn verify(&self, source: &Source, revision: &Revision) -> anyhow::Result<()> {
        self.validate()?;
        self.revision.validate(source)?;
        anyhow::ensure!(
            &self.revision == revision,
            "SCIM inventory changed; review again"
        );
        Ok(())
    }
}
#[derive(Clone, Debug)]
pub struct Candidate {
    revision: Revision,
    snapshot: Snapshot,
    inventory_sha256: String,
}
impl Candidate {
    /// verified_at is an explicit administrator attestation time, not the time
    /// of the last PATCH or the time an automatic worker happens to execute.
    /// The repository/API records the attestation with this exact
    /// inventory digest and recheck revision before handing it to policy review.
    pub fn prepare(
        source: Source,
        revision: Revision,
        generation: u64,
        resources: &[Resource],
        verified_at: i64,
        now: i64,
    ) -> Result<Self> {
        if verified_at <= 0 || verified_at > now || now.saturating_sub(verified_at) > 300 {
            return Err(INVALID);
        }
        Self::project(source, revision, generation, resources, verified_at, now)
    }
    /// Read-only projection. No completed-at or attestation is returned: a last
    /// PATCH is not a provider signal that provisioning is complete.
    pub fn inspect(
        source: Source,
        revision: Revision,
        resources: &[Resource],
        now: i64,
    ) -> Result<(crate::identity::management::Draft, String)> {
        let projection = Self::project(source, revision, 1, resources, now, now)?;
        Ok((projection.snapshot.into(), projection.inventory_sha256))
    }
    fn project(
        source: Source,
        revision: Revision,
        generation: u64,
        resources: &[Resource],
        verified_at: i64,
        now: i64,
    ) -> Result<Self> {
        revision.validate(&source)?;
        if resources.len() > directory::MAX_PEOPLE + directory::MAX_GROUPS {
            return Err(LIMIT);
        }
        let mut ids = BTreeSet::new();
        let mut names = BTreeSet::new();
        let mut rows = Vec::with_capacity(resources.len());
        let mut snapshot = Snapshot {
            schema: directory::SCHEMA.into(),
            source,
            generation,
            completed_at: verified_at,
            people: vec![],
            groups: vec![],
            memberships: BTreeSet::new(),
            delegations: BTreeSet::new(),
        };
        let mut size = 0usize;
        for resource in resources {
            let bytes = resource.encode(&snapshot.source)?;
            size = size.checked_add(bytes.len()).ok_or(LIMIT)?;
            if size > MAX_STAGED_BYTES {
                return Err(LIMIT);
            }
            if resource.modified() > verified_at || !ids.insert(resource.id()) {
                return Err(INVALID);
            }
            if let Some(name) = resource.data().user_name_key()
                && !names.insert(name)
            {
                return Err(Error::new(
                    409,
                    "uniqueness",
                    "SCIM userName is already assigned within this source.",
                ));
            }
            rows.push((resource.id(), crate::message::digest(&bytes)));
            match resource.data().kind() {
                ResourceType::User => {
                    snapshot.people.push(resource.person());
                    if snapshot.people.len() > directory::MAX_PEOPLE {
                        return Err(LIMIT);
                    }
                }
                ResourceType::Group => {
                    snapshot.groups.push(resource.group());
                    if snapshot.groups.len() > directory::MAX_GROUPS {
                        return Err(LIMIT);
                    }
                    for member in resource.data().members() {
                        snapshot.memberships.insert(Membership {
                            group: resource.id().into(),
                            member: member.clone(),
                        });
                        if snapshot.memberships.len() > directory::MAX_MEMBERSHIPS {
                            return Err(LIMIT);
                        }
                    }
                }
            }
        }
        // Existing graph validation also rejects dangling, foreign-source,
        // wrong-kind and cyclic memberships. No partial candidate is returned.
        snapshot.validate(now).map_err(|_| INVALID)?;
        snapshot.people.sort_by(|a, b| a.id.cmp(&b.id));
        snapshot.groups.sort_by(|a, b| a.id.cmp(&b.id));
        rows.sort();
        let inventory_sha256 =
            crate::message::digest(&serde_json::to_vec(&(&revision, rows)).map_err(|_| INVALID)?);
        Ok(Self {
            revision,
            snapshot,
            inventory_sha256,
        })
    }
    pub fn revision(&self) -> &Revision {
        &self.revision
    }
    pub fn inventory_sha256(&self) -> &str {
        &self.inventory_sha256
    }
    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }
    pub fn verify_current(&self, current: &Revision) -> Result<()> {
        if current == &self.revision {
            Ok(())
        } else {
            Err(super::STALE)
        }
    }
}
/// Delete handling must use this operation inside the same transaction as the
/// resource deletion. References removed from each group advance its ETag.
/// The repository must apply it to every referencing group from this source.
impl Resource {
    pub fn without_member(&self, deleted: &Resource, now: i64) -> Result<Self> {
        if self.source_id() != deleted.source_id()
            || self.source_sha256() != deleted.source_sha256()
        {
            return Err(INVALID);
        }
        let mut data = self.data().clone();
        let member = match deleted.data().kind() {
            ResourceType::User => Member::Person(deleted.id().into()),
            ResourceType::Group => Member::Group(deleted.id().into()),
        };
        data.members.remove(&member);
        self.changed(data, None, now)
    }
}
