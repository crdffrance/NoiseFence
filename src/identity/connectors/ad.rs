//! Signed, offline Active Directory collection. No LDAP connection from an MX.
//! Trust is an explicitly enrolled key, never a key embedded in an upload.
use super::entra::Collected;
use crate::identity::{
    directory::{
        self, Activity, Group, Kind, Member, Membership, Person, Provider, Snapshot, Source,
    },
    mailbox,
};
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use ring::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

pub const PROTOCOL: &str = "noisefence-ad-export-1";
pub const SIGNING_PREFIX: &[u8] = b"noisefence:ad-export-1\0";
pub const MAX_ENVELOPE_BYTES: usize = 23 * 1024 * 1024;
pub const MAX_AGE_SECONDS: i64 = 900;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub protocol: String,
    pub id: String,
    pub key_id: String,
    pub payload: String,
    pub signature: String,
}
pub struct PublicKey {
    bytes: Vec<u8>,
}
impl PublicKey {
    pub fn new(authority: &str, value: &str) -> Result<Self> {
        authority_parts(authority)?;
        ensure!(value.len() == 88, "Invalid AD collector public key");
        let bytes = STANDARD
            .decode(value)
            .context("Invalid AD collector public key")?;
        ensure!(
            bytes.len() == 65 && bytes[0] == 4,
            "Expected uncompressed P-256 public key"
        );
        Ok(Self { bytes })
    }
    pub fn id(&self) -> String {
        crate::message::digest(&self.bytes)
    }
    pub fn verify(&self, source: &Source, envelope: Envelope, now: i64) -> Result<VerifiedExport> {
        source.validate()?;
        ensure!(
            source.provider == Provider::ActiveDirectory,
            "Expected Active Directory source"
        );
        ensure!(
            envelope.protocol == PROTOCOL
                && canonical_uuid(&envelope.id)
                && envelope.key_id == self.id(),
            "Invalid AD export identity"
        );
        ensure!(
            envelope.payload.len() <= directory::MAX_BYTES.div_ceil(3) * 4
                && envelope.signature.len() == 88,
            "AD export exceeds limit"
        );
        let payload = STANDARD
            .decode(envelope.payload)
            .context("Invalid AD export encoding")?;
        ensure!(
            payload.len() <= directory::MAX_BYTES,
            "AD export exceeds limit"
        );
        let signature = STANDARD
            .decode(envelope.signature)
            .context("Invalid AD signature encoding")?;
        ensure!(signature.len() == 64, "Invalid AD signature length");
        let mut signed = Vec::with_capacity(SIGNING_PREFIX.len() + payload.len());
        signed.extend_from_slice(SIGNING_PREFIX);
        signed.extend_from_slice(&payload);
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &self.bytes)
            .verify(&signed, &signature)
            .map_err(|_| anyhow::anyhow!("AD export signature refused"))?;
        // Parse only authenticated bytes. No provider-supplied scope, role or generation.
        let data: Payload = serde_json::from_slice(&payload).context("Invalid AD export schema")?;
        let (domain, guid) = authority_parts(&source.authority)?;
        ensure!(
            data.collection_id == envelope.id
                && data.source_id == source.id
                && data.domain_dns == domain
                && data.domain_guid == guid,
            "AD export authority mismatch"
        );
        ensure!(
            hostname(&data.controller) && data.complete,
            "Incomplete AD export"
        );
        ensure!(
            data.started_at > 0
                && data.completed_at >= data.started_at
                && data.completed_at - data.started_at <= 300
                && data.completed_at <= now
                && now.saturating_sub(data.completed_at) <= MAX_AGE_SECONDS,
            "AD export is stale or has invalid timestamps"
        );
        ensure!(
            data.people.len() <= directory::MAX_PEOPLE
                && data.groups.len() <= directory::MAX_GROUPS
                && data.memberships.len() <= directory::MAX_MEMBERSHIPS,
            "AD complexity limit exceeded"
        );
        ensure!(
            data.people.len() == data.counts.people
                && data.groups.len() == data.counts.groups
                && data.memberships.len() == data.counts.memberships,
            "Incomplete AD export counts"
        );
        ensure!(
            (1..=4096).contains(&data.requests)
                && data.pages > 0
                && data.pages <= data.requests
                && data.excluded_members.len() <= 2,
            "Invalid AD coverage"
        );
        let mut excluded = 0usize;
        for (kind, count) in &data.excluded_members {
            ensure!(
                matches!(kind.as_str(), "device" | "external_membership") && *count > 0,
                "Invalid AD exclusion"
            );
            excluded = excluded
                .checked_add(*count)
                .context("AD coverage overflow")?;
        }
        ensure!(
            excluded <= directory::MAX_MEMBERSHIPS,
            "AD coverage limit exceeded"
        );
        Ok(VerifiedExport {
            data,
            bytes: payload.len(),
            source: source.clone(),
        })
    }
}
fn hostname(value: &str) -> bool {
    value.len() <= 253
        && value.contains('.')
        && value.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}
fn canonical_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|v| !v.is_nil() && v.to_string() == value)
}
fn authority_parts(value: &str) -> Result<(&str, &str)> {
    let (domain, guid) = value
        .split_once(':')
        .context("Expected AD DNS domain:objectGUID authority")?;
    ensure!(
        hostname(domain) && canonical_uuid(guid),
        "Invalid AD domain authority"
    );
    Ok((domain, guid))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    collection_id: String,
    source_id: String,
    domain_dns: String,
    domain_guid: String,
    controller: String,
    started_at: i64,
    completed_at: i64,
    complete: bool,
    requests: usize,
    pages: usize,
    counts: Counts,
    people: Vec<User>,
    groups: Vec<AdGroup>,
    memberships: Vec<Membership>,
    excluded_members: BTreeMap<String, usize>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Counts {
    people: usize,
    groups: usize,
    memberships: usize,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct User {
    id: String,
    display_name: String,
    enabled: Option<bool>,
    mail: Option<String>,
    proxy_addresses: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdGroup {
    id: String,
    display_name: String,
    mail: Option<String>,
    proxy_addresses: Vec<String>,
}
/// Only PublicKey::verify can construct this authenticated, source-bound value.
pub struct VerifiedExport {
    data: Payload,
    bytes: usize,
    source: Source,
}
impl VerifiedExport {
    pub fn id(&self) -> &str {
        &self.data.collection_id
    }
    pub fn collect(self, generation: u64, now: i64) -> Result<Collected> {
        ensure!(
            now >= self.data.completed_at && now - self.data.completed_at <= MAX_AGE_SECONDS,
            "AD export expired before preparation"
        );
        let mut ids = BTreeSet::new();
        let mut people = Vec::with_capacity(self.data.people.len());
        for user in self.data.people {
            ensure!(
                canonical_uuid(&user.id) && ids.insert(user.id.clone()),
                "Duplicate or invalid AD objectGUID"
            );
            people.push(Person {
                id: user.id,
                display_name: user.display_name,
                kind: Kind::Person,
                activity: match user.enabled {
                    Some(true) => Activity::Active,
                    Some(false) => Activity::Inactive,
                    None => Activity::Unknown,
                },
                addresses: addresses(user.mail, user.proxy_addresses)?,
                protected_roles: BTreeSet::new(),
            });
        }
        let mut groups = Vec::with_capacity(self.data.groups.len());
        for group in self.data.groups {
            ensure!(
                canonical_uuid(&group.id) && ids.insert(group.id.clone()),
                "Duplicate or invalid AD objectGUID"
            );
            groups.push(Group {
                id: group.id,
                display_name: group.display_name,
                activity: Activity::Active,
                addresses: addresses(group.mail, group.proxy_addresses)?,
                protected: false,
            });
        }
        let mut memberships = BTreeSet::new();
        for entry in self.data.memberships {
            let (Member::Person(id) | Member::Group(id)) = &entry.member;
            ensure!(
                canonical_uuid(&entry.group) && canonical_uuid(id) && memberships.insert(entry),
                "Duplicate or invalid AD membership"
            );
        }
        let snapshot = Snapshot {
            schema: directory::SCHEMA.into(),
            source: self.source,
            generation,
            completed_at: self.data.completed_at,
            people,
            groups,
            memberships,
            delegations: BTreeSet::new(),
        };
        snapshot.validate(now)?;
        ensure!(
            serde_json::to_vec(&snapshot)?.len() <= directory::MAX_BYTES,
            "Normalized AD snapshot exceeds size limit"
        );
        Ok(Collected {
            snapshot,
            requests: self.data.requests,
            pages: self.data.pages,
            bytes: self.bytes,
            excluded_members: self.data.excluded_members,
        })
    }
}
fn addresses(mail: Option<String>, proxies: Vec<String>) -> Result<BTreeSet<String>> {
    ensure!(proxies.len() <= 128, "Too many AD proxy addresses");
    let mut result = BTreeSet::new();
    if let Some(value) = mail.filter(|v| !v.is_empty()) {
        result.insert(mailbox(&value)?);
    }
    for proxy in proxies {
        ensure!(
            proxy.len() <= 1024 && !proxy.chars().any(char::is_control),
            "Invalid AD proxy address"
        );
        if let Some((kind, value)) = proxy.split_once(':')
            && kind.eq_ignore_ascii_case("smtp")
        {
            result.insert(mailbox(value)?);
        }
    }
    ensure!(result.len() <= 32, "Too many AD mail aliases");
    Ok(result)
}
#[cfg(test)]
mod tests;
