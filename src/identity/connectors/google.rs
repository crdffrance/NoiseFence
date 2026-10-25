//! Bounded read-only Google Workspace Directory collection. The immutable
//! customer is selected by the administrator; response data cannot change it.
pub use super::entra::{Collected, Limits};
use super::graph::{PAGE_BYTES, client_builder, read_body};
use crate::identity::{
    directory::{
        self, Activity, Group, Kind, Member, Membership, Person, Provider, Snapshot, Source,
    },
    mailbox, scope,
};
use anyhow::{Result, anyhow, ensure};
use reqwest::{
    Client, Url,
    header::{AUTHORIZATION, HeaderValue},
};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    time::Duration,
};

pub fn valid_customer(id: &str) -> bool {
    id.starts_with('C')
        && (2..=64).contains(&id.len())
        && id.bytes().all(|b| b.is_ascii_alphanumeric())
}
fn object_id(id: &str) -> bool {
    (1..=128).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}
// Request-only token; never Debug/Serialize or copied into durable receipts.
pub struct Credentials {
    customer: String,
    authorization: HeaderValue,
}
impl Credentials {
    pub fn new(customer: &str, token: String) -> Result<Self> {
        ensure!(
            valid_customer(customer),
            "Invalid immutable Google customer ID"
        );
        ensure!(
            !token.is_empty()
                && token.len() <= 8192
                && token
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-._~+/=".contains(&b)),
            "Invalid Google access token"
        );
        let mut authorization = HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| anyhow!("Invalid Google access token"))?;
        authorization.set_sensitive(true);
        Ok(Self {
            customer: customer.into(),
            authorization,
        })
    }
}
#[derive(Clone)]
enum Resource {
    Domains,
    Users,
    Groups,
    Members(String),
}
impl Resource {
    fn name(&self) -> &'static str {
        match self {
            Self::Domains => "domains",
            Self::Users => "users",
            Self::Groups => "groups",
            Self::Members(_) => "members",
        }
    }
    fn fields(&self) -> &'static str {
        match self {
            Self::Domains => {
                "kind,domains(domainName,verified,domainAliases(domainAliasName,verified))"
            }
            Self::Users => {
                "kind,nextPageToken,users(id,customerId,primaryEmail,name(fullName,givenName,familyName),aliases,nonEditableAliases,suspended,archived,isGuestUser)"
            }
            Self::Groups => "kind,nextPageToken,groups(id,email,name,aliases,nonEditableAliases)",
            Self::Members(_) => "kind,nextPageToken,members(id,email,type,status)",
        }
    }
}
#[derive(Clone)]
struct Request {
    url: Url,
    resource: Resource,
}
impl Request {
    fn new(customer: &str, resource: Resource) -> Result<Self> {
        ensure!(valid_customer(customer), "Invalid Google customer");
        let path = match &resource {
            Resource::Domains => format!("customer/{customer}/domains"),
            Resource::Members(id) => {
                ensure!(object_id(id), "Invalid Google group ID");
                format!("groups/{id}/members")
            }
            other => other.name().into(),
        };
        let mut url = Url::parse(&format!(
            "https://admin.googleapis.com/admin/directory/v1/{path}"
        ))?;
        url.query_pairs_mut()
            .append_pair("fields", resource.fields());
        match &resource {
            Resource::Domains => {}
            Resource::Members(_) => {
                url.query_pairs_mut()
                    .append_pair("maxResults", "200")
                    .append_pair("includeDerivedMembership", "false");
            }
            _ => {
                url.query_pairs_mut()
                    .append_pair("customer", customer)
                    .append_pair("maxResults", "200");
            }
        }
        if matches!(resource, Resource::Users) {
            url.query_pairs_mut()
                .append_pair("viewType", "admin_view")
                .append_pair("projection", "full")
                .append_pair("showDeleted", "false");
        }
        Ok(Self { url, resource })
    }
    fn next(&self, token: &str) -> Result<Self> {
        ensure!(
            !matches!(self.resource, Resource::Domains)
                && !token.is_empty()
                && token.len() <= 4096
                && !token.chars().any(char::is_control),
            "Invalid Google page token"
        );
        let mut next = self.clone();
        let pairs: Vec<_> = self
            .url
            .query_pairs()
            .filter(|(k, _)| k != "pageToken")
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        next.url.set_query(None);
        next.url
            .query_pairs_mut()
            .extend_pairs(pairs)
            .append_pair("pageToken", token);
        Ok(next)
    }
}
struct Page {
    status: u16,
    retry_after: Option<Duration>,
    bytes: Vec<u8>,
}
trait Transport: Sync {
    fn get(&self, request: &Request) -> impl Future<Output = Result<Page>> + Send;
}
struct Http {
    client: Client,
    authorization: HeaderValue,
}
impl Transport for Http {
    async fn get(&self, request: &Request) -> Result<Page> {
        let response = self
            .client
            .get(request.url.clone())
            .header(AUTHORIZATION, self.authorization.clone())
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|_| anyhow!("Google directory request unavailable"))?;
        let status = response.status().as_u16();
        let retry_after = response.headers().get("retry-after").map(|v| {
            v.to_str()
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .map(Duration::from_secs)
                .unwrap_or(Duration::from_secs(3600))
        });
        let bytes = if status == 200 {
            read_body(response, PAGE_BYTES).await?
        } else {
            vec![]
        };
        Ok(Page {
            status,
            retry_after,
            bytes,
        })
    }
}
struct Budget {
    limits: Limits,
    requests: usize,
    pages: usize,
    bytes: usize,
}
impl Budget {
    async fn page<T: Transport>(&mut self, http: &T, request: &Request) -> Result<Vec<u8>> {
        for attempt in 0..3 {
            ensure!(
                self.requests < self.limits.max_requests,
                "Google request budget exhausted"
            );
            self.requests += 1;
            let page = http.get(request).await?;
            ensure!(page.bytes.len() <= PAGE_BYTES, "Google page exceeds limit");
            self.bytes = self.bytes.saturating_add(page.bytes.len());
            ensure!(
                self.bytes <= self.limits.max_bytes,
                "Google byte budget exhausted"
            );
            if page.status == 200 {
                self.pages += 1;
                return Ok(page.bytes);
            }
            if matches!(page.status, 429 | 502 | 503 | 504) && attempt < 2 {
                let delay = page
                    .retry_after
                    .unwrap_or(Duration::from_secs(1 << attempt))
                    .max(Duration::from_millis(100));
                ensure!(
                    delay <= Duration::from_secs(10),
                    "Google requested a later retry"
                );
                tokio::time::sleep(delay).await;
            } else {
                return Err(anyhow!(
                    "Google directory collection refused (HTTP {})",
                    page.status
                ));
            }
        }
        Err(anyhow!("Google retry budget exhausted"))
    }
    async fn collect<T: Transport, V: DeserializeOwned>(
        &mut self,
        http: &T,
        mut request: Request,
        maximum: usize,
    ) -> Result<Vec<V>> {
        let mut visited = BTreeSet::new();
        let mut records = Vec::new();
        loop {
            ensure!(
                visited.insert(request.url.to_string()),
                "Google pagination loop"
            );
            let bytes = self.page(http, &request).await?;
            let mut body: serde_json::Map<String, Value> = serde_json::from_slice(&bytes)
                .map_err(|_| anyhow!("Invalid Google directory page"))?;
            let name = request.resource.name();
            ensure!(
                body.get("kind").and_then(Value::as_str)
                    == Some(format!("admin#directory#{name}").as_str()),
                "Unexpected Google collection kind"
            );
            ensure!(
                body.keys()
                    .all(|k| matches!(k.as_str(), "kind" | "etag" | "nextPageToken") || k == name),
                "Unexpected Google collection fields"
            );
            let values = match body.remove(name) {
                None => Vec::new(),
                Some(value) => serde_json::from_value::<Vec<V>>(value)
                    .map_err(|_| anyhow!("Invalid Google directory records"))?,
            };
            ensure!(
                records.len().saturating_add(values.len()) <= maximum,
                "Google object limit exceeded"
            );
            records.extend(values);
            match body.get("nextPageToken") {
                None => return Ok(records),
                Some(Value::String(token)) => request = request.next(token)?,
                _ => return Err(anyhow!("Invalid Google continuation")),
            }
        }
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Domain {
    domain_name: String,
    verified: Option<bool>,
    #[serde(default)]
    domain_aliases: Vec<DomainAlias>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DomainAlias {
    domain_alias_name: String,
    verified: Option<bool>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct User {
    id: String,
    customer_id: String,
    primary_email: String,
    name: Option<Name>,
    suspended: Option<bool>,
    archived: Option<bool>,
    is_guest_user: Option<bool>,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    non_editable_aliases: Vec<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Name {
    full_name: Option<String>,
    given_name: Option<String>,
    family_name: Option<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RemoteGroup {
    id: String,
    email: String,
    name: String,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    non_editable_aliases: Vec<String>,
}
#[derive(Deserialize)]
struct RemoteMember {
    id: Option<String>,
    email: Option<String>,
    #[serde(rename = "type")]
    kind: String,
    status: Option<String>,
}
fn addresses(
    primary: &str,
    aliases: Vec<String>,
    non_editable: Vec<String>,
) -> Result<BTreeSet<String>> {
    ensure!(
        aliases.len() + non_editable.len() < 64,
        "Google alias limit exceeded"
    );
    let mut values = BTreeSet::new();
    for value in std::iter::once(primary.to_string())
        .chain(aliases)
        .chain(non_editable)
    {
        values.insert(mailbox(&value).map_err(|_| anyhow!("Invalid Google email address"))?);
    }
    ensure!(values.len() <= 32, "Too many Google identity aliases");
    Ok(values)
}
fn domain(value: &str) -> Result<String> {
    let value = value.to_ascii_lowercase();
    ensure!(scope(&value), "Invalid Google directory domain");
    Ok(value)
}
pub async fn synchronize(
    source: &Source,
    generation: u64,
    credentials: &Credentials,
    limits: Limits,
) -> Result<Collected> {
    source.validate()?;
    limits.validate()?;
    ensure!(
        source.provider == Provider::Google && source.authority == credentials.customer,
        "Google credential authority mismatch"
    );
    ensure!(
        generation > 0 && generation <= i64::MAX as u64,
        "Invalid directory generation"
    );
    let http = Http {
        client: client_builder()
            .build()
            .map_err(|_| anyhow!("Google transport unavailable"))?,
        authorization: credentials.authorization.clone(),
    };
    tokio::time::timeout(
        Duration::from_secs(limits.timeout_seconds),
        collect(&http, source, generation, limits, crate::now),
    )
    .await
    .map_err(|_| anyhow!("Google directory synchronization deadline exceeded"))?
}
async fn collect<T: Transport>(
    http: &T,
    source: &Source,
    generation: u64,
    limits: Limits,
    now: impl Fn() -> i64,
) -> Result<Collected> {
    let mut budget = Budget {
        limits,
        requests: 0,
        pages: 0,
        bytes: 0,
    };
    let remote_domains: Vec<Domain> = budget
        .collect(
            http,
            Request::new(&source.authority, Resource::Domains)?,
            1000,
        )
        .await?;
    let mut domains = BTreeSet::new();
    let mut verified = BTreeSet::new();
    for d in remote_domains {
        let name = domain(&d.domain_name)?;
        ensure!(
            domains.insert(name.clone()),
            "Duplicate Google directory domain"
        );
        if d.verified == Some(true) {
            verified.insert(name);
        }
        ensure!(
            d.domain_aliases.len() <= 1000,
            "Too many Google domain aliases"
        );
        for a in d.domain_aliases {
            let name = domain(&a.domain_alias_name)?;
            ensure!(
                domains.len() < 1000 && domains.insert(name.clone()),
                "Duplicate or excessive Google domain aliases"
            );
            if a.verified == Some(true) {
                verified.insert(name);
            }
        }
    }
    ensure!(
        !domains.is_empty(),
        "Google customer has no visible domains"
    );
    ensure!(
        source.scopes.iter().all(|s| verified.contains(s)),
        "Source scope is not a verified domain of the Google customer"
    );
    let users: Vec<User> = budget
        .collect(
            http,
            Request::new(&source.authority, Resource::Users)?,
            directory::MAX_PEOPLE,
        )
        .await?;
    let mut people = Vec::new();
    let mut person_addresses = BTreeMap::new();
    for u in users {
        ensure!(
            object_id(&u.id)
                && u.customer_id == source.authority
                && !person_addresses.contains_key(&u.id),
            "Invalid, duplicate or cross-customer Google user"
        );
        let addresses = addresses(&u.primary_email, u.aliases, u.non_editable_aliases)?;
        let display_name = u
            .name
            .map(|n| {
                n.full_name
                    .filter(|s| !s.trim().is_empty())
                    .unwrap_or_else(|| {
                        [
                            n.given_name.unwrap_or_default(),
                            n.family_name.unwrap_or_default(),
                        ]
                        .join(" ")
                        .trim()
                        .to_string()
                    })
            })
            .filter(|s| !s.is_empty())
            .unwrap_or(u.primary_email);
        let activity = match (u.suspended, u.archived, u.is_guest_user) {
            (Some(true), _, _) | (_, Some(true), _) => Activity::Inactive,
            (Some(false), Some(false), Some(false)) => Activity::Active,
            _ => Activity::Unknown,
        };
        person_addresses.insert(u.id.clone(), addresses.clone());
        people.push(Person {
            id: u.id,
            display_name,
            kind: Kind::Person,
            activity,
            addresses,
            protected_roles: BTreeSet::new(),
        });
    }
    let remote_groups: Vec<RemoteGroup> = budget
        .collect(
            http,
            Request::new(&source.authority, Resource::Groups)?,
            directory::MAX_GROUPS,
        )
        .await?;
    let mut groups = Vec::new();
    let mut group_addresses = BTreeMap::new();
    for g in remote_groups {
        ensure!(
            object_id(&g.id) && !group_addresses.contains_key(&g.id),
            "Invalid or duplicate Google group"
        );
        let addresses = addresses(&g.email, g.aliases, g.non_editable_aliases)?;
        group_addresses.insert(g.id.clone(), addresses.clone());
        groups.push(Group {
            id: g.id,
            display_name: g.name,
            activity: Activity::Active,
            addresses,
            protected: false,
        });
    }
    let mut memberships = BTreeSet::new();
    let mut excluded_members = BTreeMap::new();
    let mut observed = 0;
    for group in &groups {
        let values: Vec<RemoteMember> = budget
            .collect(
                http,
                Request::new(&source.authority, Resource::Members(group.id.clone()))?,
                directory::MAX_MEMBERSHIPS.saturating_sub(observed),
            )
            .await?;
        observed += values.len();
        let mut seen = BTreeSet::new();
        for m in values {
            ensure!(
                seen.insert((m.kind.clone(), m.id.clone(), m.email.clone())),
                "Duplicate Google group member"
            );
            if m.kind == "CUSTOMER" {
                ensure!(
                    m.id.as_deref() == Some(source.authority.as_str()),
                    "Cross-customer Google membership"
                );
                *excluded_members
                    .entry("customer_wide_membership".into())
                    .or_insert(0) += 1;
                continue;
            }
            ensure!(
                matches!(m.kind.as_str(), "USER" | "GROUP" | "EXTERNAL"),
                "Unsupported Google member type"
            );
            let email = m
                .email
                .as_deref()
                .map(mailbox)
                .transpose()
                .map_err(|_| anyhow!("Invalid Google member address"))?;
            let known = match m.kind.as_str() {
                "USER" => &person_addresses,
                "GROUP" => &group_addresses,
                _ => &person_addresses,
            };
            if m.kind != "EXTERNAL"
                && let Some(id) = m.id.as_ref()
                && let Some(addresses) = known.get(id)
            {
                ensure!(
                    email.as_ref().is_some_and(|e| addresses.contains(e)),
                    "Google member address changed during collection"
                );
                // A missing/non-active member status cannot supply an active edge.
                if m.status.as_deref() != Some("ACTIVE") {
                    *excluded_members
                        .entry("inactive_or_unknown_membership".into())
                        .or_insert(0) += 1;
                    continue;
                }
                ensure!(
                    memberships.insert(Membership {
                        group: group.id.clone(),
                        member: if m.kind == "USER" {
                            Member::Person(id.clone())
                        } else {
                            Member::Group(id.clone())
                        }
                    }),
                    "Duplicate Google membership"
                );
            } else {
                ensure!(
                    email.as_ref().is_some_and(|e| e
                        .rsplit_once('@')
                        .is_some_and(|(_, d)| !domains.contains(d))),
                    "Google member missing from customer directory; retry a complete collection"
                );
                *excluded_members
                    .entry("external_membership".into())
                    .or_insert(0) += 1;
            }
        }
    }
    let completed_at = now();
    let snapshot = Snapshot {
        schema: directory::SCHEMA.into(),
        source: source.clone(),
        generation,
        completed_at,
        people,
        groups,
        memberships,
        delegations: BTreeSet::new(),
    };
    snapshot.validate(completed_at)?;
    Ok(Collected {
        snapshot,
        requests: budget.requests,
        pages: budget.pages,
        bytes: budget.bytes,
        excluded_members,
    })
}
#[cfg(test)]
mod tests;
