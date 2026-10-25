//! Read-only, request-scoped Okta collection. Only the configured standard org
//! receives the bearer token; a complete reviewed candidate is the sole output.
pub use super::entra::{Collected, Limits};
use super::graph::{PAGE_BYTES, client_builder, read_body};
use crate::identity::{
    directory::{
        self, Activity, Group, Kind, Member, Membership, Person, Provider, Snapshot, Source,
    },
    mailbox,
};
use anyhow::{Result, anyhow, ensure};
use reqwest::{
    Client, Url,
    header::{AUTHORIZATION, HeaderValue},
};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    time::Duration,
};

const DEPROVISIONED: &str = "status eq \"DEPROVISIONED\"";
/// Standard public org domains only. Custom aliases/government orgs require a
/// separate reviewed endpoint policy rather than arbitrary server-side URLs.
pub fn valid_org(host: &str) -> bool {
    [".okta.com", ".okta-emea.com", ".oktapreview.com"]
        .iter()
        .any(|suffix| {
            host.strip_suffix(suffix).is_some_and(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            })
        })
}
// Deliberately not Debug/Serialize. Tokens never enter settings or audit events.
pub struct Credentials {
    org: String,
    authorization: HeaderValue,
}
impl Credentials {
    pub fn new(org: &str, token: String) -> Result<Self> {
        ensure!(valid_org(org), "Invalid Okta organization hostname");
        ensure!(
            !token.is_empty()
                && token.len() <= 8192
                && token
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-._~+/=".contains(&b)),
            "Invalid Okta access token"
        );
        let mut authorization = HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| anyhow!("Invalid Okta access token"))?;
        authorization.set_sensitive(true);
        Ok(Self {
            org: org.into(),
            authorization,
        })
    }
}
#[derive(Clone)]
struct Request {
    url: Url,
    filter: Option<&'static str>,
}
impl Request {
    fn new(org: &str, path: &str, filter: Option<&'static str>) -> Result<Self> {
        ensure!(valid_org(org), "Invalid Okta organization hostname");
        let allowed = matches!(path, "/api/v1/users" | "/api/v1/groups")
            || path
                .strip_prefix("/api/v1/groups/")
                .and_then(|p| p.strip_suffix("/users"))
                .is_some_and(|id| object_id(id, "00g"));
        ensure!(
            allowed
                && (filter.is_none() || (path == "/api/v1/users" && filter == Some(DEPROVISIONED))),
            "Invalid Okta collection"
        );
        let mut url = Url::parse(&format!("https://{org}{path}"))?;
        url.query_pairs_mut().append_pair("limit", "200");
        if let Some(filter) = filter {
            url.query_pairs_mut().append_pair("filter", filter);
        }
        Ok(Self { url, filter })
    }
    fn next(&self, raw: &str) -> Result<Self> {
        ensure!(
            raw.len() <= 8192 && !raw.chars().any(char::is_control),
            "Invalid Okta continuation"
        );
        let url = Url::parse(raw).map_err(|_| anyhow!("Invalid Okta continuation"))?;
        ensure!(
            url.scheme() == "https"
                && url.host_str() == self.url.host_str()
                && url.port().is_none()
                && url.username().is_empty()
                && url.password().is_none()
                && url.fragment().is_none()
                && url.path() == self.url.path(),
            "Okta continuation changed authority or resource"
        );
        let mut seen = BTreeSet::new();
        for (key, value) in url.query_pairs() {
            ensure!(
                seen.insert(key.to_string()),
                "Duplicate Okta continuation parameter"
            );
            match key.as_ref() {
                "after" => ensure!(!value.is_empty(), "Missing Okta cursor"),
                "limit" => ensure!(value == "200", "Okta continuation changed page size"),
                "filter" => ensure!(
                    Some(value.as_ref()) == self.filter,
                    "Okta continuation changed filter"
                ),
                _ => return Err(anyhow!("Unsupported Okta continuation parameter")),
            }
        }
        ensure!(
            seen.contains("after")
                && seen.contains("limit")
                && seen.contains("filter") == self.filter.is_some(),
            "Incomplete Okta continuation"
        );
        Ok(Self {
            url,
            filter: self.filter,
        })
    }
}
/// Conservative Link parser: opaque URIs may contain commas. Ambiguous or
/// unsupported syntax aborts the collection, never silently truncates it.
fn next_link(headers: &[String]) -> Result<Option<String>> {
    ensure!(
        headers.len() <= 16 && headers.iter().map(String::len).sum::<usize>() <= 16384,
        "Okta Link headers exceed limit"
    );
    let mut next = None;
    for header in headers {
        ensure!(
            !header.chars().any(char::is_control),
            "Invalid Okta Link header"
        );
        let mut start = 0;
        let mut angle = false;
        let mut quote = false;
        let mut escaped = false;
        let mut parts = Vec::new();
        for (i, ch) in header.char_indices() {
            if escaped {
                escaped = false;
                continue;
            }
            match ch {
                '\\' if quote => escaped = true,
                '"' if !angle => quote = !quote,
                '<' if !quote => {
                    ensure!(!angle, "Invalid Okta Link URI");
                    angle = true;
                }
                '>' if !quote => {
                    ensure!(angle, "Invalid Okta Link URI");
                    angle = false;
                }
                ',' if !quote && !angle => {
                    parts.push(&header[start..i]);
                    start = i + 1;
                }
                _ => {}
            }
        }
        ensure!(!angle && !quote && !escaped, "Incomplete Okta Link header");
        parts.push(&header[start..]);
        for part in parts {
            let (uri, attributes) = part
                .trim()
                .strip_prefix('<')
                .and_then(|s| s.split_once('>'))
                .ok_or_else(|| anyhow!("Invalid Okta Link header"))?;
            let relation = attributes
                .trim()
                .strip_prefix(';')
                .map(str::trim)
                .and_then(|s| s.strip_prefix("rel="))
                .ok_or_else(|| anyhow!("Unsupported Okta Link attributes"))?;
            let relation = relation
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .unwrap_or(relation);
            match relation {
                "self" => {}
                "next" => {
                    ensure!(
                        next.is_none() && !uri.is_empty(),
                        "Ambiguous Okta next link"
                    );
                    next = Some(uri.to_string());
                }
                _ => return Err(anyhow!("Unsupported Okta Link relation")),
            }
        }
    }
    Ok(next)
}
struct Page {
    status: u16,
    retry_after: Option<Duration>,
    links: Vec<String>,
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
            .map_err(|_| anyhow!("Okta request unavailable"))?;
        let status = response.status().as_u16();
        let retry_after = response
            .headers()
            .get("retry-after")
            .map(|v| {
                v.to_str()
                    .ok()
                    .and_then(|s| s.parse::<u64>().ok())
                    .map(Duration::from_secs)
                    .unwrap_or(Duration::from_secs(3600))
            })
            .or_else(|| {
                response.headers().get("x-rate-limit-reset").map(|v| {
                    v.to_str()
                        .ok()
                        .and_then(|s| s.parse::<i64>().ok())
                        .and_then(|n| n.checked_sub(crate::now()))
                        .and_then(|n| u64::try_from(n).ok())
                        .map(Duration::from_secs)
                        .unwrap_or(Duration::from_secs(3600))
                })
            });
        let links = if status == 200 {
            response
                .headers()
                .get_all("link")
                .iter()
                .map(|v| {
                    v.to_str()
                        .map(str::to_string)
                        .map_err(|_| anyhow!("Invalid Okta Link header"))
                })
                .collect::<Result<Vec<_>>>()?
        } else {
            vec![]
        };
        let bytes = if status == 200 {
            read_body(response, PAGE_BYTES).await?
        } else {
            vec![]
        };
        Ok(Page {
            status,
            retry_after,
            links,
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
    async fn page<T: Transport>(&mut self, http: &T, request: &Request) -> Result<Page> {
        for attempt in 0..3 {
            ensure!(
                self.requests < self.limits.max_requests,
                "Okta request budget exhausted"
            );
            self.requests += 1;
            let page = http.get(request).await?;
            ensure!(
                page.bytes.len() <= PAGE_BYTES,
                "Okta page exceeds size limit"
            );
            self.bytes = self.bytes.saturating_add(page.bytes.len());
            ensure!(
                self.bytes <= self.limits.max_bytes,
                "Okta byte budget exhausted"
            );
            if page.status == 200 {
                self.pages += 1;
                return Ok(page);
            }
            if matches!(page.status, 429 | 503) && attempt < 2 {
                let delay = page
                    .retry_after
                    .unwrap_or(Duration::from_secs(1 << attempt))
                    .max(Duration::from_millis(100));
                ensure!(
                    delay <= Duration::from_secs(10),
                    "Okta requested a later retry"
                );
                tokio::time::sleep(delay).await;
            } else {
                return Err(anyhow!("Okta collection refused (HTTP {})", page.status));
            }
        }
        Err(anyhow!("Okta retry budget exhausted"))
    }
    async fn collect<T: Transport, V: serde::de::DeserializeOwned>(
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
                "Okta pagination loop"
            );
            let page = self.page(http, &request).await?;
            let values: Vec<V> = serde_json::from_slice(&page.bytes)
                .map_err(|_| anyhow!("Invalid Okta collection response"))?;
            ensure!(
                records.len().saturating_add(values.len()) <= maximum,
                "Okta object limit exceeded"
            );
            records.extend(values);
            match next_link(&page.links)? {
                Some(next) => request = request.next(&next)?,
                None => return Ok(records),
            }
        }
    }
}
fn object_id(id: &str, prefix: &str) -> bool {
    id.starts_with(prefix)
        && (4..=100).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}
#[derive(Deserialize)]
struct User {
    id: String,
    status: Option<String>,
    profile: Profile,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Profile {
    display_name: Option<String>,
    first_name: Option<String>,
    last_name: Option<String>,
    email: Option<String>,
}
#[derive(Deserialize)]
struct RemoteGroup {
    id: String,
    #[serde(rename = "type")]
    kind: String,
    profile: GroupProfile,
}
#[derive(Deserialize)]
struct GroupProfile {
    name: String,
}
#[derive(Deserialize)]
struct RemoteMember {
    id: String,
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
        source.provider == Provider::Okta && source.authority == credentials.org,
        "Okta credential authority mismatch"
    );
    ensure!(
        generation > 0 && generation <= i64::MAX as u64,
        "Invalid directory generation"
    );
    let http = Http {
        client: client_builder()
            .build()
            .map_err(|_| anyhow!("Okta transport unavailable"))?,
        authorization: credentials.authorization.clone(),
    };
    tokio::time::timeout(
        Duration::from_secs(limits.timeout_seconds),
        collect(&http, source, generation, limits, crate::now),
    )
    .await
    .map_err(|_| anyhow!("Okta synchronization deadline exceeded"))?
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
    // Okta's default list omits deprovisioned users. The explicit second pass
    // preserves them. A user crossing the two sets aborts this non-atomic scan.
    let mut users: Vec<User> = budget
        .collect(
            http,
            Request::new(&source.authority, "/api/v1/users", None)?,
            directory::MAX_PEOPLE,
        )
        .await?;
    ensure!(
        users
            .iter()
            .all(|u| u.status.as_deref() != Some("DEPROVISIONED")),
        "Unexpected Okta default user set"
    );
    let inactive: Vec<User> = budget
        .collect(
            http,
            Request::new(&source.authority, "/api/v1/users", Some(DEPROVISIONED))?,
            directory::MAX_PEOPLE.saturating_sub(users.len()),
        )
        .await?;
    ensure!(
        inactive
            .iter()
            .all(|u| u.status.as_deref() == Some("DEPROVISIONED")),
        "Unexpected Okta deprovisioned user set"
    );
    users.extend(inactive);
    let mut people = Vec::new();
    let mut person_ids = BTreeSet::new();
    for user in users {
        ensure!(
            object_id(&user.id, "00u") && person_ids.insert(user.id.clone()),
            "Invalid or duplicate Okta user ID"
        );
        let profile = user.profile;
        let display_name = profile
            .display_name
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| {
                [
                    profile.first_name.unwrap_or_default(),
                    profile.last_name.unwrap_or_default(),
                ]
                .join(" ")
                .trim()
                .to_string()
            });
        let addresses = match profile.email.filter(|s| !s.is_empty()) {
            Some(s) => {
                BTreeSet::from([mailbox(&s).map_err(|_| anyhow!("Invalid Okta email address"))?])
            }
            None => BTreeSet::new(),
        };
        let activity = match user.status.as_deref() {
            Some("ACTIVE") => Activity::Active,
            Some("DEPROVISIONED" | "SUSPENDED") => Activity::Inactive,
            _ => Activity::Unknown,
        };
        people.push(Person {
            id: user.id,
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
            Request::new(&source.authority, "/api/v1/groups", None)?,
            directory::MAX_GROUPS,
        )
        .await?;
    let mut groups = Vec::new();
    let mut group_ids = BTreeSet::new();
    for group in remote_groups {
        ensure!(
            object_id(&group.id, "00g")
                && group_ids.insert(group.id.clone())
                && matches!(group.kind.as_str(), "OKTA_GROUP" | "APP_GROUP" | "BUILT_IN"),
            "Invalid or duplicate Okta group"
        );
        groups.push(Group {
            id: group.id,
            display_name: group.profile.name,
            activity: Activity::Active,
            addresses: BTreeSet::new(),
            protected: false,
        });
    }
    let mut memberships = BTreeSet::new();
    for group in &groups {
        let members: Vec<RemoteMember> = budget
            .collect(
                http,
                Request::new(
                    &source.authority,
                    &format!("/api/v1/groups/{}/users", group.id),
                    None,
                )?,
                directory::MAX_MEMBERSHIPS.saturating_sub(memberships.len()),
            )
            .await?;
        for member in members {
            ensure!(
                person_ids.contains(&member.id),
                "Okta membership refers to a missing user; retry a complete collection"
            );
            ensure!(
                memberships.insert(Membership {
                    group: group.id.clone(),
                    member: Member::Person(member.id)
                }),
                "Duplicate Okta membership"
            );
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
        excluded_members: BTreeMap::new(),
    })
}
#[cfg(test)]
mod tests;
