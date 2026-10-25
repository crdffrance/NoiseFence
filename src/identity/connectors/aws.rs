//! Read-only Identity Store collection. SigV4 is confined to three fixed JSON
//! operations at approved commercial-region hosts; no environment credentials.
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
    Client,
    header::{AUTHORIZATION, HeaderMap, HeaderValue},
};
use ring::hmac;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    time::Duration,
};

const REGIONS: &[&str] = &[
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "af-south-1",
    "ap-east-1",
    "ap-east-2",
    "ap-south-1",
    "ap-south-2",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-southeast-3",
    "ap-southeast-4",
    "ap-southeast-5",
    "ap-southeast-6",
    "ap-southeast-7",
    "ap-northeast-1",
    "ap-northeast-2",
    "ap-northeast-3",
    "ca-central-1",
    "ca-west-1",
    "eu-central-1",
    "eu-central-2",
    "eu-west-1",
    "eu-west-2",
    "eu-west-3",
    "eu-north-1",
    "eu-south-1",
    "eu-south-2",
    "il-central-1",
    "mx-central-1",
    "me-south-1",
    "me-central-1",
    "sa-east-1",
];
fn hex_id(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn uuid_id(s: &str) -> bool {
    s.len() == 36 && uuid::Uuid::parse_str(s).is_ok_and(|u| u.to_string() == s && !u.is_nil())
}
fn resource_id(s: &str) -> bool {
    s.is_ascii()
        && (uuid_id(s)
            || (s.len() == 47
                && hex_id(&s[..10], 10)
                && s.as_bytes()[10] == b'-'
                && uuid_id(&s[11..])))
}
fn authority(raw: &str) -> Result<(&str, &str)> {
    let (region, store) = raw
        .split_once(':')
        .ok_or_else(|| anyhow!("Expected AWS region:identity-store-id"))?;
    ensure!(REGIONS.contains(&region), "Unsupported AWS region");
    ensure!(
        store.strip_prefix("d-").is_some_and(|s| hex_id(s, 10)) || uuid_id(store),
        "Invalid AWS identity store ID"
    );
    Ok((region, store))
}
fn token(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+/=._~-".contains(&b))
}
// Intentionally not Debug or Serialize. Only explicit short-lived STS credentials.
pub struct Credentials {
    authority: String,
    region: String,
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
}
impl Credentials {
    pub fn new(
        raw: &str,
        access_key_id: String,
        secret_access_key: String,
        session_token: String,
    ) -> Result<Self> {
        let (region, _) = authority(raw)?;
        ensure!(
            access_key_id.len() == 20
                && access_key_id.starts_with("ASIA")
                && access_key_id
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()),
            "Use a temporary AWS access key ID"
        );
        ensure!(
            secret_access_key.len() == 40
                && token(&secret_access_key, 40)
                && token(&session_token, 8192),
            "Invalid temporary AWS credential"
        );
        Ok(Self {
            authority: raw.into(),
            region: region.into(),
            access_key_id,
            secret_access_key,
            session_token,
        })
    }
}
#[derive(Clone, Copy)]
enum Operation {
    Users,
    Groups,
    Memberships,
}
impl Operation {
    fn target(self) -> &'static str {
        match self {
            Self::Users => "AWSIdentityStore.ListUsers",
            Self::Groups => "AWSIdentityStore.ListGroups",
            Self::Memberships => "AWSIdentityStore.ListGroupMemberships",
        }
    }
    fn field(self) -> &'static str {
        match self {
            Self::Users => "Users",
            Self::Groups => "Groups",
            Self::Memberships => "GroupMemberships",
        }
    }
}
struct Request {
    operation: Operation,
    body: Vec<u8>,
}
fn mac(key: &[u8], bytes: &[u8]) -> Vec<u8> {
    hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), bytes)
        .as_ref()
        .to_vec()
}
fn signed_headers(credentials: &Credentials, request: &Request, now: i64) -> Result<HeaderMap> {
    ensure!(
        (946684800..=4102444799).contains(&now),
        "AWS signing clock out of range"
    );
    let d = mail_parser::DateTime::from_timestamp(now);
    let day = format!("{:04}{:02}{:02}", d.year, d.month, d.day);
    let stamp = format!("{day}T{:02}{:02}{:02}Z", d.hour, d.minute, d.second);
    let host = format!("identitystore.{}.amazonaws.com", credentials.region);
    let scope = format!("{day}/{}/identitystore/aws4_request", credentials.region);
    let mut values = BTreeMap::from([
        ("content-type", "application/x-amz-json-1.1".to_owned()),
        ("host", host),
        ("x-amz-date", stamp.clone()),
        ("x-amz-security-token", credentials.session_token.clone()),
        ("x-amz-target", request.operation.target().to_owned()),
    ]);
    let names = values.keys().copied().collect::<Vec<_>>().join(";");
    let canonical_headers = values
        .iter()
        .map(|(k, v)| format!("{k}:{v}\n"))
        .collect::<String>();
    let canonical = format!(
        "POST\n/\n\n{canonical_headers}\n{names}\n{}",
        crate::message::digest(&request.body)
    );
    let to_sign = format!(
        "AWS4-HMAC-SHA256\n{stamp}\n{scope}\n{}",
        crate::message::digest(canonical.as_bytes())
    );
    let date_key = mac(
        format!("AWS4{}", credentials.secret_access_key).as_bytes(),
        day.as_bytes(),
    );
    let region_key = mac(&date_key, credentials.region.as_bytes());
    let service_key = mac(&region_key, b"identitystore");
    let key = mac(&service_key, b"aws4_request");
    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={names}, Signature={}",
        credentials.access_key_id,
        hex::encode(mac(&key, to_sign.as_bytes()))
    );
    values.insert("authorization", authorization);
    let mut headers = HeaderMap::new();
    for (name, value) in values {
        let mut header =
            HeaderValue::from_str(&value).map_err(|_| anyhow!("Invalid AWS signing header"))?;
        if name == "x-amz-security-token" || name == AUTHORIZATION {
            header.set_sensitive(true);
        }
        headers.insert(name, header);
    }
    Ok(headers)
}
struct Page {
    status: u16,
    throttled: bool,
    retry_after: Option<Duration>,
    bytes: Vec<u8>,
}
trait Transport: Sync {
    fn post(&self, request: &Request) -> impl Future<Output = Result<Page>> + Send;
}
struct Http<'a> {
    client: Client,
    credentials: &'a Credentials,
}
impl Transport for Http<'_> {
    async fn post(&self, request: &Request) -> Result<Page> {
        let response = self
            .client
            .post(format!(
                "https://identitystore.{}.amazonaws.com/",
                self.credentials.region
            ))
            .headers(signed_headers(self.credentials, request, crate::now())?)
            .body(request.body.clone())
            .send()
            .await
            .map_err(|_| anyhow!("AWS Identity Store unavailable"))?;
        let status = response.status().as_u16();
        let retry_after = response.headers().get("retry-after").map(|h| {
            h.to_str()
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .map(Duration::from_secs)
                .unwrap_or(Duration::from_secs(3600))
        });
        let bytes = read_body(response, if status == 200 { PAGE_BYTES } else { 16384 }).await?;
        let error: Value = if status == 200 {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(Value::Null)
        };
        let throttled = error
            .get("__type")
            .and_then(Value::as_str)
            .is_some_and(|s| s.rsplit('#').next() == Some("ThrottlingException"));
        let retry_after = retry_after.or_else(|| {
            error.get("RetryAfterSeconds").map(|n| {
                n.as_u64()
                    .map(Duration::from_secs)
                    .unwrap_or(Duration::from_secs(3600))
            })
        });
        Ok(Page {
            status,
            throttled,
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
                "AWS request budget exhausted"
            );
            self.requests += 1;
            let page = http.post(request).await?;
            ensure!(page.bytes.len() <= PAGE_BYTES, "AWS page too large");
            self.bytes = self.bytes.saturating_add(page.bytes.len());
            ensure!(
                self.bytes <= self.limits.max_bytes,
                "AWS byte budget exhausted"
            );
            if page.status == 200 {
                self.pages += 1;
                return Ok(page.bytes);
            }
            if (matches!(page.status, 429 | 500 | 503) || (page.status == 400 && page.throttled))
                && attempt < 2
            {
                let delay = page
                    .retry_after
                    .unwrap_or(Duration::from_secs(1 << attempt))
                    .max(Duration::from_millis(100));
                ensure!(
                    delay <= Duration::from_secs(10),
                    "AWS requested a later retry"
                );
                tokio::time::sleep(delay).await;
            } else {
                return Err(anyhow!("AWS collection refused (HTTP {})", page.status));
            }
        }
        Err(anyhow!("AWS retry budget exhausted"))
    }
    async fn collect<T: Transport, V: serde::de::DeserializeOwned>(
        &mut self,
        http: &T,
        store: &str,
        operation: Operation,
        group: Option<&str>,
        maximum: usize,
    ) -> Result<Vec<V>> {
        let mut visited = BTreeSet::new();
        let mut next: Option<String> = None;
        let mut records = Vec::new();
        loop {
            let mut body = json!({"IdentityStoreId":store,"MaxResults":100});
            if let Some(g) = group {
                body["GroupId"] = json!(g);
            }
            if let Some(token) = &next {
                body["NextToken"] = json!(token);
            }
            let bytes = self
                .page(
                    http,
                    &Request {
                        operation,
                        body: serde_json::to_vec(&body)?,
                    },
                )
                .await?;
            let mut page: Value = serde_json::from_slice(&bytes)
                .map_err(|_| anyhow!("Invalid AWS collection response"))?;
            let list = page
                .get_mut(operation.field())
                .ok_or_else(|| anyhow!("AWS response lacks collection"))?
                .take();
            let values: Vec<V> = serde_json::from_value(list)
                .map_err(|_| anyhow!("Invalid AWS collection records"))?;
            ensure!(
                values.len() <= 100 && records.len().saturating_add(values.len()) <= maximum,
                "AWS object limit exceeded"
            );
            records.extend(values);
            match page.get("NextToken") {
                None | Some(Value::Null) => return Ok(records),
                Some(Value::String(s))
                    if !s.is_empty()
                        && s.len() <= 65535
                        && s.bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"-+=/:_".contains(&b))
                        && visited.insert(crate::message::digest(s.as_bytes())) =>
                {
                    next = Some(s.clone())
                }
                _ => return Err(anyhow!("Invalid or repeated AWS pagination token")),
            }
        }
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct User {
    identity_store_id: String,
    user_id: String,
    display_name: Option<String>,
    name: Option<Name>,
    user_status: Option<String>,
    #[serde(default)]
    emails: Vec<Email>,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Name {
    given_name: Option<String>,
    family_name: Option<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Email {
    value: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RemoteGroup {
    identity_store_id: String,
    group_id: String,
    display_name: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct RemoteMember {
    identity_store_id: String,
    group_id: String,
    membership_id: String,
    member_id: UserMember,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct UserMember {
    user_id: String,
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
        source.provider == Provider::AwsIdentityStore && source.authority == credentials.authority,
        "AWS credential authority mismatch"
    );
    ensure!(
        generation > 0 && generation <= i64::MAX as u64,
        "Invalid directory generation"
    );
    let http = Http {
        client: client_builder()
            .build()
            .map_err(|_| anyhow!("AWS transport unavailable"))?,
        credentials,
    };
    tokio::time::timeout(
        Duration::from_secs(limits.timeout_seconds),
        collect(&http, source, generation, limits, crate::now),
    )
    .await
    .map_err(|_| anyhow!("AWS synchronization deadline exceeded"))?
}
async fn collect<T: Transport>(
    http: &T,
    source: &Source,
    generation: u64,
    limits: Limits,
    now: impl Fn() -> i64,
) -> Result<Collected> {
    let (_, store) = authority(&source.authority)?;
    let mut budget = Budget {
        limits,
        requests: 0,
        pages: 0,
        bytes: 0,
    };
    let users: Vec<User> = budget
        .collect(http, store, Operation::Users, None, directory::MAX_PEOPLE)
        .await?;
    let mut people = Vec::new();
    let mut ids = BTreeSet::new();
    for mut u in users {
        u.user_id.make_ascii_lowercase();
        ensure!(
            u.identity_store_id == store
                && u.user_id.is_ascii()
                && resource_id(&u.user_id)
                && ids.insert(u.user_id.clone()),
            "AWS user authority or ID mismatch"
        );
        let display_name = u
            .display_name
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| {
                u.name
                    .map(|n| {
                        [
                            n.given_name.unwrap_or_default(),
                            n.family_name.unwrap_or_default(),
                        ]
                        .join(" ")
                        .trim()
                        .to_owned()
                    })
                    .unwrap_or_default()
            });
        ensure!(u.emails.len() <= 100, "AWS email limit exceeded");
        let addresses = u
            .emails
            .into_iter()
            .map(|e| mailbox(&e.value).map_err(|_| anyhow!("Invalid AWS email address")))
            .collect::<Result<BTreeSet<_>>>()?;
        let activity = match u.user_status.as_deref() {
            Some("ENABLED") => Activity::Active,
            Some("DISABLED") => Activity::Inactive,
            _ => Activity::Unknown,
        };
        people.push(Person {
            id: u.user_id,
            display_name,
            kind: Kind::Person,
            activity,
            addresses,
            protected_roles: BTreeSet::new(),
        });
    }
    let remote: Vec<RemoteGroup> = budget
        .collect(http, store, Operation::Groups, None, directory::MAX_GROUPS)
        .await?;
    let mut groups = Vec::new();
    let mut group_ids = BTreeSet::new();
    for mut g in remote {
        g.group_id.make_ascii_lowercase();
        ensure!(
            g.identity_store_id == store
                && g.group_id.is_ascii()
                && resource_id(&g.group_id)
                && group_ids.insert(g.group_id.clone()),
            "AWS group authority or ID mismatch"
        );
        groups.push(Group {
            id: g.group_id,
            display_name: g.display_name,
            activity: Activity::Active,
            addresses: BTreeSet::new(),
            protected: false,
        });
    }
    let mut memberships = BTreeSet::new();
    let mut member_ids = BTreeSet::new();
    for g in &groups {
        let members: Vec<RemoteMember> = budget
            .collect(
                http,
                store,
                Operation::Memberships,
                Some(&g.id),
                directory::MAX_MEMBERSHIPS.saturating_sub(memberships.len()),
            )
            .await?;
        for mut m in members {
            m.group_id.make_ascii_lowercase();
            m.membership_id.make_ascii_lowercase();
            m.member_id.user_id.make_ascii_lowercase();
            ensure!(
                m.identity_store_id == store
                    && m.group_id == g.id
                    && m.membership_id.is_ascii()
                    && resource_id(&m.membership_id)
                    && member_ids.insert(m.membership_id),
                "AWS membership authority or ID mismatch"
            );
            ensure!(
                ids.contains(&m.member_id.user_id),
                "AWS membership refers to missing user; retry complete collection"
            );
            ensure!(
                memberships.insert(Membership {
                    group: g.id.clone(),
                    member: Member::Person(m.member_id.user_id)
                }),
                "Duplicate AWS membership"
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
