//! Read-only Microsoft Entra collection. Public-cloud client credentials are
//! acquired against the administrator-selected tenant; no recipient scope or
//! protected role is accepted from remote data. Returns a candidate only.
pub use super::graph::Credentials;
use super::graph::{self, Page, Request, Transport};
use crate::identity::{
    directory::{
        self, Activity, Group, Kind, Member, Membership, Person, Provider, Snapshot, Source,
    },
    mailbox,
};
use anyhow::{Result, anyhow, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub timeout_seconds: u64,
    pub max_requests: usize,
    pub max_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            timeout_seconds: 300,
            max_requests: 4096,
            max_bytes: 64 * 1024 * 1024,
        }
    }
}
impl Limits {
    pub(super) fn validate(&self) -> Result<()> {
        ensure!(
            (1..=900).contains(&self.timeout_seconds)
                && (1..=10000).contains(&self.max_requests)
                && (1024..=128 * 1024 * 1024).contains(&self.max_bytes),
            "Invalid directory sync limits"
        );
        Ok(())
    }
}
#[derive(Debug, Serialize)]
pub struct Collected {
    pub snapshot: Snapshot,
    pub requests: usize,
    pub pages: usize,
    pub bytes: usize,
    /// Known non-mail-identity member types are excluded explicitly. Unknown
    /// types or missing person/group references abort the candidate.
    pub excluded_members: BTreeMap<String, usize>,
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
                "Directory request budget exhausted"
            );
            self.requests += 1;
            let Page {
                status,
                retry_after,
                bytes,
            } = http.get(request).await?;
            ensure!(
                bytes.len() <= graph::PAGE_BYTES,
                "Directory page exceeds size limit"
            );
            self.bytes = self
                .bytes
                .checked_add(bytes.len())
                .ok_or_else(|| anyhow!("Directory byte budget exhausted"))?;
            ensure!(
                self.bytes <= self.limits.max_bytes,
                "Directory byte budget exhausted"
            );
            if status == 200 {
                self.pages += 1;
                return Ok(bytes);
            }
            if matches!(status, 429 | 503) && attempt < 2 {
                let delay = retry_after.unwrap_or(Duration::from_secs(1 << attempt));
                ensure!(
                    delay <= Duration::from_secs(10),
                    "Directory provider requested a later retry"
                );
                tokio::time::sleep(delay).await;
            } else {
                return Err(anyhow!("Directory request refused (HTTP {status})"));
            }
        }
        Err(anyhow!("Directory retry budget exhausted"))
    }
    async fn collect<T: Transport>(
        &mut self,
        http: &T,
        mut request: Request,
        maximum: usize,
    ) -> Result<Vec<Value>> {
        #[derive(Deserialize)]
        struct Collection {
            value: Vec<Value>,
            #[serde(rename = "@odata.nextLink")]
            next: Option<String>,
            #[serde(rename = "@odata.deltaLink")]
            delta: Option<Value>,
        }
        let mut visited = BTreeSet::new();
        let mut records = Vec::new();
        loop {
            ensure!(
                visited.insert(request.identity().to_string()),
                "Directory pagination loop"
            );
            let bytes = self.page(http, &request).await?;
            let page: Collection = serde_json::from_slice(&bytes)
                .map_err(|_| anyhow!("Invalid directory collection"))?;
            ensure!(
                page.delta.is_none(),
                "A delta response cannot replace a full directory"
            );
            ensure!(
                records.len().saturating_add(page.value.len()) <= maximum,
                "Directory collection exceeds object limit"
            );
            records.extend(page.value);
            match page.next {
                Some(next) => request = request.next(&next)?,
                None => return Ok(records),
            }
        }
    }
}

fn guid(value: &str) -> Result<String> {
    let id = uuid::Uuid::parse_str(value).map_err(|_| anyhow!("Invalid Entra object ID"))?;
    ensure!(value.len() == 36 && !id.is_nil(), "Invalid Entra object ID");
    Ok(id.to_string())
}
fn explicit_addresses(mail: Option<String>, aliases: Vec<String>) -> Result<BTreeSet<String>> {
    ensure!(aliases.len() <= 128, "Directory alias count exceeds limit");
    let mut result = BTreeSet::new();
    if let Some(mail) = mail
        && !mail.is_empty()
    {
        result.insert(mailbox(&mail).map_err(|_| anyhow!("Invalid directory email address"))?);
    }
    for alias in aliases {
        if let Some((scheme, address)) = alias.split_once(':')
            && scheme.eq_ignore_ascii_case("smtp")
        {
            result.insert(mailbox(address).map_err(|_| anyhow!("Invalid directory SMTP alias"))?);
        }
    }
    ensure!(
        result.len() <= 32,
        "Directory email alias count exceeds limit"
    );
    Ok(result)
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct User {
    id: String,
    display_name: String,
    mail: Option<String>,
    proxy_addresses: Vec<String>,
    account_enabled: Option<bool>,
    #[serde(rename = "@odata.type")]
    object_type: Option<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RemoteGroup {
    id: String,
    display_name: String,
    mail: Option<String>,
    proxy_addresses: Vec<String>,
    #[serde(rename = "@odata.type")]
    object_type: Option<String>,
}

/// No live provider call occurs unless this function is explicitly invoked by an
/// authorized asynchronous sync job. No global state is changed on any outcome.
pub async fn synchronize(
    source: &Source,
    generation: u64,
    credentials: &Credentials,
    limits: Limits,
) -> Result<Collected> {
    source.validate()?;
    limits.validate()?;
    ensure!(
        source.provider == Provider::Entra
            && guid(&source.authority)? == credentials.tenant.to_string(),
        "Directory credential authority mismatch"
    );
    ensure!(
        generation > 0 && generation <= i64::MAX as u64,
        "Invalid directory generation"
    );
    tokio::time::timeout(Duration::from_secs(limits.timeout_seconds), async {
        let http = graph::Http::authenticate(credentials).await?;
        collect(&http, source, generation, limits, crate::now).await
    })
    .await
    .map_err(|_| anyhow!("Directory synchronization deadline exceeded"))?
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
    let values = budget
        .collect(
            http,
            Request::collection(
                "/v1.0/users",
                "id,displayName,mail,proxyAddresses,accountEnabled",
            )?,
            directory::MAX_PEOPLE,
        )
        .await?;
    let mut people = Vec::new();
    let mut person_ids = BTreeSet::new();
    for value in values {
        ensure!(
            value.get("@removed").is_none(),
            "Removed record in a full directory"
        );
        let user: User = serde_json::from_value(value)
            .map_err(|_| anyhow!("Incomplete directory user properties"))?;
        ensure!(
            user.object_type
                .as_deref()
                .is_none_or(|kind| kind == "#microsoft.graph.user"),
            "Unsupported directory user type"
        );
        let id = guid(&user.id)?;
        ensure!(
            person_ids.insert(id.clone()),
            "Duplicate directory person ID"
        );
        people.push(Person {
            id,
            display_name: user.display_name,
            kind: Kind::Person,
            activity: match user.account_enabled {
                Some(true) => Activity::Active,
                Some(false) => Activity::Inactive,
                None => Activity::Unknown,
            },
            addresses: explicit_addresses(user.mail, user.proxy_addresses)?,
            protected_roles: BTreeSet::new(),
        });
    }
    let values = budget
        .collect(
            http,
            Request::collection("/v1.0/groups", "id,displayName,mail,proxyAddresses")?,
            directory::MAX_GROUPS,
        )
        .await?;
    let mut groups = Vec::new();
    let mut group_ids = BTreeSet::new();
    for value in values {
        ensure!(
            value.get("@removed").is_none(),
            "Removed record in a full directory"
        );
        let group: RemoteGroup = serde_json::from_value(value)
            .map_err(|_| anyhow!("Incomplete directory group properties"))?;
        ensure!(
            group
                .object_type
                .as_deref()
                .is_none_or(|kind| kind == "#microsoft.graph.group"),
            "Unsupported directory group type"
        );
        let id = guid(&group.id)?;
        ensure!(group_ids.insert(id.clone()), "Duplicate directory group ID");
        groups.push(Group {
            id,
            display_name: group.display_name,
            activity: Activity::Active,
            addresses: explicit_addresses(group.mail, group.proxy_addresses)?,
            protected: false,
        });
    }
    let mut memberships = BTreeSet::new();
    let mut excluded_members = BTreeMap::new();
    let mut observed_members = 0usize;
    for group in &groups {
        let request = Request::collection(&format!("/v1.0/groups/{}/members", group.id), "id")?;
        let values = budget
            .collect(
                http,
                request,
                directory::MAX_MEMBERSHIPS.saturating_sub(observed_members),
            )
            .await?;
        observed_members += values.len();
        let mut group_members = BTreeSet::new();
        for value in values {
            let id = guid(
                value
                    .get("id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("Missing directory member identity"))?,
            )?;
            let kind = value
                .get("@odata.type")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("Missing directory member type"))?;
            ensure!(
                group_members.insert((kind.to_string(), id.clone())),
                "Duplicate directory group member"
            );
            let member = match kind {
                "#microsoft.graph.user" => {
                    ensure!(
                        person_ids.contains(&id),
                        "Directory changed during synchronization; user missing"
                    );
                    Member::Person(id)
                }
                "#microsoft.graph.group" => {
                    ensure!(
                        group_ids.contains(&id),
                        "Directory changed during synchronization; group missing"
                    );
                    Member::Group(id)
                }
                "#microsoft.graph.device"
                | "#microsoft.graph.servicePrincipal"
                | "#microsoft.graph.orgContact" => {
                    *excluded_members
                        .entry(kind.trim_start_matches("#microsoft.graph.").to_string())
                        .or_insert(0) += 1;
                    continue;
                }
                _ => return Err(anyhow!("Unsupported directory group member type")),
            };
            memberships.insert(Membership {
                group: group.id.clone(),
                member,
            });
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
mod tests {
    use super::*;
    use std::{collections::VecDeque, sync::Mutex};
    const NOW: i64 = 1800000000;
    const USERS1: &[u8] = include_bytes!("../../../tests/fixtures/identity/entra/users-1.json");
    const USERS2: &[u8] = include_bytes!("../../../tests/fixtures/identity/entra/users-2.json");
    const GROUPS: &[u8] = include_bytes!("../../../tests/fixtures/identity/entra/groups.json");
    const MEMBERS: &[u8] = include_bytes!("../../../tests/fixtures/identity/entra/members.json");
    struct Fixture {
        pages: Mutex<VecDeque<Page>>,
        paths: Mutex<Vec<String>>,
    }
    impl Fixture {
        fn new(values: &[&[u8]]) -> Self {
            Self {
                pages: Mutex::new(
                    values
                        .iter()
                        .map(|bytes| Page {
                            status: 200,
                            retry_after: None,
                            bytes: bytes.to_vec(),
                        })
                        .collect(),
                ),
                paths: Mutex::new(vec![]),
            }
        }
        fn count(&self) -> usize {
            self.paths.lock().unwrap().len()
        }
    }
    impl Transport for Fixture {
        async fn get(&self, request: &Request) -> Result<Page> {
            self.paths
                .lock()
                .unwrap()
                .push(request.identity().to_string());
            self.pages
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| anyhow!("Unexpected fixture request"))
        }
    }
    fn source() -> Source {
        Source {
            id: "tenant-a".into(),
            provider: Provider::Entra,
            label: "Synthetic Entra".into(),
            authority: "40000000-0000-4000-8000-000000000001".into(),
            scopes: BTreeSet::from(["example.test".into()]),
            stale_after_seconds: 86400,
        }
    }
    async fn run(fixture: &Fixture) -> Result<Collected> {
        collect(fixture, &source(), 1, Limits::default(), || NOW).await
    }
    #[tokio::test]
    async fn paginated_source_preserves_only_explicit_mail_and_local_authority() {
        let fixture = Fixture::new(&[USERS1, USERS2, GROUPS, MEMBERS]);
        let result = run(&fixture).await.unwrap();
        assert_eq!((result.pages, result.requests), (4, 4));
        assert_eq!(result.snapshot.source, source());
        assert_eq!(result.snapshot.people.len(), 3);
        assert_eq!(
            result.snapshot.people[0].addresses,
            BTreeSet::from(["Alice@example.test".into(), "finance@example.test".into()])
        );
        assert!(result.snapshot.people[0].protected_roles.is_empty());
        assert!(result.snapshot.people[1].addresses.is_empty());
        assert_eq!(result.snapshot.people[1].activity, Activity::Inactive);
        assert_eq!(result.snapshot.people[2].activity, Activity::Unknown);
        assert!(!result.snapshot.groups[0].protected);
        assert_eq!(result.snapshot.memberships.len(), 2);
        assert_eq!(result.excluded_members.get("device"), Some(&1));
        assert_eq!(result.snapshot.completed_at, NOW);
        assert!(result.snapshot.delegations.is_empty());
    }
    #[tokio::test]
    async fn refused_second_page_never_yields_a_partial_replacement() {
        let fixture = Fixture::new(&[USERS1]);
        fixture.pages.lock().unwrap().push_back(Page {
            status: 403,
            retry_after: None,
            bytes: vec![],
        });
        assert!(run(&fixture).await.unwrap_err().to_string().contains("403"));
        assert_eq!(fixture.count(), 2);
    }
    #[tokio::test]
    async fn redirects_and_unapproved_continuations_are_not_followed() {
        let fixture = Fixture::new(&[]);
        fixture.pages.lock().unwrap().push_back(Page {
            status: 302,
            retry_after: None,
            bytes: vec![],
        });
        assert!(run(&fixture).await.is_err());
        assert_eq!(fixture.count(), 1);
        let mut value: Value = serde_json::from_slice(USERS1).unwrap();
        value["@odata.nextLink"] = "https://attacker.test/leak?secret=private".into();
        let bytes = serde_json::to_vec(&value).unwrap();
        let fixture = Fixture::new(&[&bytes]);
        let error = run(&fixture).await.unwrap_err().to_string();
        assert!(!error.contains("private"));
        assert_eq!(fixture.count(), 1);
    }
    #[tokio::test]
    async fn provider_backoff_is_bounded_and_never_ignored() {
        let fixture = Fixture::new(&[USERS1, USERS2, GROUPS, MEMBERS]);
        fixture.pages.lock().unwrap().push_front(Page {
            status: 429,
            retry_after: Some(Duration::ZERO),
            bytes: vec![],
        });
        assert_eq!(run(&fixture).await.unwrap().requests, 5);
        let fixture = Fixture::new(&[]);
        fixture.pages.lock().unwrap().push_back(Page {
            status: 503,
            retry_after: Some(Duration::from_secs(60)),
            bytes: vec![],
        });
        assert!(
            run(&fixture)
                .await
                .unwrap_err()
                .to_string()
                .contains("later retry")
        );
        assert_eq!(fixture.count(), 1);
    }
    #[tokio::test]
    async fn request_and_byte_budgets_abort_the_whole_candidate() {
        let fixture = Fixture::new(&[USERS1, USERS2, GROUPS, MEMBERS]);
        let limits = Limits {
            max_requests: 1,
            ..Limits::default()
        };
        assert!(
            collect(&fixture, &source(), 1, limits, || NOW)
                .await
                .is_err()
        );
        assert_eq!(fixture.count(), 1);
        let fixture = Fixture::new(&[USERS1]);
        let limits = Limits {
            max_bytes: 1,
            ..Limits::default()
        };
        assert!(
            collect(&fixture, &source(), 1, limits, || NOW)
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn malformed_partial_delta_and_duplicated_objects_are_rejected() {
        for bytes in [
            b"{}".as_slice(),
            b"{\"value\":null}",
            b"{\"value\":[],\"@odata.deltaLink\":\"private\"}",
            b"{\"value\":[{\"@removed\":{}}]}",
        ] {
            assert!(run(&Fixture::new(&[bytes])).await.is_err());
        }
        let mut value: Value = serde_json::from_slice(USERS1).unwrap();
        value.as_object_mut().unwrap().remove("@odata.nextLink");
        let user = value["value"][0].clone();
        value["value"].as_array_mut().unwrap().push(user);
        assert!(
            run(&Fixture::new(&[&serde_json::to_vec(&value).unwrap()]))
                .await
                .is_err()
        );
        value["value"][0]
            .as_object_mut()
            .unwrap()
            .remove("proxyAddresses");
        assert!(
            run(&Fixture::new(&[&serde_json::to_vec(&value).unwrap()]))
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn missing_membership_reference_and_unknown_member_types_abort_sync() {
        for kind in ["#microsoft.graph.user", "#microsoft.graph.unrecognized"] {
            let members = serde_json::to_vec(&serde_json::json!({"value":[{"id":"50000000-0000-4000-8000-000000000001","@odata.type":kind}]})).unwrap();
            assert!(
                run(&Fixture::new(&[USERS1, USERS2, GROUPS, &members]))
                    .await
                    .is_err()
            );
        }
    }
    #[tokio::test]
    async fn duplicate_members_are_not_silently_deduplicated_during_collection() {
        let mut value: Value = serde_json::from_slice(MEMBERS).unwrap();
        let first = value["value"][0].clone();
        value["value"].as_array_mut().unwrap().push(first);
        assert!(
            run(&Fixture::new(&[
                USERS1,
                USERS2,
                GROUPS,
                &serde_json::to_vec(&value).unwrap()
            ]))
            .await
            .is_err()
        );
    }
    #[tokio::test]
    async fn empty_successful_source_is_explicit_and_still_requires_deletion_review() {
        let old = run(&Fixture::new(&[USERS1, USERS2, GROUPS, MEMBERS]))
            .await
            .unwrap()
            .snapshot;
        let next = collect(
            &Fixture::new(&[b"{\"value\":[]}", b"{\"value\":[]}"]),
            &source(),
            2,
            Limits::default(),
            || NOW + 1,
        )
        .await
        .unwrap();
        let change = directory::changes(Some(&old), &next.snapshot, NOW + 1).unwrap();
        assert!(change.requires_review);
        assert_eq!(change.removed_or_disabled, 2);
    }
    #[tokio::test]
    async fn authority_mismatch_fails_before_authentication_or_network() {
        let credentials = Credentials::new(
            "40000000-0000-4000-8000-000000000099",
            "40000000-0000-4000-8000-000000000098",
            "fixture-only".into(),
        )
        .unwrap();
        assert!(
            synchronize(&source(), 1, &credentials, Limits::default())
                .await
                .unwrap_err()
                .to_string()
                .contains("authority mismatch")
        );
    }
    #[test]
    fn alias_parsing_never_guesses_login_or_protected_roles() {
        assert_eq!(
            explicit_addresses(
                None,
                vec![
                    "SIP:alice@example.test".into(),
                    "smtp:Alias@EXAMPLE.TEST".into()
                ]
            )
            .unwrap(),
            BTreeSet::from(["Alias@example.test".into()])
        );
        assert!(explicit_addresses(Some("not a mailbox".into()), vec![]).is_err());
        assert!(explicit_addresses(None, vec!["smtp:bad".into()]).is_err());
    }
}
