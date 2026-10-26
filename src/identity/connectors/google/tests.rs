use super::*;
use serde_json::json;
use std::sync::Mutex;
const CUSTOMER: &str = "C01234567";
const NOW: i64 = 1792900000;
struct Fixture {
    pages: Mutex<std::collections::VecDeque<Page>>,
    requests: Mutex<Vec<String>>,
}
impl Fixture {
    fn new(pages: Vec<Page>) -> Self {
        Self {
            pages: Mutex::new(pages.into()),
            requests: Mutex::new(vec![]),
        }
    }
}
impl Transport for Fixture {
    async fn get(&self, request: &Request) -> Result<Page> {
        self.requests.lock().unwrap().push(request.url.to_string());
        self.pages
            .lock()
            .unwrap()
            .pop_front()
            .ok_or_else(|| anyhow!("Fixture exhausted"))
    }
}
fn page(value: Value) -> Page {
    Page {
        status: 200,
        retry_after: None,
        bytes: serde_json::to_vec(&value).unwrap(),
    }
}
fn source() -> Source {
    Source {
        id: "google-directory".into(),
        provider: Provider::Google,
        label: "Google Workspace".into(),
        authority: CUSTOMER.into(),
        scopes: BTreeSet::from(["example.test".into()]),
        stale_after_seconds: 86400,
    }
}
fn user(id: &str) -> Value {
    json!({"id":id,"customerId":CUSTOMER,"primaryEmail":format!("person{id}@example.test"),"name":{"fullName":"Alex Example"},"aliases":[format!("alias{id}@example.test")],"nonEditableAliases":[format!("person{id}@alias.example.test")],"suspended":false,"archived":false,"isGuestUser":false,"recoveryEmail":"not-an-alias@external.test","isAdmin":true,"protected_roles":["executive"]})
}
fn fixtures() -> Vec<Page> {
    let mut suspended = user("102");
    suspended["suspended"] = json!(true);
    vec![
        page(
            json!({"kind":"admin#directory#domains","domains":[{"domainName":"example.test","verified":true,"domainAliases":[{"domainAliasName":"alias.example.test","verified":true}]}]}),
        ),
        page(json!({"kind":"admin#directory#users","users":[user("101"),suspended]})),
        page(
            json!({"kind":"admin#directory#groups","groups":[{"id":"g1","email":"finance@example.test","name":"Finance","aliases":["accounts@example.test"]},{"id":"g2","email":"team@example.test","name":"Team"}]}),
        ),
        page(
            json!({"kind":"admin#directory#members","members":[{"id":"101","email":"person101@example.test","type":"USER","status":"ACTIVE"},{"id":"g2","email":"team@example.test","type":"GROUP","status":"ACTIVE"},{"id":"outside","email":"partner@external.test","type":"USER","status":"ACTIVE"},{"id":CUSTOMER,"type":"CUSTOMER"},{"id":"102","email":"person102@example.test","type":"USER","status":"SUSPENDED"}]}),
        ),
        page(json!({"kind":"admin#directory#members"})),
    ]
}
fn edit(pages: &mut [Page], index: usize, f: impl FnOnce(&mut Value)) {
    let mut v = serde_json::from_slice(&pages[index].bytes).unwrap();
    f(&mut v);
    pages[index] = page(v);
}
#[tokio::test]
async fn complete_customer_keeps_aliases_disabled_users_nested_groups_and_visible_exclusions() {
    let fixture = Fixture::new(fixtures());
    let result = collect(&fixture, &source(), 1, Limits::default(), || NOW)
        .await
        .unwrap();
    assert_eq!(result.requests, 5);
    assert_eq!(result.snapshot.people.len(), 2);
    assert_eq!(result.snapshot.people[0].activity, Activity::Active);
    assert_eq!(result.snapshot.people[1].activity, Activity::Inactive);
    assert_eq!(result.snapshot.people[0].addresses.len(), 3);
    assert!(result.snapshot.people[0].protected_roles.is_empty());
    assert!(
        !serde_json::to_string(&result.snapshot)
            .unwrap()
            .contains("not-an-alias")
    );
    assert_eq!(result.snapshot.memberships.len(), 2);
    assert_eq!(
        result.excluded_members,
        BTreeMap::from([
            ("external_membership".into(), 1),
            ("customer_wide_membership".into(), 1),
            ("inactive_or_unknown_membership".into(), 1)
        ])
    );
    assert!(!result.snapshot.groups[0].protected);
    let requests = fixture.requests.lock().unwrap();
    for value in requests.iter() {
        let u = Url::parse(value).unwrap();
        assert_eq!(u.host_str(), Some("admin.googleapis.com"));
        assert_eq!(u.scheme(), "https");
    }
    let users = Url::parse(&requests[1]).unwrap();
    let query: BTreeMap<_, _> = users.query_pairs().collect();
    assert_eq!(query["customer"], CUSTOMER);
    assert_eq!(query["viewType"], "admin_view");
    assert_eq!(query["showDeleted"], "false");
    assert!(!query["fields"].contains("recoveryEmail"));
}
#[test]
fn authority_credentials_and_pagination_never_accept_remote_urls_or_headers() {
    for customer in [
        "my_customer",
        "example.test",
        "https://admin.googleapis.com",
        "C01/other",
        "C01?x=2",
        "C",
        "c123",
    ] {
        assert!(Credentials::new(customer, "test-token".into()).is_err());
    }
    for token in ["", "Bearer test", "x\r\nInjected: yes", " token"] {
        assert!(Credentials::new(CUSTOMER, token.into()).is_err());
    }
    assert!(Credentials::new(CUSTOMER, "test-token".into()).is_ok());
    let req = Request::new(CUSTOMER, Resource::Users).unwrap();
    let next = req
        .next("https://evil.test/path?customer=other&fields=password#token")
        .unwrap();
    assert_eq!(next.url.host_str(), req.url.host_str());
    assert_eq!(next.url.path(), req.url.path());
    let params: BTreeMap<_, _> = next.url.query_pairs().collect();
    assert_eq!(params["customer"], CUSTOMER);
    assert_eq!(params["fields"], Resource::Users.fields());
    assert!(params["pageToken"].starts_with("https://evil.test"));
    for token in ["", "x\n"] {
        assert!(req.next(token).is_err());
    }
    assert!(req.next(&"a".repeat(4097)).is_err());
    assert!(
        Request::new(CUSTOMER, Resource::Domains)
            .unwrap()
            .next("x")
            .is_err()
    );
    for id in ["../users", "x/y", "x?fields=other", "x#token", ""] {
        assert!(Request::new(CUSTOMER, Resource::Members(id.into())).is_err());
    }
}
#[tokio::test]
async fn bounded_paging_and_transient_retry_keep_customer_and_fields() {
    let mut pages = fixtures();
    pages.insert(
        1,
        page(json!({"kind":"admin#directory#users","nextPageToken":"opaque+/=&value"})),
    );
    pages.insert(
        0,
        Page {
            status: 429,
            retry_after: Some(Duration::ZERO),
            bytes: vec![],
        },
    );
    let fixture = Fixture::new(pages);
    let r = collect(&fixture, &source(), 1, Limits::default(), || NOW)
        .await
        .unwrap();
    assert_eq!((r.requests, r.pages), (7, 6));
    let requests = fixture.requests.lock().unwrap();
    let u = Url::parse(&requests[3]).unwrap();
    assert!(
        u.query_pairs()
            .any(|(k, v)| k == "pageToken" && v == "opaque+/=&value")
    );
}
#[tokio::test]
async fn partial_error_wrong_customer_and_wrong_scope_never_produce_a_candidate() {
    for change in 0..8 {
        let mut pages = fixtures();
        match change {
            0 => edit(&mut pages, 1, |v| {
                v["users"][0]["customerId"] = json!("COTHER")
            }),
            1 => edit(&mut pages, 1, |v| v["users"][1]["id"] = json!("101")),
            2 => edit(&mut pages, 1, |v| v["users"] = Value::Null),
            3 => edit(&mut pages, 1, |v| v["kind"] = json!("other")),
            4 => edit(&mut pages, 0, |v| {
                v["domains"][0]["verified"] = json!(false)
            }),
            5 => edit(&mut pages, 3, |v| {
                v["members"][0]["id"] = json!("missing-internal")
            }),
            6 => edit(&mut pages, 3, |v| {
                v["members"][0]["email"] = json!("changed@example.test")
            }),
            _ => {
                pages[3] = Page {
                    status: 403,
                    retry_after: None,
                    bytes: vec![],
                }
            }
        }
        assert!(
            collect(
                &Fixture::new(pages),
                &source(),
                1,
                Limits::default(),
                || NOW
            )
            .await
            .is_err(),
            "change {change}"
        );
    }
}
#[tokio::test]
async fn loops_cycles_and_duplicate_members_are_rejected() {
    let mut pages = fixtures();
    pages.insert(
        1,
        page(json!({"kind":"admin#directory#users","nextPageToken":"repeat"})),
    );
    pages.insert(
        2,
        page(json!({"kind":"admin#directory#users","nextPageToken":"repeat"})),
    );
    assert!(
        collect(
            &Fixture::new(pages),
            &source(),
            1,
            Limits::default(),
            || NOW
        )
        .await
        .is_err()
    );
    for duplicate in [false, true] {
        let mut pages = fixtures();
        if duplicate {
            edit(&mut pages, 3, |v| {
                let member = v["members"][0].clone();
                v["members"].as_array_mut().unwrap().push(member);
            });
        } else {
            edit(
                &mut pages,
                4,
                |v| v["members"] = json!([{"id":"g1","email":"finance@example.test","type":"GROUP","status":"ACTIVE"}]),
            );
        }
        assert!(
            collect(
                &Fixture::new(pages),
                &source(),
                1,
                Limits::default(),
                || NOW
            )
            .await
            .is_err()
        );
    }
}
#[tokio::test]
async fn byte_request_and_retry_budgets_are_global_and_never_return_partial_success() {
    let small = Limits {
        max_requests: 4,
        ..Default::default()
    };
    assert!(
        collect(&Fixture::new(fixtures()), &source(), 1, small, || NOW)
            .await
            .is_err()
    );
    let small = Limits {
        max_bytes: 1024,
        ..Default::default()
    };
    assert!(
        collect(&Fixture::new(fixtures()), &source(), 1, small, || NOW)
            .await
            .is_err()
    );
    for status in [302, 401, 429, 503] {
        let mut pages = fixtures();
        pages[0] = Page {
            status,
            retry_after: Some(Duration::from_secs(11)),
            bytes: vec![],
        };
        assert!(
            collect(
                &Fixture::new(pages),
                &source(),
                1,
                Limits::default(),
                || NOW
            )
            .await
            .is_err()
        );
    }
    let mut pages = fixtures();
    pages[0].bytes = vec![0; PAGE_BYTES + 1];
    assert!(
        collect(
            &Fixture::new(pages),
            &source(),
            1,
            Limits::default(),
            || NOW
        )
        .await
        .is_err()
    );
}
#[tokio::test]
async fn missing_activity_and_non_active_members_never_supply_active_relationships() {
    let mut pages = fixtures();
    edit(&mut pages, 1, |v| {
        v["users"][0].as_object_mut().unwrap().remove("suspended");
    });
    edit(&mut pages, 3, |v| {
        v["members"][0].as_object_mut().unwrap().remove("status");
    });
    let r = collect(
        &Fixture::new(pages),
        &source(),
        1,
        Limits::default(),
        || NOW,
    )
    .await
    .unwrap();
    assert_eq!(r.snapshot.people[0].activity, Activity::Unknown);
    assert_eq!(r.snapshot.memberships.len(), 1);
    assert_eq!(r.excluded_members["inactive_or_unknown_membership"], 2);
}
