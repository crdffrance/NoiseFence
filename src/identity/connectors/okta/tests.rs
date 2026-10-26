use super::*;
use serde_json::{Value, json};
use std::sync::Mutex;
const ORG: &str = "example.okta.com";
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
        links: vec![],
        bytes: serde_json::to_vec(&value).unwrap(),
    }
}
fn user(id: &str, status: &str) -> Value {
    json!({"id":id,"status":status,"profile":{"firstName":"Alex","lastName":"Example","email":format!("{id}@example.test"),"login":"not-an-alias@external.test","secondEmail":"recovery@external.test","protected_roles":["executive"]}})
}
fn source() -> Source {
    Source {
        id: "okta-org".into(),
        provider: Provider::Okta,
        label: "Okta".into(),
        authority: ORG.into(),
        scopes: BTreeSet::from(["example.test".into()]),
        stale_after_seconds: 86400,
    }
}
fn fixtures() -> Vec<Page> {
    vec![
        page(json!([
            user("00uA", "ACTIVE"),
            user("00uB", "SUSPENDED"),
            user("00uC", "LOCKED_OUT")
        ])),
        page(json!([user("00uD", "DEPROVISIONED")])),
        page(
            json!([{"id":"00gA","type":"OKTA_GROUP","profile":{"name":"Finance","email":"not-a-list@example.test"}}]),
        ),
        page(json!([{"id":"00uA"},{"id":"00uD"}])),
    ]
}
#[tokio::test]
async fn complete_snapshot_preserves_disabled_users_without_inventing_trust_or_aliases() {
    let fixture = Fixture::new(fixtures());
    let collected = collect(&fixture, &source(), 1, Limits::default(), || NOW)
        .await
        .unwrap();
    assert_eq!(collected.requests, 4);
    assert_eq!(collected.snapshot.people.len(), 4);
    assert_eq!(collected.snapshot.people[1].activity, Activity::Inactive);
    assert_eq!(collected.snapshot.people[2].activity, Activity::Unknown);
    assert_eq!(collected.snapshot.people[3].activity, Activity::Inactive);
    for p in &collected.snapshot.people {
        assert_eq!(p.addresses.len(), 1);
        assert!(p.protected_roles.is_empty());
    }
    assert!(collected.snapshot.groups[0].addresses.is_empty());
    assert_eq!(collected.snapshot.memberships.len(), 2);
    let requests = fixture.requests.lock().unwrap();
    assert!(
        Url::parse(&requests[1])
            .unwrap()
            .query_pairs()
            .any(|(k, v)| k == "filter" && v == DEPROVISIONED)
    );
}
#[test]
fn org_and_credentials_never_accept_arbitrary_hosts_or_header_injection() {
    for host in [
        "localhost",
        "127.0.0.1",
        "okta.com",
        "example.okta.com.evil.test",
        "x.y.okta.com",
        "Example.okta.com",
        "https://example.okta.com",
        "example.okta.com:443",
        "-example.okta.com",
        "example-.okta.com",
    ] {
        assert!(Credentials::new(host, "private-token".into()).is_err());
    }
    for host in [ORG, "example.okta-emea.com", "example.oktapreview.com"] {
        assert!(Credentials::new(host, "test-token".into()).is_ok());
    }
    for token in ["", "x\r\nsecret", "Bearer x", " x"] {
        assert!(Credentials::new(ORG, token.into()).is_err());
    }
}
#[test]
fn continuation_is_pinned_to_resource_authority_and_filter() {
    let initial = Request::new(ORG, "/api/v1/users", None).unwrap();
    for bad in [
        "http://example.okta.com/api/v1/users?limit=200&after=x",
        "https://example.okta.com.evil.test/api/v1/users?limit=200&after=x",
        "https://example.okta.com/api/v1/groups?limit=200&after=x",
        "https://example.okta.com/api/v1/users?limit=200&after=x&search=foo",
        "https://example.okta.com/api/v1/users?limit=200&after=x&after=y",
        "https://example.okta.com/api/v1/users?after=x",
        "https://example.okta.com/api/v1/users?limit=200&after=x#f",
    ] {
        assert!(initial.next(bad).is_err());
    }
    assert!(
        initial
            .next("https://example.okta.com/api/v1/users?limit=200&after=opaque%2Bcursor")
            .is_ok()
    );
    let filtered = Request::new(ORG, "/api/v1/users", Some(DEPROVISIONED)).unwrap();
    assert!(
        filtered
            .next("https://example.okta.com/api/v1/users?limit=200&after=x")
            .is_err()
    );
    let mut next = filtered.url.clone();
    next.query_pairs_mut().append_pair("after", "opaque");
    assert!(filtered.next(next.as_str()).is_ok());
}
#[test]
fn links_cannot_silently_truncate_or_choose_between_ambiguous_next_pages() {
    assert_eq!(next_link(&[]).unwrap(), None);
    assert_eq!(next_link(&["<https://example.okta.com/a>; rel=\"self\", <https://example.okta.com/a?cursor=a,b>; rel=\"next\"".into()]).unwrap(),Some("https://example.okta.com/a?cursor=a,b".into()));
    for bad in [
        "",
        "<x>; rel=\"next",
        "<x>; rel=\"self next\"",
        "<x>; rel=\"next\", <y>; rel=\"next\"",
        "<x>; title=\"next\"",
        "<x>; rel=\"next\"\n",
    ] {
        assert!(next_link(&[bad.into()]).is_err());
    }
}
#[tokio::test]
async fn pagination_and_transient_retry_are_bounded() {
    let mut pages = fixtures();
    let mut first = page(json!([]));
    first.links =
        vec!["<https://example.okta.com/api/v1/users?limit=200&after=next>; rel=\"next\"".into()];
    pages.insert(0, first);
    pages.insert(
        0,
        Page {
            status: 429,
            retry_after: Some(Duration::ZERO),
            links: vec![],
            bytes: vec![],
        },
    );
    let collected = collect(
        &Fixture::new(pages),
        &source(),
        1,
        Limits::default(),
        || NOW,
    )
    .await
    .unwrap();
    assert_eq!((collected.requests, collected.pages), (6, 5));
    let mut pages = fixtures();
    pages[0].status = 429;
    pages[0].retry_after = Some(Duration::from_secs(60));
    let fixture = Fixture::new(pages);
    assert!(
        collect(&fixture, &source(), 1, Limits::default(), || NOW)
            .await
            .is_err()
    );
    assert_eq!(fixture.requests.lock().unwrap().len(), 1);
}
#[tokio::test]
async fn partial_or_inconsistent_directory_never_returns_a_candidate() {
    for case in 0..9 {
        let mut pages = fixtures();
        let mut limits = Limits::default();
        match case {
            0 => pages[3].status = 403,
            1 => pages[1] = page(json!([user("00uA", "DEPROVISIONED")])),
            2 => pages[1] = page(json!([user("00uD", "ACTIVE")])),
            3 => pages[3] = page(json!([{"id":"00uMissing"}])),
            4 => pages[3] = page(json!([{"id":"00uA"},{"id":"00uA"}])),
            5 => {
                pages[0].links = vec![
                    "<https://elsewhere.test/api/v1/users?after=x&limit=200>; rel=\"next\"".into(),
                ]
            }
            6 => limits.max_requests = 2,
            7 => limits.max_bytes = 1,
            8 => pages[0].bytes = vec![b'x'; PAGE_BYTES + 1],
            _ => unreachable!(),
        }
        assert!(
            collect(&Fixture::new(pages), &source(), 1, limits, || NOW)
                .await
                .is_err(),
            "case {case}"
        );
    }
}
#[tokio::test]
async fn loop_is_rejected_and_authority_mismatch_fails_before_network() {
    let link = "<https://example.okta.com/api/v1/users?after=x&limit=200>; rel=\"next\"";
    let mut a = page(json!([]));
    a.links = vec![link.into()];
    let mut b = page(json!([]));
    b.links = vec![link.into()];
    let fixture = Fixture::new(vec![a, b]);
    assert!(
        collect(&fixture, &source(), 1, Limits::default(), || NOW)
            .await
            .is_err()
    );
    assert_eq!(fixture.requests.lock().unwrap().len(), 2);
    let credentials = Credentials::new("other.okta.com", "test-token".into()).unwrap();
    assert!(
        synchronize(&source(), 1, &credentials, Limits::default())
            .await
            .is_err()
    );
}
