use super::*;
use std::{collections::VecDeque, sync::Mutex};
const NOW: i64 = 1792929600;
const U: &str = "11111111-1111-4111-8111-111111111111";
const G: &str = "22222222-2222-4222-8222-222222222222";
const M: &str = "33333333-3333-4333-8333-333333333333";
fn source() -> Source {
    Source {
        id: "aws".into(),
        provider: Provider::AwsIdentityStore,
        label: "Fixture directory".into(),
        authority: "eu-west-3:d-1234567890".into(),
        scopes: BTreeSet::from(["example.test".into()]),
        stale_after_seconds: 86400,
    }
}
fn credentials() -> Credentials {
    Credentials::new(
        &source().authority,
        "ASIAAAAAAAAAAAAAAAAA".into(),
        "a".repeat(40),
        "synthetic-session-token".into(),
    )
    .unwrap()
}
fn user() -> Value {
    json!({"IdentityStoreId":"d-1234567890","UserId":U,"DisplayName":"Alice Example","UserName":"not-an-alias@example.test","Emails":[{"Value":"Alice@Example.test"}],"UserStatus":"ENABLED"})
}
fn group() -> Value {
    json!({"IdentityStoreId":"d-1234567890","GroupId":G,"DisplayName":"Finance"})
}
fn member() -> Value {
    json!({"IdentityStoreId":"d-1234567890","GroupId":G,"MembershipId":M,"MemberId":{"UserId":U}})
}
fn page(value: Value) -> Page {
    Page {
        status: 200,
        throttled: false,
        retry_after: None,
        bytes: serde_json::to_vec(&value).unwrap(),
    }
}
struct Fake {
    pages: Mutex<VecDeque<Page>>,
    requests: Mutex<Vec<(String, Value)>>,
}
impl Fake {
    fn new(pages: Vec<Page>) -> Self {
        Self {
            pages: Mutex::new(pages.into()),
            requests: Mutex::new(vec![]),
        }
    }
}
impl Transport for Fake {
    async fn post(&self, r: &Request) -> Result<Page> {
        self.requests.lock().unwrap().push((
            r.operation.target().into(),
            serde_json::from_slice(&r.body).unwrap(),
        ));
        self.pages
            .lock()
            .unwrap()
            .pop_front()
            .ok_or_else(|| anyhow!("Fixture exhausted"))
    }
}
#[test]
fn signature_matches_independent_botocore_1_42_59_vector() {
    // Generated offline by botocore.auth.SigV4Auth with frozen UTC clock and
    // synthetic credentials; no provider/network request. Exact JSON bytes matter.
    let r = Request {
        operation: Operation::Users,
        body: br#"{"IdentityStoreId":"d-1234567890","MaxResults":100}"#.to_vec(),
    };
    let h = signed_headers(&credentials(), &r, NOW).unwrap();
    assert_eq!(h["x-amz-date"], "20261025T120000Z");
    assert_eq!(h["host"], "identitystore.eu-west-3.amazonaws.com");
    assert_eq!(
        h[AUTHORIZATION],
        "AWS4-HMAC-SHA256 Credential=ASIAAAAAAAAAAAAAAAAA/20261025/eu-west-3/identitystore/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-amz-target, Signature=d79e0a811560a1776f393897477c368997388fd3ad56d10c08e5ec464f3954ae"
    );
    assert!(h[AUTHORIZATION].is_sensitive() && h["x-amz-security-token"].is_sensitive());
    assert!(signed_headers(&credentials(), &r, 0).is_err());
}
#[test]
fn authority_and_temporary_credentials_cannot_select_arbitrary_hosts() {
    for a in [
        "https://example.test",
        "us-gov-west-1:d-1234567890",
        "cn-north-1:d-1234567890",
        "eu-west-3.evil.test:d-1234567890",
        "eu-west-3:d-1234567890:evil",
        "eu-west-3:arn:aws:identitystore::123456789012:identitystore/d-1234567890",
    ] {
        assert!(authority(a).is_err());
    }
    assert!(authority("eu-west-3:11111111-1111-4111-8111-111111111111").is_ok());
    for id in ["AKIAAAAAAAAAAAAAAAAA", "ASIAAAAAAAAAAAAAAAA\n", "ASIA"] {
        assert!(
            Credentials::new(
                &source().authority,
                id.into(),
                "a".repeat(40),
                "token".into()
            )
            .is_err()
        );
    }
    for token in ["", "token\nINJECTION", "token with spaces"] {
        assert!(
            Credentials::new(
                &source().authority,
                "ASIAAAAAAAAAAAAAAAAA".into(),
                "a".repeat(40),
                token.into()
            )
            .is_err()
        );
    }
    assert!(!resource_id(&"é".repeat(47)));
}
#[tokio::test]
async fn full_pagination_preserves_explicit_mail_state_membership_and_scope() {
    let mut second = user();
    second["UserId"] = json!("44444444-4444-4444-8444-444444444444");
    second["Emails"] = json!([]);
    second["UserStatus"] = json!("DISABLED");
    let http = Fake::new(vec![
        page(json!({"Users":[user()],"NextToken":"a:b/+="})),
        page(json!({"Users":[second]})),
        page(json!({"Groups":[group()]})),
        page(json!({"GroupMemberships":[member()]})),
    ]);
    let result = collect(&http, &source(), 1, Limits::default(), || NOW)
        .await
        .unwrap();
    assert_eq!(result.pages, 4);
    assert_eq!(result.snapshot.source, source());
    assert_eq!(
        result.snapshot.people[0].addresses,
        BTreeSet::from(["Alice@example.test".into()])
    );
    assert_eq!(result.snapshot.people[0].activity, Activity::Active);
    assert_eq!(result.snapshot.people[1].activity, Activity::Inactive);
    assert!(result.snapshot.people[1].addresses.is_empty());
    assert!(result.snapshot.groups[0].addresses.is_empty() && !result.snapshot.groups[0].protected);
    assert_eq!(result.snapshot.memberships.len(), 1);
    assert!(result.snapshot.delegations.is_empty());
    let requests = http.requests.lock().unwrap();
    assert_eq!(requests[1].1["NextToken"], "a:b/+=");
    assert_eq!(requests[3].1["GroupId"], G);
    assert!(
        !serde_json::to_string(&result)
            .unwrap()
            .contains("synthetic-session-token")
    );
}
#[tokio::test]
async fn absent_status_never_means_active_or_a_login_name_becomes_an_alias() {
    for status in [Value::Null, json!("FUTURE")] {
        let mut u = user();
        u["UserStatus"] = status;
        u.as_object_mut().unwrap().remove("Emails");
        let http = Fake::new(vec![page(json!({"Users":[u]})), page(json!({"Groups":[]}))]);
        let r = collect(&http, &source(), 1, Limits::default(), || NOW)
            .await
            .unwrap();
        assert_eq!(r.snapshot.people[0].activity, Activity::Unknown);
        assert!(r.snapshot.people[0].addresses.is_empty());
    }
}
#[tokio::test]
async fn partial_duplicate_cross_store_and_dangling_records_abort_candidate() {
    let mut cross = user();
    cross["IdentityStoreId"] = json!("d-9999999999");
    let mut invalid = user();
    invalid["UserId"] = json!("not-an-id");
    for value in [
        json!({}),
        json!({"Users":[cross]}),
        json!({"Users":[invalid]}),
        json!({"Users":[user(),user()]}),
    ] {
        assert!(
            collect(
                &Fake::new(vec![page(value)]),
                &source(),
                1,
                Limits::default(),
                || NOW
            )
            .await
            .is_err()
        );
    }
    let mut variants = vec![];
    let mut m = member();
    m["MemberId"]["UserId"] = json!("55555555-5555-4555-8555-555555555555");
    variants.push(json!([m]));
    let mut m = member();
    m["IdentityStoreId"] = json!("d-9999999999");
    variants.push(json!([m]));
    let mut m = member();
    m["GroupId"] = json!(U);
    variants.push(json!([m]));
    let mut m = member();
    m["MemberId"]["GroupId"] = json!(G);
    variants.push(json!([m]));
    variants.push(json!([member(), member()]));
    for members in variants {
        let h = Fake::new(vec![
            page(json!({"Users":[user()]})),
            page(json!({"Groups":[group()]})),
            page(json!({"GroupMemberships":members})),
        ]);
        assert!(
            collect(&h, &source(), 1, Limits::default(), || NOW)
                .await
                .is_err()
        );
    }
}
#[tokio::test]
async fn paging_loops_and_limits_do_not_publish_partial_success() {
    for pages in [
        vec![
            page(json!({"Users":[],"NextToken":"loop"})),
            page(json!({"Users":[],"NextToken":"loop"})),
        ],
        vec![page(json!({"Users":[],"NextToken":""}))],
        vec![page(json!({"Users":[],"NextToken":42}))],
        vec![page(json!({"Users":vec![user();101]}))],
    ] {
        assert!(
            collect(&Fake::new(pages), &source(), 1, Limits::default(), || NOW)
                .await
                .is_err()
        );
    }
    let h = Fake::new(vec![page(json!({"Users":[]}))]);
    assert!(
        collect(
            &h,
            &source(),
            1,
            Limits {
                max_requests: 1,
                ..Limits::default()
            },
            || NOW
        )
        .await
        .is_err()
    );
    assert_eq!(h.requests.lock().unwrap().len(), 1);
    let h = Fake::new(vec![page(json!({"Users":[user()]}))]);
    assert!(
        collect(
            &h,
            &source(),
            1,
            Limits {
                max_bytes: 1,
                ..Limits::default()
            },
            || NOW
        )
        .await
        .is_err()
    );
}
#[tokio::test]
async fn throttling_retries_are_bounded_and_auth_failures_are_not_retried() {
    let error = |status, throttled, seconds| Page {
        status,
        throttled,
        retry_after: Some(Duration::from_secs(seconds)),
        bytes: br#"{"Message":"PRIVATE-PROVIDER-TEXT"}"#.to_vec(),
    };
    let h = Fake::new(vec![
        error(400, true, 0),
        page(json!({"Users":[]})),
        page(json!({"Groups":[]})),
    ]);
    assert_eq!(
        collect(&h, &source(), 1, Limits::default(), || NOW)
            .await
            .unwrap()
            .requests,
        3
    );
    for p in [
        error(403, false, 0),
        error(400, false, 0),
        error(429, true, 11),
        error(302, false, 0),
    ] {
        let h = Fake::new(vec![p]);
        let e = collect(&h, &source(), 1, Limits::default(), || NOW)
            .await
            .unwrap_err();
        assert!(!e.to_string().contains("PRIVATE-PROVIDER-TEXT"));
        assert_eq!(h.requests.lock().unwrap().len(), 1);
    }
    let h = Fake::new(vec![
        error(429, true, 0),
        error(429, true, 0),
        error(429, true, 0),
    ]);
    assert!(
        collect(&h, &source(), 1, Limits::default(), || NOW)
            .await
            .is_err()
    );
    assert_eq!(h.requests.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn resource_uuid_case_is_canonical_across_pages_and_memberships() {
    let upper = "ABCDEFAB-1111-4111-8111-111111111111";
    let mut u = user();
    u["UserId"] = json!(upper);
    let mut m = member();
    m["MemberId"]["UserId"] = json!(upper.to_lowercase());
    let h = Fake::new(vec![
        page(json!({"Users":[u]})),
        page(json!({"Groups":[group()]})),
        page(json!({"GroupMemberships":[m]})),
    ]);
    let r = collect(&h, &source(), 1, Limits::default(), || NOW)
        .await
        .unwrap();
    assert_eq!(r.snapshot.people[0].id, upper.to_lowercase());
    assert_eq!(r.snapshot.memberships.len(), 1);
}
