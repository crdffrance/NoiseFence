#![allow(dead_code)]
use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Request, StatusCode},
};
use noisefence::{api, control::Controller, identity::scim, store::Store};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;
pub const ADMIN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
pub const READER: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
pub const ORIGIN: &str = "https://console.example.test";
pub async fn router(
    base: Arc<noisefence::config::Config>,
    store: Store,
) -> (Router, Arc<Controller>) {
    let mut cfg = (*base).clone();
    cfg.web.public_origin = ORIGIN.into();
    cfg.web.secure_cookies = true;
    let cfg = Arc::new(cfg);
    let control = Controller::load(cfg.clone(), store.clone()).await.unwrap();
    (
        api::router_controlled(cfg, store, Some(control.clone())).unwrap(),
        control,
    )
}
pub async fn call(router: &Router, req: Request<Body>) -> (StatusCode, HeaderMap, Value) {
    let res = router.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let bytes = axum::body::to_bytes(res.into_body(), 2 * 1024 * 1024)
        .await
        .unwrap();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, headers, value)
}
pub fn admin_request(token: &str, path: &str, body: Option<Value>, csrf: bool) -> Request<Body> {
    let mut req = Request::builder()
        .uri(format!("/api/v1{path}"))
        .header("cookie", format!("noisefence_session={token}"));
    let body = if let Some(v) = body {
        req = req
            .method("POST")
            .header("origin", ORIGIN)
            .header("content-type", "application/json");
        if csrf {
            req = req.header("x-csrf-token", "csrf-http");
        }
        Body::from(v.to_string())
    } else {
        Body::empty()
    };
    req.body(body).unwrap()
}
pub fn enroll_input(id: &str, previous: Option<&str>) -> Value {
    json!({"revision":0,"catalog_sha256":null,"expected_generation":previous,"source":{"id":id,"label":"Fixture provisioning","provider":"scim","authority":"synthetic-tenant","scopes":["example.test"],"stale_after_seconds":86400},"expires":noisefence::now()+3600})
}
pub async fn enroll(router: &Router, id: &str, previous: Option<&str>) -> Value {
    let (s, _, v) = call(
        router,
        admin_request(
            ADMIN,
            "/admin/identity/scim/enroll",
            Some(enroll_input(id, previous)),
            true,
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    v
}
pub fn provisioning(token: &str, method: &str, path: &str, body: Body) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/scim+json")
        .header("host", "attacker.invalid")
        .header("forwarded", "host=attacker.invalid;proto=http")
        .header("x-forwarded-host", "attacker.invalid")
        .body(body)
        .unwrap()
}
pub fn user(name: &str) -> Body {
    Body::from(json!({"schemas":[scim::USER_SCHEMA],"userName":name,"displayName":"Fixture Person","emails":[{"value":format!("{name}@example.test")}]}).to_string())
}
pub async fn exercise(router: &Router, control: &Arc<Controller>) {
    let input = enroll_input("source-a", None);
    for (token, csrf, status) in [
        ("", true, StatusCode::UNAUTHORIZED),
        (READER, true, StatusCode::FORBIDDEN),
        (ADMIN, false, StatusCode::FORBIDDEN),
    ] {
        assert_eq!(
            call(
                router,
                admin_request(
                    token,
                    "/admin/identity/scim/enroll",
                    Some(input.clone()),
                    csrf
                )
            )
            .await
            .0,
            status
        );
    }
    for changed in [
        json!({"verifier":"untrusted"}),
        json!({"operation":"11111111-1111-4111-8111-111111111111"}),
    ] {
        let mut bad = input.clone();
        bad.as_object_mut()
            .unwrap()
            .extend(changed.as_object().unwrap().clone());
        assert_eq!(
            call(
                router,
                admin_request(ADMIN, "/admin/identity/scim/enroll", Some(bad), true)
            )
            .await
            .0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }
    let e = enroll(router, "source-a", None).await;
    let token = e["bearer"].as_str().unwrap();
    assert_eq!(e["base_url"], format!("{ORIGIN}/scim/source-a/v2"));
    assert!(uuid::Uuid::parse_str(e["generation"].as_str().unwrap()).is_ok());
    assert_eq!(token.len(), 109);
    let (_, _, status) = call(
        router,
        admin_request(ADMIN, "/admin/identity/connections", None, false),
    )
    .await;
    assert!(!status.to_string().contains(token));
    assert!(status["connections"][0]["schedule"].is_null());
    assert_eq!(
        call(
            router,
            admin_request(ADMIN, "/admin/identity/scim/enroll", Some(input), true)
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let (s, h, u) = call(
        router,
        provisioning(token, "POST", "/scim/source-a/v2/Users", user("alice")),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{u}");
    assert_eq!(h["content-type"], "application/scim+json");
    assert_eq!(h["cache-control"], "no-store");
    assert_eq!(h["etag"].to_str().unwrap(), u["meta"]["version"]);
    let path = format!("/scim/source-a/v2/Users/{}", u["id"].as_str().unwrap());
    assert_eq!(h["location"], format!("{ORIGIN}{path}"));
    assert_eq!(u["meta"]["location"], format!("{ORIGIN}{path}"));
    let mut req = provisioning(token, "GET", &path, Body::empty());
    req.headers_mut().insert("if-none-match", h["etag"].clone());
    let (s, h304, empty) = call(router, req).await;
    assert_eq!(s, StatusCode::NOT_MODIFIED);
    assert!(empty.is_null());
    assert_eq!(h304["etag"], h["etag"]);
    assert_eq!(
        call(
            router,
            provisioning(
                token,
                "GET",
                "/scim/source-a/v2/Users?filter=userName%20eq%20%22ALICE%22",
                Body::empty()
            )
        )
        .await
        .2["totalResults"],
        1
    );
    for query in [
        "count=1&count=2",
        "sortBy=userName",
        "filter=%ff",
        "filter=%xy",
        "attributes=id",
    ] {
        assert_eq!(
            call(
                router,
                provisioning(
                    token,
                    "GET",
                    &format!("/scim/source-a/v2/Users?{query}"),
                    Body::empty()
                )
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
    }
    let mut req=provisioning(token,"PATCH",&path,Body::from(json!({"schemas":[scim::PATCH_SCHEMA],"Operations":[{"op":"replace","path":"displayName","value":"Changed"}]}).to_string()));
    req.headers_mut().insert("if-match", h["etag"].clone());
    let (s, h2, _) = call(router, req).await;
    assert_eq!(s, StatusCode::OK);
    assert_ne!(h2["etag"], h["etag"]);
    let mut req = provisioning(token, "DELETE", &path, Body::empty());
    req.headers_mut().insert("if-match", h["etag"].clone());
    let (s, _, v) = call(router, req).await;
    assert_eq!(s, StatusCode::PRECONDITION_FAILED);
    assert!(v.get("scimType").is_none());
    let (_, _, sp) = call(
        router,
        provisioning(
            token,
            "GET",
            "/scim/source-a/v2/ServiceProviderConfig",
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(sp["patch"]["supported"], true);
    assert_eq!(sp["bulk"]["supported"], false);
    assert_eq!(sp["sort"]["supported"], false);
    assert_eq!(
        call(
            router,
            provisioning(
                token,
                "GET",
                "/scim/source-a/v2/ResourceTypes",
                Body::empty()
            )
        )
        .await
        .2["totalResults"],
        2
    );
    let schema = format!(
        "/scim/source-a/v2/Schemas/{}",
        scim::USER_SCHEMA.replace(':', "%3A")
    );
    assert_eq!(
        call(router, provisioning(token, "GET", &schema, Body::empty()))
            .await
            .2["id"],
        scim::USER_SCHEMA
    );
    for (method, endpoint, allowed) in [
        ("DELETE", "/scim/source-a/v2/Users", "GET, HEAD, POST"),
        ("POST", path.as_str(), "GET, HEAD, PUT, PATCH, DELETE"),
        (
            "POST",
            "/scim/source-a/v2/ServiceProviderConfig",
            "GET, HEAD",
        ),
    ] {
        let (status, headers, _) =
            call(router, provisioning(token, method, endpoint, Body::empty())).await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(headers["allow"], allowed);
    }
    let other = enroll(router, "source-b", None).await;
    assert_eq!(
        call(
            router,
            provisioning(
                other["bearer"].as_str().unwrap(),
                "GET",
                &path,
                Body::empty()
            )
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    let mut bad = provisioning(token, "POST", "/scim/source-a/v2/Users", user("alice"));
    bad.headers_mut()
        .insert("content-type", "text/plain".parse().unwrap());
    assert_eq!(
        call(router, bad).await.0,
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
    let mut duplicate = provisioning(token, "GET", &path, Body::empty());
    duplicate
        .headers_mut()
        .append("authorization", "Bearer wrong".parse().unwrap());
    assert_eq!(call(router, duplicate).await.0, StatusCode::UNAUTHORIZED);
    let group = json!({"schemas":[scim::GROUP_SCHEMA],"displayName":"Team","members":[{"value":u["id"],"$ref":"http://127.0.0.1/private"}]});
    let (s, _, g) = call(
        router,
        provisioning(
            token,
            "POST",
            "/scim/source-a/v2/Groups",
            Body::from(group.to_string()),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
    let rotated = enroll(router, "source-a", e["generation"].as_str()).await;
    assert_ne!(rotated["bearer"], e["bearer"]);
    assert_eq!(
        call(router, provisioning(token, "GET", &path, Body::empty()))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let token = rotated["bearer"].as_str().unwrap();
    assert_eq!(
        call(router, provisioning(token, "GET", &path, Body::empty()))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        call(router, provisioning(token, "DELETE", &path, Body::empty()))
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    let group_path = format!("/scim/source-a/v2/Groups/{}", g["id"].as_str().unwrap());
    assert_eq!(
        call(
            router,
            provisioning(token, "GET", &group_path, Body::empty())
        )
        .await
        .2["members"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    let reference = json!({"source_id":"source-a","generation":rotated["generation"]});
    assert_eq!(
        call(
            router,
            admin_request(
                ADMIN,
                "/admin/identity/connections/revoke",
                Some(reference),
                true
            )
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        call(
            router,
            provisioning(token, "GET", &group_path, Body::empty())
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    assert!(control.snapshot().config.identity.is_none());
    assert_eq!(control.snapshot().revision, 0);
}
