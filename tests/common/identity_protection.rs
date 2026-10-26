use super::http;
use axum::{Router, http::StatusCode};
use noisefence::{
    config::Config,
    control::Controller,
    identity::{directory, runtime},
};
use serde_json::json;
use std::sync::Arc;

pub fn install(config: &mut Config) {
    let mut source: directory::Snapshot =
        serde_json::from_str(include_str!("../fixtures/identity/directory.json")).unwrap();
    source.source.provider = directory::Provider::Entra;
    source.completed_at = noisefence::now() - 86401;
    let document = runtime::Document {
        schema: runtime::SCHEMA.into(),
        sources: vec![source],
    };
    let selection = runtime::prepare(
        &config.data_dir,
        &serde_json::to_vec(&document).unwrap(),
        noisefence::now(),
        0,
    )
    .unwrap();
    config.identity = selection.apply(&config.data_dir, None).unwrap();
    config.web.public_origin = http::ORIGIN.into();
    config.web.secure_cookies = true;
}
pub async fn exercise(router: &Router, control: &Arc<Controller>) {
    let config = control.snapshot().config.clone();
    let hash = config.identity.as_ref().unwrap().sha256.clone();
    let before = serde_json::to_value(&control.snapshot().settings).unwrap();
    let input = json!({"revision":0,"catalog_sha256":hash,"edit":{"operation":"update_protection","source_id":"example-directory","patch":{"people":[{"id":"person-alice","roles":["executive"]}]}}});
    for (token, csrf, expected) in [
        ("", true, StatusCode::UNAUTHORIZED),
        (http::READER, true, StatusCode::FORBIDDEN),
        (http::ADMIN, false, StatusCode::FORBIDDEN),
    ] {
        assert_eq!(
            http::call(
                router,
                http::admin_request(token, "/admin/identity/prepare", Some(input.clone()), csrf)
            )
            .await
            .0,
            expected
        );
    }
    let mut stale = input.clone();
    stale["revision"] = json!(99);
    assert_eq!(
        http::call(
            router,
            http::admin_request(http::ADMIN, "/admin/identity/prepare", Some(stale), true)
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let (status, _, prepared) = http::call(
        router,
        http::admin_request(
            http::ADMIN,
            "/admin/identity/prepare",
            Some(input.clone()),
            true,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{prepared}");
    assert_eq!(prepared["active"], false);
    assert_eq!(prepared["review"]["operation"], "protection");
    assert_eq!(prepared["review"]["after"]["fresh"], false);
    assert_eq!(
        prepared["review"]["after"]["completed_at"],
        prepared["review"]["before"]["completed_at"]
    );
    assert_eq!(
        serde_json::to_value(&control.snapshot().settings).unwrap(),
        before
    );
    // Existing selected-authority activation is still mandatory. No routing or
    // permission changes can be smuggled through a protection assignment.
    let mut settings = before.clone();
    settings["identity_directory"] = prepared["selection"].clone();
    let (status, _, result) = http::call(
        router,
        http::admin_request(
            http::ADMIN,
            "/admin/config",
            Some(json!({"revision":0,"settings":settings})),
            true,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{result}");
    if result["staged"] == true {
        assert_eq!(control.snapshot().revision, 0);
        assert_eq!(
            serde_json::to_value(&control.snapshot().settings).unwrap(),
            before
        );
        // A selected management database uses coordinated activation, even in
        // this one-participant fixture. Only the durable release installs it.
        for _ in 0..4 {
            control.advance_activation().await.unwrap();
        }
        assert!(control.cluster_ready());
    }
    assert_eq!(control.snapshot().revision, 1);
    let (status, _, view) = http::call(
        router,
        http::admin_request(
            http::ADMIN,
            "/admin/identity?source=example-directory",
            None,
            false,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{view}");
    assert_eq!(
        view["draft"]["people"][0]["protected_roles"],
        json!(["executive"])
    );
    assert_eq!(view["sources"][0]["fresh"], false);
    assert_eq!(view["sources"][0]["generation"], 2);
    let mut after = serde_json::to_value(&control.snapshot().settings).unwrap();
    after["identity_directory"] = before["identity_directory"].clone();
    assert_eq!(after, before);
    assert_eq!(
        http::call(
            router,
            http::admin_request(http::ADMIN, "/admin/identity/prepare", Some(input), true)
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let mut forged = json!({"revision":1,"catalog_sha256":view["catalog_sha256"],"edit":{"operation":"update_protection","source_id":"example-directory","patch":{"people":[{"id":"person-alice","roles":[],"addresses":["intruder@example.test"]}]}}});
    assert_eq!(
        http::call(
            router,
            http::admin_request(
                http::ADMIN,
                "/admin/identity/prepare",
                Some(forged.clone()),
                true
            )
        )
        .await
        .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    forged["edit"]["patch"] = json!({"people":[{"id":"foreign","roles":[]}]});
    assert_eq!(
        http::call(
            router,
            http::admin_request(http::ADMIN, "/admin/identity/prepare", Some(forged), true)
        )
        .await
        .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
}
