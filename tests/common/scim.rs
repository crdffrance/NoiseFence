#![allow(dead_code)]
use noisefence::{
    identity::{
        connections::{Credential, Metadata, PROTOCOL, Record, Reference},
        directory::{Provider, Source},
        scim::{
            self, Candidate, Command, ListQuery, Reply, Resource, ResourceType,
            access::{Access, Bearer},
        },
    },
    store::Store,
};
use serde_json::{Value, json};
pub const SESSION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
pub struct Enrollment {
    pub record: Record,
    pub token: String,
}
impl Enrollment {
    pub fn access(&self) -> Access {
        Access::new(self.record.metadata.source.id.clone(), self.token.clone()).unwrap()
    }
    pub fn reference(&self) -> Reference {
        Reference {
            source_id: self.record.metadata.source.id.clone(),
            generation: self.record.metadata.generation.clone(),
        }
    }
}
pub async fn enroll(store: &Store, id: &str, previous: Option<&Enrollment>) -> Enrollment {
    let (key, version) = store
        .identity_connection_prepare("admin".into(), SESSION.into())
        .await
        .unwrap();
    let generation = uuid::Uuid::new_v4().to_string();
    let (token, verifier) = Bearer::issue(&generation).unwrap();
    let token = token.into_value();
    let now = noisefence::now();
    let source = previous
        .map(|e| e.record.metadata.source.clone())
        .unwrap_or(Source {
            id: id.into(),
            label: format!("Synthetic {id}"),
            provider: Provider::Scim,
            authority: format!("tenant-{id}"),
            scopes: ["example.test".into()].into(),
            stale_after_seconds: 86400,
        });
    let record = key
        .seal(
            Metadata {
                protocol: PROTOCOL.into(),
                source,
                generation,
                supersedes: previous.map(|p| p.record.metadata.generation.clone()),
                authority: store.directory_connection_authority(),
                key_id: key.id(),
                owner: "admin".into(),
                owner_version: version,
                created: now,
                expires: now + 3600,
            },
            &Credential::ScimBearerVerifier {
                verifier: verifier.clone(),
            },
        )
        .unwrap();
    let encoded = record.encode().unwrap();
    assert!(!encoded.contains(&token));
    assert!(!encoded.contains(&verifier));
    store
        .identity_connection_save(
            previous.map(|p| p.record.metadata.generation.clone()),
            record.clone(),
            "admin".into(),
            SESSION.into(),
        )
        .await
        .unwrap();
    Enrollment { record, token }
}
pub fn bytes(value: Value) -> Vec<u8> {
    serde_json::to_vec(&value).unwrap()
}
pub fn user(name: &str) -> Command {
    Command::Create {
        kind: ResourceType::User,
        body: bytes(
            json!({"schemas":[scim::USER_SCHEMA],"userName":name,"displayName":"Fixture Person","active":true,"emails":[{"value":format!("{name}@example.test")}] }),
        ),
    }
}
pub fn group(name: &str, members: Value) -> Command {
    Command::Create {
        kind: ResourceType::Group,
        body: bytes(json!({"schemas":[scim::GROUP_SCHEMA],"displayName":name,"members":members})),
    }
}
pub fn patch(row: &Resource, ops: Value) -> Command {
    Command::Patch {
        kind: row.data().kind(),
        id: row.id().into(),
        expected: Some(row.etag()),
        body: bytes(json!({"schemas":[scim::PATCH_SCHEMA],"Operations":ops})),
    }
}
pub async fn resource(store: &Store, enrollment: &Enrollment, cmd: Command) -> Resource {
    match store.scim_request(enrollment.access(), cmd).await.unwrap() {
        Reply::Resource(r) => *r,
        _ => panic!("expected SCIM resource"),
    }
}
pub async fn get(store: &Store, e: &Enrollment, row: &Resource) -> Resource {
    resource(
        store,
        e,
        Command::Get {
            kind: row.data().kind(),
            id: row.id().into(),
        },
    )
    .await
}
pub fn status(result: anyhow::Result<Reply>, expected: u16) {
    match result {
        Ok(_) => panic!("expected SCIM error"),
        Err(error) => assert_eq!(
            error.downcast_ref::<scim::Error>().map(|e| e.status),
            Some(expected),
            "unexpected sanitized error: {error}"
        ),
    }
}
/// The same behavioral suite runs against both real repository implementations.
pub async fn exercise(store: &Store) {
    let a = enroll(store, "scim-a", None).await;
    let b = enroll(store, "scim-b", None).await;
    let alice = resource(store, &a, user("alice")).await;
    let bob = resource(store, &a, user("bob")).await;
    let external = resource(store, &b, user("alice")).await;
    status(store.scim_request(a.access(), user("ALICE")).await, 409);
    status(
        store
            .scim_request(
                a.access(),
                Command::Get {
                    kind: ResourceType::User,
                    id: external.id().into(),
                },
            )
            .await,
        404,
    );
    status(
        store
            .scim_request(
                a.access(),
                group("Foreign", json!([{"value":external.id()}])),
            )
            .await,
        400,
    );
    status(
        store
            .scim_request(
                Access::new(a.record.metadata.source.id.clone(), b.token.clone()).unwrap(),
                Command::Authenticate,
            )
            .await,
        401,
    );
    let team = resource(
        store,
        &a,
        group("Team", json!([{"value":alice.id()},{"value":bob.id()}])),
    )
    .await;
    let before = store
        .scim_inventory(a.reference(), "admin".into(), SESSION.into())
        .await
        .unwrap();
    assert_eq!(
        (
            before.stage.users,
            before.stage.groups,
            before.stage.memberships
        ),
        (2, 1, 2)
    );
    let candidate = Candidate::prepare(
        before.source.clone(),
        before.stage.revision.clone(),
        1,
        &before.resources,
        noisefence::now(),
        noisefence::now(),
    )
    .unwrap();
    assert!(candidate.snapshot().delegations.is_empty());
    assert!(
        store
            .scim_inventory(a.reference(), "reader".into(), SESSION.into())
            .await
            .is_err()
    );
    assert!(
        store
            .scim_inventory(a.reference(), "admin".into(), "wrong".into())
            .await
            .is_err()
    );
    let (one, two) = tokio::join!(
        store.scim_request(
            a.access(),
            patch(
                &alice,
                json!([{"op":"replace","path":"displayName","value":"One"}])
            )
        ),
        store.scim_request(
            a.access(),
            patch(
                &alice,
                json!([{"op":"replace","path":"displayName","value":"Two"}])
            )
        )
    );
    assert_ne!(one.is_ok(), two.is_ok());
    if one.is_err() {
        status(one, 412);
    } else {
        status(two, 412);
    }
    let current = get(store, &a, &alice).await;
    let inventory = store
        .scim_inventory(a.reference(), "admin".into(), SESSION.into())
        .await
        .unwrap();
    status(store.scim_request(a.access(),patch(&current,json!([{"op":"replace","path":"displayName","value":"Should roll back"},{"op":"remove","path":"userName"}]))).await,400);
    assert_eq!(get(store, &a, &current).await, current);
    assert_eq!(
        store
            .scim_inventory(a.reference(), "admin".into(), SESSION.into())
            .await
            .unwrap()
            .stage
            .revision,
        inventory.stage.revision
    );
    status(
        store
            .scim_request(
                a.access(),
                Command::Get {
                    kind: ResourceType::User,
                    id: team.id().into(),
                },
            )
            .await,
        404,
    );
    let query = ListQuery::parse(
        ResourceType::User,
        &[("filter".into(), "userName eq \"ALICE\"".into())],
    )
    .unwrap();
    match store
        .scim_request(
            a.access(),
            Command::List {
                kind: ResourceType::User,
                query,
            },
        )
        .await
        .unwrap()
    {
        Reply::List(v) => {
            assert_eq!(v["totalResults"], 1);
            assert_eq!(v["Resources"][0]["id"], alice.id());
        }
        _ => panic!("expected list"),
    }
    let noop = resource(
        store,
        &a,
        Command::Replace {
            kind: ResourceType::User,
            id: current.id().into(),
            expected: Some(current.etag()),
            body: bytes(current.document()),
        },
    )
    .await;
    assert_eq!(noop, current);
    match store
        .scim_request(
            a.access(),
            Command::Delete {
                kind: ResourceType::User,
                id: alice.id().into(),
                expected: Some(current.etag()),
            },
        )
        .await
        .unwrap()
    {
        Reply::Deleted => (),
        _ => panic!("expected delete"),
    }
    let pruned = get(store, &a, &team).await;
    assert_ne!(pruned.etag(), team.etag());
    assert_eq!(pruned.data().members().len(), 1);
    status(
        store
            .scim_request(
                a.access(),
                patch(
                    &team,
                    json!([{"op":"replace","path":"displayName","value":"Old version"}]),
                ),
            )
            .await,
        412,
    );
    let inventory = store
        .scim_inventory(a.reference(), "admin".into(), SESSION.into())
        .await
        .unwrap();
    assert_eq!((inventory.stage.users, inventory.stage.memberships), (1, 1));
    let rotated = enroll(store, "scim-a", Some(&a)).await;
    status(
        store.scim_request(a.access(), Command::Authenticate).await,
        401,
    );
    let recovered = get(store, &rotated, &team).await;
    assert_eq!(recovered, pruned);
    let after = store
        .scim_inventory(rotated.reference(), "admin".into(), SESSION.into())
        .await
        .unwrap();
    assert_eq!(
        after.stage.revision.sequence,
        inventory.stage.revision.sequence
    );
    assert_ne!(
        after.stage.revision.enrollment,
        inventory.stage.revision.enrollment
    );
    store
        .identity_connection_revoke(
            rotated.record.metadata.source.id.clone(),
            rotated.record.metadata.generation.clone(),
            "admin".into(),
            SESSION.into(),
        )
        .await
        .unwrap();
    status(
        store
            .scim_request(rotated.access(), Command::Authenticate)
            .await,
        401,
    );
    assert_eq!(get(store, &b, &external).await, external);
}

/// Exercise membership batch boundaries through real repository calls, including
/// partial removal, unchanged edges, and the serialized inventory accounting.
pub async fn membership_batches(store: &Store) {
    let e = enroll(store, "scim-batches", None).await;
    let mut people = Vec::new();
    for i in 0..130 {
        people.push(resource(store, &e, user(&format!("member-{i}"))).await);
    }
    let members: Vec<_> = people.iter().map(|p| json!({"value":p.id()})).collect();
    let team = resource(store, &e, group("Large team", json!(members))).await;
    assert_eq!(get(store, &e, &team).await.data().members().len(), 130);
    let renamed = resource(
        store,
        &e,
        patch(
            &team,
            json!([
                {"op":"replace","path":"displayName","value":"Renamed team"}
            ]),
        ),
    )
    .await;
    assert_eq!(renamed.data().members(), team.data().members());
    let small = resource(
        store,
        &e,
        patch(
            &renamed,
            json!([
                {"op":"replace","path":"members","value":[{"value":people[0].id()}]}
            ]),
        ),
    )
    .await;
    assert_eq!(get(store, &e, &small).await.data().members().len(), 1);
    let restored = resource(
        store,
        &e,
        patch(
            &small,
            json!([
                {"op":"add","path":"members","value":members}
            ]),
        ),
    )
    .await;
    assert_eq!(restored.data().members(), team.data().members());
    let inventory = store
        .scim_inventory(e.reference(), "admin".into(), SESSION.into())
        .await
        .unwrap();
    assert_eq!(
        (
            inventory.stage.users,
            inventory.stage.groups,
            inventory.stage.memberships
        ),
        (130, 1, 130)
    );
    assert_eq!(inventory.stage.revision.sequence, 134);
    assert!(
        Candidate::prepare(
            inventory.source,
            inventory.stage.revision,
            1,
            &inventory.resources,
            noisefence::now(),
            noisefence::now()
        )
        .is_ok()
    );
}
