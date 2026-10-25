use super::*;
use ring::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair},
};
use serde_json::{Value, json};
const NOW: i64 = 1792929600;
const ID: &str = "2905b910-836f-4466-bba4-ae2a00661c74";
const USER: &str = "ea68885a-80df-434b-8aa4-de28dd5f46ed";
const GROUP: &str = "9905b910-836f-4466-bba4-ae2a00661c74";
fn source() -> Source {
    Source {
        id: "internal-ad".into(),
        provider: Provider::ActiveDirectory,
        label: "Internal AD".into(),
        authority: format!("corp.example:{ID}"),
        scopes: BTreeSet::from(["example.com".into()]),
        stale_after_seconds: 86400,
    }
}
fn key() -> (EcdsaKeyPair, PublicKey) {
    let rng = SystemRandom::new();
    let pkcs = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let key =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs.as_ref(), &rng).unwrap();
    let public = PublicKey::new(
        &source().authority,
        &STANDARD.encode(key.public_key().as_ref()),
    )
    .unwrap();
    (key, public)
}
fn payload() -> Value {
    json!({
        "collection_id": ID, "source_id":"internal-ad", "domain_dns":"corp.example", "domain_guid":ID,
        "controller":"dc1.corp.example", "started_at":NOW-10, "completed_at":NOW, "complete":true,
        "requests":6, "pages":2, "counts":{"people":1,"groups":1,"memberships":1},
        "people":[{"id":USER,"display_name":"Alice Example","enabled":true,"mail":"Alice@Example.com","proxy_addresses":["SMTP:alice@example.com","smtp:accounts@example.com","X500:/o=Example"]}],
        "groups":[{"id":GROUP,"display_name":"Accounts","mail":null,"proxy_addresses":[]}],
        "memberships":[{"group":GROUP,"member":{"kind":"person","id":USER}}], "excluded_members":{}
    })
}
fn envelope(key: &EcdsaKeyPair, p: &Value) -> Envelope {
    let bytes = serde_json::to_vec(p).unwrap();
    let signed = [SIGNING_PREFIX, &bytes].concat();
    Envelope {
        protocol: PROTOCOL.into(),
        id: ID.into(),
        key_id: crate::message::digest(key.public_key().as_ref()),
        payload: STANDARD.encode(&bytes),
        signature: STANDARD.encode(key.sign(&SystemRandom::new(), &signed).unwrap().as_ref()),
    }
}
fn collected(p: &Value) -> Result<Collected> {
    let (k, v) = key();
    v.verify(&source(), envelope(&k, p), NOW)?.collect(2, NOW)
}
#[test]
fn valid_export_is_source_bound_and_has_no_inferred_privileges() {
    let c = collected(&payload()).unwrap();
    assert_eq!(c.snapshot.generation, 2);
    assert_eq!(c.snapshot.completed_at, NOW);
    assert_eq!(
        c.snapshot.people[0].addresses,
        BTreeSet::from([
            "Alice@example.com".into(),
            "alice@example.com".into(),
            "accounts@example.com".into()
        ])
    );
    assert!(c.snapshot.people[0].protected_roles.is_empty());
    assert!(c.snapshot.delegations.is_empty());
    assert!(!c.snapshot.groups[0].protected);
}
#[test]
fn invalid_signature_key_and_bytes_are_rejected_before_json() {
    let (k, v) = key();
    let mut e = envelope(&k, &payload());
    e.payload = STANDARD.encode(b"not json");
    assert!(
        v.verify(&source(), e, NOW)
            .unwrap_err_text()
            .contains("signature")
    );
    let (_, other) = key();
    assert!(
        other
            .verify(&source(), envelope(&k, &payload()), NOW)
            .is_err()
    );
    let mut e = envelope(&k, &payload());
    e.signature = STANDARD.encode([0u8; 64]);
    assert!(v.verify(&source(), e, NOW).is_err());
}
trait ErrorText {
    fn unwrap_err_text(self) -> String;
}
impl<T> ErrorText for Result<T> {
    fn unwrap_err_text(self) -> String {
        match self {
            Err(e) => e.to_string(),
            Ok(_) => panic!("Expected error"),
        }
    }
}
#[test]
fn replay_cannot_change_signed_job_id() {
    let (k, v) = key();
    let mut e = envelope(&k, &payload());
    e.id = uuid::Uuid::new_v4().to_string();
    assert!(v.verify(&source(), e, NOW).is_err());
}
#[test]
fn age_future_duration_and_partial_exports_fail() {
    for (field, value) in [
        ("complete", json!(false)),
        ("completed_at", json!(NOW + 1)),
        ("started_at", json!(NOW - 301)),
        ("started_at", json!(NOW + 1)),
    ] {
        let mut p = payload();
        p[field] = value;
        assert!(collected(&p).is_err(), "{field}");
    }
    let (k, v) = key();
    assert!(
        v.verify(&source(), envelope(&k, &payload()), NOW + 901)
            .is_err()
    );
    let verified = v.verify(&source(), envelope(&k, &payload()), NOW).unwrap();
    assert!(verified.collect(1, NOW + 901).is_err());
}
#[test]
fn foreign_authority_source_and_unsupported_protocol_fail() {
    for field in ["source_id", "domain_dns", "domain_guid"] {
        let mut p = payload();
        p[field] = json!("foreign");
        assert!(collected(&p).is_err());
    }
    let (k, v) = key();
    let mut e = envelope(&k, &payload());
    e.protocol = "other".into();
    assert!(v.verify(&source(), e, NOW).is_err());
}
#[test]
fn unknown_state_is_not_active_and_login_is_never_an_alias() {
    let mut p = payload();
    p["people"][0]["enabled"] = Value::Null;
    p["people"][0]["mail"] = Value::Null;
    p["people"][0]["proxy_addresses"] = json!([]);
    let c = collected(&p).unwrap();
    assert_eq!(c.snapshot.people[0].activity, Activity::Unknown);
    assert!(c.snapshot.people[0].addresses.is_empty());
    p["people"][0]["enabled"] = json!(false);
    assert_eq!(
        collected(&p).unwrap().snapshot.people[0].activity,
        Activity::Inactive
    );
    p["people"][0]["user_principal_name"] = json!("alice@example.com");
    assert!(collected(&p).is_err());
}
#[test]
fn duplicates_dangling_cycles_and_incomplete_counts_fail() {
    let mut p = payload();
    p["counts"]["people"] = json!(2);
    assert!(collected(&p).is_err());
    let user = p["people"][0].clone();
    p["people"].as_array_mut().unwrap().push(user);
    assert!(collected(&p).is_err());
    let mut p = payload();
    p["groups"][0]["id"] = json!(USER);
    assert!(collected(&p).is_err());
    let mut p = payload();
    p["memberships"][0]["member"]["id"] = json!(ID);
    assert!(collected(&p).is_err());
    let mut p = payload();
    p["memberships"][0]["member"] = json!({"kind":"group","id":GROUP});
    assert!(collected(&p).is_err());
    let mut p = payload();
    let m = p["memberships"][0].clone();
    p["memberships"].as_array_mut().unwrap().push(m);
    p["counts"]["memberships"] = json!(2);
    assert!(collected(&p).is_err());
}
#[test]
fn exclusions_are_explicit_and_bounded() {
    let mut p = payload();
    p["excluded_members"] = json!({"device":2,"external_membership":1});
    assert_eq!(collected(&p).unwrap().excluded_members["device"], 2);
    for exclusion in [
        json!({"unknown":1}),
        json!({"device":0}),
        json!({"device":100001}),
        json!({"device":100000,"external_membership":1}),
    ] {
        p["excluded_members"] = exclusion;
        assert!(collected(&p).is_err());
    }
}
#[test]
fn injected_roles_and_excess_aliases_are_rejected() {
    let mut p = payload();
    p["people"][0]["protected_roles"] = json!(["executive"]);
    assert!(collected(&p).is_err());
    let mut p = payload();
    p["people"][0]["proxy_addresses"] = json!(
        (0..129)
            .map(|i| format!("smtp:a{i}@example.com"))
            .collect::<Vec<_>>()
    );
    assert!(collected(&p).is_err());
    let mut p = payload();
    p["people"][0]["mail"] = json!("alice@example.com\r\nInjected: true");
    assert!(collected(&p).is_err());
}
#[test]
fn public_enrollment_is_bounded_and_cannot_schedule_a_pull() {
    use crate::identity::{
        connections::{Credential, Metadata},
        schedule::Grant,
    };
    let (k, _) = key();
    let cred = Credential::AdCollectorPublicKey {
        public_key: STANDARD.encode(k.public_key().as_ref()),
    };
    assert!(cred.validate(&source(), NOW, NOW + 90 * 86400).is_ok());
    assert!(cred.validate(&source(), NOW, NOW + 90 * 86400 + 1).is_err());
    let metadata = Metadata {
        protocol: crate::identity::connections::PROTOCOL.into(),
        source: source(),
        generation: ID.into(),
        supersedes: None,
        authority: "local".into(),
        key_id: "a".repeat(64),
        owner: "admin".into(),
        owner_version: 1,
        created: NOW,
        expires: NOW + 86400,
    };
    metadata.validate().unwrap();
    let grant = Grant {
        protocol: crate::identity::schedule::PROTOCOL.into(),
        id: GROUP.into(),
        connection: crate::identity::connections::Reference {
            source_id: source().id,
            generation: ID.into(),
        },
        created: NOW,
        expires: NOW + 86400,
        interval_seconds: 900,
    };
    assert!(grant.validate(&metadata).is_err());
}
#[test]
fn invalid_authority_key_and_resource_limits_are_rejected() {
    let (k, v) = key();
    for authority in [
        "corp.example",
        "corp.example:00000000-0000-0000-0000-000000000000",
        "Corp.example:2905b910-836f-4466-bba4-ae2a00661c74",
    ] {
        assert!(PublicKey::new(authority, &STANDARD.encode(k.public_key().as_ref())).is_err());
    }
    assert!(PublicKey::new(&source().authority, "private-key").is_err());
    let mut e = envelope(&k, &payload());
    e.payload = "a".repeat(directory::MAX_BYTES.div_ceil(3) * 4 + 1);
    assert!(v.verify(&source(), e, NOW).is_err());
    for (field, value) in [
        ("requests", json!(4097)),
        ("pages", json!(0)),
        ("pages", json!(7)),
    ] {
        let mut p = payload();
        p[field] = value;
        assert!(collected(&p).is_err());
    }
}
#[test]
fn dotnet_collector_signature_and_mapping_are_compatible() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/identity/ad-signed-export.json"
    ))
    .unwrap();
    let key = PublicKey::new(&source().authority, fixture["public_key"].as_str().unwrap()).unwrap();
    let envelope = serde_json::from_value(fixture["envelope"].clone()).unwrap();
    let collected = key
        .verify(&source(), envelope, NOW)
        .unwrap()
        .collect(3, NOW)
        .unwrap();
    assert_eq!(collected.snapshot.people[0].display_name, "Alice Example");
    assert_eq!(collected.snapshot.memberships.len(), 1);
}
