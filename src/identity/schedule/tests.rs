use super::*;
use crate::identity::sync;
use crate::identity::{
    connections::{Credential, Metadata, PROTOCOL as CONNECTION_PROTOCOL, vault::Key},
    directory::{Provider, Source},
};
const NOW: i64 = 1800000000;
fn setup() -> (tempfile::TempDir, Key, Record) {
    let root = tempfile::tempdir().unwrap();
    let key = Key::initialize(root.path()).unwrap();
    let metadata = Metadata {
        protocol: CONNECTION_PROTOCOL.into(),
        source: Source {
            id: "synthetic".into(),
            label: "Synthetic".into(),
            provider: Provider::Entra,
            authority: "11111111-1111-4111-8111-111111111111".into(),
            scopes: ["example.test".into()].into_iter().collect(),
            stale_after_seconds: 86400,
        },
        generation: uuid::Uuid::new_v4().to_string(),
        supersedes: None,
        authority: "sqlite".into(),
        key_id: key.id(),
        owner: "admin".into(),
        owner_version: 2,
        created: NOW,
        expires: NOW + 86400,
    };
    let record = key
        .seal(
            metadata,
            &Credential::EntraApplication {
                client_id: "22222222-2222-4222-8222-222222222222".into(),
                client_secret: "SYNTHETIC-SCHEDULE-SECRET".into(),
            },
        )
        .unwrap();
    (root, key, record)
}
fn grant(r: &Record) -> Grant {
    Grant {
        protocol: PROTOCOL.into(),
        id: uuid::Uuid::new_v4().to_string(),
        connection: Reference {
            source_id: r.metadata.source.id.clone(),
            generation: r.metadata.generation.clone(),
        },
        created: NOW,
        expires: NOW + 7200,
        interval_seconds: 900,
    }
}
fn enabled(key: &Key, r: &mut Record) {
    let g = grant(r);
    let sig = key.sign_schedule(&r.metadata, &g).unwrap();
    enable(r, None, g, sig, "admin", 2, NOW).unwrap();
}
fn request(r: &Record) -> Request {
    Request {
        scim: None,
        connection: Some(Reference {
            source_id: r.metadata.source.id.clone(),
            generation: r.metadata.generation.clone(),
        }),
        scheduled: Some(r.schedule.as_ref().unwrap().binding(&r.metadata).unwrap()),
        id: uuid::Uuid::new_v4().to_string(),
        source_id: r.metadata.source.id.clone(),
        runner: uuid::Uuid::new_v4().to_string(),
        revision: 4,
        catalog_sha256: None,
        created: NOW,
        deadline: NOW + 360,
    }
}
#[test]
fn finite_grants_bind_owner_source_authority_lifetime_and_key() {
    let (_root, key, mut r) = setup();
    enabled(&key, &mut r);
    key.verify_schedule(&r).unwrap();
    for field in [
        "owner",
        "authority",
        "scope",
        "cadence",
        "expiry",
        "generation",
    ] {
        let mut changed = r.clone();
        match field {
            "owner" => changed.metadata.owner = "other".into(),
            "authority" => changed.metadata.authority = "postgres:other".into(),
            "scope" => {
                changed.metadata.source.scopes.insert("other.test".into());
            }
            "cadence" => changed.schedule.as_mut().unwrap().grant.interval_seconds = 1800,
            "expiry" => changed.schedule.as_mut().unwrap().grant.expires += 1,
            "generation" => changed.metadata.generation = uuid::Uuid::new_v4().to_string(),
            _ => unreachable!(),
        }
        assert!(key.verify_schedule(&changed).is_err(), "{field}");
    }
    let other = tempfile::tempdir().unwrap();
    assert!(
        Key::initialize(other.path())
            .unwrap()
            .verify_schedule(&r)
            .is_err()
    );
    assert!(
        r.schedule
            .as_ref()
            .unwrap()
            .live(&r.metadata, NOW + 7200)
            .is_err()
    );
}
#[test]
fn claims_are_finite_and_restart_or_failure_does_not_create_a_retry_storm() {
    let (_root, key, mut r) = setup();
    enabled(&key, &mut r);
    let req = request(&r);
    claim(&mut r, &req, NOW).unwrap();
    authorize(&r, &req, NOW + 1).unwrap();
    assert!(claim(&mut r, &req, NOW + 1).is_err());
    let recovered = Record::decode(&r.encode().unwrap(), "synthetic", "sqlite").unwrap();
    assert!(!recovered.schedule.as_ref().unwrap().due(NOW + 361, 4));
    assert!(recovered.schedule.as_ref().unwrap().due(NOW + 901, 4));
    assert!(authorize(&recovered, &req, NOW + 361).is_err());
    let event = Event {
        request: req,
        outcome: Outcome::Failed {
            reason: sync::Failure::Deadline,
        },
    };
    assert!(completed(&mut r, &event, NOW + 361).unwrap());
    let schedule = r.schedule.as_ref().unwrap();
    assert_eq!(schedule.failures, 1);
    assert_eq!(schedule.next_due, NOW + 361 + 1800);
    assert!(!schedule.due(NOW + 1800, 4));
    key.verify_schedule(&r).unwrap();
}
#[test]
fn pending_review_stops_repeated_candidate_writes_but_a_new_revision_allows_refresh() {
    let (_root, key, mut r) = setup();
    enabled(&key, &mut r);
    let req = request(&r);
    claim(&mut r, &req, NOW).unwrap();
    let s = r.schedule.as_mut().unwrap();
    let run = s.last_run.as_mut().unwrap();
    run.state = RunState::Ready;
    run.completed_at = Some(NOW + 2);
    r.validate().unwrap();
    let s = r.schedule.as_ref().unwrap();
    assert!(!s.due(NOW + 901, 4));
    assert!(s.due(NOW + 901, 5));
}
#[test]
fn stop_is_generation_bound_and_an_old_result_cannot_modify_a_new_grant() {
    let (_root, key, mut r) = setup();
    enabled(&key, &mut r);
    let req = request(&r);
    claim(&mut r, &req, NOW).unwrap();
    let binding = r.schedule.as_ref().unwrap().binding(&r.metadata).unwrap();
    disable(&mut r, &binding, NOW + 1).unwrap();
    assert!(authorize(&r, &req, NOW + 2).is_err());
    assert!(!r.schedule.as_ref().unwrap().due(NOW + 1000, 5));
    let old = r.schedule.as_ref().unwrap().grant.clone();
    let sig = key.sign_schedule(&r.metadata, &old).unwrap();
    assert!(enable(&mut r, Some(&old.id), old.clone(), sig, "admin", 2, NOW + 2).is_err());
    let new = grant(&r);
    let sig = key.sign_schedule(&r.metadata, &new).unwrap();
    enable(&mut r, Some(&old.id), new, sig, "admin", 2, NOW + 2).unwrap();
    assert!(disable(&mut r, &binding, NOW + 3).is_err());
    assert!(
        !completed(
            &mut r,
            &Event {
                request: req,
                outcome: Outcome::Failed {
                    reason: sync::Failure::Authorization
                }
            },
            NOW + 4
        )
        .unwrap()
    );
    assert!(r.schedule.as_ref().unwrap().last_run.is_none());
}
#[test]
fn saving_requires_the_current_owner_and_a_bounded_explicit_lease() {
    let (_root, key, mut r) = setup();
    let g = grant(&r);
    let signature = key.sign_schedule(&r.metadata, &g).unwrap();
    assert!(
        enable(
            &mut r,
            None,
            g.clone(),
            signature.clone(),
            "different-admin",
            2,
            NOW
        )
        .is_err()
    );
    assert!(enable(&mut r, None, g.clone(), signature, "admin", 3, NOW).is_err());
    for cadence in [0, 899, 86401] {
        let mut bad = g.clone();
        bad.interval_seconds = cadence;
        assert!(key.sign_schedule(&r.metadata, &bad).is_err());
    }
    let mut bad = g;
    bad.expires = r.metadata.expires + 1;
    assert!(key.sign_schedule(&r.metadata, &bad).is_err());
}
#[test]
fn legacy_records_and_one_shot_receipts_do_not_gain_schedule_fields() {
    let (_root, key, mut r) = setup();
    let encoded = r.encode().unwrap();
    assert!(!encoded.contains("schedule"));
    assert!(
        Record::decode(&encoded, "synthetic", "sqlite")
            .unwrap()
            .schedule
            .is_none()
    );
    enabled(&key, &mut r);
    let mut req = request(&r);
    req.scheduled = None;
    req.connection = None;
    let wire = Event {
        request: req,
        outcome: Outcome::Running,
    }
    .encode()
    .unwrap();
    assert!(!wire.contains("scheduled") && !wire.contains("connection"));
    assert_eq!(Event::decode(&wire).unwrap().encode().unwrap(), wire);
}
