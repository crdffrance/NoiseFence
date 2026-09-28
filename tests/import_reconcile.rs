#[allow(dead_code)]
mod common;
use noisefence::{
    central::{
        history,
        import::{Mirror, MirrorLog, ReconciledSpools, SpoolSnapshot},
        logs, outbox,
    },
    engine::Engine,
};
fn sources() -> Vec<SpoolSnapshot> {
    let root = tempfile::tempdir().unwrap();
    let scan = Engine::new(common::config(root.path()))
        .unwrap()
        .offline(common::MESSAGE);
    let id = uuid::Uuid::new_v4().to_string();
    let record:noisefence::cluster::history::Record=serde_json::from_value(serde_json::json!({"id":id,"generation":100,"created":noisefence::now(),"sender":"sender@example.test","scan":scan,"is_dsn":false,"raw_present":false,"deliveries":[{"address":"alice@example.test","destination":"alice@example.test","status":"delivered","attempts":3,"next_attempt":0,"error":null,"action":"deliver","held_until":null,"released_at":null,"filtering":null,"logs":[]}]})).unwrap();
    let mut mirror: noisefence::cluster::history::Record =
        serde_json::from_value(serde_json::to_value(&record).unwrap()).unwrap();
    // Old mirror state and generations need not equal current owner state.
    mirror.generation = 1;
    mirror.deliveries[0].status = "pending".into();
    mirror.raw_present = true;
    let trace:noisefence::delivery_log::Attempt=serde_json::from_value(serde_json::json!({"route":"mx.example.test","peer":null,"started":1,"elapsed_ms":1,"outcome":"deferred","events":[],"truncated":false})).unwrap();
    let log = logs::Log { attempt: 1, trace };
    let owner = SpoolSnapshot {
        identity: outbox::Identity {
            node: "mx2".into(),
            epoch: uuid::Uuid::new_v4().to_string(),
        },
        metadata: vec![history::Event {
            receipt: outbox::Entry {
                id: id.clone(),
                generation: 100,
                deleted: false,
            },
            record: Some(record),
        }],
        logs: (1..=2)
            .map(|local_id| logs::Event {
                receipt: logs::Receipt {
                    local_id,
                    generation: 101 + local_id,
                    deleted: false,
                },
                message_id: id.clone(),
                recipient: "alice@example.test".into(),
                log: Some(log.clone()),
            })
            .collect(),
        mirrors: vec![],
        mirror_logs: vec![],
    };
    let coordinator = SpoolSnapshot {
        identity: outbox::Identity {
            node: "mx1".into(),
            epoch: uuid::Uuid::new_v4().to_string(),
        },
        metadata: vec![],
        logs: vec![],
        mirrors: vec![Mirror {
            owner: "mx2".into(),
            updated: 1,
            record: mirror,
        }],
        mirror_logs: vec![MirrorLog {
            owner: "mx2".into(),
            local_id: 50,
            message_id: id,
            recipient: "alice@example.test".into(),
            log,
        }],
    };
    vec![coordinator, owner]
}
#[test]
fn reconciles_stale_copies_only_when_envelope_and_all_retained_logs_exist_at_owner() {
    let (sources, report) = ReconciledSpools::verify(sources()).unwrap().into_sources();
    assert_eq!(report.owner_records, 1);
    assert_eq!(report.owner_transcripts, 2);
    assert_eq!(report.duplicate_mirrors, 1);
    assert_eq!(report.duplicate_mirror_transcripts, 1);
    assert!(
        sources
            .iter()
            .all(|s| s.mirrors.is_empty() && s.mirror_logs.is_empty())
    );
    assert_eq!(
        sources[1].metadata[0].record.as_ref().unwrap().deliveries[0].status,
        "delivered"
    );
    assert!(!sources[1].metadata[0].record.as_ref().unwrap().raw_present);
}
#[test]
fn missing_owners_deleted_messages_and_changed_envelopes_are_explicit_conflicts() {
    for case in 0..7 {
        let mut input = sources();
        match case {
            0 => {
                input.pop();
            }
            1 => {
                input[1].metadata.clear();
            }
            2 => {
                input[1].metadata[0].record = None;
                input[1].metadata[0].receipt.deleted = true;
            }
            3 => {
                input[0].mirrors[0].record.sender = "different@example.test".into();
            }
            4 => {
                input[0].mirrors[0].record.deliveries[0].destination =
                    "different@example.test".into();
            }
            5 => {
                input[0].mirrors[0].record.is_dsn = true;
            }
            _ => {
                input[1].identity.node = "mx3".into();
            }
        }
        assert!(ReconciledSpools::verify(input).is_err(), "case {case}");
    }
}
#[test]
fn missing_or_changed_transcripts_and_duplicate_claims_cannot_be_discarded() {
    for case in 0..6 {
        let mut input = sources();
        match case {
            0 => input[1].logs.clear(),
            1 => input[0].mirror_logs[0].log.trace.outcome = "changed".into(),
            2 => input[0].mirror_logs[0].recipient = "hidden@example.test".into(),
            3 => {
                for local_id in [51, 52] {
                    let e = &input[0].mirror_logs[0];
                    let extra = MirrorLog {
                        owner: e.owner.clone(),
                        local_id,
                        message_id: e.message_id.clone(),
                        recipient: e.recipient.clone(),
                        log: e.log.clone(),
                    };
                    input[0].mirror_logs.push(extra);
                }
            }
            4 => {
                let duplicate: history::Event =
                    serde_json::from_value(serde_json::to_value(&input[1].metadata[0]).unwrap())
                        .unwrap();
                input[0].metadata.push(duplicate);
            }
            _ => input[0].identity.node = input[1].identity.node.clone(),
        }
        assert!(ReconciledSpools::verify(input).is_err(), "case {case}");
    }
}
