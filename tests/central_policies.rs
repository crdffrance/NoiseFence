#[allow(dead_code)]
mod common;
#[path = "common/postgres.rs"]
mod postgres;
#[allow(dead_code)]
#[path = "common/web_auth.rs"]
mod web_auth;
use noisefence::{
    central::{outbox::Identity, policies::Proposal},
    cluster::{
        activation::{Acknowledgement, Phase, Progress, transport::PROTOCOL},
        artifacts::{self, Bundle},
    },
    control::Settings,
};

fn proposal<'a>(
    base: &Bundle,
    candidate: Bundle,
    actor: &'a str,
    session: &'a str,
    scope: Option<&'a str>,
) -> Proposal<'a> {
    Proposal {
        revision: candidate.revision - 1,
        base_digest: base.digest.clone(),
        candidate,
        actor,
        session_hash: session,
        scope,
        max_stale_seconds: 60,
    }
}
fn next(base: &Bundle) -> Bundle {
    let mut bundle = base.clone();
    bundle.revision += 1;
    bundle.digest = bundle.hash().unwrap();
    bundle
}

async fn check_incident_authority(
    c: &noisefence::central::Central,
    owner: &Identity,
    epoch: &noisefence::cluster::activation::Epoch,
) {
    assert_eq!(
        c.policy_incident_epoch(owner).await.unwrap(),
        Some(epoch.clone())
    );
    assert!(
        c.record_policy_incident(owner, epoch, Some("runtime_preparation_failed"))
            .await
            .unwrap()
    );
    assert_eq!(
        c.policy_view(owner, "admin", true, 0, false).await.unwrap()["incident"]["code"],
        "runtime_preparation_failed"
    );
    assert!(
        c.policy_view(owner, "alice", false, 0, false)
            .await
            .unwrap()["incident"]
            .is_null()
    );
    let mut stale_epoch = epoch.clone();
    stale_epoch.sequence += 1;
    assert!(
        !c.record_policy_incident(owner, &stale_epoch, None)
            .await
            .unwrap()
    );
    assert!(
        c.record_policy_incident(owner, epoch, Some("private provider error"))
            .await
            .is_err()
    );
    let wrong_owner = Identity {
        epoch: uuid::Uuid::new_v4().to_string(),
        ..owner.clone()
    };
    assert!(
        c.record_policy_incident(&wrong_owner, epoch, None)
            .await
            .is_err()
    );
    assert!(c.record_policy_incident(owner, epoch, None).await.unwrap());
    assert!(c.policy_view(owner, "admin", true, 0, false).await.unwrap()["incident"].is_null());
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL on 127.0.0.1:15432 and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn policy_commit_is_atomic_authorized_fenced_and_recoverable() {
    let f = postgres::Fixture::new().await;
    let c = &f.central;
    let db = f.connect().await;
    let root = tempfile::tempdir().unwrap();
    let mut cfg = (*common::config(root.path())).clone();
    cfg.preferences.enabled = true;
    let base = artifacts::capture(&cfg, Settings::from_config(&cfg), 0)
        .unwrap()
        .bundle;
    let owner = Identity {
        node: "mx1".into(),
        epoch: uuid::Uuid::new_v4().to_string(),
    };
    let peer = Identity {
        node: "mx2".into(),
        epoch: uuid::Uuid::new_v4().to_string(),
    };
    c.register_source(&owner).await.unwrap();
    c.register_source(&peer).await.unwrap();
    let admin_session = "a".repeat(64);
    let user_session = "b".repeat(64);
    for (actor, admin, session) in [
        ("admin", true, &admin_session),
        ("alice", false, &user_session),
    ] {
        db.execute(
            "INSERT INTO noisefence.users(username,password,admin) VALUES($1,'synthetic',$2)",
            &[&actor, &admin],
        )
        .await
        .unwrap();
        db.execute("INSERT INTO noisefence.sessions(token_hash,username,csrf,expires) VALUES($1,$2,'synthetic',$3)",&[session,&actor,&(noisefence::now()+3600)]).await.unwrap();
    }
    db.execute(
        "INSERT INTO noisefence.grants VALUES('alice','alice@example.test')",
        &[],
    )
    .await
    .unwrap();
    c.initialize_policy(&owner, base.clone()).await.unwrap();
    c.initialize_policy(&owner, base.clone()).await.unwrap(); // Lost response is harmless.
    assert!(c.initialize_policy(&owner, next(&base)).await.is_err());
    assert!(
        c.stage_policy(
            &owner,
            proposal(&base, next(&base), "admin", &admin_session, None)
        )
        .await
        .is_err()
    ); // Missing peer readiness.
    c.report_policy_peer(&peer, PROTOCOL, env!("CARGO_PKG_VERSION"), 0, &base.digest)
        .await
        .unwrap();
    for invalid in [i64::MIN, 0, 59, 7 * 86400 + 1, i64::MAX] {
        let mut change = proposal(&base, next(&base), "admin", &admin_session, None);
        change.max_stale_seconds = invalid;
        let error = c.stage_policy(&owner, change).await.err().unwrap();
        assert!(error.to_string().contains("Invalid policy freshness bound"));
    }
    assert!(
        c.stage_policy(
            &owner,
            proposal(&base, next(&base), "alice", &user_session, None)
        )
        .await
        .is_err()
    );
    assert!(
        c.stage_policy(
            &owner,
            proposal(
                &base,
                next(&base),
                "alice",
                &user_session,
                Some("bob@example.test")
            )
        )
        .await
        .is_err()
    );
    let mut wrong_base = proposal(&base, next(&base), "admin", &admin_session, None);
    wrong_base.base_digest = "0".repeat(64);
    assert!(c.stage_policy(&owner, wrong_base).await.is_err());
    let mut upper_bound = proposal(&base, next(&base), "admin", &admin_session, None);
    upper_bound.max_stale_seconds = 7 * 86400;
    let staged = c.stage_policy(&owner, upper_bound).await.unwrap();
    let epoch = staged.rollout().unwrap().epoch().clone();
    assert_eq!(
        c.stage_policy(
            &owner,
            proposal(&base, next(&base), "admin", &admin_session, None)
        )
        .await
        .unwrap()
        .rollout()
        .unwrap()
        .epoch(),
        &epoch
    );
    assert!(c.commit_policy(&owner, &epoch).await.is_err());
    Box::pin(check_incident_authority(c, &owner, &epoch)).await;
    assert_eq!(c.activated_policy().await.unwrap().unwrap().0, 0);
    assert!(
        c.acknowledge_policy(
            &peer,
            &Acknowledgement {
                epoch: epoch.clone(),
                progress: Progress::Applied
            }
        )
        .await
        .is_err()
    );
    for node in [&owner, &peer] {
        c.acknowledge_policy(
            node,
            &Acknowledgement {
                epoch: epoch.clone(),
                progress: Progress::Prepared,
            },
        )
        .await
        .unwrap();
    }
    // The browser session and account version are checked again at commit.
    db.execute(
        "UPDATE noisefence.sessions SET expires=0 WHERE username='admin'",
        &[],
    )
    .await
    .unwrap();
    assert!(c.commit_policy(&owner, &epoch).await.is_err());
    db.execute(
        "UPDATE noisefence.sessions SET expires=$1 WHERE username='admin'",
        &[&(noisefence::now() + 3600)],
    )
    .await
    .unwrap();
    db.execute(
        "UPDATE noisefence.users SET version=version+1 WHERE username='admin'",
        &[],
    )
    .await
    .unwrap();
    assert!(c.commit_policy(&owner, &epoch).await.is_err());
    c.abort_policy(&owner, &epoch, "admin", &admin_session)
        .await
        .unwrap();
    assert_eq!(c.activated_policy().await.unwrap().unwrap().0, 0);
    c.record_policy_incident(&owner, &epoch, Some("activation_step_failed"))
        .await
        .unwrap();
    let staged = c
        .stage_policy(
            &owner,
            proposal(&base, next(&base), "admin", &admin_session, None),
        )
        .await
        .unwrap();
    let epoch = staged.rollout().unwrap().epoch().clone();
    assert!(epoch.sequence > 1);
    assert!(
        db.query_one(
            "SELECT incident IS NULL FROM noisefence.policy_authority",
            &[]
        )
        .await
        .unwrap()
        .get::<_, bool>(0)
    );
    let wrong = Identity {
        epoch: uuid::Uuid::new_v4().to_string(),
        ..peer.clone()
    };
    assert!(
        c.acknowledge_policy(
            &wrong,
            &Acknowledgement {
                epoch: epoch.clone(),
                progress: Progress::Prepared
            }
        )
        .await
        .is_err()
    );
    for node in [&owner, &peer] {
        c.acknowledge_policy(
            node,
            &Acknowledgement {
                epoch: epoch.clone(),
                progress: Progress::Prepared,
            },
        )
        .await
        .unwrap();
    }
    // Force a failure after the INSERT revision, before commit: both the new
    // revision and the barrier must roll back, then succeed together on retry.
    db.batch_execute("CREATE FUNCTION noisefence.fail_policy_head() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic failure'; END $$; CREATE TRIGGER synthetic_head_failure BEFORE UPDATE ON noisefence.policy_head FOR EACH ROW EXECUTE FUNCTION noisefence.fail_policy_head();").await.unwrap();
    assert!(c.commit_policy(&owner, &epoch).await.is_err());
    assert_eq!(
        db.query_one("SELECT count(*) FROM noisefence.policy_revisions", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    assert_eq!(
        c.policy_journal(&owner)
            .await
            .unwrap()
            .rollout()
            .unwrap()
            .phase(),
        Phase::Preparing
    );
    db.batch_execute("DROP TRIGGER synthetic_head_failure ON noisefence.policy_head; DROP FUNCTION noisefence.fail_policy_head();").await.unwrap();
    c.commit_policy(&owner, &epoch).await.unwrap();
    c.commit_policy(&owner, &epoch).await.unwrap();
    assert!(c.activated_policy().await.unwrap().is_none());
    assert!(
        c.abort_policy(&owner, &epoch, "admin", &admin_session)
            .await
            .is_err()
    );
    assert!(c.release_policy(&owner, &epoch).await.is_err());
    // An unavailable authority must never manufacture a release decision.
    f.suspend().await;
    assert!(c.policy_journal(&owner).await.is_err());
    f.resume().await;
    let db = f.connect().await;
    let restarted = noisefence::central::Central::new(&f.settings).unwrap();
    assert_eq!(
        restarted
            .policy_journal(&owner)
            .await
            .unwrap()
            .rollout()
            .unwrap()
            .phase(),
        Phase::Committed
    );
    c.acknowledge_policy(
        &owner,
        &Acknowledgement {
            epoch: epoch.clone(),
            progress: Progress::Applied,
        },
    )
    .await
    .unwrap();
    // Recovery is a new fenced revision, never an in-place rewind.
    let recovery = c
        .recover_policy(&owner, &epoch, "admin", &admin_session)
        .await
        .unwrap();
    let recovered_epoch = recovery.rollout().unwrap().epoch().clone();
    assert_eq!(recovered_epoch.revision, 2);
    assert_eq!(recovery.rollout().unwrap().recovery_of(), Some(&epoch));
    assert_eq!(
        c.recover_policy(&owner, &epoch, "admin", &admin_session)
            .await
            .unwrap()
            .rollout()
            .unwrap()
            .epoch(),
        &recovered_epoch
    );
    assert!(
        c.abort_policy(&owner, &recovered_epoch, "admin", &admin_session)
            .await
            .is_err()
    );
    assert!(
        c.acknowledge_policy(
            &peer,
            &Acknowledgement {
                epoch: epoch.clone(),
                progress: Progress::Applied
            }
        )
        .await
        .is_err()
    );
    for node in [&owner, &peer] {
        c.acknowledge_policy(
            node,
            &Acknowledgement {
                epoch: recovered_epoch.clone(),
                progress: Progress::Prepared,
            },
        )
        .await
        .unwrap();
    }
    c.commit_policy(&owner, &recovered_epoch).await.unwrap();
    for node in [&owner, &peer] {
        c.acknowledge_policy(
            node,
            &Acknowledgement {
                epoch: recovered_epoch.clone(),
                progress: Progress::Applied,
            },
        )
        .await
        .unwrap();
    }
    let released = c.release_policy(&owner, &recovered_epoch).await.unwrap();
    c.release_policy(&owner, &recovered_epoch).await.unwrap();
    assert_eq!(released.rollout().unwrap().phase(), Phase::Released);
    assert_eq!(c.activated_policy().await.unwrap().unwrap().0, 2);
    assert_eq!(released.current().settings, base.settings);
    assert_eq!(
        db.query_one("SELECT count(*) FROM noisefence.policy_revisions", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        3
    );
    assert_eq!(
        db.query_one(
            "SELECT count(*) FROM noisefence.audit WHERE action='configuration'",
            &[]
        )
        .await
        .unwrap()
        .get::<_, i64>(0),
        2
    );
    // Personal proposals cannot alter thresholds or other mailboxes.
    c.report_policy_peer(
        &peer,
        PROTOCOL,
        env!("CARGO_PKG_VERSION"),
        2,
        &released.current().digest,
    )
    .await
    .unwrap();
    let mut personal = next(released.current());
    personal.settings.preferences.mailboxes.insert(
        "alice@example.test".into(),
        noisefence::preferences::Preference {
            profile: None,
            rules: Vec::new(),
        },
    );
    personal.digest = personal.hash().unwrap();
    let mut outside = personal.clone();
    outside.settings.filters.threshold = 91.;
    outside.digest = outside.hash().unwrap();
    assert!(
        c.stage_policy(
            &owner,
            proposal(
                released.current(),
                outside,
                "alice",
                &user_session,
                Some("alice@example.test")
            )
        )
        .await
        .is_err()
    );
    let staged = c
        .stage_policy(
            &owner,
            proposal(
                released.current(),
                personal,
                "alice",
                &user_session,
                Some("alice@example.test"),
            ),
        )
        .await
        .unwrap();
    let epoch = staged.rollout().unwrap().epoch().clone();
    c.record_policy_incident(&owner, &epoch, Some("runtime_preparation_failed"))
        .await
        .unwrap();
    assert_eq!(
        c.policy_view(&owner, "alice", false, released.current().revision, false)
            .await
            .unwrap()["incident"]["code"],
        "runtime_preparation_failed"
    );
    for node in [&owner, &peer] {
        c.acknowledge_policy(
            node,
            &Acknowledgement {
                epoch: epoch.clone(),
                progress: Progress::Prepared,
            },
        )
        .await
        .unwrap();
    }
    db.execute("DELETE FROM noisefence.grants WHERE username='alice'", &[])
        .await
        .unwrap();
    assert!(
        c.policy_view(&owner, "alice", false, released.current().revision, false)
            .await
            .unwrap()["incident"]
            .is_null()
    );
    assert!(c.commit_policy(&owner, &epoch).await.is_err());
    c.abort_policy(&owner, &epoch, "admin", &admin_session)
        .await
        .unwrap();
    db.execute(
        "UPDATE noisefence.sources SET enabled=false WHERE node='mx2'",
        &[],
    )
    .await
    .unwrap();
    assert!(c.policy_journal(&owner).await.is_err());
    let view = c
        .policy_view(&owner, "admin", true, base.revision, true)
        .await
        .unwrap();
    assert_eq!(view["incident"]["code"], "membership_changed");
    assert_eq!(view["smtp_ready"], false);
    assert_eq!(view["abortable"], false);
    assert!(
        c.record_policy_incident(&owner, &epoch, Some("activation_step_failed"))
            .await
            .unwrap()
    );
    assert_eq!(
        db.query_one(
            "SELECT incident->>'code' FROM noisefence.policy_authority",
            &[]
        )
        .await
        .unwrap()
        .get::<_, String>(0),
        "membership_changed"
    );
    f.finish().await;
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL on 127.0.0.1:15432 and NOISEFENCE_TEST_PG_PASSWORD_FILE"]
async fn controller_uses_central_policy_and_local_admission_fences() {
    use noisefence::{central::outbox, cluster, control::Controller, store::Store};
    use std::sync::Arc;
    let _ = rustls::crypto::ring::default_provider().install_default();
    let f = postgres::Fixture::new().await;
    let db = f.connect().await;
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let mut config = (*common::config(a.path())).clone();
    config.cluster = Some(cluster::Settings {
        role: cluster::Role::Coordinator,
        node_id: "mx1".into(),
        coordinator_url: None,
        credential_file: None,
        poll_seconds: 2,
        max_stale_seconds: 60,
        allow_loopback_http: true,
    });
    let config = Arc::new(config);
    let local = Store::open(a.path()).unwrap();
    cluster::prepare(&config, &local).await.unwrap();
    let owner = local.run(|db| outbox::initialize(db, "mx1")).await.unwrap();
    let peer = Identity {
        node: "mx2".into(),
        epoch: uuid::Uuid::new_v4().to_string(),
    };
    for node in [&owner, &peer] {
        f.central.register_source(node).await.unwrap();
    }
    let publication = artifacts::bind_credentials(
        artifacts::capture(&config, Settings::from_config(&config), 0).unwrap(),
    )
    .unwrap();
    artifacts::freeze(a.path(), &publication, 0).unwrap();
    let base = publication.bundle.clone();
    f.central
        .initialize_policy(&owner, base.clone())
        .await
        .unwrap();
    f.central
        .report_policy_peer(&peer, PROTOCOL, env!("CARGO_PKG_VERSION"), 0, &base.digest)
        .await
        .unwrap();
    let raw_session = "a".repeat(64);
    let session = noisefence::message::digest(raw_session.as_bytes());
    db.execute(
        "INSERT INTO noisefence.users(username,password,admin) VALUES('admin','synthetic',true)",
        &[],
    )
    .await
    .unwrap();
    db.execute("INSERT INTO noisefence.sessions(token_hash,username,csrf,expires) VALUES($1,'admin','synthetic',$2)",&[&session,&(noisefence::now()+3600)]).await.unwrap();
    // No matching SQLite administrator or configuration may be needed or used.
    local.run(|db|{db.execute("INSERT INTO console_revisions(id,created,username,settings) VALUES(999,0,'stale','{}')",[])?;Ok(())}).await.unwrap();
    let store = local
        .clone()
        .with_management(f.central.clone())
        .await
        .unwrap();
    let control = Controller::load(config.clone(), store).await.unwrap();
    assert_eq!(control.snapshot().revision, 0);
    assert!(
        control
            .apply_session(0, base.settings.clone(), "admin".into(), session.clone())
            .await
            .is_err()
    );
    let mut settings = base.settings.clone();
    settings.filters.threshold = 96.;
    let staged = control
        .stage_activation_session(0, settings, "admin".into(), session.clone())
        .await
        .unwrap();
    let epoch = staged.rollout().unwrap().epoch().clone();
    let mut worker_config = (*common::config(b.path())).clone();
    worker_config.cluster = Some(cluster::Settings {
        role: cluster::Role::Worker,
        node_id: "mx2".into(),
        coordinator_url: Some("http://127.0.0.1:1".into()),
        credential_file: Some(b.path().join("identity")),
        poll_seconds: 2,
        max_stale_seconds: 60,
        allow_loopback_http: true,
    });
    let worker_store = Store::open(b.path()).unwrap();
    cluster::prepare(&worker_config, &worker_store)
        .await
        .unwrap();
    // Freeze both bound credential generations, as authenticated transport will.
    let keys = noisefence::credentials::Snapshot::capture(&publication.config).unwrap();
    noisefence::credentials::generations::freeze(b.path(), &keys).unwrap();
    let worker = Controller::load(Arc::new(worker_config), worker_store)
        .await
        .unwrap();
    let ack = worker
        .synchronize_activation(staged, keys.clone(), noisefence::now())
        .await
        .unwrap()
        .unwrap();
    f.central.acknowledge_policy(&peer, &ack).await.unwrap();
    let committed = control.advance_activation().await.unwrap().unwrap();
    assert_eq!(committed.rollout().unwrap().phase(), Phase::Committed);
    assert!(!control.cluster_ready());
    assert!(!worker.cluster_ready());
    let ack = worker
        .synchronize_activation(committed, keys.clone(), noisefence::now())
        .await
        .unwrap()
        .unwrap();
    f.central.acknowledge_policy(&peer, &ack).await.unwrap();
    let released = control.advance_activation().await.unwrap().unwrap();
    assert_eq!(released.rollout().unwrap().phase(), Phase::Released);
    assert!(!control.cluster_ready()); // Central release is not a local install proof.
    worker
        .synchronize_activation(released, keys, noisefence::now())
        .await
        .unwrap();
    control.advance_activation().await.unwrap();
    assert!(control.cluster_ready());
    assert!(worker.cluster_ready());
    assert_eq!(control.snapshot().revision, 1);
    assert_eq!(control.snapshot().settings.filters.threshold, 96.);
    f.central
        .record_policy_incident(&owner, &epoch, Some("runtime_generation_busy"))
        .await
        .unwrap();
    assert_eq!(
        control.activation_view("admin".into(), true).await.unwrap()["incident"]["code"],
        "runtime_generation_busy"
    );
    control.advance_activation().await.unwrap();
    assert!(control.activation_view("admin".into(), true).await.unwrap()["incident"].is_null());
    let app = noisefence::api::router_controlled(
        config.clone(),
        control.store.clone(),
        Some(control.clone()),
    )
    .unwrap();
    let cookie = format!("noisefence_session={raw_session}");
    let (status, revisions, _) = web_auth::call(
        &app,
        &config.web.public_origin,
        "/admin/revisions",
        &cookie,
        "",
        None,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK);
    assert_eq!(revisions.as_array().unwrap().len(), 2);
    assert_eq!(revisions[0]["id"], 1);
    assert_eq!(revisions[1]["id"], 0);
    for id in [0, 1] {
        let (status, settings, _) = web_auth::call(
            &app,
            &config.web.public_origin,
            &format!("/admin/revisions/{id}"),
            &cookie,
            "",
            None,
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::OK);
        assert_eq!(
            settings["filters"]["threshold"],
            if id == 0 {
                config.filter.threshold
            } else {
                96.
            }
        );
    }
    assert_eq!(
        web_auth::call(
            &app,
            &config.web.public_origin,
            "/admin/revisions/999",
            &cookie,
            "",
            None
        )
        .await
        .0,
        axum::http::StatusCode::NOT_FOUND
    );
    assert!(
        f.central
            .policy_revisions("missing")
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        f.central
            .policy_revision("missing", 1)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        control.activation_view("admin".into(), true).await.unwrap()["committed_revision"],
        1
    );
    assert_eq!(
        local
            .read(|db| Ok(
                db.query_row("SELECT MAX(id) FROM console_revisions", [], |r| r
                    .get::<_, i64>(0))?
            ))
            .await
            .unwrap(),
        999
    );
    // The already-verified local participant cache can restart through a central
    // outage, but it never grants permission to stage a policy without PostgreSQL.
    local
        .run(|db| {
            db.execute(
                "UPDATE cluster_state SET value=?1 WHERE key='last_sync'",
                [(noisefence::now() - 120).to_string()],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    f.suspend().await;
    let restarted = Controller::load(config, control.store.clone())
        .await
        .unwrap();
    assert_eq!(restarted.snapshot().revision, 1);
    assert!(!restarted.cluster_ready()); // An expired cache cannot accept mail.
    assert!(
        restarted
            .stage_activation_session(1, base.settings, "admin".into(), session)
            .await
            .is_err()
    );
    f.resume().await;
    assert_eq!(
        f.central
            .policy_journal(&owner)
            .await
            .unwrap()
            .current_epoch(),
        epoch
    );
    f.finish().await;
}
