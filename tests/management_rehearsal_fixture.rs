//! Generate synthetic enrolled installations for the isolated systemd/SSH rehearsal.
//! Never point this helper at a production directory: the output must not exist.
#[allow(dead_code)]
mod common;
use noisefence::{
    central::outbox,
    cluster::{
        activation::{Acknowledgement, Journal, Progress},
        artifacts,
    },
    control::Settings,
    store::Store,
};
use std::{os::unix::fs::PermissionsExt, path::PathBuf};

#[tokio::test]
#[ignore = "requires NOISEFENCE_REHEARSAL_OUTPUT naming a new synthetic output directory"]
async fn generate_two_enrolled_synthetic_mxs() {
    let root = PathBuf::from(
        std::env::var_os("NOISEFENCE_REHEARSAL_OUTPUT").expect("explicit new output path required"),
    );
    assert!(root.is_absolute() && !root.exists());
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let token = noisefence::api::random_token();
    let replica_token = noisefence::api::random_token();
    let password = noisefence::api::random_token();
    let password_hash = noisefence::api::hash_password(&password).unwrap();
    noisefence::cluster::protocol::private_write(
        &root.join("test-admin.json"),
        serde_json::to_string(&serde_json::json!({"username":"admin","password":password}))
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    let mut configs = Vec::new();
    let mut dbs = Vec::new();
    for i in 1..=2 {
        let folder = root.join(format!("mx{i}"));
        std::fs::create_dir(&folder).unwrap();
        let data = folder.join("data");
        std::fs::create_dir(&data).unwrap();
        std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700)).unwrap();
        drop(Store::open(&data).unwrap());
        let mut config = (*common::config(&data)).clone();
        config.hostname = format!("mx{i}.example.test");
        config.smtp.listen = "127.0.0.1:2525".parse().unwrap();
        config.web.listen = "127.0.0.1:18080".parse().unwrap();
        config.web.public_origin = "http://127.0.0.1:18080".into();
        config.relay.port = 2530; // No external delivery in this isolated rehearsal.
        let role = if i == 1 { "coordinator" } else { "worker" };
        let mut cluster: toml::Table =
            toml::from_str(&format!("role='{role}'\nnode_id='mx{i}'\npoll_seconds=2")).unwrap();
        if i == 2 {
            cluster.insert("coordinator_url".into(), "http://127.0.0.1:19080".into());
            cluster.insert(
                "credential_file".into(),
                "/etc/noisefence/worker.key".into(),
            );
            cluster.insert("allow_loopback_http".into(), true.into());
        }
        config.cluster = Some(cluster.try_into().unwrap());
        config.replication=Some(toml::from_str(&format!("peer_id='mx{}'\npeer_url='http://127.0.0.1:19080'\ncredential_file='/etc/noisefence/replica.key'\nallow_loopback_http=true",3-i)).unwrap());
        config.validate().unwrap();
        noisefence::cluster::protocol::private_write(&folder.join("worker.key"), token.as_bytes())
            .unwrap();
        noisefence::cluster::protocol::private_write(
            &folder.join("replica.key"),
            replica_token.as_bytes(),
        )
        .unwrap();
        let mut db = rusqlite::Connection::open(data.join("state.sqlite3")).unwrap();
        db.execute(
            "INSERT INTO cluster_state VALUES('role',?1),('node_id',?2)",
            rusqlite::params![role, format!("mx{i}")],
        )
        .unwrap();
        outbox::initialize(&mut db, &format!("mx{i}")).unwrap();
        if i == 1 {
            noisefence::mfa::Key::open(&data).unwrap();
            db.execute("INSERT INTO users VALUES('admin',?1,1,0)", [&password_hash])
                .unwrap();
            db.execute("INSERT INTO cluster_nodes(id,name,token_hash,enabled,created,version) VALUES('mx2','Synthetic worker',?1,1,1,1)",[noisefence::message::digest(token.as_bytes())]).unwrap();
        }
        dbs.push(db);
        configs.push(config);
    }
    let baseline = artifacts::bind_credentials(
        artifacts::capture(&configs[0], Settings::from_config(&configs[0]), 0).unwrap(),
    )
    .unwrap();
    let mut publication = baseline.clone();
    publication.bundle.revision = 1;
    publication.bundle.digest = publication.bundle.hash().unwrap();
    for config in &configs {
        artifacts::freeze(&config.data_dir, &publication, 0).unwrap();
    }
    let tx = dbs[0].transaction().unwrap();
    Journal::initialize(&tx, "mx1", baseline.bundle).unwrap();
    let journal = Journal::begin(
        &tx,
        publication.bundle.clone(),
        vec!["mx1".into(), "mx2".into()],
        1,
    )
    .unwrap();
    let epoch = journal.rollout().unwrap().epoch().clone();
    for node in ["mx1", "mx2"] {
        Journal::acknowledge(
            &tx,
            node,
            &Acknowledgement {
                epoch: epoch.clone(),
                progress: Progress::Prepared,
            },
            2,
        )
        .unwrap();
    }
    Journal::commit(&tx, &epoch, 3).unwrap();
    for node in ["mx1", "mx2"] {
        Journal::acknowledge(
            &tx,
            node,
            &Acknowledgement {
                epoch: epoch.clone(),
                progress: Progress::Applied,
            },
            4,
        )
        .unwrap();
    }
    let released = Journal::release(&tx, &epoch, 5).unwrap();
    tx.execute(
        "INSERT INTO console_revisions VALUES(1,3,'admin',?1)",
        [serde_json::to_string(&released.current().settings).unwrap()],
    )
    .unwrap();
    tx.commit().unwrap();
    for (i, db) in dbs.iter_mut().enumerate() {
        let local = serde_json::json!({"version":1,"node":format!("mx{}",i+1),"authority":released,"installed":released.current(),"installed_epoch":epoch,"prepared":epoch});
        db.execute(
            "INSERT INTO cluster_state VALUES('activation_participant',?1)",
            [local.to_string()],
        )
        .unwrap();
        db.pragma_update(None, "user_version", 6).unwrap();
        db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)").unwrap();
        let folder = configs[i].data_dir.parent().unwrap().to_owned();
        configs[i].data_dir = "/var/lib/noisefence".into();
        noisefence::cluster::protocol::private_write(
            &folder.join("config.toml"),
            toml::to_string(&configs[i]).unwrap().as_bytes(),
        )
        .unwrap();
    }
    println!("Synthetic enrolled fixture written to {}", root.display());
}
