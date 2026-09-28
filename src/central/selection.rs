//! Durable local authority selection. Version seven fences older binaries.
use super::{binding::Binding, outbox::Identity};
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OptionalExtension, Transaction};
use serde::{Deserialize, Serialize};
use std::{
    io::Read,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};

pub const FORMAT: i64 = 7;
const PROTOCOL: &str = "noisefence-management-selection-1";
const KEY: &str = "management_selection";
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub protocol: String,
    pub database: Binding,
    pub node: Identity,
    pub role: crate::cluster::Role,
    pub baseline: crate::cluster::activation::Epoch,
    pub mfa_key_sha256: Option<String>,
}
impl Selection {
    pub fn new(
        database: Binding,
        node: Identity,
        role: crate::cluster::Role,
        baseline: crate::cluster::activation::Epoch,
        mfa_key_sha256: Option<String>,
    ) -> Result<Self> {
        let value = Self {
            protocol: PROTOCOL.into(),
            database,
            node,
            role,
            baseline,
            mfa_key_sha256,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<()> {
        self.database.validate()?;
        self.baseline.validate()?;
        ensure!(
            self.protocol == PROTOCOL
                && crate::cluster::valid_id(&self.node.node)
                && uuid::Uuid::parse_str(&self.node.epoch)
                    .is_ok_and(|id| id.to_string() == self.node.epoch),
            "Invalid local management selection"
        );
        ensure!(
            match self.role {
                crate::cluster::Role::Coordinator => self
                    .mfa_key_sha256
                    .as_deref()
                    .is_some_and(crate::compatibility::valid_hash),
                crate::cluster::Role::Worker => self.mfa_key_sha256.is_none(),
            },
            "Invalid selected MFA key binding"
        );
        Ok(())
    }
    /// Final local cutover transaction only, after the importer has verified
    /// PostgreSQL. Never accepts a partially enrolled participant or rollout.
    pub fn install(&self, tx: &Transaction<'_>) -> Result<()> {
        self.validate()?;
        let version: i64 = tx.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version == FORMAT {
            ensure!(
                Self::read(tx)?.as_ref() == Some(self),
                "Another management authority is already selected"
            );
            return Ok(());
        }
        ensure!(
            version == 6,
            "Central selection requires coordinated storage format six"
        );
        self.verify_identity(tx)?;
        let local = crate::cluster::activation::participant::Local::read(tx)?
            .context("Enrol this MX in coordinated activation before migration")?;
        ensure!(
            local.authority().released() && local.installed_epoch() == &self.baseline,
            "Resolve the local policy fence before selecting central management"
        );
        let existing: Option<String> = tx
            .query_row("SELECT value FROM cluster_state WHERE key=?1", [KEY], |r| {
                r.get(0)
            })
            .optional()?;
        ensure!(
            existing.is_none(),
            "Unexpected management selection in legacy storage"
        );
        for (name, value) in [
            ("runtime_history_protocol", crate::runtime_history::PROTOCOL),
            ("management_transport", super::transport::PROTOCOL),
        ] {
            let previous: Option<String> = tx
                .query_row(
                    "SELECT value FROM cluster_state WHERE key=?1",
                    [name],
                    |r| r.get(0),
                )
                .optional()?;
            ensure!(
                previous.as_deref().is_none_or(|old| old == value),
                "Unknown central protocol marker"
            );
            tx.execute(
                "INSERT OR IGNORE INTO cluster_state VALUES(?1,?2)",
                [name, value],
            )?;
        }
        tx.execute(
            "INSERT INTO cluster_state VALUES(?1,?2)",
            [KEY, &serde_json::to_string(self)?],
        )?;
        tx.pragma_update(None, "user_version", FORMAT)?;
        Ok(())
    }
    pub fn read(db: &Connection) -> Result<Option<Self>> {
        let version: i64 = db.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        let table:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='cluster_state')",[],|r|r.get(0))?;
        if !table {
            ensure!(version < FORMAT, "Central selection is missing");
            return Ok(None);
        }
        let raw:Option<Option<String>>=db.query_row("SELECT CASE WHEN length(value)<=8192 THEN value END FROM cluster_state WHERE key=?1",[KEY],|r|r.get::<_,Option<String>>(0)).optional()?;
        match raw {
            Some(raw) => {
                let raw = raw.context("Central selection is oversized")?;
                ensure!(
                    version == FORMAT,
                    "Central selection has an incompatible storage format"
                );
                let selection: Self = serde_json::from_str(&raw)?;
                selection.validate()?;
                selection.verify_identity(db)?;
                for (key, expected) in [
                    ("runtime_history_protocol", crate::runtime_history::PROTOCOL),
                    ("management_transport", super::transport::PROTOCOL),
                ] {
                    let value: Option<String> = db
                        .query_row("SELECT value FROM cluster_state WHERE key=?1", [key], |r| {
                            r.get(0)
                        })
                        .optional()?;
                    ensure!(
                        value.as_deref() == Some(expected),
                        "Selected management protocol marker is missing or incompatible"
                    );
                }
                Ok(Some(selection))
            }
            None => {
                ensure!(
                    version < FORMAT,
                    "Central selection is missing or oversized"
                );
                Ok(None)
            }
        }
    }
    fn verify_identity(&self, db: &Connection) -> Result<()> {
        let expected_role = match self.role {
            crate::cluster::Role::Coordinator => "coordinator",
            crate::cluster::Role::Worker => "worker",
        };
        let matches:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM cluster_state WHERE key='node_id' AND value=?1) AND EXISTS(SELECT 1 FROM cluster_state WHERE key='role' AND value=?2)",[&self.node.node,expected_role],|r|r.get(0))?;
        ensure!(
            matches && super::outbox::identity(db)? == self.node,
            "Management selection belongs to another spool"
        );
        Ok(())
    }
    pub fn verify_key(&self, root: &Path) -> Result<()> {
        self.validate()?;
        if let Some(expected) = &self.mfa_key_sha256 {
            ensure!(
                &key_digest(root)? == expected,
                "Restore the original MFA key before starting the console"
            );
        }
        Ok(())
    }
}
/// Read only: never create a replacement key while opening selected storage.
pub fn key_digest(root: &Path) -> Result<String> {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(root.join("mfa.key"))?;
    let info = file.metadata()?;
    ensure!(
        info.is_file() && info.len() == 32 && info.permissions().mode() & 0o077 == 0,
        "MFA key must be the original private regular file"
    );
    let mut bytes = [0u8; 32];
    file.read_exact(&mut bytes)?;
    Ok(crate::message::digest(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cluster::{
        Role,
        activation::{Acknowledgement, Journal, Progress, participant::Local},
        artifacts,
    };
    fn prepared() -> (tempfile::TempDir, rusqlite::Connection, Selection) {
        prepared_node("mx1", Role::Coordinator)
    }
    fn prepared_node(
        node: &str,
        role: Role,
    ) -> (tempfile::TempDir, rusqlite::Connection, Selection) {
        let root = tempfile::tempdir().unwrap();
        drop(crate::store::Store::open(root.path()).unwrap());
        crate::mfa::Key::open(root.path()).unwrap();
        let mut db = rusqlite::Connection::open(root.path().join("state.sqlite3")).unwrap();
        let identity = crate::central::outbox::initialize(&mut db, node).unwrap();
        let mut config: crate::config::Config =
            toml::from_str(include_str!("../../config/development.toml")).unwrap();
        config.data_dir = root.path().into();
        let active = artifacts::capture(&config, crate::control::Settings::from_config(&config), 0)
            .unwrap()
            .bundle;
        let mut candidate = active.clone();
        candidate.revision = 1;
        candidate.digest = candidate.hash().unwrap();
        let tx = db.transaction().unwrap();
        tx.execute(
            "INSERT INTO cluster_state VALUES('role',?1),('node_id',?2)",
            rusqlite::params![
                if role == Role::Coordinator {
                    "coordinator"
                } else {
                    "worker"
                },
                node
            ],
        )
        .unwrap();
        // A worker observes the coordinator's journal; it must never create
        // an authority in storage whose role is worker.
        let authority_root = tempfile::tempdir().unwrap();
        let mut authority_db = if role == Role::Worker {
            drop(crate::store::Store::open(authority_root.path()).unwrap());
            let db =
                rusqlite::Connection::open(authority_root.path().join("state.sqlite3")).unwrap();
            db.execute_batch(
                "INSERT INTO cluster_state VALUES('role','coordinator'),('node_id','mx1')",
            )
            .unwrap();
            Some(db)
        } else {
            None
        };
        let authority_tx = authority_db.as_mut().map(|db| db.transaction().unwrap());
        let authority = authority_tx.as_ref().unwrap_or(&tx);
        Journal::initialize(authority, "mx1", active).unwrap();
        let journal =
            Journal::begin(authority, candidate, vec!["mx1".into(), "mx2".into()], 1).unwrap();
        let epoch = journal.rollout().unwrap().epoch().clone();
        let mut local = Local::observe(None, node, journal).unwrap();
        local.prepared().unwrap();
        local.save(&tx).unwrap();
        for participant in ["mx1", "mx2"] {
            Journal::acknowledge(
                authority,
                participant,
                &Acknowledgement {
                    epoch: epoch.clone(),
                    progress: Progress::Prepared,
                },
                2,
            )
            .unwrap();
        }
        let journal = Journal::commit(authority, &epoch, 3).unwrap();
        local = Local::observe(Some(local), node, journal).unwrap();
        local.applied().unwrap();
        local.save(&tx).unwrap();
        for participant in ["mx1", "mx2"] {
            Journal::acknowledge(
                authority,
                participant,
                &Acknowledgement {
                    epoch: epoch.clone(),
                    progress: Progress::Applied,
                },
                4,
            )
            .unwrap();
        }
        let journal = Journal::release(authority, &epoch, 5).unwrap();
        local = Local::observe(Some(local), node, journal).unwrap();
        local.save(&tx).unwrap();
        if let Some(authority_tx) = authority_tx {
            authority_tx.commit().unwrap();
        }
        tx.commit().unwrap();
        let selection = Selection::new(
            Binding {
                instance: uuid::Uuid::new_v4().to_string(),
                source_digest: "a".repeat(64),
            },
            identity,
            role,
            epoch,
            (role == Role::Coordinator).then(|| key_digest(root.path()).unwrap()),
        )
        .unwrap();
        (root, db, selection)
    }
    fn central(selection: &Selection) -> crate::central::Central {
        crate::central::Central::new_bound(
            &crate::central::Settings {
                host: "/unavailable/postgresql".into(),
                port: 5432,
                database: "test".into(),
                username: "test".into(),
                password_file: None,
                ca_file: None,
                max_connections: 1,
                allow_loopback_plaintext: false,
            },
            &selection.database,
        )
        .unwrap()
    }
    #[test]
    fn selection_is_atomic_replay_safe_and_blocks_legacy_storage_without_postgres() {
        let (root, mut db, selection) = prepared();
        {
            let tx = db.transaction().unwrap();
            selection.install(&tx).unwrap();
        }
        assert!(Selection::read(&db).unwrap().is_none());
        assert_eq!(
            db.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            6
        );
        let tx = db.transaction().unwrap();
        selection.install(&tx).unwrap();
        tx.commit().unwrap();
        assert_eq!(Selection::read(&db).unwrap(), Some(selection.clone()));
        assert!(crate::store::Store::open(root.path()).is_err());
        // The explicit constructor is offline: a database outage cannot stop
        // opening the durable local queue and cached participant state.
        let store =
            crate::store::Store::open_bound(root.path(), &selection, Some(central(&selection)))
                .unwrap();
        assert!(store.management().is_some());
        let tx = db.transaction().unwrap();
        selection.install(&tx).unwrap();
        crate::store::require_format(&tx, 3).unwrap();
        assert_eq!(
            tx.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            7
        );
        tx.commit().unwrap();
        let mut wrong = selection.clone();
        wrong.database.instance = uuid::Uuid::new_v4().to_string();
        assert!(
            crate::store::Store::open_bound(root.path(), &wrong, Some(central(&wrong))).is_err()
        );
        let tx = db.transaction().unwrap();
        assert!(wrong.install(&tx).is_err());
    }
    #[test]
    fn key_and_spool_mismatches_fail_closed_without_generating_a_replacement() {
        let (root, mut db, selection) = prepared();
        let tx = db.transaction().unwrap();
        selection.install(&tx).unwrap();
        tx.commit().unwrap();
        selection.verify_key(root.path()).unwrap();
        std::fs::remove_file(root.path().join("mfa.key")).unwrap();
        assert!(selection.verify_key(root.path()).is_err());
        assert!(!root.path().join("mfa.key").exists());
        crate::mfa::Key::open(root.path()).unwrap();
        assert!(selection.verify_key(root.path()).is_err());
        db.execute(
            "UPDATE management_journal SET epoch=?1",
            [uuid::Uuid::new_v4().to_string()],
        )
        .unwrap();
        assert!(Selection::read(&db).is_err());
        assert!(
            crate::store::Store::open_bound(root.path(), &selection, Some(central(&selection)))
                .is_err()
        );
    }
    #[tokio::test]
    async fn selected_bootstrap_and_console_open_offline_from_cache_without_stale_policy() {
        use crate::central::bootstrap::{Management, Purpose};
        let (root, mut db, selection) = prepared();
        let tx = db.transaction().unwrap();
        selection.install(&tx).unwrap();
        tx.commit().unwrap();
        db.execute(
            "INSERT INTO console_revisions VALUES(999,1,'stale','invalid obsolete settings')",
            [],
        )
        .unwrap();
        let mut config: crate::config::Config =
            toml::from_str(include_str!("../../config/development.toml")).unwrap();
        config.data_dir = root.path().into();
        config.cluster = Some(toml::from_str("role='coordinator'\nnode_id='mx1'").unwrap());
        config.management = Some(Management::PostgreSql {
            connection: crate::central::Settings {
                host: "/unavailable/postgresql".into(),
                port: 5432,
                database: "test".into(),
                username: "test".into(),
                password_file: None,
                ca_file: None,
                max_connections: 1,
                allow_loopback_plaintext: false,
            },
        });
        let config = std::sync::Arc::new(config);
        let effective = crate::central::bootstrap::effective_config(config.clone()).unwrap();
        assert!(effective.management.is_some());
        let store = crate::central::bootstrap::open(&config, Purpose::Runtime).unwrap();
        crate::cluster::prepare(&config, &store).await.unwrap();
        let control = crate::control::Controller::load(config.clone(), store.clone())
            .await
            .unwrap();
        assert_eq!(control.snapshot().revision, selection.baseline.revision);
        let _ =
            crate::api::router_controlled(config.clone(), store.clone(), Some(control)).unwrap();
        assert!(store.management().unwrap().health().await.is_err());
        std::fs::remove_file(root.path().join("mfa.key")).unwrap();
        assert!(crate::central::bootstrap::open(&config, Purpose::Runtime).is_err());
        // A privileged reset may still reach the bound PG account repository,
        // but that bypass must never let a console generate a replacement key.
        let recovery = crate::central::bootstrap::open(&config, Purpose::Operator).unwrap();
        assert!(crate::api::router(config, recovery).is_err());
        assert!(!root.path().join("mfa.key").exists());
    }

    #[test]
    fn recovery_requeues_owned_history_above_both_watermarks_without_touching_deliveries() {
        let (_root, mut db, selected) = prepared();
        let tx = db.transaction().unwrap();
        selected.install(&tx).unwrap();
        tx.commit().unwrap();
        let operation = uuid::Uuid::new_v4().to_string();
        let replay = crate::central::recovery::outbox::requeue;
        assert!(replay(&mut db, &selected, &operation, 1000, 500).is_err());
        db.execute("INSERT INTO cluster_state VALUES('management_recovery_required',?1)",
            [serde_json::json!({"protocol":"noisefence-management-recovery-1","operation":operation}).to_string()]).unwrap();
        let owned = uuid::Uuid::new_v4().to_string();
        let deleted = uuid::Uuid::new_v4().to_string();
        let mirror = uuid::Uuid::new_v4().to_string();
        for id in [&owned, &deleted, &mirror] {
            db.execute("INSERT INTO messages(id,created,sender,scan) VALUES(?1,0,'sender@example.test','{}')", [id]).unwrap();
        }
        db.execute(
            "INSERT INTO cluster_origin VALUES(?1,'mx2',?1,0,0,1)",
            [&mirror],
        )
        .unwrap();
        db.execute("INSERT INTO deliveries(message_id,address,destination,hosts,next_attempt,status) VALUES(?1,'alice@example.test','alice@example.test','[]',0,'delivered')", [&owned]).unwrap();
        let delivery = db.last_insert_rowid();
        db.execute(
            "INSERT INTO delivery_attempts(delivery_id,attempt,trace) VALUES(?1,1,'{}')",
            [delivery],
        )
        .unwrap();
        let live_log = db.last_insert_rowid();
        let old = crate::central::outbox::pending(&db, 12).unwrap();
        crate::central::outbox::acknowledge(&mut db, &selected.node, &old).unwrap();
        db.execute("DELETE FROM management_log_outbox", []).unwrap();
        db.execute(
            "INSERT INTO delivery_attempts(delivery_id,attempt,trace) VALUES(?1,2,'{}')",
            [delivery],
        )
        .unwrap();
        let deleted_log = db.last_insert_rowid();
        db.execute("DELETE FROM delivery_attempts WHERE id=?1", [deleted_log])
            .unwrap();
        db.execute("DELETE FROM messages WHERE id=?1", [&deleted])
            .unwrap();
        let prior_sequence = crate::central::outbox::status(&db).unwrap().sequence;
        assert!(replay(&mut db, &selected, &operation, i64::MAX, 500).is_err());
        assert_eq!(
            crate::central::outbox::status(&db).unwrap().sequence,
            prior_sequence
        );
        assert_eq!(
            db.query_row(
                "SELECT seq FROM sqlite_sequence WHERE name='delivery_attempts'",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            deleted_log
        );
        assert!(replay(&mut db, &selected, &operation, 1000, i64::MAX).is_err());
        let result = replay(&mut db, &selected, &operation, 1000, 500).unwrap();
        assert_eq!(result["scheduled_messages"], 2);
        assert_eq!(result["scheduled_logs"], 2);
        let entries = crate::central::outbox::pending(&db, 12).unwrap();
        assert!(
            entries
                .iter()
                .all(|v| v.generation > 1000 && v.generation > prior_sequence && v.id != mirror)
        );
        assert!(entries.iter().any(|v| v.id == deleted && v.deleted));
        assert!(entries.iter().any(|v| v.id == owned && !v.deleted));
        assert_eq!(
            crate::central::outbox::acknowledge(&mut db, &selected.node, &old).unwrap(),
            0
        );
        assert_eq!(
            db.query_row(
                "SELECT status FROM deliveries WHERE id=?1",
                [delivery],
                |r| r.get::<_, String>(0)
            )
            .unwrap(),
            "delivered"
        );
        assert_eq!(db.query_row("SELECT count(*) FROM management_log_outbox WHERE (log_id=?1 AND deleted=0) OR (log_id=?2 AND deleted=1)",rusqlite::params![live_log,deleted_log],|r|r.get::<_,i64>(0)).unwrap(),2);
        assert_eq!(
            replay(&mut db, &selected, &operation, 1000, 500).unwrap(),
            result
        );
        db.execute("UPDATE messages SET scan='{}' WHERE id=?1", [&owned])
            .unwrap();
        assert_eq!(
            crate::central::outbox::acknowledge(&mut db, &selected.node, &entries).unwrap(),
            1
        );
        let later = crate::central::outbox::pending(&db, 12).unwrap();
        assert_eq!(later.len(), 1);
        assert_eq!(later[0].id, owned);
        assert!(later[0].generation > result["sequence"].as_i64().unwrap());
        assert_eq!(
            replay(&mut db, &selected, &operation, 1000, 500).unwrap(),
            result
        );
        assert_eq!(crate::central::outbox::pending(&db, 12).unwrap(), later);
        assert!(replay(&mut db, &selected, &operation, 1001, 500).is_err());
        assert!(
            replay(
                &mut db,
                &selected,
                &uuid::Uuid::new_v4().to_string(),
                1000,
                500
            )
            .is_err()
        );
        assert!(replay(&mut db, &selected, &operation, 1000, 501).is_err());
        db.execute(
            "INSERT INTO delivery_attempts(delivery_id,attempt,trace) VALUES(?1,3,'{}')",
            [delivery],
        )
        .unwrap();
        assert_eq!(db.last_insert_rowid(), 501);
        assert_eq!(
            replay(&mut db, &selected, &operation, 1000, 500).unwrap(),
            result
        );
        db.execute(
            "INSERT INTO delivery_attempts(delivery_id,attempt,trace) VALUES(?1,4,'{}')",
            [delivery],
        )
        .unwrap();
        assert_eq!(db.last_insert_rowid(), 502);
        assert_eq!(Selection::read(&db).unwrap(), Some(selected));
        assert!(db.query_row("SELECT EXISTS(SELECT 1 FROM cluster_state WHERE key='management_recovery_required')",[],|r|r.get::<_,bool>(0)).unwrap());
    }

    #[tokio::test]
    async fn selected_queue_restore_is_fenced_bound_and_offline_without_replaying_delivered_mail() {
        use crate::central::bootstrap::Management;
        let (target, mut target_db, selected) = prepared();
        let tx = target_db.transaction().unwrap();
        selected.install(&tx).unwrap();
        tx.commit().unwrap();
        target_db
            .execute("UPDATE quality_exposure_state SET tracking_since=1", [])
            .unwrap();
        let (peer, mut peer_db, mut peer_selection) = prepared_node("mx2", Role::Worker);
        peer_selection.database = selected.database.clone();
        assert_eq!(peer_selection.baseline, selected.baseline);
        let tx = peer_db.transaction().unwrap();
        peer_selection.install(&tx).unwrap();
        tx.commit().unwrap();
        let mut config: crate::config::Config =
            toml::from_str(include_str!("../../config/development.toml")).unwrap();
        config.data_dir = target.path().into();
        config.cluster = Some(toml::from_str("role='coordinator'\nnode_id='mx1'").unwrap());
        config.management = Some(Management::PostgreSql {
            connection: crate::central::Settings {
                host: "/unavailable/postgresql".into(),
                port: 5432,
                database: "test".into(),
                username: "test".into(),
                password_file: None,
                ca_file: None,
                max_connections: 1,
                allow_loopback_plaintext: false,
            },
        });
        config.replication = Some(crate::ha::Settings {
            peer_id: "mx2".into(),
            peer_url: "https://mx2.example.test".into(),
            credential_file: target.path().join("replica.key"),
            timeout_seconds: 5,
            max_replica_bytes: 1024 * 1024,
            allow_loopback_http: false,
        });
        let fence = target.path().join("fence.json");
        crate::cluster::protocol::private_write(&fence, serde_json::to_string(&serde_json::json!({
            "owner":"mx1","fenced":true,"created":crate::now(),"operation":uuid::Uuid::new_v4().to_string(),"fixture_only":true
        })).unwrap().as_bytes()).unwrap();
        assert!(
            crate::ha::recovery::restore_queue(peer.path(), target.path(), "mx1", &fence)
                .await
                .is_err()
        );
        let held = crate::central::import::SourceLocks::acquire(peer.path()).unwrap();
        assert!(
            crate::ha::recovery::restore_queue_config(
                &config,
                peer.path(),
                target.path(),
                "mx1",
                &fence
            )
            .await
            .is_err()
        );
        drop(held);
        let (wrong, mut wrong_db, wrong_selection) = prepared_node("mx2", Role::Worker);
        let tx = wrong_db.transaction().unwrap();
        wrong_selection.install(&tx).unwrap();
        tx.commit().unwrap();
        assert!(
            crate::ha::recovery::restore_queue_config(
                &config,
                wrong.path(),
                target.path(),
                "mx1",
                &fence
            )
            .await
            .is_err()
        );
        assert_eq!(
            target_db
                .query_row("SELECT count(*) FROM messages", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0
        );
        let preopened =
            crate::central::bootstrap::open(&config, crate::central::bootstrap::Purpose::Runtime)
                .unwrap();
        let raw = b"Subject: selected recovery fixture\r\n\r\nSynthetic message, never delivered.";
        let id = uuid::Uuid::new_v4().to_string();
        let hash = crate::message::digest(raw);
        let delivery = |address: &str, status: &str| crate::ha::replica::Delivery {
            address: address.into(),
            destination: address.into(),
            hosts: vec!["mx.example.test".into()],
            status: status.into(),
            attempts: 1,
            next_attempt: 0,
            error: None,
            dsn_id: None,
            action: "tag".into(),
            held_until: None,
            released_at: None,
            filtering: None,
        };
        let manifest = crate::ha::replica::Manifest {
            protocol: crate::ha::PROTOCOL.into(),
            owner: "mx1".into(),
            id: id.clone(),
            generation: 5,
            confirmed: true,
            created: crate::now(),
            sender: "sender@example.test".into(),
            scan: serde_json::to_value(crate::engine::extract(raw, 1024)).unwrap(),
            is_dsn: false,
            body_hash: Some(hash.clone()),
            body_bytes: raw.len() as u64,
            deliveries: vec![
                delivery("alice@example.test", "delivered"),
                delivery("bob@example.test", "sending"),
            ],
        };
        let bodies = peer.path().join("replicas/mx1");
        std::fs::create_dir_all(&bodies).unwrap();
        std::fs::write(bodies.join(format!("{id}.eml")), raw).unwrap();
        peer_db
            .execute(
                "INSERT INTO ha_remote VALUES('mx1',?1,5,?2,?3,?4,1,?5)",
                rusqlite::params![
                    id,
                    serde_json::to_string(&manifest).unwrap(),
                    hash,
                    raw.len() as i64,
                    crate::now()
                ],
            )
            .unwrap();
        let report = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            crate::ha::recovery::restore_queue_config(
                &config,
                peer.path(),
                target.path(),
                "mx1",
                &fence,
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(report["copied"], 1);
        assert_eq!(report["held_recipients"], 1);
        assert_eq!(report["central_management_recovery_required"], true);
        let error =
            crate::central::bootstrap::open(&config, crate::central::bootstrap::Purpose::Runtime)
                .err()
                .unwrap();
        assert!(
            error
                .to_string()
                .contains("coordinated management recovery")
        );
        assert_eq!(report["network_used"], false);
        let startup_guard = preopened.daemon_lock().unwrap();
        assert!(crate::central::bootstrap::require_complete_recovery(&config).is_err());
        drop(startup_guard);
        assert_eq!(report["smtp_started"], false);
        assert_eq!(
            std::fs::read(target.path().join("spool").join(format!("{id}.eml"))).unwrap(),
            raw
        );
        let statuses = target_db
            .prepare("SELECT status FROM deliveries ORDER BY address")
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(statuses, vec!["delivered", "quarantined"]);
        assert_eq!(Selection::read(&target_db).unwrap(), Some(selected));
        assert_eq!(
            target_db
                .query_row(
                    "SELECT acked FROM ha_local WHERE message_id=?1",
                    [&id],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            0
        );
        assert_eq!(
            target_db
                .query_row(
                    "SELECT tracking_since FROM quality_exposure_state WHERE id=1",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            1
        );
        let again = crate::ha::recovery::restore_queue_config(
            &config,
            peer.path(),
            target.path(),
            "mx1",
            &fence,
        )
        .await
        .unwrap();
        assert_eq!(again["already_restored"], 1);
    }

    #[tokio::test]
    async fn selected_queue_resync_preserves_management_binding_during_database_outage() {
        use crate::central::bootstrap::{Management, Purpose};
        let (root, mut db, selection) = prepared();
        let tx = db.transaction().unwrap();
        selection.install(&tx).unwrap();
        tx.commit().unwrap();
        let scan = serde_json::to_string(&crate::engine::extract(
            b"Subject: synthetic\r\n\r\nfixture",
            1024,
        ))
        .unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        db.execute("INSERT INTO messages(id,created,sender,scan,raw_present) VALUES(?1,1,'sender@example.test',?2,1)",rusqlite::params![id,scan]).unwrap();
        db.execute("INSERT INTO deliveries(message_id,address,destination,hosts,status,next_attempt) VALUES(?1,'alice@example.test','alice@example.test','[]','delivered',0)",[&id]).unwrap();
        db.execute("INSERT INTO ha_local VALUES(?1,5,5)", [&id])
            .unwrap();
        db.execute("INSERT INTO cluster_state VALUES('ha_required','1')", [])
            .unwrap();
        let mut config: crate::config::Config =
            toml::from_str(include_str!("../../config/development.toml")).unwrap();
        config.data_dir = root.path().into();
        config.cluster = Some(toml::from_str("role='coordinator'\nnode_id='mx1'").unwrap());
        config.management = Some(Management::PostgreSql {
            connection: crate::central::Settings {
                host: "/unavailable/postgresql".into(),
                port: 5432,
                database: "test".into(),
                username: "test".into(),
                password_file: None,
                ca_file: None,
                max_connections: 1,
                allow_loopback_plaintext: false,
            },
        });
        let store = crate::central::bootstrap::open(&config, Purpose::Queue).unwrap();
        let guard = store.daemon_lock().unwrap();
        assert!(
            crate::ha::recovery::resync_config(&config, root.path())
                .await
                .is_err()
        );
        drop(guard);
        assert!(crate::ha::recovery::resync(root.path()).await.is_err());
        let other = tempfile::tempdir().unwrap();
        assert!(
            crate::ha::recovery::resync_config(&config, other.path())
                .await
                .is_err()
        );
        let report = crate::ha::recovery::resync_config(&config, root.path())
            .await
            .unwrap();
        assert_eq!(report["tracked"], 1);
        assert_eq!(report["network_used"], false);
        assert_eq!(
            db.query_row(
                "SELECT generation,acked FROM ha_local WHERE message_id=?1",
                [&id],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))
            )
            .unwrap(),
            (6, 0)
        );
        assert_eq!(
            db.query_row(
                "SELECT status FROM deliveries WHERE message_id=?1",
                [&id],
                |r| r.get::<_, String>(0)
            )
            .unwrap(),
            "delivered"
        );
        assert_eq!(
            db.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            7
        );
        assert_eq!(Selection::read(&db).unwrap(), Some(selection));
    }

    #[test]
    fn selected_history_never_falls_back_when_transport_markers_are_missing() {
        let (root, mut db, selection) = prepared();
        let tx = db.transaction().unwrap();
        selection.install(&tx).unwrap();
        tx.commit().unwrap();
        db.execute("DELETE FROM cluster_state WHERE key IN ('management_transport','runtime_history_protocol')",[]).unwrap();
        assert!(Selection::read(&db).is_err());
        assert!(crate::runtime_history::open(root.path()).is_err());
        assert!(
            crate::store::Store::open_bound(root.path(), &selection, Some(central(&selection)))
                .is_err()
        );
    }

    #[test]
    fn oversized_selection_does_not_disappear_after_a_format_downgrade() {
        let (root, db, _selection) = prepared();
        db.execute(
            "INSERT INTO cluster_state VALUES('management_selection',?1)",
            ["x".repeat(8193)],
        )
        .unwrap();
        assert!(Selection::read(&db).is_err());
        assert!(crate::store::Store::open(root.path()).is_err());
    }
    #[tokio::test]
    async fn selected_transport_keeps_pending_history_until_database_bound_acknowledgement() {
        use axum::{Json, Router, response::IntoResponse, routing::post};
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (root, mut db, selection) = prepared();
        let tx = db.transaction().unwrap();
        selection.install(&tx).unwrap();
        tx.commit().unwrap();
        let store =
            crate::store::Store::open_bound(root.path(), &selection, Some(central(&selection)))
                .unwrap();
        let mut config: crate::config::Config =
            toml::from_str(include_str!("../../config/development.toml")).unwrap();
        config.data_dir = root.path().to_path_buf();
        let scan = crate::engine::Engine::new(Arc::new(config))
            .unwrap()
            .offline(b"From: sender@example.test\r\nSubject: Synthetic\r\n\r\nHello");
        let id = uuid::Uuid::new_v4().to_string();
        store.run(move |db| {
            db.execute("INSERT INTO messages(id,created,sender,scan) VALUES(?1,?2,'sender@example.test',?3)",rusqlite::params![id,crate::now(),serde_json::to_string(&scan)?])?;
            db.execute("INSERT INTO deliveries(message_id,address,destination,hosts,next_attempt) VALUES(?1,'alice@example.test','alice@example.test','[]',0)",[id])?;
            Ok(())
        }).await.unwrap();
        let expected = crate::central::binding::header_value(Some(&selection.database))
            .unwrap()
            .unwrap();
        let case = Arc::new(AtomicUsize::new(0));
        let response_case = case.clone();
        let node = selection.node.clone();
        let app=Router::new().route("/api/v1/cluster/v3/history",post(move|headers:axum::http::HeaderMap,Json(body):Json<serde_json::Value>|{
            let expected=expected.clone();let node=node.clone();let case=response_case.clone();
            async move {
                assert_eq!(headers.get(crate::central::binding::HEADER),Some(&expected));
                let receipts=body["events"].as_array().unwrap().iter().map(|event|event["receipt"].clone()).collect::<Vec<_>>();
                let mut response=Json(serde_json::json!({"protocol":crate::central::transport::PROTOCOL,"identity":node,"receipts":receipts})).into_response();
                match case.load(Ordering::SeqCst) {
                    0=>{},
                    1=>{response.headers_mut().insert(crate::central::binding::HEADER,"wrong".parse().unwrap());},
                    2=>{response.headers_mut().append(crate::central::binding::HEADER,expected.clone());response.headers_mut().append(crate::central::binding::HEADER,expected);},
                    _=>{response.headers_mut().insert(crate::central::binding::HEADER,expected);},
                }
                response
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let http = reqwest::Client::builder().no_proxy().build().unwrap();
        for value in 0..3 {
            case.store(value, Ordering::SeqCst);
            assert!(
                crate::central::transport::synchronize_metadata_once(&store, &http, &url)
                    .await
                    .is_err()
            );
            assert_eq!(crate::central::outbox::status(&db).unwrap().pending, 1);
        }
        case.store(3, Ordering::SeqCst);
        assert_eq!(
            crate::central::transport::synchronize_metadata_once(&store, &http, &url)
                .await
                .unwrap(),
            1
        );
        assert_eq!(crate::central::outbox::status(&db).unwrap().pending, 0);
        assert!(
            crate::central::transport::remote_enabled(&store)
                .await
                .unwrap()
        );
        db.execute(
            "DELETE FROM cluster_state WHERE key='management_transport'",
            [],
        )
        .unwrap();
        assert!(
            crate::central::transport::remote_enabled(&store)
                .await
                .is_err()
        );
        server.abort();
    }
}
