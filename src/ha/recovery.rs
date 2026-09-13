//! Offline, fenced disaster recovery. No network and no SMTP acceptance or delivery.
use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde_json::json;
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::Path,
    time::{Duration, Instant},
};

pub fn snapshot_database(source: &Path, destination: &Path) -> Result<()> {
    ensure!(
        source.is_file() && !destination.exists(),
        "Snapshot needs an existing source and a new destination"
    );
    let input = Connection::open_with_flags(source, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    input.busy_timeout(Duration::from_millis(250))?;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination)?;
    let mut output = Connection::open(destination)?;
    let result = (|| -> Result<()> {
        let backup = rusqlite::backup::Backup::new(&input, &mut output)?;
        let started = Instant::now();
        loop {
            ensure!(
                started.elapsed() < Duration::from_secs(30),
                "SQLite snapshot deadline exceeded"
            );
            match backup.step(256)? {
                rusqlite::backup::StepResult::Done => break,
                rusqlite::backup::StepResult::More => {}
                _ => std::thread::sleep(Duration::from_millis(20)),
            }
        }
        drop(backup);
        ensure!(
            output.query_row("PRAGMA quick_check", [], |r| r.get::<_, String>(0))? == "ok",
            "Invalid SQLite snapshot"
        );
        Ok(())
    })();
    drop(output);
    if result.is_err() {
        let _ = fs::remove_file(destination);
    }
    result?;
    File::open(destination)?.sync_all()?;
    File::open(destination.parent().context("Snapshot parent")?)?.sync_all()?;
    Ok(())
}

/// Rebuild acknowledgements after replacing a peer. Requires the queue to be stopped.
pub async fn resync(root: &Path) -> Result<serde_json::Value> {
    let store = crate::store::Store::open(root)?;
    let _lock = store.daemon_lock()?;
    store.run(|db| {
        let tx=db.transaction()?;
        ensure!(tx.query_row("SELECT EXISTS(SELECT 1 FROM cluster_state WHERE key='ha_required' AND value='1')",[],|r|r.get::<_,bool>(0))?,"Queue does not require replication");
        tx.execute("INSERT OR IGNORE INTO ha_local(message_id,generation,acked) SELECT id,1,0 FROM messages m WHERE raw_present=1 AND NOT EXISTS(SELECT 1 FROM cluster_origin WHERE message_id=m.id)",[])?;
        let tracked=tx.execute("UPDATE ha_local SET generation=generation+1,acked=0",[])?;
        tx.execute("INSERT INTO audit(created,username,action,object_id) VALUES(?1,'local-administrator','ha_rejoin_resync','pair')",[crate::now()])?;
        tx.commit()?;
        Ok(json!({"tracked":tracked,"smtp_started":false,"network_used":false,"bodies_deleted":false}))
    }).await
}

/// Check the copied MFA key against every encrypted record without exposing secrets.
pub fn verify_mfa(root: &Path) -> Result<()> {
    let db =
        Connection::open_with_flags(root.join("state.sqlite3"), OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    crate::mfa::require_no_missing_key(root, &db)?;
    let key = crate::mfa::Key::open(root)?;
    let mut q = db.prepare("SELECT username,secret FROM mfa_credentials")?;
    for row in q.query_map([], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
    })? {
        let (user, secret) = row?;
        key.open_secret(&user, &secret)
            .context("MFA recovery key does not match the checkpoint")?;
    }
    Ok(())
}

/// Overlay the freshest peer journal onto a *staged*, stopped console snapshot.
/// The caller must fence the original owner. We require a private, matching receipt
/// and never infer fencing from a failed ping or a stale heartbeat.
pub async fn restore_queue(
    source: &Path,
    target: &Path,
    owner: &str,
    fence: &Path,
) -> Result<serde_json::Value> {
    use std::os::unix::fs::PermissionsExt;
    ensure!(
        crate::cluster::valid_id(owner) && source != target,
        "Invalid recovery roots"
    );
    let meta = fs::metadata(fence)?;
    ensure!(
        meta.is_file() && meta.len() <= 4096 && meta.permissions().mode() & 0o077 == 0,
        "Private fence receipt required"
    );
    let receipt: serde_json::Value = serde_json::from_slice(&fs::read(fence)?)?;
    ensure!(
        receipt["owner"] == owner
            && receipt["fenced"] == true
            && receipt["operation"]
                .as_str()
                .is_some_and(|v| uuid::Uuid::parse_str(v).is_ok_and(|id| id.to_string() == v)),
        "Fence receipt does not name this owner"
    );
    let fenced_at = receipt["created"]
        .as_i64()
        .context("Fence timestamp missing")?;
    ensure!(
        (0..=3600).contains(&crate::now().saturating_sub(fenced_at)),
        "Fence receipt expired"
    );
    let store = crate::store::Store::open(target)?;
    let _lock = store.daemon_lock()?;
    let owner = owner.to_owned();
    let query_owner = owner.clone();
    let db = Connection::open_with_flags(
        source.join("state.sqlite3"),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    db.execute_batch("BEGIN")?;
    let raw = db
        .prepare("SELECT manifest FROM ha_remote WHERE owner=?1 ORDER BY id")?
        .query_map([&owner], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    ensure!(
        raw.len() <= 100000,
        "Replica journal exceeds recovery limit"
    );
    let manifests = raw
        .iter()
        .map(|r| serde_json::from_str::<super::replica::Manifest>(r))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let known = manifests
        .iter()
        .map(|m| m.id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let journal_ids = known.clone();
    store.read(move|db| {
        let identity:Option<String>=db.query_row("SELECT value FROM cluster_state WHERE key='node_id'",[],|r|r.get(0)).optional()?;
        ensure!(identity.as_ref().is_none_or(|v|v==&query_owner),"Never restore one node over another node's active queue");
        let required=db.prepare("SELECT id FROM messages WHERE raw_present=1 AND NOT EXISTS(SELECT 1 FROM cluster_origin WHERE message_id=messages.id)")?.query_map([],|r|r.get::<_,String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;
        ensure!(required.iter().all(|id|known.contains(id)),"Snapshot references an unprotected body; supply the missing original before recovery");
        Ok(())
    }).await?;
    let recovered_owner = owner.clone();
    store
        .run(move |db| {
            let tx = db.transaction()?;
            tx.execute(
                "INSERT OR REPLACE INTO cluster_state VALUES('ha_required','1')",
                [],
            )?;
            tx.execute(
                "INSERT OR REPLACE INTO cluster_state VALUES('node_id',?1)",
                [recovered_owner],
            )?;
            tx.execute(
                "INSERT OR REPLACE INTO cluster_state VALUES('role','coordinator')",
                [],
            )?;
            tx.execute("DELETE FROM ha_remote", [])?;
            tx.execute("DELETE FROM ha_blobs", [])?;
            tx.execute_batch("PRAGMA user_version=5")?;
            tx.commit()?;
            Ok(())
        })
        .await?;
    let manifests=store.read(move |db| {
        let mut result=Vec::with_capacity(manifests.len());
        for mut m in manifests {
            let checkpoint:Option<(i64,i64,String,String,bool,bool)>=db.query_row("SELECT h.generation,m.created,m.sender,m.scan,m.is_dsn,m.raw_present FROM messages m JOIN ha_local h ON h.message_id=m.id WHERE m.id=?1 AND NOT EXISTS(SELECT 1 FROM cluster_origin WHERE message_id=m.id)",[&m.id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).optional()?;
            if let Some((generation,created,sender,scan,is_dsn,present))=checkpoint.filter(|c|c.0>=m.generation) {
                let mut newer=m.clone();newer.deliveries=super::replica::read_deliveries(db,&m.id)?;
                ensure!(m.sender==sender && m.is_dsn==is_dsn && m.identity()==newer.identity(),"Checkpoint and replica envelopes disagree");
                newer.generation=generation;newer.created=created;newer.scan=serde_json::from_str(&scan)?;newer.confirmed=true;
                if present {ensure!(newer.body_hash.is_some(),"Checkpoint references an absent replica body");}
                else {ensure!(newer.resolved(),"Checkpoint lost an unresolved body");newer.body_hash=None;newer.body_bytes=0;}
                m=newer;
            }
            result.push(m);
        }
        Ok(result)
    }).await?;
    let mut copied = 0_u64;
    let mut held = 0_u64;
    let mut pending = 0_u64;
    let mut skipped = 0_u64;
    for mut m in manifests {
        ensure!(
            m.protocol == super::PROTOCOL && m.owner == owner && super::replica::valid_id(&m.id),
            "Invalid replica identity"
        );
        let lookup = m.id.clone();
        let query_owner = owner.clone();
        if store
            .read(move |db| {
                Ok(db.query_row(
                    "SELECT EXISTS(SELECT 1 FROM ha_recoveries WHERE owner=?1 AND id=?2)",
                    params![query_owner, lookup],
                    |r| r.get::<_, bool>(0),
                )?)
            })
            .await?
        {
            skipped += 1;
            continue;
        }
        if let Some(hash) = &m.body_hash {
            ensure!(
                crate::compatibility::valid_hash(hash),
                "Invalid replica digest"
            );
            let from = source
                .join("replicas")
                .join(&owner)
                .join(format!("{}.eml", m.id));
            ensure!(
                crate::cluster::artifacts::file_digest(&from)? == (m.body_bytes, hash.clone()),
                "Recovery body checksum mismatch"
            );
            let destination = store.raw_path(&m.id);
            let temp = store
                .root
                .join("incoming")
                .join(uuid::Uuid::new_v4().to_string());
            let mut input = File::open(from)?;
            let mut output = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&temp)?;
            std::io::copy(&mut input, &mut output)?;
            output.sync_all()?;
            drop(output);
            ensure!(
                crate::cluster::artifacts::file_digest(&temp)? == (m.body_bytes, hash.clone()),
                "Recovery copy changed"
            );
            fs::rename(temp, destination)?;
            File::open(store.root.join("spool"))?.sync_all()?;
            copied += 1;
        }
        let uncertain = !m.confirmed && !m.resolved();
        for d in &mut m.deliveries {
            // "notified" records local DSN enqueue, not necessarily its delivery.
            // A crash before the DSN's first replication must not retire the original.
            let missing_notice = m.body_hash.is_some()
                && d.status == "notified"
                && d.dsn_id
                    .as_ref()
                    .is_some_and(|id| !journal_ids.contains(id));
            if uncertain || d.status == "sending" || missing_notice {
                d.status = "quarantined".into();
                d.action = "quarantine".into();
                d.held_until = None;
                d.error=Some(if missing_notice {
                    "Retake: notification of failure missing from copy; check or re-create notice before resolution."
                } else {
                    "Recovery: acceptance or result SMTP uncertain; verification required before re-launching."
                }.into());
                held += 1;
            } else if d.status == "pending" {
                pending += 1;
            }
        }
        let owner = owner.clone();
        let operation = receipt["operation"].as_str().unwrap().to_owned();
        store.run(move|db| {
            let tx=db.transaction()?;
            ensure!(!tx.query_row("SELECT EXISTS(SELECT 1 FROM cluster_origin WHERE message_id=?1)",[&m.id],|r|r.get::<_,bool>(0))?,"Foreign queue ownership collision");
            let present=m.body_hash.is_some();
            tx.execute("INSERT INTO messages(id,created,sender,scan,is_dsn,raw_present) VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(id) DO UPDATE SET scan=excluded.scan,raw_present=excluded.raw_present",params![m.id,m.created,m.sender,serde_json::to_string(&m.scan)?,m.is_dsn,present])?;
            for d in m.deliveries {
                tx.execute("INSERT INTO deliveries(message_id,address,destination,hosts,status,attempts,next_attempt,error,dsn_id) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9) ON CONFLICT(message_id,address) DO UPDATE SET status=excluded.status,attempts=excluded.attempts,next_attempt=excluded.next_attempt,error=excluded.error,dsn_id=excluded.dsn_id",params![m.id,d.address,d.destination,serde_json::to_string(&d.hosts)?,d.status,d.attempts,d.next_attempt,d.error,d.dsn_id])?;
                let delivery_id:i64=tx.query_row("SELECT id FROM deliveries WHERE message_id=?1 AND address=?2",params![m.id,d.address],|r|r.get(0))?;
                tx.execute("INSERT INTO delivery_policy VALUES(?1,?2,?3,?4) ON CONFLICT(delivery_id) DO UPDATE SET action=excluded.action,held_until=excluded.held_until,released_at=excluded.released_at",params![delivery_id,d.action,d.held_until,d.released_at])?;
                if let Some(filtering)=d.filtering {tx.execute("INSERT OR REPLACE INTO delivery_filtering VALUES(?1,?2)",params![delivery_id,serde_json::to_string(&filtering)?])?;}
            }
            tx.execute("INSERT INTO ha_recoveries VALUES(?1,?2,?3,?4,'staged')",params![owner,m.id,m.generation,crate::now()])?;
            tx.execute("INSERT INTO audit(created,username,action,object_id) VALUES(?1,'recovery','fenced_queue_restore',?2)",params![crate::now(),format!("{operation}:{}",m.id)])?;
            // Restored mail cannot bypass the next required replication acknowledgement.
            tx.execute("UPDATE ha_local SET acked=0,generation=MAX(generation,?2+1) WHERE message_id=?1",params![m.id,m.generation])?;
            tx.commit()?;Ok(())
        }).await?;
    }
    let result = json!({"owner":owner,"copied":copied,"held_recipients":held,"pending_recipients":pending,"already_restored":skipped,"smtp_started":false,"network_used":false,"operation":receipt["operation"]});
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(target.join("ha-recovery.json"))?;
    file.write_all(serde_json::to_string(&result)?.as_bytes())?;
    file.sync_all()?;
    Ok(result)
}
