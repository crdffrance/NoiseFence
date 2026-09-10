//! Short-lived recipient-scoped change proofs. Unrelated corrections do not
//! force SMTP retries. No mailbox keys or revisions are serialized into scans.
use anyhow::{Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};
#[path = "epoch_legacy.rs"]
mod legacy;
const MAX_KEYS: usize = 131_072;
const RETAIN_SECONDS: i64 = 60; // strictly longer than a five-second live proof

/// SQL identifiers/expressions below are internal constants, never input text.
fn canonical(value: &str) -> String {
    format!("substr({value},1,instr({value},'@'))||lower(substr({value},instr({value},'@')+1))")
}
fn grants(value: &str) -> String {
    format!("SELECT 'g' AS kind,{} AS a,'' AS b", canonical(value))
}
fn pairs(condition: &str) -> String {
    format!(
        "SELECT 'p' AS kind,h.recipient AS a,h.destination AS b FROM sender_history_receipts h WHERE h.received>unixepoch()-{} AND ({condition})",
        super::TTL_SECONDS
    )
}
fn account(user: &str) -> String {
    format!(
        "{} UNION SELECT 'g' AS kind,{} AS a,'' AS b FROM grants g WHERE g.username={user}",
        pairs(&format!(
            "EXISTS(SELECT 1 FROM feedback f JOIN console_access ca ON ca.username=f.username AND ca.delivery_id=h.delivery_id WHERE f.message_id=h.message_id AND f.username={user})"
        )),
        canonical("g.address")
    )
}
fn bump(select: &str) -> String {
    // Each invocation owns its generation. Never depend on SQLite's relative
    // firing order for separate triggers (including older binary triggers).
    format!(
        "UPDATE sender_history_revision_state SET sequence=sequence+1 WHERE id=1;
      UPDATE sender_history_epoch SET revision=revision+1 WHERE id=1;
      INSERT INTO sender_history_revisions(kind,a,b,revision,updated)
      SELECT changed.kind,changed.a,changed.b,s.sequence,unixepoch()
      FROM ({select}) AS changed CROSS JOIN sender_history_revision_state s WHERE s.id=1
      ON CONFLICT(kind,a,b) DO UPDATE SET revision=excluded.revision,updated=excluded.updated;"
    )
}
fn trigger(db: &Connection, name: &str, event: &str, select: &str) -> Result<()> {
    db.execute_batch(&format!(
        "CREATE TRIGGER IF NOT EXISTS history_scope_{name} {event} BEGIN {} END;",
        bump(select)
    ))?;
    Ok(())
}
pub fn install(db: &Connection) -> Result<()> {
    legacy::install(db)?;
    db.execute_batch(&format!("CREATE TABLE IF NOT EXISTS sender_history_revision_state(
      id INTEGER PRIMARY KEY CHECK(id=1),
      sequence INTEGER NOT NULL DEFAULT 0 CHECK(typeof(sequence)='integer' AND sequence>=0),
      overflow_revision INTEGER NOT NULL DEFAULT 0,
      records INTEGER NOT NULL DEFAULT 0 CHECK(records>=0 AND records<={MAX_KEYS}));
      INSERT OR IGNORE INTO sender_history_revision_state(id) VALUES(1);
      CREATE TABLE IF NOT EXISTS sender_history_revisions(
      kind TEXT NOT NULL CHECK(kind IN ('p','g')),a TEXT NOT NULL,b TEXT NOT NULL,
      revision INTEGER NOT NULL,updated INTEGER NOT NULL,PRIMARY KEY(kind,a,b)) WITHOUT ROWID;
      CREATE INDEX IF NOT EXISTS history_revision_expiry ON sender_history_revisions(updated);
      CREATE TRIGGER IF NOT EXISTS history_revision_capacity BEFORE INSERT ON sender_history_revisions
      WHEN NOT EXISTS(SELECT 1 FROM sender_history_revisions WHERE kind=NEW.kind AND a=NEW.a AND b=NEW.b)
        AND (SELECT records FROM sender_history_revision_state WHERE id=1)>={MAX_KEYS}
      BEGIN
        UPDATE sender_history_revision_state SET overflow_revision=sequence WHERE id=1;
        SELECT RAISE(IGNORE);
      END;
      CREATE TRIGGER IF NOT EXISTS history_revision_insert AFTER INSERT ON sender_history_revisions
      BEGIN UPDATE sender_history_revision_state SET records=records+1 WHERE id=1; END;
      CREATE TRIGGER IF NOT EXISTS history_revision_delete AFTER DELETE ON sender_history_revisions
      BEGIN UPDATE sender_history_revision_state SET records=records-1 WHERE id=1; END;"))?;
    for table in ["feedback", "feedback_categories"] {
        for (op, selector) in [("INSERT", "NEW.message_id"), ("DELETE", "OLD.message_id")] {
            trigger(
                db,
                &format!("{table}_{op}"),
                &format!("AFTER {op} ON {table}"),
                &pairs(&format!(
                    "h.message_id={selector} AND EXISTS(SELECT 1 FROM console_access ca WHERE ca.delivery_id=h.delivery_id AND ca.username={}.username)",
                    if op == "INSERT" { "NEW" } else { "OLD" }
                )),
            )?;
        }
        trigger(
            db,
            &format!("{table}_UPDATE"),
            &format!("AFTER UPDATE ON {table}"),
            &pairs(
                "(h.message_id=OLD.message_id AND EXISTS(SELECT 1 FROM console_access ca WHERE ca.delivery_id=h.delivery_id AND ca.username=OLD.username)) OR (h.message_id=NEW.message_id AND EXISTS(SELECT 1 FROM console_access ca WHERE ca.delivery_id=h.delivery_id AND ca.username=NEW.username))",
            ),
        )?;
    }
    for (op, value) in [("INSERT", "NEW.address"), ("DELETE", "OLD.address")] {
        trigger(
            db,
            &format!("grants_{op}"),
            &format!("AFTER {op} ON grants"),
            &grants(value),
        )?;
    }
    trigger(
        db,
        "grants_UPDATE",
        "AFTER UPDATE ON grants",
        &format!("{} UNION {}", grants("OLD.address"), grants("NEW.address")),
    )?;
    // BEFORE sees labels/grants before FK cascades. AFTER covers a changed name.
    trigger(
        db,
        "users_DELETE",
        "BEFORE DELETE ON users",
        &account("OLD.username"),
    )?;
    trigger(
        db,
        "users_UPDATE_before",
        "BEFORE UPDATE ON users",
        &account("OLD.username"),
    )?;
    trigger(
        db,
        "users_UPDATE_after",
        "AFTER UPDATE ON users",
        &account("NEW.username"),
    )?;
    trigger(
        db,
        "users_INSERT",
        "AFTER INSERT ON users",
        &account("NEW.username"),
    )?;
    trigger(
        db,
        "deliveries_UPDATE",
        "AFTER UPDATE OF address,destination,message_id ON deliveries",
        &pairs("h.delivery_id IN (OLD.id,NEW.id)"),
    )?;
    trigger(
        db,
        "messages_UPDATE",
        "AFTER UPDATE OF created,is_dsn,scan ON messages WHEN EXISTS(SELECT 1 FROM feedback WHERE message_id=NEW.id)",
        &pairs("h.message_id=NEW.id"),
    )?;
    let row = |prefix: &str| {
        format!(
            "SELECT 'p' AS kind,{prefix}.recipient AS a,{prefix}.destination AS b WHERE {prefix}.received>unixepoch()-{}",
            super::TTL_SECONDS
        )
    };
    trigger(
        db,
        "receipt_DELETE",
        "AFTER DELETE ON sender_history_receipts",
        &row("OLD"),
    )?;
    trigger(
        db,
        "receipt_UPDATE",
        "AFTER UPDATE OF message_id,delivery_id,recipient,destination,sender,domain,received,raw_hash,campaign,simhash,eligible ON sender_history_receipts",
        &format!("{} UNION {}", row("OLD"), row("NEW")),
    )?;
    trigger(
        db,
        "receipt_INSERT",
        "AFTER INSERT ON sender_history_receipts WHEN EXISTS(SELECT 1 FROM feedback WHERE message_id=NEW.message_id)",
        &row("NEW"),
    )?;
    Ok(())
}

pub(super) fn prune(db: &Connection, now: i64) -> Result<()> {
    db.execute(
        "DELETE FROM sender_history_revisions WHERE updated<=?1",
        [now - RETAIN_SECONDS],
    )?;
    Ok(())
}

#[derive(Clone)]
struct Stamp {
    kind: &'static str,
    a: String,
    b: String,
    revision: Option<i64>,
}
#[derive(Clone)]
pub struct Epoch {
    sequence: i64,
    overflow: i64,
    recipients: Vec<Vec<Stamp>>,
    as_of: i64,
    expires: i64,
}
impl std::fmt::Debug for Epoch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HistoryEpoch { private recipient snapshots }")
    }
}
impl Epoch {
    pub(super) fn capture(db: &Connection, now: i64, scopes: &[(String, String)]) -> Result<Self> {
        ensure!(
            !db.is_autocommit(),
            "history epoch requires a read snapshot"
        );
        ensure!(
            !scopes.is_empty() && scopes.len() <= super::MAX_RECIPIENTS,
            "invalid history snapshot scope"
        );
        let (sequence, overflow) = db.query_row(
            "SELECT sequence,overflow_revision FROM sender_history_revision_state WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let mut query = db.prepare_cached(
            "SELECT revision FROM sender_history_revisions WHERE kind=?1 AND a=?2 AND b=?3",
        )?;
        let mut recipients = Vec::with_capacity(scopes.len());
        for (address, destination) in scopes {
            let address = super::mailbox(address)
                .ok_or_else(|| anyhow::anyhow!("invalid history recipient"))?;
            let destination = super::mailbox(destination)
                .ok_or_else(|| anyhow::anyhow!("invalid history destination"))?;
            let domains = std::collections::BTreeSet::from([
                address.rsplit_once('@').unwrap().1.to_owned(),
                destination.rsplit_once('@').unwrap().1.to_owned(),
            ]);
            let mut keys = vec![
                ("p", address, destination.clone()),
                ("g", destination, String::new()),
            ];
            keys.extend(
                domains
                    .into_iter()
                    .map(|d| ("g", format!("*@{d}"), String::new())),
            );
            let mut stamps = Vec::with_capacity(keys.len());
            for (kind, a, b) in keys {
                let revision = query
                    .query_row(params![kind, a, b], |r| r.get(0))
                    .optional()?;
                stamps.push(Stamp {
                    kind,
                    a,
                    b,
                    revision,
                });
            }
            recipients.push(stamps);
        }
        Ok(Self {
            sequence,
            overflow,
            recipients,
            as_of: now,
            expires: now + 5,
        })
    }
    pub(super) fn select(&self, indices: &[usize]) -> Self {
        Self {
            recipients: indices
                .iter()
                .filter_map(|i| self.recipients.get(*i).cloned())
                .collect(),
            sequence: self.sequence,
            overflow: self.overflow,
            as_of: self.as_of,
            expires: self.expires,
        }
    }
    pub(super) fn expire_before(&mut self, deadline: i64) {
        self.expires = self.expires.min(deadline);
    }
    pub(crate) fn validate(&self, db: &Connection, now: i64) -> Result<()> {
        ensure!(
            !db.is_autocommit(),
            "history epoch requires the enqueue transaction"
        );
        ensure!(
            now >= self.as_of && now < self.expires,
            "sender history snapshot expired; retry analysis"
        );
        ensure!(!self.recipients.is_empty(), "empty history snapshot scope");
        let (sequence, overflow): (i64, i64) = db.query_row(
            "SELECT sequence,overflow_revision FROM sender_history_revision_state WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        ensure!(
            sequence >= self.sequence && overflow == self.overflow,
            "sender history changed; retry analysis"
        );
        let mut query = db.prepare_cached(
            "SELECT revision FROM sender_history_revisions WHERE kind=?1 AND a=?2 AND b=?3",
        )?;
        for stamp in self.recipients.iter().flatten() {
            let current: Option<i64> = query
                .query_row(params![stamp.kind, stamp.a, stamp.b], |r| r.get(0))
                .optional()?;
            // Pruning only removes changes at least 60 seconds old. Any change
            // after this <=5s snapshot remains present; missing old rows need
            // not force retries. Recreated rows get a fresh monotonic revision.
            ensure!(
                current.is_none() || current == stamp.revision,
                "sender history changed; retry analysis"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "epoch_tests.rs"]
mod tests;
