//! Bounded, recipient-scoped operational history. Never read or return message content.
use crate::{now, store::Store};
use anyhow::Result;
use rusqlite::{OptionalExtension, params};
use serde::Serialize;

pub const LIMIT: usize = 50;
/// SQLite row IDs can be reused after retention. Audit links must bind the immutable message and recipient.
pub(crate) fn audit_object(message: &str, recipient: &str) -> String {
    format!("quarantine-v1:{message}:{recipient}")
}
#[derive(Serialize)]
pub struct Event {
    pub at: i64,
    pub actor: String,
    pub action: String,
}
#[derive(Serialize)]
pub struct Request {
    pub id: String,
    pub node: String,
    pub actor: String,
    pub action: String,
    pub requested_at: i64,
    pub expires_at: i64,
    pub result: String,
    pub finished_at: Option<i64>,
    pub execution_result: Option<String>,
    pub acknowledged_at: Option<i64>,
}
#[derive(Serialize)]
pub struct History {
    pub schema: &'static str,
    pub message_id: String,
    pub recipient: String,
    pub checked_at: i64,
    pub snapshot_at: Option<i64>,
    pub source: &'static str,
    pub node: Option<String>,
    pub status: String,
    pub raw_available: bool,
    pub held_until: Option<i64>,
    pub released_at: Option<i64>,
    pub pending_command: Option<String>,
    pub events: Vec<Event>,
    pub requests: Vec<Request>,
    pub events_truncated: bool,
    pub requests_truncated: bool,
}
pub fn result(value: Option<&str>, expires: i64, at: i64) -> String {
    match value {
        Some("done" | "conflict" | "expired" | "revoked") => value.unwrap().into(),
        Some(_) => "unknown".into(),
        None if expires <= at => "expired".into(),
        None => "pending".into(),
    }
}
pub fn execution(value: Option<&str>) -> Option<String> {
    value.map(|v| {
        match v {
            "done" | "conflict" | "expired" => v,
            _ => "unknown",
        }
        .into()
    })
}
impl History {
    pub fn bound(&mut self) {
        self.events_truncated = self.events.len() > LIMIT;
        self.requests_truncated = self.requests.len() > LIMIT;
        self.events.truncate(LIMIT);
        self.requests.truncate(LIMIT);
    }
}
impl Store {
    pub async fn quarantine_history(
        &self,
        username: String,
        session: String,
        message: String,
        recipient: String,
    ) -> Result<Option<History>> {
        if let Some(central) = self.management() {
            return central
                .quarantine_history(&username, &session, &message, &recipient)
                .await;
        }
        self.read(move |db| {
            let at = now();
            let row = db.query_row(
                "SELECT d.status,(m.raw_present=1 OR COALESCE(o.raw_present=1,0)),
                        p.held_until,p.released_at,o.node_id,o.updated
                 FROM deliveries d JOIN messages m ON m.id=d.message_id
                 JOIN console_access g ON g.delivery_id=d.id
                 LEFT JOIN delivery_policy p ON p.delivery_id=d.id
                 LEFT JOIN cluster_origin o ON o.message_id=m.id
                 WHERE d.message_id=?1 AND d.address=?2 AND g.username=?3
                   AND (m.created>=?5-30*86400 OR m.raw_present=1 OR o.raw_present=1)
                   AND EXISTS(SELECT 1 FROM sessions s
                     WHERE s.username=?3 AND s.token_hash=?4 AND s.expires>?5
                       AND (EXISTS(SELECT 1 FROM mfa_sessions verified WHERE verified.token_hash=s.token_hash)
                         OR NOT EXISTS(SELECT 1 FROM mfa_credentials k WHERE k.username=s.username AND k.enabled=1)))",
                params![message, recipient, username, session, at],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, bool>(1)?,
                    r.get::<_, Option<i64>>(2)?, r.get::<_, Option<i64>>(3)?,
                    r.get::<_, Option<String>>(4)?, r.get::<_, Option<i64>>(5)?)),
            ).optional()?;
            let Some((status, raw_available, held_until, released_at, node, snapshot_at)) = row else {
                return Ok(None);
            };
            let mut events = Vec::new();
            if node.is_none() {
                let mut query = db.prepare(
                    "SELECT created,username,action FROM audit
                     WHERE object_id=?1 AND created>=?2
                       AND action IN ('quarantine_release','quarantine_delete','quarantine_expire')
                     ORDER BY id DESC LIMIT 51",
                )?;
                events = query.query_map(params![audit_object(&message, &recipient), at-30*86400], |r| {
                    Ok(Event { at: r.get(0)?, actor: r.get(1)?, action: r.get(2)? })
                })?.collect::<rusqlite::Result<_>>()?;
            }
            let mut query = db.prepare(
                r#"SELECT id,node_id,username,command,created,expires,result,finished
                   FROM cluster_commands WHERE message_id=?1 AND recipient=?2 AND created>=?3
                     AND command IN ('"release"','"delete"')
                   ORDER BY created DESC,id DESC LIMIT 51"#,
            )?;
            let requests = query.query_map(params![message, recipient, at-30*86400], |r| {
                let raw: Option<String> = r.get(6)?;
                let expiry = r.get(5)?;
                let finished = r.get(7)?;
                let command: String = r.get(3)?;
                Ok(Request {
                    id: r.get(0)?, node: r.get(1)?, actor: r.get(2)?,
                    action: command.trim_matches('"').into(), requested_at: r.get(4)?,
                    expires_at: expiry, result: result(raw.as_deref(), expiry, at),
                    finished_at: finished,
                    // Legacy storage conflates expiry decisions and receipts; only done is proof of execution.
                    execution_result: raw.as_deref().filter(|v| *v == "done").map(str::to_owned),
                    acknowledged_at: if raw.as_deref() == Some("done") { finished } else { None },
                })
            })?.collect::<rusqlite::Result<Vec<_>>>()?;
            let pending_command = requests.iter().find(|c| c.result == "pending").map(|c| c.id.clone());
            let mut view = History {
                schema: "quarantine-history-1", message_id: message, recipient, checked_at: at,
                snapshot_at: if node.is_some() { snapshot_at } else { Some(at) },
                source: if node.is_some() { "replicated" } else { "local" },
                node, status, raw_available, held_until, released_at, pending_command,
                events, requests, events_truncated: false, requests_truncated: false,
            };
            view.bound();
            Ok(Some(view))
        }).await
    }
}
