//! Read-only explanations and recipient-scoped SMTP history. Never expose the
//! retained training vectors, message body, or another recipient's delivery.
use crate::{
    config::{Config, Mode},
    delivery_log::Attempt,
    engine::Scan,
    now,
    store::Store,
};
use anyhow::Result;
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnalysisPolicy {
    pub version: String,
    pub threshold: f64,
    pub mode: Mode,
    pub require_corroboration: bool,
    pub rule_weights: BTreeMap<String, f64>,
}
impl AnalysisPolicy {
    pub fn capture(config: &Config) -> Self {
        Self {
            version: crate::decision::VERSION.into(),
            threshold: config.filter.threshold,
            mode: config.filter.mode,
            require_corroboration: config.filter.require_corroboration,
            rule_weights: config.filter.rule_weights.clone(),
        }
    }
}

#[derive(Serialize)]
pub struct Analysis {
    pub elapsed_ms: u64,
    pub feature_version: u32,
    pub features_complete: Option<bool>,
    pub policy: Option<AnalysisPolicy>,
    pub lexical_logit: Option<f64>,
    pub semantic_contribution: Option<f64>,
    pub rule_weight_total: f64,
    pub evidence: Option<crate::evidence::Evidence>,
    pub heuristics: Option<crate::heuristics::Report>,
    pub content_inspection: Option<crate::content_inspection::Report>,
    pub research_execution: Option<crate::research_engines::Execution>,
    pub sandbox_pipeline: Option<crate::sandbox_pipeline::Report>,
}
impl From<Scan> for Analysis {
    fn from(scan: Scan) -> Self {
        Self {
            elapsed_ms: scan.elapsed_ms,
            feature_version: scan.feature_version,
            features_complete: scan.features_complete,
            policy: scan.analysis_policy,
            lexical_logit: scan.evidence.as_ref().and_then(|e| e.lexical_logit),
            semantic_contribution: scan.semantic.contribution,
            rule_weight_total: scan
                .reasons
                .iter()
                .filter(|r| r.id != "model_contribution")
                .map(|r| r.weight)
                .sum(),
            evidence: scan.evidence,
            heuristics: scan.heuristics,
            content_inspection: scan.content_inspection,
            research_execution: scan.research_execution,
            sandbox_pipeline: scan.sandbox_pipeline,
        }
    }
}
#[derive(Serialize)]
pub struct AttemptLog {
    pub id: i64,
    pub attempt: u32,
    #[serde(flatten)]
    pub trace: Attempt,
}
#[derive(Serialize)]
pub struct RecipientDiagnostics {
    pub sender_history: Option<crate::sender_history::Report>,
    pub delivery_id: i64,
    pub address: String,
    pub destination: String,
    pub status: String,
    pub attempts: u32,
    pub next_attempt: i64,
    pub last_error: Option<String>,
    pub logs_available: usize,
    pub logs_truncated: bool,
    pub logs: Vec<AttemptLog>,
}
#[derive(Serialize)]
pub struct MessageDiagnostics {
    pub message_id: String,
    pub analysis: Analysis,
    pub recipients: Vec<RecipientDiagnostics>,
    pub sandbox_results: Vec<SandboxDiagnostic>,
}

/// Attachment-wide observations, without payload digests, remote task ids,
/// backend paths, endpoint names or recipient scopes. Read under the same ACL
/// snapshot as the message and recipient traces.
#[derive(Serialize)]
pub struct SandboxDiagnostic {
    pub part: usize,
    pub state: crate::sandbox_pipeline::State,
    pub detail: Option<crate::sandbox_pipeline::Detail>,
    pub result: Option<SandboxResult>,
}
#[derive(Serialize)]
pub struct SandboxResult {
    pub status: crate::sandbox::Status,
    pub outcome: crate::sandbox::Outcome,
    pub detail: Option<crate::sandbox::Detail>,
    pub findings: Vec<crate::sandbox::Finding>,
    pub findings_truncated: bool,
    pub engine_version: Option<String>,
    pub isolation_verified: bool,
}
fn sandbox_diagnostics(db: &rusqlite::Connection, id: &str) -> Result<Vec<SandboxDiagnostic>> {
    let mut query = db.prepare("SELECT o.part,o.state,o.detail,o.summary FROM sandbox_pipeline_outbox o JOIN sandbox_pipeline_messages p USING(message_id) WHERE o.message_id=?1 AND p.expires>?2 ORDER BY o.part LIMIT 32")?;
    query
        .query_map(params![id, now()], |r| {
            Ok((
                r.get::<_, usize>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, Option<String>>(3)?,
            ))
        })?
        .map(|row| {
            let (part, state, detail, summary) = row?;
            let result = summary
                .map(|json| -> Result<_> {
                    let s: crate::sandbox::Summary = serde_json::from_str(&json)?;
                    s.validate()?;
                    Ok(SandboxResult {
                        status: s.status,
                        outcome: s.outcome,
                        detail: s.detail,
                        findings: s.findings,
                        findings_truncated: s.findings_truncated,
                        engine_version: s.provenance.engine_version,
                        isolation_verified: s.provenance.isolation_verified,
                    })
                })
                .transpose()?;
            Ok(SandboxDiagnostic {
                part,
                state: serde_json::from_value(serde_json::Value::String(state))?,
                detail: detail.map(|v| serde_json::from_str(&v)).transpose()?,
                result,
            })
        })
        .collect()
}
impl Store {
    pub async fn diagnostics(
        &self,
        username: String,
        id: String,
    ) -> Result<Option<MessageDiagnostics>> {
        self.diagnostics_for(username, id, None).await
    }
    pub async fn diagnostics_for(
        &self,
        username: String,
        id: String,
        delivery_id: Option<i64>,
    ) -> Result<Option<MessageDiagnostics>> {
        self.read(move |db| {
            // The same read snapshot checks both message visibility and every
            // recipient. Knowing a queue id never grants transcript access.
            let scan: Option<String> = db.query_row(
                "SELECT m.scan FROM messages m WHERE m.id=?1 AND (m.created>=?3 OR m.raw_present=1) AND EXISTS(SELECT 1 FROM deliveries d JOIN console_access g ON g.delivery_id=d.id WHERE d.message_id=m.id AND g.username=?2 AND (?4 IS NULL OR d.id=?4))",
                params![id, username, now()-30*86400,delivery_id], |r| r.get(0),
            ).optional()?;
            let Some(scan) = scan else { return Ok(None) };
            let analysis = serde_json::from_str::<Scan>(&scan)?.into();
            let mut query = db.prepare("SELECT d.id,d.address,d.destination,d.status,d.attempts,d.next_attempt,NULLIF(d.error,''),(SELECT COUNT(*) FROM delivery_attempts a WHERE a.delivery_id=d.id) FROM deliveries d JOIN console_access g ON g.delivery_id=d.id WHERE d.message_id=?1 AND g.username=?2 AND (?3 IS NULL OR d.id=?3) ORDER BY d.id")?;
            let mut recipients = query.query_map(params![id,username,delivery_id], |r| Ok(RecipientDiagnostics {
                sender_history: None,
                delivery_id:r.get(0)?, address:r.get(1)?, destination:r.get(2)?, status:r.get(3)?, attempts:r.get(4)?, next_attempt:r.get(5)?, last_error:r.get(6)?, logs_available:r.get(7)?,logs_truncated:false,logs:Vec::new(),
            }))?.collect::<rusqlite::Result<Vec<_>>>()?;
            // Prevent a many-recipient message from expanding into thousands of
            // transcripts. A scoped follow-up can load a recipient's full history.
            let mut remaining = 100usize;
            let mut logs = db.prepare("SELECT id,attempt,trace FROM delivery_attempts WHERE delivery_id=?1 ORDER BY id DESC LIMIT ?2")?;
            for recipient in &mut recipients {
                let history: Option<String> = db.query_row(
                    "SELECT sender_history FROM recipient_research WHERE delivery_id=?1",
                    [recipient.delivery_id], |row| row.get(0),
                ).optional()?;
                recipient.sender_history = history.as_deref().map(serde_json::from_str).transpose()?;
                for row in logs.query_map(params![recipient.delivery_id,remaining.min(50)],|r| Ok((r.get::<_,i64>(0)?,r.get::<_,u32>(1)?,r.get::<_,String>(2)?)))? {
                    let (id,attempt,trace) = row?;
                    let mut trace: Attempt = serde_json::from_str(&trace)?;
                    trace.sanitize();
                    recipient.logs.push(AttemptLog{id,attempt,trace});
                }
                remaining -= recipient.logs.len();
                recipient.logs_truncated = recipient.logs_available > recipient.logs.len();
                recipient.last_error = recipient.last_error.as_deref().map(crate::delivery_log::sanitize_text);
            }
            let sandbox_results = sandbox_diagnostics(db, &id)?;
            Ok(Some(MessageDiagnostics{message_id:id,analysis,recipients,sandbox_results}))
        }).await
    }
}
