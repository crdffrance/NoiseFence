//! Private evaluation export of immutable decisions. Explicit whitelist: no
//! policy trace, rule IDs, subjects, identities, reason text or provider excerpts.
use crate::{decision_record::Coverage, engine::Scan};
use serde_json::{Value, json};

pub const SCHEMA: &str = "noisefence-quality-decisions-1";

pub fn snapshot(scan: &Scan) -> Value {
    if crate::scoring::validate_transport(scan).is_err() {
        return json!({"schema":SCHEMA,"provenance":"invalid","engine":null,"final":null,"action":null});
    }
    let view = crate::assessment::historical(scan);
    let engine = scan
        .analysis_result
        .as_ref()
        .map(|r| &r.detector_decision)
        .or(scan.decision.as_ref());
    let complete = scan
        .analysis_result
        .as_ref()
        .map_or(scan.complete, |r| r.coverage == Coverage::Complete);
    let raw = scan
        .analysis_result
        .as_ref()
        .map_or(view.score.raw, |r| r.score.raw);
    json!({
        "schema":SCHEMA,
        "provenance": if scan.recipient_decision.is_some() {"recipient_receipt"} else if scan.analysis_result.is_some() {"analysis_receipt"} else {"legacy"},
        "engine":engine.map(|d| json!({"source":d.source,"outcome":d.outcome,"complete":complete,"raw_score":raw})),
        "final":{"category":view.category,"classification":scan.recipient_decision.as_ref().map(|r| r.classification),
            "classification_source":view.classification_source,"complete":view.complete,"score":view.score.value},
        "action":view.action.map(|a| json!({"requested":a.requested,"effective":a.effective}))
    })
}
