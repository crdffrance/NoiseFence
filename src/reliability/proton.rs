//! A visible compatibility checklist, separate from quality metrics and activation.
use crate::config::{CompatibilityReport, Config, PROTON_CASES};
use serde_json::{Value, json};
use std::path::Path;

pub fn inspect(config: &Config, path: Option<&Path>, prefix: &str) -> Value {
    let pending = |status: &str| {
        json!({"prefix":prefix,"status":status,"valid":false,"tested_at":null,
        "cases":PROTON_CASES.iter().map(|c|json!({"id":c,"passed":false,"evidence_present":false})).collect::<Vec<_>>(),"bypass_limit_accepted":false})
    };
    let Some(path) = path else {
        return pending("not_configured");
    };
    let report = crate::native_filter::read_bounded(path, 128 * 1024)
        .ok()
        .and_then(|raw| serde_json::from_slice::<CompatibilityReport>(&raw).ok());
    let Some(report) = report else {
        return pending("invalid");
    };
    let current = report.tested_at > 0
        && report.tested_at <= crate::now()
        && crate::now() - report.tested_at < 30 * 86400;
    let bound = report.hostname == config.hostname
        && report.prefix == prefix
        && config
            .domains
            .iter()
            .all(|d| report.domains.contains(&d.name));
    let valid = report.validate_prefix(config, prefix).is_ok();
    json!({"prefix":prefix,"status":if valid {"validated"} else if !bound {"mismatched"} else if !current {"stale"} else {"incomplete"},
        "valid":valid,"tested_at":report.tested_at,"bypass_limit_accepted":report.bypass_limit_accepted,
        "cases":PROTON_CASES.iter().map(|id|json!({"id":id,"passed":report.cases.get(*id).is_some_and(|c|c.passed),
            "evidence_present":report.cases.get(*id).is_some_and(|c|c.evidence.trim().len()>=20)})).collect::<Vec<_>>()})
}

pub fn checklist(config: &Config) -> Value {
    json!({"spam":inspect(config,config.filter.proton_report.as_deref(),"[SPAM]"),
        "publicity":inspect(config,config.mailing.as_ref().and_then(|m|m.proton_report.as_deref()),"[PUB]"),
        "mode":config.filter.mode,"activation_requested":false,
        "required_receipts":["direct_inbox_or_spam","relayed_unmodified_inbox_or_spam","relayed_tagged_inbox_or_spam","original_authentication_headers","final_authentication_headers"],
        "note":"Une acceptation SMTP ne prouve pas le dossier d'arrivée. Le résultat Proton ne sert pas de label automatique de spam."})
}
