//! Read the committed migration receipt after an uncertain activation response.
use crate::central::{Central, binding::Binding, database_error, selection::Selection};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Serialize)]
pub struct ImportStatus {
    pub database: Binding,
    pub phase: String,
    pub activated_at: Option<i64>,
    pub selections: Vec<Selection>,
}
impl Central {
    /// Read-only receipt inspection. Does not prove SMTP, artifacts or source
    /// liveness, and never treats database unavailability as an inactive state.
    pub async fn import_status(&self, binding: &Binding) -> Result<ImportStatus> {
        binding.validate()?;
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let db=self.interactive.get().await.context("Import receipt database unavailable")?;
            let row=db.query_opt("SELECT report->>'phase',activated_at,CASE WHEN octet_length(coalesce(report->'selections','[]'::jsonb)::text)<=524288 THEN coalesce(report->'selections','[]'::jsonb) END FROM noisefence.migration_state WHERE id=1 AND source_digest=$1 AND report->>'instance'=$2 AND report->>'protocol'='noisefence-offline-import-1' AND (SELECT count(*)=1 FROM noisefence.schema_migrations) AND EXISTS(SELECT 1 FROM noisefence.schema_migrations WHERE version=1 AND sha256=$3)", &[&binding.source_digest,&binding.instance,&crate::message::digest(include_bytes!("../schema.sql"))])
                .await.map_err(database_error)?.context("Import receipt or schema does not match this authority")?;
            let phase:String=row.get::<_,Option<String>>(0).context("Import phase is missing")?;
            let activated_at:Option<i64>=row.get(1);
            let value:serde_json::Value=row.get::<_,Option<_>>(2).context("Import selection receipt exceeds bounds")?;
            let selections:Vec<Selection>=serde_json::from_value(value)
                .map_err(|_|anyhow::anyhow!("Invalid import selection receipt"))?;
            ensure!(matches!(phase.as_str(),"claimed"|"accounts"|"metadata"|"recipient_ids"|"smtp_logs"|"quality"|"copied_not_activated"|"failed"|"active"),"Unknown import phase");
            ensure!((phase=="active")==activated_at.is_some(),"Inconsistent import activation receipt");
            if activated_at.is_some() {
                let mut nodes=BTreeSet::new();
                ensure!((1..=64).contains(&selections.len()) && selections.iter().filter(|s|s.role==crate::cluster::Role::Coordinator).count()==1,"Incomplete active import selection receipt");
                for selection in &selections {
                    selection.validate()?;
                    ensure!(&selection.database==binding && nodes.insert(&selection.node.node),"Import selection authority mismatch");
                }
            } else { ensure!(selections.is_empty(),"Inactive import contains committed selection receipts"); }
            Ok(ImportStatus{database:binding.clone(),phase,activated_at,selections})
        }).await.context("Import receipt inspection deadline exceeded")?
    }
}
