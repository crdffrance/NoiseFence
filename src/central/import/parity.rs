//! Compare the inactive destination to the frozen source projections.
use super::{PreparedImport, policy, quality, verify_tables};
use crate::central::database_error;
use anyhow::{Result, ensure};
use deadpool_postgres::Transaction;
use serde_json::{Value, json};
use std::collections::BTreeSet;

pub(super) async fn lock(tx: &Transaction<'_>) -> Result<()> {
    // Also fence ordinary repository writes, which do not all take the
    // management advisory lock. Names come from quoted PostgreSQL identifiers.
    let rows = tx.query("SELECT quote_ident(n.nspname)||'.'||quote_ident(c.relname) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='noisefence' AND c.relkind IN ('r','p') ORDER BY c.relname", &[]).await.map_err(database_error)?;
    let names = rows
        .iter()
        .map(|r| r.get::<_, String>(0))
        .collect::<Vec<_>>()
        .join(",");
    let mut expected: BTreeSet<String> = [
        "schema_migrations",
        "sources",
        "message_versions",
        "messages",
        "deliveries",
        "delivery_log_versions",
        "delivery_logs",
        "policy_head",
        "policy_authority",
        "policy_peers",
        "queue_commands",
        "command_tombstones",
        "quality_worker_status",
        "migration_state",
    ]
    .into_iter()
    .map(|name| format!("noisefence.{name}"))
    .collect();
    for spec in super::TABLES
        .iter()
        .chain(quality::TABLES)
        .chain(policy::TABLES)
    {
        expected.insert(format!("noisefence.{}", spec.name));
    }
    let actual: BTreeSet<String> = rows.iter().map(|r| r.get(0)).collect();
    ensure!(
        actual == expected,
        "Migration destination table set differs from verifier"
    );
    ensure!(!names.is_empty(), "Missing migration destination tables");
    tx.batch_execute(&format!("LOCK TABLE {names} IN SHARE MODE"))
        .await
        .map_err(database_error)?;
    Ok(())
}
async fn count(tx: &Transaction<'_>, table: &str, expected: usize) -> Result<()> {
    // All callers supply static application table names.
    let actual: i64 = tx
        .query_one(&format!("SELECT count(*) FROM noisefence.{table}"), &[])
        .await
        .map_err(database_error)?
        .get(0);
    ensure!(
        actual == expected as i64,
        "Migration destination row count mismatch in {table}"
    );
    Ok(())
}
async fn value(
    tx: &Transaction<'_>,
    table: &'static str,
    query: &str,
    params: &[&(dyn tokio_postgres::types::ToSql + Sync)],
    expected: Value,
) -> Result<()> {
    let rows = tx.query(query, params).await.map_err(database_error)?;
    ensure!(
        rows.len() == 1,
        "Migration destination cardinality mismatch in {table}"
    );
    let actual: Value = rows[0].get(0);
    if !super::json_equivalence::equal(&actual, &expected) {
        // Only projected column names, never values, recipients, message IDs,
        // SQL arguments or nested message content, enter diagnostics.
        let columns = expected
            .as_object()
            .map(|object| {
                object
                    .iter()
                    .filter(|(key, value)| {
                        !actual
                            .get(*key)
                            .is_some_and(|v| super::json_equivalence::equal(v, value))
                    })
                    .map(|(key, _)| key.as_str())
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .unwrap_or_default();
        anyhow::bail!("Migration destination content mismatch in {table} (columns: {columns})");
    }
    Ok(())
}

pub(super) async fn verify(tx: &Transaction<'_>, p: &PreparedImport) -> Result<()> {
    verify_tables(tx, super::TABLES, &p.accounts.tables).await?;
    verify_tables(tx, quality::TABLES, &p.quality.tables).await?;
    verify_tables(tx, policy::TABLES, &p.policy.tables).await?;
    let mut versions = 0;
    let mut messages = 0;
    let mut deliveries = 0;
    let mut log_versions = 0;
    let mut logs = 0;
    for source in &p.sources {
        let node = &source.identity.node;
        let epoch = &source.identity.epoch;
        let sequence = source
            .metadata
            .iter()
            .map(|e| e.receipt.generation)
            .max()
            .unwrap_or(0);
        value(tx,"sources","SELECT jsonb_build_object('epoch',epoch,'enabled',enabled,'last_sequence',last_sequence) FROM noisefence.sources WHERE node=$1",&[node],json!({"epoch":epoch,"enabled":p.policy.membership.contains_key(node),"last_sequence":sequence})).await?;
        let deleted: BTreeSet<_> = source
            .metadata
            .iter()
            .filter(|e| e.receipt.deleted)
            .map(|e| e.receipt.id.as_str())
            .collect();
        for event in &source.metadata {
            versions += 1;
            let id = &event.receipt.id;
            value(tx,"message_versions","SELECT jsonb_build_object('node',node,'epoch',epoch,'generation',generation,'deleted',deleted) FROM noisefence.message_versions WHERE id=$1",&[id],json!({"node":node,"epoch":epoch,"generation":event.receipt.generation,"deleted":event.receipt.deleted})).await?;
            if let Some(record) = &event.record {
                messages += 1;
                let assessment = crate::assessment::historical(&record.scan);
                let mut rules = record
                    .scan
                    .reasons
                    .iter()
                    .map(|r| r.id.as_str())
                    .collect::<Vec<_>>()
                    .join(" ");
                let mut limit = 16384.min(rules.len());
                while !rules.is_char_boundary(limit) {
                    limit -= 1;
                }
                rules.truncate(limit);
                value(tx,"messages","SELECT jsonb_build_object('created',created,'sender',sender,'scan',scan,'is_dsn',is_dsn,'raw_present',raw_present,'category',category,'score',score,'rules',rules) FROM noisefence.messages WHERE id=$1",&[id],json!({"created":record.created,"sender":record.sender,"scan":record.scan,"is_dsn":record.is_dsn,"raw_present":record.raw_present,"category":assessment.category.as_str(),"score":assessment.score.value,"rules":rules})).await?;
                for delivery in &record.deliveries {
                    deliveries += 1;
                    let mut expected = serde_json::to_value(delivery)?;
                    expected["error"] = json!(
                        delivery
                            .error
                            .as_ref()
                            .map(|v| crate::delivery_log::sanitize(v, 2048).0)
                    );
                    // Source capture omits summary logs; all transcripts are
                    // verified separately below, without the five-log ceiling.
                    ensure!(
                        delivery.logs.is_empty(),
                        "Unexpected summary logs in offline snapshot"
                    );
                    value(tx,"deliveries","SELECT to_jsonb(d)-'id'-'message_id' FROM noisefence.deliveries d WHERE message_id=$1 AND address=$2",&[id,&delivery.address],expected).await?;
                }
            }
        }
        for event in &source.logs {
            // Ingestion deliberately acknowledges without creating a log row
            // when the entire message is already a tombstone.
            if deleted.contains(event.message_id.as_str()) {
                continue;
            }
            log_versions += 1;
            let local_id = event.receipt.local_id;
            value(tx,"delivery_log_versions","SELECT jsonb_build_object('message_id',v.message_id,'recipient',d.address,'delivery_message_id',d.message_id,'generation',v.generation,'deleted',v.deleted) FROM noisefence.delivery_log_versions v LEFT JOIN noisefence.deliveries d ON d.id=v.delivery_id WHERE v.node=$1 AND v.epoch=$2 AND v.local_id=$3",&[node,epoch,&local_id],json!({"message_id":event.message_id,"recipient":event.recipient,"delivery_message_id":event.message_id,"generation":event.receipt.generation,"deleted":event.receipt.deleted})).await?;
            if let Some(log) = &event.log {
                logs += 1;
                value(tx,"delivery_logs","SELECT jsonb_build_object('message_id',message_id,'attempt',attempt,'trace',trace) FROM noisefence.delivery_logs WHERE node=$1 AND epoch=$2 AND local_id=$3",&[node,epoch,&local_id],json!({"message_id":event.message_id,"attempt":log.attempt,"trace":log.trace})).await?;
            }
        }
    }
    for (table, expected) in [
        ("sources", p.sources.len()),
        ("message_versions", versions),
        ("messages", messages),
        ("deliveries", deliveries),
        ("delivery_log_versions", log_versions),
        ("delivery_logs", logs),
    ] {
        count(tx, table, expected).await?;
    }
    for row in &p.deliveries.rows {
        let id = row["id"].as_i64().unwrap();
        value(tx,"deliveries","SELECT jsonb_build_object('id',id,'message_id',message_id,'address',address,'destination',destination) FROM noisefence.deliveries WHERE id=$1",&[&id],row.clone()).await?;
    }
    let owner = p.policy.journal.owner();
    count(tx, "policy_authority", 1).await?;
    value(tx,"policy_authority","SELECT to_jsonb(a) FROM noisefence.policy_authority a WHERE id=1",&[],json!({"id":1,"node":owner,"epoch":p.policy.epochs[owner],"journal":p.policy.journal,"membership":p.policy.membership,"actor":null,"actor_version":null,"session_hash":null,"scope":null,"incident":null})).await?;
    count(tx, "policy_head", 1).await?;
    value(tx,"policy_head","SELECT to_jsonb(h) FROM noisefence.policy_head h WHERE id=1",&[],json!({"id":1,"revision":p.policy.journal.current().revision,"activated_at":0,"activation_epoch":p.policy.journal.current_epoch()})).await?;
    for table in [
        "policy_peers",
        "queue_commands",
        "command_tombstones",
        "quality_worker_status",
    ] {
        count(tx, table, 0).await?;
    }
    let valid_ids: bool = tx
        .query_one(
            "SELECT NOT EXISTS(SELECT 1 FROM noisefence.deliveries WHERE id<=0)",
            &[],
        )
        .await
        .map_err(database_error)?
        .get(0);
    ensure!(valid_ids, "Invalid imported recipient identity");
    let history_unused: bool = tx
        .query_one(
            "SELECT last_value=1 AND NOT is_called FROM noisefence.runtime_history_generation",
            &[],
        )
        .await
        .map_err(database_error)?
        .get(0);
    ensure!(
        history_unused,
        "Destination runtime history already published before activation"
    );
    // Generated recipient/revision/audit IDs must remain above the restored IDs.
    // Gaps are valid; lowering a sequence can break the first runtime insert.
    for table in ["deliveries", "policy_revisions", "audit"] {
        let valid:bool=tx.query_one(&format!("SELECT last_value >= coalesce((SELECT max(id) FROM noisefence.{table}),0) AND (is_called OR NOT EXISTS(SELECT 1 FROM noisefence.{table} WHERE id>=last_value)) FROM noisefence.{table}_id_seq"),&[]).await.map_err(database_error)?.get(0);
        ensure!(
            valid,
            "Migration destination sequence is behind restored records"
        );
    }
    Ok(())
}
