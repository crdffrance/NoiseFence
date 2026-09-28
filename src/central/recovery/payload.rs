//! Read-only content parity after inventory reconciliation. No repair or startup.
use crate::{
    central::{database_error, import::json_equivalence::equal, selection::Selection},
    store::Store,
};
use anyhow::{Result, ensure};
use serde_json::{Value, json};

pub(super) async fn verify(
    db: &tokio_postgres::Client,
    store: &Store,
    selected: &Selection,
    messages: &[String],
    traces: &[(i64, String, String)],
) -> Result<()> {
    // Inspect one bounded record at a time, without loading bodies or holding a
    // SQLite writer across a network await. The caller holds source process locks.
    for id in messages {
        let key = id.clone();
        let expected = store
            .read(move |sqlite| {
                let mut record = crate::cluster::history::snapshot(sqlite, key, 1, false)?;
                for delivery in &mut record.deliveries {
                    delivery.error = delivery
                        .error
                        .as_ref()
                        .map(|s| crate::delivery_log::sanitize(s, 2048).0);
                }
                record.deliveries.sort_by(|a, b| a.address.cmp(&b.address));
                let mut value = serde_json::to_value(record)?;
                value.as_object_mut().unwrap().remove("generation");
                ensure!(
                    serde_json::to_vec(&value)?.len() <= 3 * 1024 * 1024,
                    "Recovery message exceeds parity limit"
                );
                Ok(value)
            })
            .await?;
        let row=db.query_one(
            "SELECT jsonb_build_object('id',m.id,'created',m.created,'sender',m.sender,'scan',m.scan,'is_dsn',m.is_dsn,'raw_present',m.raw_present,'deliveries',COALESCE((SELECT jsonb_agg(jsonb_build_object('address',d.address,'destination',d.destination,'status',d.status,'attempts',d.attempts,'next_attempt',d.next_attempt,'error',d.error,'action',d.action,'held_until',d.held_until,'released_at',d.released_at,'filtering',d.filtering,'logs','[]'::jsonb) ORDER BY d.address COLLATE \"C\") FROM noisefence.deliveries d WHERE d.message_id=m.id),'[]'::jsonb)) FROM noisefence.messages m JOIN noisefence.message_versions v ON v.id=m.id WHERE m.id=$1 AND v.node=$2 AND v.epoch=$3 AND NOT v.deleted",
            &[id,&selected.node.node,&selected.node.epoch],
        ).await.map_err(database_error)?;
        let actual: Value = row.get(0);
        ensure!(
            equal(&expected, &actual),
            "Recovery message payload differs from its source"
        );
    }
    for (local_id, _, _) in traces {
        let key = *local_id;
        let expected = store
            .read(move |sqlite| {
                let (attempt, raw): (u32, String) = sqlite.query_row(
                    "SELECT attempt,trace FROM delivery_attempts WHERE id=?1",
                    [key],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?;
                ensure!(
                    raw.len() <= 512 * 1024,
                    "Recovery transcript exceeds parity limit"
                );
                let mut trace: crate::delivery_log::Attempt = serde_json::from_str(&raw)?;
                trace.sanitize();
                Ok(json!({"attempt":attempt,"trace":trace}))
            })
            .await?;
        let row=db.query_one(
            "SELECT jsonb_build_object('attempt',attempt,'trace',trace) FROM noisefence.delivery_logs WHERE node=$1 AND epoch=$2 AND local_id=$3",
            &[&selected.node.node,&selected.node.epoch,local_id],
        ).await.map_err(database_error)?;
        let actual: Value = row.get(0);
        ensure!(
            equal(&expected, &actual),
            "Recovery transcript payload differs from its source"
        );
    }
    Ok(())
}
