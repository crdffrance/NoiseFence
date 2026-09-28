//! Background projection of authorized detector inputs; no SMTP-time DB calls.
use super::{Central, database_error, nodes::Authenticated};
use crate::runtime_history::{MAX_BYTES, PROTOCOL, Row, Snapshot, Vote};
use anyhow::{Context, Result, ensure};
impl Central {
    pub async fn runtime_history(&self, node: Option<&Authenticated>) -> Result<Snapshot> {
        let mut db = self
            .interactive
            .get()
            .await
            .context("Runtime history capacity unavailable")?;
        let tx = db
            .build_transaction()
            .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
            .start()
            .await
            .map_err(database_error)?;
        if let Some(node) = node {
            node.check(&tx).await?;
        }
        let generation: i64 = tx
            .query_one(
                "SELECT nextval('noisefence.runtime_history_generation')",
                &[],
            )
            .await
            .map_err(database_error)?
            .get(0);
        let mut snapshot = Snapshot {
            protocol: PROTOCOL.into(),
            generation,
            created: crate::now(),
            rows: Vec::new(),
        };
        // Include recent unlabelled rows: the campaign detector limits its window
        // before joining feedback. Dropping them would expand that window.
        let query=tx.prepare("WITH eligible AS (SELECT DISTINCT m.id FROM noisefence.messages m JOIN noisefence.training_feedback f ON f.message_id=m.id JOIN noisefence.users u ON u.username=f.username WHERE m.created>=$1 AND u.admin AND NOT u.disabled), recent AS (SELECT id FROM noisefence.messages WHERE created>=$1 ORDER BY created DESC,id DESC LIMIT 1000) SELECT m.id,m.created,m.is_dsn,jsonb_build_object('fingerprint',m.scan->'fingerprint','simhash',m.scan->'campaign_simhash','raw_sha256',m.scan->'raw_sha256','native',m.scan#>'{native_filter,features}','sender_key',m.scan#>'{sender_history,key}','behavior',m.scan#>'{sender_history,behavior,sample}'),CASE WHEN jsonb_typeof(m.scan->'features')='array' THEN LEAST(jsonb_array_length(m.scan->'features'),80) ELSE 0 END,ARRAY(SELECT DISTINCT lower(split_part(d.destination,'@',2)) FROM noisefence.deliveries d WHERE d.message_id=m.id),COALESCE((SELECT jsonb_agg(jsonb_build_object('actor',f.username,'spam',f.spam,'created',f.created)) FROM noisefence.training_feedback f JOIN noisefence.users u ON u.username=f.username WHERE f.message_id=m.id AND u.admin AND NOT u.disabled),'[]'::jsonb) FROM noisefence.messages m WHERE m.id IN (SELECT id FROM eligible UNION SELECT id FROM recent) ORDER BY m.created DESC,m.id DESC LIMIT 50001").await.map_err(database_error)?;
        let portal = tx
            .bind(&query, &[&(snapshot.created - 30 * 86400)])
            .await
            .map_err(database_error)?;
        let mut bytes = 0;
        loop {
            let rows = tx.query_portal(&portal, 32).await.map_err(database_error)?;
            if rows.is_empty() {
                break;
            }
            for r in rows {
                ensure!(
                    snapshot.rows.len() < 50000,
                    "Runtime history exceeds row capacity"
                );
                let projection: serde_json::Value = r.get(3);
                let digest = |field: &str| {
                    projection[field]
                        .as_str()
                        .filter(|s| crate::compatibility::valid_hash(s))
                        .map(str::to_owned)
                };
                let mut votes: Vec<Vote> = serde_json::from_value(r.get(6))?;
                for vote in &mut votes {
                    vote.actor = crate::message::digest(
                        format!("runtime-history-actor-1\0{}", vote.actor).as_bytes(),
                    );
                }
                let row = Row {
                    id: r.get(0),
                    created: r.get(1),
                    is_dsn: r.get(2),
                    fingerprint: digest("fingerprint").unwrap_or_default(),
                    raw_sha256: digest("raw_sha256"),
                    sender_key: digest("sender_key"),
                    simhash: projection["simhash"]
                        .as_str()
                        .filter(|s| s.len() == 16 && s.bytes().all(|b| b.is_ascii_hexdigit()))
                        .map(str::to_owned),
                    feature_count: r.get::<_, i32>(4).try_into()?,
                    native: serde_json::from_value::<crate::native_filter::input::Features>(
                        projection["native"].clone(),
                    )
                    .ok()
                    .filter(|f| f.validate().is_ok()),
                    behavior: serde_json::from_value::<crate::quality::behavior::Sample>(
                        projection["behavior"].clone(),
                    )
                    .ok()
                    .filter(|s| s.valid()),
                    domains: r.get(5),
                    votes,
                };
                bytes += serde_json::to_vec(&row)?.len() + 1;
                ensure!(
                    bytes < MAX_BYTES - 1024,
                    "Runtime history exceeds byte capacity"
                );
                snapshot.rows.push(row);
            }
        }
        snapshot.validate()?;
        tx.commit().await.map_err(database_error)?;
        Ok(snapshot)
    }
    pub async fn refresh_runtime_history(&self, store: &crate::store::Store) -> Result<usize> {
        let snapshot = self.runtime_history(None).await?;
        let count = snapshot.rows.len();
        crate::runtime_history::install(&store.root, snapshot).await?;
        Ok(count)
    }
}
