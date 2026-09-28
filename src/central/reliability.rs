//! Recipient-scoped quality accounting from one authorized central snapshot.
use super::{Central, database_error};
use crate::reliability::{Accumulator, MAX_BYTES, MAX_ROWS, Options};
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::time::{Duration, Instant};

impl Central {
    pub async fn reliability_audit(&self, username: &str, options: &Options) -> Result<Value> {
        options.validate()?;
        let mut db = self
            .interactive
            .get()
            .await
            .context("Reliability capacity unavailable")?;
        let tx = db
            .build_transaction()
            .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
            .read_only(true)
            .start()
            .await
            .map_err(database_error)?;
        let active: bool = tx
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM noisefence.users WHERE username=$1 AND NOT disabled)",
                &[&username],
            )
            .await
            .map_err(database_error)?
            .get(0);
        ensure!(active, "Active account required");
        let now = crate::now();
        let since = now - i64::from(options.days) * 86400;
        let query = tx.prepare("SELECT m.created,m.scan::text,l.risk,f.spam FROM noisefence.messages m
            LEFT JOIN noisefence.quality_labels l ON l.message_id=m.id AND l.username=$1 AND l.created>=m.created AND l.created<=$3
            LEFT JOIN noisefence.feedback f ON f.message_id=m.id AND f.username=$1 AND f.created>=m.created AND f.created<=$3
            WHERE NOT m.is_dsn AND m.created>=$2 AND m.created<=$3 AND EXISTS(
              SELECT 1 FROM noisefence.deliveries d JOIN noisefence.console_access a ON a.delivery_id=d.id
              WHERE d.message_id=m.id AND a.username=$1 AND ($4='' OR lower(split_part(d.destination,'@',2))=$4 OR lower(split_part(d.address,'@',2))=$4))
            ORDER BY m.created DESC,m.id LIMIT 5001").await.map_err(database_error)?;
        let portal = tx
            .bind(&query, &[&username, &since, &now, &options.domain])
            .await
            .map_err(database_error)?;
        let started = Instant::now();
        let mut bytes = 0;
        let mut count = 0;
        let mut truncated = false;
        let mut result = Accumulator::default();
        'read: loop {
            let rows = tx.query_portal(&portal, 8).await.map_err(database_error)?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                if count == MAX_ROWS || started.elapsed() > Duration::from_secs(2) {
                    truncated = true;
                    break 'read;
                }
                let raw: String = row.get(1);
                bytes += raw.len();
                count += 1;
                if bytes > MAX_BYTES {
                    truncated = true;
                    break 'read;
                }
                let risk: Option<String> = row.get(2);
                let feedback: Option<bool> = row.get(3);
                result.record(
                    &raw,
                    row.get(0),
                    risk.as_deref(),
                    feedback.map(i64::from),
                    now,
                );
            }
        }
        tx.commit().await.map_err(database_error)?;
        Ok(result.report(options, now, truncated))
    }
}
