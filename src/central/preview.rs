//! Bounded input snapshots for administrator-requested recipient policy previews.
use super::{Central, database_error};
use anyhow::{Context, Result, ensure};
pub type Snapshots = Vec<(String, Option<(String, String)>)>;
impl Central {
    pub async fn preview_snapshots(
        &self,
        actor: &str,
        ids: &[String],
        address: &str,
    ) -> Result<Snapshots> {
        ensure!(
            (1..=50).contains(&ids.len())
                && ids.iter().all(|id| uuid::Uuid::parse_str(id).is_ok())
                && ids.iter().collect::<std::collections::HashSet<_>>().len() == ids.len()
                && crate::config::valid_address(address),
            "Invalid preview sample"
        );
        let mut db = self
            .interactive
            .get()
            .await
            .context("Preview capacity unavailable")?;
        let tx = db
            .build_transaction()
            .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
            .read_only(true)
            .start()
            .await
            .map_err(database_error)?;
        let active:bool = tx.query_one("SELECT EXISTS(SELECT 1 FROM noisefence.users WHERE username=$1 AND admin AND NOT disabled)", &[&actor]).await.map_err(database_error)?.get(0);
        ensure!(active, "Administrator rights revoked");
        let query = tx.prepare("SELECT requested.id,m.sender,m.scan::text FROM unnest($1::text[]) WITH ORDINALITY AS requested(id,position)
            LEFT JOIN noisefence.messages m ON m.id=requested.id AND (m.created>=$3 OR m.raw_present)
              AND EXISTS(SELECT 1 FROM noisefence.deliveries d WHERE d.message_id=m.id AND d.address=$2)
            ORDER BY requested.position").await.map_err(database_error)?;
        let portal = tx
            .bind(&query, &[&ids, &address, &(crate::now() - 30 * 86400)])
            .await
            .map_err(database_error)?;
        let mut snapshots = Vec::new();
        let mut bytes = 0usize;
        loop {
            let rows = tx.query_portal(&portal, 1).await.map_err(database_error)?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                let sender: Option<String> = row.get(1);
                let scan: Option<String> = row.get(2);
                if let Some(scan) = &scan {
                    bytes = bytes.saturating_add(scan.len());
                }
                ensure!(
                    bytes <= 16 * 1024 * 1024,
                    "The selected sample exceeds the metadata budget; choose fewer messages"
                );
                snapshots.push((row.get(0), sender.zip(scan)));
            }
        }
        tx.commit().await.map_err(database_error)?;
        Ok(snapshots)
    }
}
