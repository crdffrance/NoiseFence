//! Complete retained-population audit: include unlabelled and unusable messages.
use super::{Central, database_error};
use crate::population::{Report, Row, Writer, project};
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use std::path::Path;
enum Item {
    Row(Value),
    Complete(Report),
}
impl Central {
    pub async fn population_export(
        &self,
        output: &Path,
        since: i64,
        until: i64,
        captured_at: i64,
    ) -> Result<Report> {
        ensure!(
            captured_at.abs_diff(crate::now()) <= 5
                && since > 0
                && since < until
                && since >= captured_at - 30 * 86400
                && until <= captured_at + 1,
            "Population interval must be within the last 30 days"
        );
        let output = output.to_owned();
        let (send, mut receive) = tokio::sync::mpsc::channel::<Item>(8);
        let writer = tokio::task::spawn_blocking(move || -> Result<Report> {
            let mut file = Writer::new(&output, since, until, captured_at)?;
            while let Some(item) = receive.blocking_recv() {
                match item {
                    Item::Row(row) => file.row(&row)?,
                    Item::Complete(report) => {
                        file.finish(&report)?;
                        return Ok(report);
                    }
                }
            }
            anyhow::bail!("Population snapshot interrupted")
        });
        let produced:Result<()>=async {
            let mut db=self.interactive.get().await.context("Central audit capacity unavailable")?;
            let tx=db.build_transaction().isolation_level(tokio_postgres::IsolationLevel::RepeatableRead).start().await.map_err(database_error)?;
            let query=tx.prepare("WITH votes AS (SELECT f.message_id,f.spam,f.created,NOT u.disabled AND EXISTS(SELECT 1 FROM noisefence.deliveries d JOIN noisefence.console_access g ON g.delivery_id=d.id WHERE d.message_id=f.message_id AND g.username=f.username) AS allowed FROM noisefence.feedback f JOIN noisefence.users u ON u.username=f.username) SELECT m.id,m.created,m.scan::text,m.is_dsn,COUNT(v.message_id),COUNT(*) FILTER(WHERE v.allowed),MIN(v.spam::integer) FILTER(WHERE v.allowed)::bigint,MAX(v.spam::integer) FILTER(WHERE v.allowed)::bigint,MAX(v.created) FILTER(WHERE v.allowed) FROM noisefence.messages m LEFT JOIN votes v ON v.message_id=m.id WHERE m.created>=$1 AND m.created<$2 GROUP BY m.id ORDER BY m.created,m.id").await.map_err(database_error)?;
            let portal=tx.bind(&query,&[&since,&until]).await.map_err(database_error)?;
            let mut report=Report::default();
            loop {
                let rows=tx.query_portal(&portal,8).await.map_err(database_error)?;if rows.is_empty(){break;}
                for r in rows {
                    let input=Row{id:r.get(0),created:r.get(1),scan:r.get(2),is_dsn:r.get(3),total_votes:r.get::<_,i64>(4).try_into()?,votes:r.get::<_,i64>(5).try_into()?,min:r.get(6),max:r.get(7),labelled_at:r.get(8)};
                    if let Some(row)=project(input,&mut report)? {send.send(Item::Row(row)).await.context("Population output unavailable")?;}
                }
            }
            tx.commit().await.map_err(database_error)?;send.send(Item::Complete(report)).await.context("Population output unavailable")?;Ok(())
        }.await;
        drop(send);
        let written = writer.await.context("Population writer unavailable")?;
        produced?;
        written
    }
}
