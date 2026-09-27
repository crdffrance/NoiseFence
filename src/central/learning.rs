//! Full-population private training exports, streamed from a consistent snapshot.
use super::{Central, adaptive::reservations, database_error};
use crate::learning::{AtomicExport, ExportReport, FeedbackRow, LearningExample, project};
use anyhow::{Context, Result};
use std::path::Path;
enum Item<T, R> {
    Example(T),
    Complete(R),
}
impl Central {
    pub async fn learning_export(
        &self,
        output: &Path,
        require_semantic: bool,
    ) -> Result<ExportReport> {
        let (send, writer) = export_writer::<Box<LearningExample>, ExportReport>(output);
        let produced:Result<()>=async {
            let mut db=self.interactive.get().await.context("Central learning capacity unavailable")?;
            let tx=db.build_transaction().isolation_level(tokio_postgres::IsolationLevel::RepeatableRead).start().await.map_err(database_error)?;
            let protected=reservations(&tx).await?;
            let query=tx.prepare("SELECT m.id,m.created,m.scan::text,MIN(f.spam::integer)::bigint,MAX(f.spam::integer)::bigint,MAX(f.created),MIN(f.category),MAX(f.category),COUNT(f.category),COUNT(*) FROM noisefence.messages m JOIN noisefence.training_feedback f ON f.message_id=m.id JOIN noisefence.users u ON u.username=f.username AND NOT u.disabled WHERE NOT m.is_dsn AND m.created>=$1 AND EXISTS(SELECT 1 FROM noisefence.deliveries d JOIN noisefence.console_access g ON g.delivery_id=d.id WHERE d.message_id=m.id AND g.username=f.username) GROUP BY m.id ORDER BY m.id").await.map_err(database_error)?;
            let portal=tx.bind(&query,&[&(crate::now()-30*86400)]).await.map_err(database_error)?;
            let mut report=ExportReport::default();
            loop {
                let rows=tx.query_portal(&portal,8).await.map_err(database_error)?;
                if rows.is_empty() {break;}
                for r in rows {
                    let input=FeedbackRow{id:r.get(0),observed_at:r.get(1),scan:r.get(2),min:r.get(3),max:r.get(4),labelled_at:r.get(5),first:r.get(6),last:r.get(7),explicit:r.get(8),votes:r.get(9)};
                    if let Some(row)=project(input,&protected,require_semantic,&mut report)? {send.send(Item::Example(Box::new(row))).await.context("Learning output unavailable")?;}
                }
            }
            tx.commit().await.map_err(database_error)?;
            send.send(Item::Complete(report)).await.context("Learning output unavailable")?;
            Ok(())
        }.await;
        drop(send);
        let written = writer.await.context("Learning writer unavailable")?;
        produced?;
        written
    }
}

impl Central {
    pub async fn native_export(
        &self,
        user: &str,
        scope: &str,
    ) -> Result<(
        Vec<crate::native_filter::bayes::Example>,
        crate::native_filter::learning::ExportReport,
    )> {
        use crate::native_filter::learning::{ExportReport, export_example};
        anyhow::ensure!(
            crate::config::valid_domain(scope) && scope == scope.to_ascii_lowercase(),
            "Invalid native export domain"
        );
        let mut db = self
            .interactive
            .get()
            .await
            .context("Central learning capacity unavailable")?;
        let tx = db
            .build_transaction()
            .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
            .start()
            .await
            .map_err(database_error)?;
        anyhow::ensure!(tx.query_opt("SELECT username FROM noisefence.users WHERE username=$1 AND admin AND NOT disabled FOR SHARE",&[&user]).await.map_err(database_error)?.is_some(),"Native domain model export requires an enabled administrator");
        let protected = reservations(&tx).await?;
        let query=tx.prepare("SELECT m.id,m.created,m.scan::text,MIN(f.spam::integer)::bigint,MAX(f.spam::integer)::bigint,MAX(f.created) FROM noisefence.messages m JOIN noisefence.training_feedback f ON f.message_id=m.id JOIN noisefence.users u ON u.username=f.username WHERE m.created>=$1 AND m.created<$2 AND NOT m.is_dsn AND f.created>=$1 AND f.created<$2 AND NOT u.disabled AND EXISTS(SELECT 1 FROM noisefence.deliveries d JOIN noisefence.console_access a ON a.delivery_id=d.id WHERE d.message_id=m.id AND a.username=f.username AND lower(split_part(d.destination,'@',2))=$3) AND EXISTS(SELECT 1 FROM noisefence.deliveries d JOIN noisefence.console_access a ON a.delivery_id=d.id WHERE d.message_id=m.id AND a.username=$4 AND lower(split_part(d.destination,'@',2))=$3) GROUP BY m.id ORDER BY m.created,m.id LIMIT 50001").await.map_err(database_error)?;
        let portal = tx
            .bind(
                &query,
                &[&(crate::now() - 30 * 86400), &crate::now(), &scope, &user],
            )
            .await
            .map_err(database_error)?;
        let mut report = ExportReport::default();
        let mut out = Vec::new();
        let mut visited = 0;
        let mut bytes = 0;
        loop {
            let rows = tx.query_portal(&portal, 8).await.map_err(database_error)?;
            if rows.is_empty() {
                break;
            }
            for r in rows {
                visited += 1;
                anyhow::ensure!(visited <= 50000, "Native export exceeds 50000 messages");
                if let Some(row) = export_example(
                    (r.get(0), r.get(1), r.get(2), r.get(3), r.get(4), r.get(5)),
                    scope,
                    &protected,
                    &mut report,
                )? {
                    bytes += serde_json::to_vec(&row)?.len() + 1;
                    anyhow::ensure!(
                        bytes <= 128 * 1024 * 1024,
                        "Native export exceeds memory limit"
                    );
                    out.push(row);
                }
            }
        }
        Ok((out, report))
    }
}

type ExportChannel<T, R> = (
    tokio::sync::mpsc::Sender<Item<T, R>>,
    tokio::task::JoinHandle<Result<R>>,
);
fn export_writer<T: serde::Serialize + Send + 'static, R: Send + 'static>(
    output: &Path,
) -> ExportChannel<T, R> {
    let output = output.to_owned();
    // A bounded handoff keeps filesystem writes off the asynchronous DB runtime.
    let (send, mut receive) = tokio::sync::mpsc::channel::<Item<T, R>>(8);
    let writer = tokio::task::spawn_blocking(move || -> Result<R> {
        let mut file = AtomicExport::new(&output)?;
        while let Some(item) = receive.blocking_recv() {
            match item {
                Item::Example(row) => file.write(&row)?,
                Item::Complete(report) => {
                    file.finish()?;
                    return Ok(report);
                }
            }
        }
        anyhow::bail!("Learning export interrupted before snapshot completion")
    });
    (send, writer)
}
impl Central {
    pub async fn corpus_export(&self, output: &Path) -> Result<usize> {
        let (send, writer) = export_writer::<crate::corpus::Example, usize>(output);
        let produced:Result<()>=async {
            let mut db=self.interactive.get().await.context("Central learning capacity unavailable")?;
            let tx=db.build_transaction().isolation_level(tokio_postgres::IsolationLevel::RepeatableRead).start().await.map_err(database_error)?;
            let protected=reservations(&tx).await?;
            let query=tx.prepare("SELECT m.scan::text,bool_and(f.spam) FROM noisefence.messages m JOIN noisefence.training_feedback f ON f.message_id=m.id JOIN noisefence.users u ON u.username=f.username AND NOT u.disabled WHERE m.created>=$1 AND NOT m.is_dsn AND EXISTS(SELECT 1 FROM noisefence.deliveries d JOIN noisefence.console_access g ON g.delivery_id=d.id WHERE d.message_id=m.id AND g.username=f.username) GROUP BY m.id HAVING bool_and(f.spam)=bool_or(f.spam) ORDER BY m.id").await.map_err(database_error)?;
            let portal=tx.bind(&query,&[&(crate::now()-30*86400)]).await.map_err(database_error)?;
            let mut count=0;
            loop {
                let rows=tx.query_portal(&portal,8).await.map_err(database_error)?;if rows.is_empty(){break;}
                for row in rows {
                    let scan=serde_json::from_str(&row.get::<_,String>(0))?;
                    if let Some(example)=crate::corpus::feedback_example(scan,row.get(1),&protected) {
                        send.send(Item::Example(example)).await.context("Learning output unavailable")?;count+=1;
                    }
                }
            }
            tx.commit().await.map_err(database_error)?;
            send.send(Item::Complete(count)).await.context("Learning output unavailable")?;Ok(())
        }.await;
        drop(send);
        let written = writer.await.context("Learning writer unavailable")?;
        produced?;
        written
    }
}
