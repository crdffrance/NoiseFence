//! Bounded management housekeeping, independent of SMTP and policy renewal.
use super::{Central, admin::management_lock, database_error};
use anyhow::{Context, Result};
use std::{collections::BTreeMap, time::Duration};

impl Central {
    pub async fn cleanup_management(&self) -> Result<BTreeMap<String, u64>> {
        tokio::time::timeout(Duration::from_secs(10), self.cleanup_management_batch())
            .await
            .context("Central housekeeping deadline exceeded")?
    }
    async fn cleanup_management_batch(&self) -> Result<BTreeMap<String, u64>> {
        let mut db = self
            .ingestion
            .get()
            .await
            .context("Central housekeeping capacity unavailable")?;
        let tx = db.transaction().await.map_err(database_error)?;
        management_lock(&tx).await?;
        let now = crate::now();
        let cutoff = now - 30 * 86400;
        let mut counts = BTreeMap::new();
        for (name, sql, before) in [
            (
                "sessions",
                "DELETE FROM noisefence.sessions WHERE token_hash IN (SELECT token_hash FROM noisefence.sessions WHERE expires<$1 ORDER BY expires,token_hash LIMIT 500)",
                now,
            ),
            (
                "invitations",
                "DELETE FROM noisefence.invitations WHERE id IN (SELECT id FROM noisefence.invitations WHERE expires<$1 ORDER BY expires,id LIMIT 500)",
                cutoff,
            ),
            (
                "mfa_attempts",
                "DELETE FROM noisefence.mfa_attempts WHERE username IN (SELECT username FROM noisefence.mfa_attempts WHERE until<$1 ORDER BY until,username LIMIT 500)",
                now,
            ),
            (
                "audit",
                "DELETE FROM noisefence.audit WHERE id IN (SELECT id FROM noisefence.audit WHERE created<$1 AND action NOT IN ('model_set_retain_started','model_set_retain_completed','model_set_retain_failed','model_set_remove_started','model_set_remove_completed','model_set_remove_failed') ORDER BY created,id LIMIT 500)",
                cutoff,
            ),
            // Delete completed pairs together. A started request without an outcome
            // remains operational evidence until explicitly reconciled.
            (
                "catalog_audit",
                "DELETE FROM noisefence.audit WHERE action IN ('model_set_retain_started','model_set_retain_completed','model_set_retain_failed','model_set_remove_started','model_set_remove_completed','model_set_remove_failed') AND object_id IN (SELECT object_id FROM noisefence.audit WHERE action IN ('model_set_retain_started','model_set_retain_completed','model_set_retain_failed','model_set_remove_started','model_set_remove_completed','model_set_remove_failed') GROUP BY object_id HAVING MAX(created)<$1 AND bool_or(action IN ('model_set_retain_completed','model_set_retain_failed','model_set_remove_completed','model_set_remove_failed')) ORDER BY object_id LIMIT 250)",
                cutoff,
            ),
            (
                "adaptive_labels",
                "DELETE FROM noisefence.adaptive_labels WHERE ctid IN (SELECT ctid FROM noisefence.adaptive_labels WHERE created<$1 ORDER BY created,username,message_id,domain LIMIT 500)",
                cutoff,
            ),
            // Never remove an in-flight job, a candidate another job still needs,
            // or a candidate named by any retained configuration revision.
            (
                "quality_jobs",
                "DELETE FROM noisefence.quality_jobs WHERE id IN (SELECT j.id FROM noisefence.quality_jobs j WHERE j.finished<$1 AND j.status NOT IN ('queued','running') AND NOT EXISTS(SELECT 1 FROM noisefence.quality_jobs dependent WHERE dependent.candidate_id=j.id) AND NOT EXISTS(SELECT 1 FROM noisefence.policy_revisions p WHERE p.settings#>>'{quality_candidate,job}'=j.id) ORDER BY j.finished,j.id LIMIT 100)",
                cutoff,
            ),
        ] {
            counts.insert(
                name.into(),
                tx.execute(sql, &[&before]).await.map_err(database_error)?,
            );
        }
        // Expiring a label or evaluation sample must not silently make its
        // messages eligible for training again. Reservations contain no labels
        // and disappear with the owning message's durable deletion tombstone.
        let labels = tx.query("DELETE FROM noisefence.quality_labels WHERE ctid IN (SELECT ctid FROM noisefence.quality_labels WHERE created<$1 ORDER BY created,username,message_id LIMIT 500) RETURNING message_id", &[&cutoff]).await.map_err(database_error)?;
        let ids: Vec<String> = labels.iter().map(|row| row.get(0)).collect();
        tx.execute("INSERT INTO noisefence.quality_reserved(message_id,created,reason) SELECT id,$2,'expired_evaluation' FROM unnest($1::text[]) AS ids(id) ON CONFLICT(message_id) DO NOTHING", &[&ids, &now]).await.map_err(database_error)?;
        counts.insert("quality_labels".into(), labels.len() as u64);
        // One sample can hold up to 50,000 members. Only retire one per batch.
        let batch = tx.query_opt("SELECT id,purpose FROM noisefence.quality_batches b WHERE created<$1 AND NOT EXISTS(SELECT 1 FROM noisefence.quality_jobs j WHERE j.batch_id=b.id) ORDER BY created,id LIMIT 1 FOR UPDATE", &[&cutoff]).await.map_err(database_error)?;
        if let Some(batch) = batch {
            let id: String = batch.get(0);
            if batch.get::<_, String>(1) != "development" {
                tx.execute("INSERT INTO noisefence.quality_reserved(message_id,created,reason) SELECT message_id,$2,'expired_evaluation' FROM noisefence.quality_members WHERE batch_id=$1 ON CONFLICT(message_id) DO NOTHING", &[&id,&now]).await.map_err(database_error)?;
            }
            counts.insert(
                "quality_batches".into(),
                tx.execute("DELETE FROM noisefence.quality_batches WHERE id=$1", &[&id])
                    .await
                    .map_err(database_error)?,
            );
        }
        tx.query_one(
            "SELECT generation FROM noisefence.quality_exposure_state WHERE id=1 FOR UPDATE",
            &[],
        )
        .await
        .map_err(database_error)?;
        let campaigns=tx.execute("DELETE FROM noisefence.quality_export_campaigns WHERE ctid IN (SELECT ctid FROM noisefence.quality_export_campaigns WHERE exposed_at<$1 ORDER BY exposed_at,fingerprint,simhash LIMIT 500)", &[&cutoff]).await.map_err(database_error)?;
        let batches=tx.execute("DELETE FROM noisefence.quality_export_batches WHERE batch_id IN (SELECT batch_id FROM noisefence.quality_export_batches WHERE exposed_at<$1 ORDER BY exposed_at,batch_id LIMIT 500)", &[&cutoff]).await.map_err(database_error)?;
        if campaigns + batches > 0 {
            tx.execute(
                "UPDATE noisefence.quality_exposure_state SET generation=generation+1 WHERE id=1",
                &[],
            )
            .await
            .map_err(database_error)?;
        }
        counts.insert("exposure_campaigns".into(), campaigns);
        counts.insert("exposure_batches".into(), batches);
        tx.commit().await.map_err(database_error)?;
        Ok(counts)
    }
}
