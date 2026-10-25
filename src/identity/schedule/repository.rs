//! Scheduled work uses a finite signed grant, never a fabricated administrator session.
use super::{Grant, local};
use crate::{
    identity::{
        connections::{Record, Reference, vault::Key},
        sync::{Event, Request},
    },
    store::Store,
};
use anyhow::Result;
impl Store {
    #[allow(clippy::too_many_arguments)]
    pub async fn identity_schedule_save(
        &self,
        reference: Reference,
        expected: Option<String>,
        grant: Grant,
        key: Key,
        actor: String,
        session: String,
    ) -> Result<()> {
        if let Some(c) = self.management() {
            return c
                .identity_schedule_save(
                    &reference,
                    expected.as_deref(),
                    grant,
                    &key,
                    &actor,
                    &session,
                )
                .await;
        }
        self.run(move |db| {
            let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            local::save(
                &tx,
                &reference,
                expected.as_deref(),
                grant,
                &key,
                &actor,
                &session,
                crate::now(),
            )?;
            tx.commit()?;
            Ok(())
        })
        .await
    }
    pub async fn identity_schedule_stop(
        &self,
        reference: Reference,
        expected: String,
        actor: String,
        session: String,
    ) -> Result<()> {
        if let Some(c) = self.management() {
            return c
                .identity_schedule_stop(&reference, &expected, &actor, &session)
                .await;
        }
        self.run(move |db| {
            let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            local::stop(&tx, &reference, &expected, &actor, &session, crate::now())?;
            tx.commit()?;
            Ok(())
        })
        .await
    }
    pub async fn identity_schedule_due(&self, revision: i64) -> Result<Vec<Record>> {
        if let Some(c) = self.management() {
            return c.identity_schedule_due(revision).await;
        }
        self.run(move |db| {
            let tx = db.transaction()?;
            local::due(&tx, crate::now(), revision)
        })
        .await
    }
    pub async fn identity_schedule_claim(&self, request: Request, key: Key) -> Result<Record> {
        if let Some(c) = self.management() {
            return c.identity_schedule_claim(&request, &key).await;
        }
        self.run(move |db| {
            let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let record = local::claim(&tx, &request, &key, crate::now())?;
            tx.commit()?;
            Ok(record)
        })
        .await
    }
    pub async fn identity_schedule_authorized(&self, request: Request) -> Result<()> {
        if let Some(c) = self.management() {
            return c.identity_schedule_authorized(&request).await;
        }
        self.run(move |db| {
            let tx = db.transaction()?;
            local::authorized(&tx, &request, crate::now())?;
            Ok(())
        })
        .await
    }
    pub async fn identity_schedule_finish(&self, event: Event, actor: String) -> Result<()> {
        if let Some(c) = self.management() {
            return c.identity_schedule_finish(&event, &actor).await;
        }
        self.run(move |db| {
            let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            local::finish(&tx, event, &actor, crate::now())?;
            tx.commit()?;
            Ok(())
        })
        .await
    }
}
