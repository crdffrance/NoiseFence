//! Selected-authority dispatch. PostgreSQL failure never reads a local shadow.
use super::{Record, View, local, vault::Key};
use crate::store::Store;
use anyhow::Result;
impl Store {
    pub fn directory_connection_authority(&self) -> String {
        self.management()
            .map(|c| c.directory_connection_authority())
            .unwrap_or_else(|| "sqlite".into())
    }
    /// Explicit administrative setup, serialized with all connection mutations.
    /// Loading a missing key with any existing record is refused, even when all
    /// records are revoked. Restore the key rather than silently replacing it.
    pub async fn identity_connection_prepare(
        &self,
        actor: String,
        session: String,
    ) -> Result<(Key, i64)> {
        if let Some(c) = self.management() {
            return c
                .identity_connection_prepare(self.root.clone(), &actor, &session)
                .await;
        }
        let root = self.root.clone();
        self.run(move |db| {
            let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let version = local::authorize(&tx, &actor, &session)?;
            local::migrate(&tx)?;
            let count: i64 =
                tx.query_row("SELECT count(*) FROM identity_connections", [], |r| {
                    r.get(0)
                })?;
            let key = Key::load_or_initialize(&root, count != 0)?;
            tx.commit()?;
            Ok((key, version))
        })
        .await
    }
    pub async fn identity_connection_save(
        &self,
        expected: Option<String>,
        next: Record,
        actor: String,
        session: String,
    ) -> Result<()> {
        if let Some(c) = self.management() {
            return c
                .identity_connection_save(expected.as_deref(), &next, &actor, &session)
                .await;
        }
        self.run(move |db| {
            let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            local::save(
                &tx,
                expected.as_deref(),
                &next,
                &actor,
                &session,
                crate::now(),
            )?;
            tx.commit()?;
            Ok(())
        })
        .await
    }
    pub async fn identity_connection_list(
        &self,
        actor: String,
        session: String,
    ) -> Result<Vec<View>> {
        if let Some(c) = self.management() {
            return c.identity_connection_list(&actor, &session).await;
        }
        self.run(move |db| {
            let tx = db.transaction()?;
            let result = local::list(&tx, &actor, &session, crate::now())?;
            tx.commit()?;
            Ok(result)
        })
        .await
    }
    pub async fn identity_connection_get(
        &self,
        source: String,
        generation: String,
        actor: String,
        session: String,
    ) -> Result<Record> {
        if let Some(c) = self.management() {
            return c
                .identity_connection_get(&source, &generation, &actor, &session)
                .await;
        }
        self.run(move |db| {
            let tx = db.transaction()?;
            let result = local::get(&tx, &source, &generation, &actor, &session, crate::now())?;
            tx.commit()?;
            Ok(result)
        })
        .await
    }
    pub async fn identity_connection_revoke(
        &self,
        source: String,
        expected: String,
        actor: String,
        session: String,
    ) -> Result<()> {
        if let Some(c) = self.management() {
            return c
                .identity_connection_revoke(&source, &expected, &actor, &session)
                .await;
        }
        self.run(move |db| {
            let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            local::revoke(&tx, &source, &expected, &actor, &session, crate::now())?;
            tx.commit()?;
            Ok(())
        })
        .await
    }
}
