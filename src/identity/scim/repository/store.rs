use super::{Command, Inventory, Reply, local};
use crate::{
    identity::{connections::Reference, scim::access::Access},
    store::Store,
};
use anyhow::{Context, Result};
use std::time::Duration;
impl Store {
    /// The selected authority is authoritative even when it is unreachable.
    /// Authentication occurs in the same transaction as every read/mutation.
    pub async fn scim_request(&self, access: Access, command: Command) -> Result<Reply> {
        if let Some(central) = self.management() {
            return tokio::time::timeout(
                Duration::from_secs(10),
                central.scim_request(self.root.clone(), access, command),
            )
            .await
            .context("SCIM operation deadline exceeded")?;
        }
        local::run(self.root.clone(), move |db, root, deadline| {
            let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let result = local::request(&tx, root, access, command, deadline)?;
            deadline.check()?;
            tx.commit()?;
            result.map_err(Into::into)
        })
        .await
    }
    /// Pre-body authorization only; the real request checks again and charges
    /// exactly once. Transport admission must bound unauthenticated attempts.
    pub async fn scim_preflight(
        &self,
        access: Access,
    ) -> Result<(Access, crate::identity::directory::Source)> {
        if let Some(central) = self.management() {
            return tokio::time::timeout(
                Duration::from_secs(10),
                central.scim_preflight(self.root.clone(), access),
            )
            .await
            .context("SCIM authorization deadline exceeded")?;
        }
        local::run(self.root.clone(), move |db, root, deadline| {
            let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let result = local::preflight(&tx, root, access)?;
            deadline.check()?;
            tx.commit()?;
            Ok(result)
        })
        .await
    }
    pub async fn scim_inventory(
        &self,
        reference: Reference,
        actor: String,
        session: String,
    ) -> Result<Inventory> {
        if let Some(central) = self.management() {
            return tokio::time::timeout(
                Duration::from_secs(10),
                central.scim_inventory(self.root.clone(), reference, &actor, &session),
            )
            .await
            .context("SCIM inventory deadline exceeded")?;
        }
        local::run(self.root.clone(), move |db, root, deadline| {
            let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let result = local::inventory(&tx, root, &reference, &actor, &session, deadline)?;
            deadline.check()?;
            tx.commit()?;
            Ok(result)
        })
        .await
    }
}
