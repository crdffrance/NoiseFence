use super::{Command, Inventory, Reply, local};
use crate::{
    identity::{connections::Reference, scim::access::Access},
    store::Store,
};
use anyhow::Result;
impl Store {
    /// The selected authority is authoritative even when it is unreachable.
    /// Authentication occurs in the same transaction as every read/mutation.
    pub async fn scim_request(&self, access: Access, command: Command) -> Result<Reply> {
        if let Some(central) = self.management() {
            return central
                .scim_request(self.root.clone(), access, command)
                .await;
        }
        let root = self.root.clone();
        self.run(move |db| {
            let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let result = local::request(&tx, &root, access, command)?;
            tx.commit()?;
            result.map_err(Into::into)
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
            return central
                .scim_inventory(self.root.clone(), reference, &actor, &session)
                .await;
        }
        let root = self.root.clone();
        self.run(move |db| {
            let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            let result = local::inventory(&tx, &root, &reference, &actor, &session)?;
            tx.commit()?;
            Ok(result)
        })
        .await
    }
}
