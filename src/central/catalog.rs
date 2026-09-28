//! Files remain local artifacts; authorization and durable operation evidence are central.
use super::{Central, admin::management_lock, database_error};
use anyhow::{Context, Result, ensure};
use std::path::PathBuf;

#[derive(Clone, Copy)]
enum Action {
    Retain,
    Remove,
}
impl Action {
    fn name(self) -> &'static str {
        match self {
            Self::Retain => "model_set_retain",
            Self::Remove => "model_set_remove",
        }
    }
}

impl Central {
    /// Commit an authorized intent before touching artifacts. Completion is a
    /// separate event: a crash or DB outage must not erase evidence of the request
    /// or imply that the file operation never happened.
    async fn catalog_operation<T: Send + 'static>(
        &self,
        actor: &str,
        session: &str,
        action: Action,
        target: &str,
        operation: impl FnOnce() -> Result<T> + Send + 'static,
    ) -> Result<T> {
        ensure!(
            crate::compatibility::valid_hash(target),
            "Invalid catalog identity"
        );
        let object = format!("{}:{target}", uuid::Uuid::new_v4());
        {
            let mut db = self
                .interactive
                .get()
                .await
                .context("Central catalog capacity unavailable")?;
            let tx = db.transaction().await.map_err(database_error)?;
            management_lock(&tx).await?;
            super::policies::approval(&tx, actor, session, None).await?;
            tx.execute("INSERT INTO noisefence.audit(created,username,action,object_id) VALUES($1,$2,$3,$4)",
                &[&crate::now(), &actor, &format!("{}_started", action.name()), &object]).await.map_err(database_error)?;
            tx.commit().await.map_err(database_error)?;
        }
        let result = tokio::task::spawn_blocking(operation)
            .await
            .context("Catalog file worker interrupted")
            .and_then(|r| r);
        // Record the outcome of the already-authorized request even if its
        // initiating session has since expired. This grants no new operation.
        let db =
            self.interactive.get().await.context(
                "Catalog outcome not recorded; inspect the retained set before retrying",
            )?;
        let suffix = if result.is_ok() {
            "completed"
        } else {
            "failed"
        };
        db.execute(
            "INSERT INTO noisefence.audit(created,username,action,object_id) VALUES($1,$2,$3,$4)",
            &[
                &crate::now(),
                &actor,
                &format!("{}_{suffix}", action.name()),
                &object,
            ],
        )
        .await
        .map_err(database_error)
        .context("Catalog outcome not recorded; inspect the retained set before retrying")?;
        result
    }
    pub async fn retain_catalog(
        &self,
        root: PathBuf,
        publication: std::sync::Arc<crate::cluster::artifacts::Publication>,
        label: String,
        reserve: u64,
        actor: &str,
        session: &str,
    ) -> Result<crate::model_catalog::Entry> {
        let target = crate::model_catalog::describe(&publication, label.clone())?.id;
        self.catalog_operation(actor, session, Action::Retain, &target, move || {
            crate::model_catalog::retain(&root, &publication, label, reserve)
        })
        .await
    }
    pub async fn remove_catalog(
        &self,
        root: PathBuf,
        id: String,
        actor: &str,
        session: &str,
    ) -> Result<()> {
        let target = id.clone();
        self.catalog_operation(actor, session, Action::Remove, &target, move || {
            crate::model_catalog::remove(&root, &id)
        })
        .await
    }
}
