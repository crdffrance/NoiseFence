//! Privileged local CLI operations, authorized by installation ownership.
use super::{Central, admin::management_lock, database_error};
use crate::operator::AccountChange;
use anyhow::{Context, Result, ensure};
impl Central {
    pub async fn operator_account(&self, username: &str, change: AccountChange) -> Result<()> {
        change.validate(username)?;
        let mut db = self
            .interactive
            .get()
            .await
            .context("Central operator capacity unavailable")?;
        let tx = db.transaction().await.map_err(database_error)?;
        management_lock(&tx).await?;
        match &change {
            AccountChange::Create {
                password_hash,
                admin,
                addresses,
            } => {
                let count: i64 = tx
                    .query_one("SELECT count(*) FROM noisefence.users", &[])
                    .await
                    .map_err(database_error)?
                    .get(0);
                ensure!(count < 1000, "Maximum account count reached");
                tx.execute(
                    "INSERT INTO noisefence.users(username,password,admin) VALUES($1,$2,$3)",
                    &[&username, password_hash, admin],
                )
                .await
                .map_err(database_error)?;
                for address in addresses {
                    tx.execute(
                        "INSERT INTO noisefence.grants(username,address) VALUES($1,$2)",
                        &[&username, address],
                    )
                    .await
                    .map_err(database_error)?;
                }
            }
            AccountChange::Disable => {
                ensure!(
                    tx.execute(
                        "UPDATE noisefence.users SET disabled=true WHERE username=$1",
                        &[&username]
                    )
                    .await
                    .map_err(database_error)?
                        == 1,
                    "Unknown user"
                );
                let admins: i64 = tx
                    .query_one(
                        "SELECT count(*) FROM noisefence.users WHERE admin AND NOT disabled",
                        &[],
                    )
                    .await
                    .map_err(database_error)?
                    .get(0);
                ensure!(
                    admins > 0,
                    "The last active administrator cannot be disabled"
                );
            }
            AccountChange::ResetPassword { password_hash } => {
                ensure!(
                    tx.execute(
                        "UPDATE noisefence.users SET password=$2 WHERE username=$1",
                        &[&username, password_hash]
                    )
                    .await
                    .map_err(database_error)?
                        == 1,
                    "Unknown user"
                );
            }
            AccountChange::ResetMfa => {
                ensure!(
                    tx.query_opt(
                        "SELECT username FROM noisefence.users WHERE username=$1 FOR UPDATE",
                        &[&username]
                    )
                    .await
                    .map_err(database_error)?
                    .is_some(),
                    "Unknown user"
                );
                tx.execute(
                    "DELETE FROM noisefence.mfa_credentials WHERE username=$1",
                    &[&username],
                )
                .await
                .map_err(database_error)?;
                tx.execute(
                    "DELETE FROM noisefence.mfa_recovery WHERE username=$1",
                    &[&username],
                )
                .await
                .map_err(database_error)?;
                tx.execute(
                    "DELETE FROM noisefence.mfa_attempts WHERE username=$1",
                    &[&username],
                )
                .await
                .map_err(database_error)?;
            }
        }
        if let Some(action) = change.audit_action() {
            tx.execute(
                "UPDATE noisefence.users SET version=version+1 WHERE username=$1",
                &[&username],
            )
            .await
            .map_err(database_error)?;
            tx.execute(
                "DELETE FROM noisefence.sessions WHERE username=$1",
                &[&username],
            )
            .await
            .map_err(database_error)?;
            tx.execute("INSERT INTO noisefence.audit(created,username,action,object_id) VALUES($1,'local-administrator',$2,$3)",&[&crate::now(),&action,&username]).await.map_err(database_error)?;
        }
        tx.commit().await.map_err(database_error)?;
        Ok(())
    }
}
