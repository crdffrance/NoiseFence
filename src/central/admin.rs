use super::{Central, database_error};
use anyhow::{Result, ensure};
use deadpool_postgres::Transaction;
use serde_json::{Value, json};

pub struct Account<'a> {
    pub username: &'a str,
    pub admin: bool,
    pub disabled: bool,
    pub addresses: &'a [String],
    pub password_hash: Option<&'a str>,
    pub version: i64,
}

/// Serialize account/invitation writes and enforce the last-admin/account-limit
/// invariants across concurrent sessions, including first account creation.
pub(super) async fn management_lock(tx: &Transaction<'_>) -> Result<()> {
    tx.query_one("SELECT pg_advisory_xact_lock(719021428124::bigint)", &[])
        .await
        .map_err(database_error)?;
    Ok(())
}
pub(super) async fn administrator(tx: &Transaction<'_>, username: &str) -> Result<i64> {
    let r=tx.query_opt("SELECT version FROM noisefence.users WHERE username=$1 AND admin AND NOT disabled FOR UPDATE", &[&username]).await.map_err(database_error)?;
    Ok(
        r.ok_or_else(|| anyhow::anyhow!("Administrator rights revoked"))?
            .get(0),
    )
}
impl Central {
    pub async fn accounts(&self, actor: &str) -> Result<Vec<Value>> {
        let db = self
            .interactive
            .get()
            .await
            .map_err(|_| anyhow::anyhow!("Central account capacity unavailable"))?;
        let rows=db.query("SELECT u.username,u.admin,u.disabled,u.version,ARRAY(SELECT g.address FROM noisefence.grants g WHERE g.username=u.username ORDER BY g.address) FROM noisefence.users u WHERE EXISTS(SELECT 1 FROM noisefence.users a WHERE a.username=$1 AND a.admin AND NOT a.disabled) ORDER BY u.username LIMIT 1000", &[&actor]).await.map_err(database_error)?;
        Ok(rows.iter().map(|r|json!({"username":r.get::<_,String>(0),"admin":r.get::<_,bool>(1),"disabled":r.get::<_,bool>(2),"version":r.get::<_,i64>(3),"addresses":r.get::<_,Vec<String>>(4)})).collect())
    }

    pub async fn save_account(&self, actor: &str, account: Account<'_>) -> Result<()> {
        ensure!(
            !account.username.is_empty()
                && account.username.len() <= 100
                && account
                    .username
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-@".contains(&b)),
            "Invalid account ID"
        );
        ensure!(
            account.addresses.len() <= 1000
                && account.addresses.iter().all(|a| a.len() <= 320
                    && (crate::config::valid_address(a)
                        || a.strip_prefix("*@")
                            .is_some_and(crate::config::valid_domain))),
            "Invalid access grants"
        );
        let mut db = self
            .interactive
            .get()
            .await
            .map_err(|_| anyhow::anyhow!("Central account capacity unavailable"))?;
        let tx = db.transaction().await.map_err(database_error)?;
        management_lock(&tx).await?;
        administrator(&tx, actor).await?;
        let current = tx
            .query_opt(
                "SELECT version FROM noisefence.users WHERE username=$1 FOR UPDATE",
                &[&account.username],
            )
            .await
            .map_err(database_error)?
            .map(|r| r.get::<_, i64>(0));
        ensure!(
            current.unwrap_or(-1) == account.version,
            "Account modified elsewhere or already existing. Reload the accounts."
        );
        ensure!(
            account.username != actor || (account.admin && !account.disabled),
            "You cannot disable your own admin access."
        );
        if current.is_none() {
            ensure!(
                account.password_hash.is_some(),
                "A new account requires a password"
            );
            let count: i64 = tx
                .query_one("SELECT count(*) FROM noisefence.users", &[])
                .await
                .map_err(database_error)?
                .get(0);
            ensure!(count < 1000, "Maximum of 1,000 accounts reached.");
            tx.execute("INSERT INTO noisefence.users(username,password,admin,disabled,version) VALUES($1,$2,$3,$4,1)", &[&account.username,&account.password_hash,&account.admin,&account.disabled]).await.map_err(database_error)?;
        } else {
            tx.execute("UPDATE noisefence.users SET admin=$2,disabled=$3,password=COALESCE($4,password),version=version+1 WHERE username=$1", &[&account.username,&account.admin,&account.disabled,&account.password_hash]).await.map_err(database_error)?;
        }
        let count: i64 = tx
            .query_one(
                "SELECT count(*) FROM noisefence.users WHERE admin AND NOT disabled",
                &[],
            )
            .await
            .map_err(database_error)?
            .get(0);
        ensure!(count > 0, "The last administrator must remain active.");
        tx.execute(
            "DELETE FROM noisefence.grants WHERE username=$1",
            &[&account.username],
        )
        .await
        .map_err(database_error)?;
        for address in account.addresses {
            tx.execute(
                "INSERT INTO noisefence.grants VALUES($1,$2)",
                &[&account.username, &address],
            )
            .await
            .map_err(database_error)?;
        }
        tx.execute(
            "DELETE FROM noisefence.sessions WHERE username=$1",
            &[&account.username],
        )
        .await
        .map_err(database_error)?;
        tx.execute("INSERT INTO noisefence.audit(created,username,action,object_id) VALUES($1,$2,'account',$3)", &[&crate::now(),&actor,&account.username]).await.map_err(database_error)?;
        tx.commit().await.map_err(database_error)?;
        Ok(())
    }

    pub async fn audit(&self, actor: &str) -> Result<Vec<Value>> {
        let db = self
            .interactive
            .get()
            .await
            .map_err(|_| anyhow::anyhow!("Central account capacity unavailable"))?;
        let rows=db.query("SELECT created,username,action,object_id FROM noisefence.audit WHERE EXISTS(SELECT 1 FROM noisefence.users a WHERE a.username=$1 AND a.admin AND NOT a.disabled) ORDER BY id DESC LIMIT 200", &[&actor]).await.map_err(database_error)?;
        Ok(rows.iter().map(|r|json!({"created":r.get::<_,i64>(0),"username":r.get::<_,String>(1),"action":r.get::<_,String>(2),"object":r.get::<_,String>(3)})).collect())
    }
}
