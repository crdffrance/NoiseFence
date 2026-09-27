//! Account authority. No authentication fallback to stale SQLite is permitted.
use super::{Central, database_error};
use anyhow::{Result, ensure};

/// Supplied only after password verification in the bounded Argon2 worker.
/// Rechecked under the user lock to fence concurrent reset/disable operations.
pub struct Login<'a> {
    pub username: &'a str,
    pub verified_password_hash: &'a str,
    pub code: &'a str,
    pub token_hash: &'a str,
    pub csrf: &'a str,
    pub previous_token_hash: Option<&'a str>,
}

impl Central {
    pub async fn password_hash(&self, username: &str) -> Result<Option<String>> {
        let db = self
            .interactive
            .get()
            .await
            .map_err(|_| anyhow::anyhow!("Central account capacity unavailable"))?;
        Ok(db
            .query_opt(
                "SELECT password FROM noisefence.users WHERE username=$1 AND NOT disabled",
                &[&username],
            )
            .await
            .map_err(database_error)?
            .map(|row| row.get(0)))
    }

    pub async fn session(&self, token_hash: &str) -> Result<Option<crate::store::User>> {
        let db = self
            .interactive
            .get()
            .await
            .map_err(|_| anyhow::anyhow!("Central account capacity unavailable"))?;
        // One statement gives a consistent snapshot of account, factor and grants.
        Ok(db.query_opt("SELECT u.username,u.admin,s.csrf,ARRAY(SELECT g.address FROM noisefence.grants g WHERE g.username=u.username ORDER BY g.address) FROM noisefence.sessions s JOIN noisefence.users u ON u.username=s.username WHERE s.token_hash=$1 AND s.expires>$2 AND NOT u.disabled AND (s.mfa_verified OR NOT EXISTS(SELECT 1 FROM noisefence.mfa_credentials m WHERE m.username=u.username AND m.enabled))", &[&token_hash,&crate::now()])
            .await.map_err(database_error)?.map(|row| crate::store::User {username:row.get(0),admin:row.get(1),csrf:row.get(2),addresses:row.get(3)}))
    }

    pub async fn create_session(&self, login: Login<'_>, key: &crate::mfa::Key) -> Result<bool> {
        ensure!(
            login.token_hash.len() == 64
                && login.token_hash.bytes().all(|b| b.is_ascii_hexdigit())
                && login.csrf.len() == 64
                && login.csrf.bytes().all(|b| b.is_ascii_hexdigit()),
            "Invalid session identity"
        );
        let mut db = self
            .interactive
            .get()
            .await
            .map_err(|_| anyhow::anyhow!("Central account capacity unavailable"))?;
        let time = crate::now();
        let tx = db.transaction().await.map_err(database_error)?;
        let account = tx
            .query_opt(
                "SELECT password,disabled FROM noisefence.users WHERE username=$1 FOR UPDATE",
                &[&login.username],
            )
            .await
            .map_err(database_error)?;
        let Some(account) = account else {
            return Ok(false);
        };
        if account.get::<_, bool>(1) || account.get::<_, String>(0) != login.verified_password_hash
        {
            return Ok(false);
        }
        // Commit failed-factor counters as well as successes; rolling them back
        // would let repeated incorrect factors bypass the persistent limiter.
        if !super::mfa::attempt(&tx, login.username, time).await? {
            tx.commit().await.map_err(database_error)?;
            return Ok(false);
        }
        let Some(verified) =
            super::mfa::consume(&tx, key, login.username, login.code, time).await?
        else {
            tx.commit().await.map_err(database_error)?;
            return Ok(false);
        };
        if let Some(previous) = login.previous_token_hash {
            tx.execute(
                "DELETE FROM noisefence.sessions WHERE token_hash=$1",
                &[&previous],
            )
            .await
            .map_err(database_error)?;
        }
        tx.execute(
            "DELETE FROM noisefence.sessions WHERE username=$1",
            &[&login.username],
        )
        .await
        .map_err(database_error)?;
        tx.execute("INSERT INTO noisefence.sessions(token_hash,username,csrf,expires,mfa_verified) VALUES($1,$2,$3,$4,$5)", &[&login.token_hash,&login.username,&login.csrf,&(time+8*3600),&verified]).await.map_err(database_error)?;
        tx.execute("INSERT INTO noisefence.audit(created,username,action,object_id) VALUES($1,$2,'login','')", &[&time,&login.username]).await.map_err(database_error)?;
        tx.commit().await.map_err(database_error)?;
        Ok(true)
    }

    pub async fn delete_session(&self, token_hash: &str) -> Result<()> {
        let db = self
            .interactive
            .get()
            .await
            .map_err(|_| anyhow::anyhow!("Central account capacity unavailable"))?;
        db.execute(
            "DELETE FROM noisefence.sessions WHERE token_hash=$1",
            &[&token_hash],
        )
        .await
        .map_err(database_error)?;
        Ok(())
    }
}
