//! Factor transitions serialize on the account row, as do logins and revocations.
use super::{Central, database_error};
use anyhow::{Result, ensure};
use deadpool_postgres::Transaction;
use serde_json::{Value, json};

pub(super) async fn attempt(tx: &Transaction<'_>, username: &str, time: i64) -> Result<bool> {
    let attempts: i32 = tx.query_one("INSERT INTO noisefence.mfa_attempts(username,until,attempts) VALUES($1,$2,1) ON CONFLICT(username) DO UPDATE SET until=CASE WHEN noisefence.mfa_attempts.until<=$3 THEN $2 ELSE noisefence.mfa_attempts.until END,attempts=CASE WHEN noisefence.mfa_attempts.until<=$3 THEN 1 ELSE LEAST(noisefence.mfa_attempts.attempts+1,11) END RETURNING attempts", &[&username,&(time+600),&time]).await.map_err(database_error)?.get(0);
    Ok(attempts <= 10)
}

pub(super) async fn consume(
    tx: &Transaction<'_>,
    key: &crate::mfa::Key,
    username: &str,
    code: &str,
    time: i64,
) -> Result<Option<bool>> {
    let factor = tx.query_opt("SELECT secret,last_step FROM noisefence.mfa_credentials WHERE username=$1 AND enabled FOR UPDATE", &[&username]).await.map_err(database_error)?;
    let Some(factor) = factor else {
        return Ok(Some(false));
    };
    if code.len() > 80 {
        return Ok(None);
    }
    let secret = key.open_secret(username, &factor.get::<_, Vec<u8>>(0))?;
    if let Some(step) = crate::mfa::matched_step(&secret, code, time, factor.get(1)) {
        tx.execute(
            "UPDATE noisefence.mfa_credentials SET last_step=$2 WHERE username=$1",
            &[&username, &step],
        )
        .await
        .map_err(database_error)?;
        return Ok(Some(true));
    }
    if code.len() == 32
        && code.bytes().all(|b| b.is_ascii_hexdigit())
        && tx
            .execute(
                "DELETE FROM noisefence.mfa_recovery WHERE username=$1 AND digest=$2",
                &[&username, &crate::message::digest(code.as_bytes())],
            )
            .await
            .map_err(database_error)?
            == 1
    {
        return Ok(Some(true));
    }
    Ok(None)
}

pub(super) async fn allowed(
    tx: &Transaction<'_>,
    username: &str,
    session: &str,
    password: Option<&str>,
) -> Result<bool> {
    let user=tx.query_opt("SELECT username FROM noisefence.users WHERE username=$1 AND NOT disabled AND ($2::text IS NULL OR password=$2) FOR UPDATE", &[&username,&password]).await.map_err(database_error)?;
    if user.is_none() {
        return Ok(false);
    }
    // Take a fresh snapshot after the account lock. A preceding MFA transition
    // can revoke cookies without changing the user row itself.
    Ok(tx.query_opt("SELECT token_hash FROM noisefence.sessions s WHERE s.username=$1 AND s.token_hash=$2 AND s.expires>$3 AND (s.mfa_verified OR NOT EXISTS(SELECT 1 FROM noisefence.mfa_credentials m WHERE m.username=s.username AND m.enabled)) FOR SHARE OF s", &[&username,&session,&crate::now()]).await.map_err(database_error)?.is_some())
}

impl Central {
    /// Fail before opening the console if the external encryption key is absent
    /// or belongs to another installation. Never replace a missing sealed key.
    pub async fn validate_mfa_key(&self, root: &std::path::Path) -> Result<()> {
        let db = self
            .interactive
            .get()
            .await
            .map_err(|_| anyhow::anyhow!("Central account capacity unavailable"))?;
        let records = db
            .query(
                "SELECT username,secret FROM noisefence.mfa_credentials LIMIT 1001",
                &[],
            )
            .await
            .map_err(database_error)?;
        ensure!(records.len() <= 1000, "Central account limit exceeded");
        if !records.is_empty() {
            ensure!(
                root.join("mfa.key").exists(),
                "MFA key missing: restore the original key before starting the console"
            );
            let key = crate::mfa::Key::open(root)?;
            for record in records {
                key.open_secret(&record.get::<_, String>(0), &record.get::<_, Vec<u8>>(1))?;
            }
        }
        Ok(())
    }
    pub async fn mfa_status(&self, username: &str) -> Result<Value> {
        let db = self
            .interactive
            .get()
            .await
            .map_err(|_| anyhow::anyhow!("Central account capacity unavailable"))?;
        let r=db.query_one("SELECT EXISTS(SELECT 1 FROM noisefence.mfa_credentials m WHERE m.username=u.username AND m.enabled),(SELECT count(*) FROM noisefence.mfa_recovery r WHERE r.username=u.username),u.admin FROM noisefence.users u WHERE u.username=$1 AND NOT u.disabled", &[&username]).await.map_err(database_error)?;
        Ok(
            json!({"enabled":r.get::<_,bool>(0),"recovery_remaining":r.get::<_,i64>(1),"recommended":r.get::<_,bool>(2)}),
        )
    }

    pub async fn challenge_password_hash(&self, username: &str) -> Result<Option<String>> {
        let mut db = self
            .interactive
            .get()
            .await
            .map_err(|_| anyhow::anyhow!("Central account capacity unavailable"))?;
        let tx = db.transaction().await.map_err(database_error)?;
        let hash=tx.query_opt("SELECT password FROM noisefence.users WHERE username=$1 AND NOT disabled FOR UPDATE", &[&username]).await.map_err(database_error)?;
        let Some(hash) = hash else {
            return Ok(None);
        };
        let permitted = attempt(&tx, username, crate::now()).await?;
        tx.commit().await.map_err(database_error)?;
        Ok(permitted.then(|| hash.get(0)))
    }

    pub async fn enroll_factor(
        &self,
        username: &str,
        session: &str,
        verified_hash: &str,
        sealed: &[u8],
    ) -> Result<bool> {
        ensure!(sealed.len() == 48, "Invalid encrypted factor");
        let mut db = self
            .interactive
            .get()
            .await
            .map_err(|_| anyhow::anyhow!("Central account capacity unavailable"))?;
        let tx = db.transaction().await.map_err(database_error)?;
        if !allowed(&tx, username, session, Some(verified_hash)).await? {
            return Ok(false);
        }
        let changed=tx.execute("INSERT INTO noisefence.mfa_credentials(username,secret,pending_until) VALUES($1,$2,$3) ON CONFLICT(username) DO UPDATE SET secret=excluded.secret,pending_until=excluded.pending_until,last_step=-1 WHERE NOT noisefence.mfa_credentials.enabled", &[&username,&sealed,&(crate::now()+600)]).await.map_err(database_error)?;
        tx.commit().await.map_err(database_error)?;
        Ok(changed == 1)
    }

    pub async fn confirm_factor(
        &self,
        username: &str,
        session: &str,
        key: &crate::mfa::Key,
        code: &str,
        recovery: &[String],
    ) -> Result<bool> {
        ensure!(
            recovery.len() == 10
                && recovery
                    .iter()
                    .all(|s| s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit())),
            "Invalid recovery tokens"
        );
        let mut db = self
            .interactive
            .get()
            .await
            .map_err(|_| anyhow::anyhow!("Central account capacity unavailable"))?;
        let tx = db.transaction().await.map_err(database_error)?;
        if !allowed(&tx, username, session, None).await? {
            return Ok(false);
        }
        if !attempt(&tx, username, crate::now()).await? {
            tx.commit().await.map_err(database_error)?;
            return Ok(false);
        }
        let factor=tx.query_opt("SELECT secret FROM noisefence.mfa_credentials WHERE username=$1 AND NOT enabled AND pending_until>$2 FOR UPDATE", &[&username,&crate::now()]).await.map_err(database_error)?;
        let step = if let Some(factor) = factor {
            let secret = key.open_secret(username, &factor.get::<_, Vec<u8>>(0))?;
            crate::mfa::matched_step(&secret, code, crate::now(), -1)
        } else {
            None
        };
        let Some(step) = step else {
            tx.commit().await.map_err(database_error)?;
            return Ok(false);
        };
        tx.execute("UPDATE noisefence.mfa_credentials SET enabled=true,pending_until=0,last_step=$2 WHERE username=$1", &[&username,&step]).await.map_err(database_error)?;
        tx.execute(
            "DELETE FROM noisefence.mfa_recovery WHERE username=$1",
            &[&username],
        )
        .await
        .map_err(database_error)?;
        for code in recovery {
            tx.execute(
                "INSERT INTO noisefence.mfa_recovery VALUES($1,$2)",
                &[&username, &crate::message::digest(code.as_bytes())],
            )
            .await
            .map_err(database_error)?;
        }
        tx.execute(
            "DELETE FROM noisefence.sessions WHERE username=$1",
            &[&username],
        )
        .await
        .map_err(database_error)?;
        tx.execute("INSERT INTO noisefence.audit(created,username,action,object_id) VALUES($1,$2,'mfa_enabled','')", &[&crate::now(),&username]).await.map_err(database_error)?;
        tx.commit().await.map_err(database_error)?;
        Ok(true)
    }

    pub async fn disable_factor(
        &self,
        username: &str,
        session: &str,
        verified_hash: &str,
        key: &crate::mfa::Key,
        code: &str,
    ) -> Result<bool> {
        let mut db = self
            .interactive
            .get()
            .await
            .map_err(|_| anyhow::anyhow!("Central account capacity unavailable"))?;
        let tx = db.transaction().await.map_err(database_error)?;
        if !allowed(&tx, username, session, Some(verified_hash)).await?
            || consume(&tx, key, username, code, crate::now()).await? != Some(true)
        {
            return Ok(false);
        }
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
            "DELETE FROM noisefence.sessions WHERE username=$1",
            &[&username],
        )
        .await
        .map_err(database_error)?;
        tx.execute("INSERT INTO noisefence.audit(created,username,action,object_id) VALUES($1,$2,'mfa_disabled','')", &[&crate::now(),&username]).await.map_err(database_error)?;
        tx.commit().await.map_err(database_error)?;
        Ok(true)
    }

    pub async fn change_password(
        &self,
        username: &str,
        session: &str,
        old: &str,
        new: &str,
    ) -> Result<bool> {
        let mut db = self
            .interactive
            .get()
            .await
            .map_err(|_| anyhow::anyhow!("Central account capacity unavailable"))?;
        let tx = db.transaction().await.map_err(database_error)?;
        if !allowed(&tx, username, session, Some(old)).await? {
            return Ok(false);
        }
        tx.execute(
            "UPDATE noisefence.users SET password=$2,version=version+1 WHERE username=$1",
            &[&username, &new],
        )
        .await
        .map_err(database_error)?;
        tx.execute(
            "DELETE FROM noisefence.sessions WHERE username=$1",
            &[&username],
        )
        .await
        .map_err(database_error)?;
        tx.execute("INSERT INTO noisefence.audit(created,username,action,object_id) VALUES($1,$2,'password','')", &[&crate::now(),&username]).await.map_err(database_error)?;
        tx.commit().await.map_err(database_error)?;
        Ok(true)
    }
}
