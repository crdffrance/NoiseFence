//! Invitations retain the creator's authority version and consume atomically.
use super::{
    Central,
    admin::{administrator, management_lock},
    database_error,
};
use anyhow::{Result, ensure};
use serde_json::{Value, json};

pub struct Invitation<'a> {
    pub id: &'a str,
    pub token_hash: &'a str,
    pub username: &'a str,
    pub admin: bool,
    pub addresses: &'a [String],
    pub expires: i64,
}
pub struct Claim {
    pub id: String,
    pub username: String,
    pub admin: bool,
    pub addresses: Vec<String>,
}
const CLAIM: &str = "SELECT i.id,i.username,i.admin,i.addresses FROM noisefence.invitations i JOIN noisefence.users u ON u.username=i.creator WHERE i.token_hash=$1 AND i.revoked IS NULL AND i.accepted IS NULL AND i.expires>$2 AND u.admin AND NOT u.disabled AND u.version=i.creator_version AND NOT EXISTS(SELECT 1 FROM noisefence.users target WHERE target.username=i.username)";
fn claim(row: tokio_postgres::Row) -> Result<Claim> {
    Ok(Claim {
        id: row.get(0),
        username: row.get(1),
        admin: row.get(2),
        addresses: serde_json::from_value(row.get(3))?,
    })
}
impl Central {
    pub async fn create_invitation(&self, actor: &str, invite: Invitation<'_>) -> Result<()> {
        ensure!(
            invite.expires > crate::now()
                && invite.expires <= crate::now() + 7 * 86400
                && (invite.admin || !invite.addresses.is_empty())
                && invite.addresses.len() <= 1000,
            "Invalid invitation"
        );
        let mut db = self
            .interactive
            .get()
            .await
            .map_err(|_| anyhow::anyhow!("Central account capacity unavailable"))?;
        let tx = db.transaction().await.map_err(database_error)?;
        management_lock(&tx).await?;
        let version = administrator(&tx, actor).await?;
        ensure!(
            tx.query_opt(
                "SELECT username FROM noisefence.users WHERE username=$1",
                &[&invite.username]
            )
            .await
            .map_err(database_error)?
            .is_none(),
            "This account already exists. Use account management."
        );
        let count:i64=tx.query_one("SELECT count(*) FROM noisefence.invitations WHERE accepted IS NULL AND revoked IS NULL AND expires>$1", &[&crate::now()]).await.map_err(database_error)?.get(0);
        ensure!(count < 1000, "Maximum of 1,000 active invitations reached.");
        tx.execute("UPDATE noisefence.invitations SET revoked=$2,version=version+1 WHERE username=$1 AND accepted IS NULL AND revoked IS NULL", &[&invite.username,&crate::now()]).await.map_err(database_error)?;
        tx.execute("INSERT INTO noisefence.invitations(id,token_hash,username,admin,addresses,creator,creator_version,created,expires) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)", &[&invite.id,&invite.token_hash,&invite.username,&invite.admin,&serde_json::to_value(invite.addresses)?,&actor,&version,&crate::now(),&invite.expires]).await.map_err(database_error)?;
        tx.execute("INSERT INTO noisefence.audit(created,username,action,object_id) VALUES($1,$2,'invitation_create',$3)", &[&crate::now(),&actor,&invite.id]).await.map_err(database_error)?;
        tx.commit().await.map_err(database_error)?;
        Ok(())
    }

    pub async fn invitations(&self, actor: &str) -> Result<Vec<Value>> {
        let db = self
            .interactive
            .get()
            .await
            .map_err(|_| anyhow::anyhow!("Central account capacity unavailable"))?;
        let rows=db.query("SELECT i.id,i.username,i.admin,i.addresses,i.created,i.expires,i.version,CASE WHEN i.accepted IS NOT NULL THEN 'accepted' WHEN i.revoked IS NOT NULL OR NOT EXISTS(SELECT 1 FROM noisefence.users u WHERE u.username=i.creator AND u.admin AND NOT u.disabled AND u.version=i.creator_version) THEN 'revoked' WHEN i.expires<=$1 THEN 'expired' ELSE 'pending' END FROM noisefence.invitations i WHERE EXISTS(SELECT 1 FROM noisefence.users a WHERE a.username=$2 AND a.admin AND NOT a.disabled) ORDER BY i.created DESC,i.id LIMIT 1000", &[&crate::now(),&actor]).await.map_err(database_error)?;
        Ok(rows.iter().map(|r|json!({"id":r.get::<_,String>(0),"username":r.get::<_,String>(1),"admin":r.get::<_,bool>(2),"addresses":r.get::<_,Value>(3),"created":r.get::<_,i64>(4),"expires":r.get::<_,i64>(5),"version":r.get::<_,i64>(6),"status":r.get::<_,String>(7)})).collect())
    }

    pub async fn revoke_invitation(&self, actor: &str, id: &str, version: i64) -> Result<()> {
        let mut db = self
            .interactive
            .get()
            .await
            .map_err(|_| anyhow::anyhow!("Central account capacity unavailable"))?;
        let tx = db.transaction().await.map_err(database_error)?;
        management_lock(&tx).await?;
        administrator(&tx, actor).await?;
        ensure!(tx.execute("UPDATE noisefence.invitations SET revoked=$3,version=version+1 WHERE id=$1 AND version=$2 AND accepted IS NULL AND revoked IS NULL", &[&id,&version,&crate::now()]).await.map_err(database_error)?==1,"Invitation modified or already used. Reload the list.");
        tx.execute("INSERT INTO noisefence.audit(created,username,action,object_id) VALUES($1,$2,'invitation_revoke',$3)", &[&crate::now(),&actor,&id]).await.map_err(database_error)?;
        tx.commit().await.map_err(database_error)?;
        Ok(())
    }

    pub async fn invitation_claim(&self, hash: &str) -> Result<Claim> {
        let db = self
            .interactive
            .get()
            .await
            .map_err(|_| anyhow::anyhow!("Central account capacity unavailable"))?;
        claim(
            db.query_one(CLAIM, &[&hash, &crate::now()])
                .await
                .map_err(database_error)?,
        )
    }

    pub async fn accept_invitation(
        &self,
        hash: &str,
        password: &str,
        config: &crate::config::Config,
        revision: Option<i64>,
    ) -> Result<String> {
        let mut db = self
            .interactive
            .get()
            .await
            .map_err(|_| anyhow::anyhow!("Central account capacity unavailable"))?;
        let tx = db.transaction().await.map_err(database_error)?;
        management_lock(&tx).await?;
        let mut c = claim(
            tx.query_one(
                &format!("{CLAIM} FOR UPDATE OF i,u"),
                &[&hash, &crate::now()],
            )
            .await
            .map_err(database_error)?,
        )?;
        if let Some(expected) = revision {
            let current:i64=tx.query_one("SELECT COALESCE((SELECT revision FROM noisefence.policy_head WHERE id=1 AND activated_at IS NOT NULL),0)::bigint", &[]).await.map_err(database_error)?.get(0);
            ensure!(current == expected, "Modified configuration, try again.");
        }
        let intended = c.addresses.clone();
        crate::onboarding::grants(config, &c.username, &mut c.addresses)?;
        ensure!(
            intended == c.addresses,
            "Accesses have changed. Ask for a new link."
        );
        let count: i64 = tx
            .query_one("SELECT count(*) FROM noisefence.users", &[])
            .await
            .map_err(database_error)?
            .get(0);
        ensure!(count < 1000, "Account limit reached.");
        tx.execute(
            "INSERT INTO noisefence.users(username,password,admin,version) VALUES($1,$2,$3,1)",
            &[&c.username, &password, &c.admin],
        )
        .await
        .map_err(database_error)?;
        for address in &c.addresses {
            tx.execute(
                "INSERT INTO noisefence.grants VALUES($1,$2)",
                &[&c.username, &address],
            )
            .await
            .map_err(database_error)?;
        }
        tx.execute(
            "UPDATE noisefence.invitations SET accepted=$2,version=version+1 WHERE id=$1",
            &[&c.id, &crate::now()],
        )
        .await
        .map_err(database_error)?;
        tx.execute("INSERT INTO noisefence.audit(created,username,action,object_id) VALUES($1,$2,'invitation_accept',$3)", &[&crate::now(),&c.username,&c.id]).await.map_err(database_error)?;
        tx.commit().await.map_err(database_error)?;
        Ok(c.username)
    }
}
