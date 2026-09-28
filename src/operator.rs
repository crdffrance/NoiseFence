//! Installation-owner account recovery. Never expose this entry point as a Web API.
use crate::store::Store;
use anyhow::{Result, ensure};

pub enum AccountChange {
    Create {
        password_hash: String,
        admin: bool,
        addresses: Vec<String>,
    },
    Disable,
    ResetPassword {
        password_hash: String,
    },
    ResetMfa,
}
impl AccountChange {
    pub(crate) fn validate(&self, username: &str) -> Result<()> {
        ensure!(
            !username.is_empty()
                && username.len() <= 100
                && username
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"._-@".contains(&c)),
            "Invalid username"
        );
        if let Self::Create { password_hash, .. } | Self::ResetPassword { password_hash } = self {
            ensure!(
                password_hash.len() <= 1024
                    && argon2::PasswordHash::new(password_hash)
                        .ok()
                        .is_some_and(|h| h.algorithm.as_str() == "argon2id"
                            && h.salt.is_some()
                            && h.hash.is_some()),
                "Invalid password hash"
            );
        }
        if let Self::Create { addresses, .. } = self {
            ensure!(
                addresses.len() <= 1000
                    && addresses.iter().all(|a| a.len() <= 320
                        && (crate::config::valid_address(a)
                            || a.strip_prefix("*@")
                                .is_some_and(crate::config::valid_domain))),
                "Invalid access grants"
            );
        }
        Ok(())
    }
    pub(crate) fn audit_action(&self) -> Option<&'static str> {
        match self {
            Self::Create { .. } => None,
            Self::ResetMfa => Some("mfa_reset"),
            _ => Some("account"),
        }
    }
}

/// The caller must already own the installation and select its fenced backend.
/// Web account operations use the separately authenticated admin repositories.
pub async fn account(store: &Store, username: String, change: AccountChange) -> Result<()> {
    change.validate(&username)?;
    if let Some(central) = store.management() {
        return central.operator_account(&username, change).await;
    }
    store.run(move|db| {
        use rusqlite::params;
        ensure!(crate::central::selection::Selection::read(db)?.is_none(), "Use the coordinator for management operations");
        let tx=db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        match &change {
            AccountChange::Create {password_hash,admin,addresses}=>{
                let count:i64=tx.query_row("SELECT COUNT(*) FROM users",[],|r|r.get(0))?;
                ensure!(count<1000,"Maximum account count reached");
                tx.execute("INSERT INTO users(username,password,admin) VALUES(?1,?2,?3)",params![username,password_hash,admin])?;
                for address in addresses {tx.execute("INSERT INTO grants(username,address) VALUES(?1,?2)",params![username,address])?;}
            }
            AccountChange::Disable=>{
                ensure!(tx.execute("UPDATE users SET disabled=1 WHERE username=?1",[&username])?==1,"Unknown user");
                let admins:i64=tx.query_row("SELECT COUNT(*) FROM users WHERE admin=1 AND disabled=0",[],|r|r.get(0))?;
                ensure!(admins>0,"The last active administrator cannot be disabled");
            }
            AccountChange::ResetPassword {password_hash}=>{
                ensure!(tx.execute("UPDATE users SET password=?2 WHERE username=?1",params![username,password_hash])?==1,"Unknown user");
            }
            AccountChange::ResetMfa=>{
                ensure!(tx.query_row("SELECT EXISTS(SELECT 1 FROM users WHERE username=?1)",[&username],|r|r.get::<_,bool>(0))?,"Unknown user");
                tx.execute("DELETE FROM mfa_credentials WHERE username=?1",[&username])?;
                tx.execute("DELETE FROM mfa_recovery WHERE username=?1",[&username])?;
                tx.execute("DELETE FROM mfa_attempts WHERE username=?1",[&username])?;
            }
        }
        if let Some(action)=change.audit_action() {
            tx.execute("DELETE FROM sessions WHERE username=?1",[&username])?;
            tx.execute("INSERT INTO console_user_versions(username,version) VALUES(?1,1) ON CONFLICT(username) DO UPDATE SET version=version+1",[&username])?;
            tx.execute("INSERT INTO audit(created,username,action,object_id) VALUES(?1,'local-administrator',?2,?3)",params![crate::now(),action,username])?;
        }
        tx.commit()?;Ok(())
    }).await
}
