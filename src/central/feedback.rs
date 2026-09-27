use super::{Central, database_error};
use anyhow::{Result, ensure};
use serde_json::{Value, json};

impl Central {
    pub async fn record_feedback(
        &self,
        username: &str,
        id: &str,
        spam: bool,
        category: Option<crate::mailing::FeedbackCategory>,
    ) -> Result<()> {
        ensure!(
            category.is_none_or(|c| spam == (c == crate::mailing::FeedbackCategory::Spam)),
            "Inconsistent feedback category"
        );
        let mut db = self
            .interactive
            .get()
            .await
            .map_err(|_| anyhow::anyhow!("Central feedback capacity unavailable"))?;
        let tx = db.transaction().await.map_err(database_error)?;
        ensure!(tx.query_opt("SELECT username FROM noisefence.users WHERE username=$1 AND NOT disabled FOR SHARE", &[&username]).await.map_err(database_error)?.is_some(),"Message not found");
        let allowed:bool=tx.query_one("SELECT EXISTS(SELECT 1 FROM noisefence.deliveries d JOIN noisefence.console_access g ON g.delivery_id=d.id JOIN noisefence.messages m ON m.id=d.message_id WHERE d.message_id=$1 AND g.username=$2 AND m.created>=$3)", &[&id,&username,&(crate::now()-30*86400)]).await.map_err(database_error)?.get(0);
        ensure!(allowed, "Message not found");
        let category = category.map(|c| c.as_str());
        tx.execute("INSERT INTO noisefence.feedback(username,message_id,spam,category,created) VALUES($1,$2,$3,$4,$5) ON CONFLICT(username,message_id) DO UPDATE SET spam=excluded.spam,category=excluded.category,created=excluded.created", &[&username,&id,&spam,&category,&crate::now()]).await.map_err(database_error)?;
        tx.execute("INSERT INTO noisefence.audit(created,username,action,object_id) VALUES($1,$2,'feedback',$3)", &[&crate::now(),&username,&id]).await.map_err(database_error)?;
        tx.commit().await.map_err(database_error)?;
        Ok(())
    }

    pub async fn stats(&self, username: &str, domain: &str) -> Result<Value> {
        ensure!(
            domain.is_empty() || crate::config::valid_domain(domain),
            "Invalid domain"
        );
        let db = self
            .interactive
            .get()
            .await
            .map_err(|_| anyhow::anyhow!("Central search capacity unavailable"))?;
        let r=db.query_one("SELECT count(DISTINCT m.id),count(DISTINCT m.id) FILTER(WHERE m.category='spam'),count(DISTINCT m.id) FILTER(WHERE d.status IN ('pending','sending')),count(DISTINCT m.id) FILTER(WHERE m.category='publicity'),count(DISTINCT m.id) FILTER(WHERE d.status='quarantined') FROM noisefence.messages m JOIN noisefence.deliveries d ON d.message_id=m.id JOIN noisefence.console_access g ON g.delivery_id=d.id WHERE g.username=$1 AND (m.created>=$2 OR m.raw_present) AND ($3='' OR lower(split_part(d.address,'@',2))=lower($3) OR lower(split_part(d.destination,'@',2))=lower($3))", &[&username,&(crate::now()-30*86400),&domain]).await.map_err(database_error)?;
        Ok(
            json!({"received":r.get::<_,i64>(0),"flagged":r.get::<_,i64>(1),"pending":r.get::<_,i64>(2),"publicity":r.get::<_,i64>(3),"quarantined":r.get::<_,i64>(4)}),
        )
    }
}
