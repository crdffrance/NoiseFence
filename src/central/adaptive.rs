//! Tenant-scoped human annotations; central exports never use stale local truth.
use super::{Central, admin::management_lock, database_error};
use crate::{
    adaptive::{
        Class,
        data::{Example, export_example},
    },
    now,
    quality::reservations::Reserved,
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};

pub(crate) async fn reservations(tx: &deadpool_postgres::Transaction<'_>) -> Result<Reserved> {
    let rows=tx.query("SELECT DISTINCT m.scan->>'fingerprint',m.scan->>'campaign_simhash' FROM noisefence.messages m JOIN noisefence.quality_protected_messages p ON p.message_id=m.id WHERE m.created>=$1 LIMIT 5001", &[&(now()-30*86400)]).await.map_err(database_error)?;
    Reserved::from_pairs(rows.iter().map(|r| (r.get(0), r.get(1))).collect())
}
impl Central {
    pub async fn adaptive_labels(&self, user: &str, id: &str) -> Result<Value> {
        let db = self
            .interactive
            .get()
            .await
            .context("Central annotations capacity unavailable")?;
        let rows=db.query("SELECT DISTINCT lower(split_part(d.destination,'@',2)),l.class FROM noisefence.deliveries d JOIN noisefence.messages m ON m.id=d.message_id JOIN noisefence.console_access a ON a.delivery_id=d.id JOIN noisefence.users u ON u.username=a.username LEFT JOIN noisefence.adaptive_labels l ON l.username=a.username AND l.message_id=m.id AND l.domain=lower(split_part(d.destination,'@',2)) WHERE m.id=$1 AND a.username=$2 AND m.created>=$3 AND NOT m.is_dsn AND NOT u.disabled ORDER BY 1", &[&id,&user,&(now()-30*86400)]).await.map_err(database_error)?;
        ensure!(!rows.is_empty(), "Message not found");
        Ok(
            json!({"domains":rows.iter().map(|r|json!({"domain":r.get::<_,String>(0),"class":r.get::<_,Option<String>>(1)})).collect::<Vec<_>>(),"observation_only":true}),
        )
    }
    pub async fn adaptive_label(
        &self,
        user: &str,
        id: &str,
        domain: &str,
        class: Option<Class>,
    ) -> Result<()> {
        ensure!(
            crate::config::valid_domain(domain) && domain == domain.to_ascii_lowercase(),
            "Invalid adaptive domain"
        );
        let mut db = self
            .interactive
            .get()
            .await
            .context("Central annotations capacity unavailable")?;
        let tx = db.transaction().await.map_err(database_error)?;
        management_lock(&tx).await?;
        ensure!(tx.query_opt("SELECT username FROM noisefence.users WHERE username=$1 AND NOT disabled FOR SHARE", &[&user]).await.map_err(database_error)?.is_some(),"Message not found");
        ensure!(tx.query_opt("SELECT m.id FROM noisefence.messages m WHERE m.id=$1 AND m.created>=$3 AND NOT m.is_dsn AND EXISTS(SELECT 1 FROM noisefence.deliveries d JOIN noisefence.console_access a ON a.delivery_id=d.id WHERE d.message_id=m.id AND a.username=$2 AND lower(split_part(d.destination,'@',2))=$4) FOR SHARE", &[&id,&user,&(now()-30*86400),&domain]).await.map_err(database_error)?.is_some(),"Message not found");
        if let Some(class) = class {
            let spam = matches!(class, Class::Spam | Class::Phishing | Class::Scam);
            let category = if spam {
                "spam"
            } else if class == Class::Publicity {
                "publicity"
            } else {
                "legitimate"
            };
            tx.execute("INSERT INTO noisefence.feedback(username,message_id,spam,category,created) VALUES($1,$2,$3,$4,$5) ON CONFLICT(username,message_id) DO UPDATE SET spam=excluded.spam,category=excluded.category,created=excluded.created", &[&user,&id,&spam,&category,&now()]).await.map_err(database_error)?;
            tx.execute("INSERT INTO noisefence.adaptive_labels(username,message_id,domain,class,created) VALUES($1,$2,$3,$4,$5) ON CONFLICT(username,message_id,domain) DO UPDATE SET class=excluded.class,created=excluded.created", &[&user,&id,&domain,&class.as_str(),&now()]).await.map_err(database_error)?;
        } else {
            tx.execute("DELETE FROM noisefence.adaptive_labels WHERE username=$1 AND message_id=$2 AND domain=$3", &[&user,&id,&domain]).await.map_err(database_error)?;
        }
        tx.execute("INSERT INTO noisefence.audit(created,username,action,object_id) VALUES($1,$2,'adaptive_label',$3)", &[&now(),&user,&id]).await.map_err(database_error)?;
        tx.commit().await.map_err(database_error)?;
        Ok(())
    }
    pub async fn adaptive_export(&self, user: &str, scope: &str) -> Result<(Vec<Example>, usize)> {
        ensure!(
            crate::config::valid_domain(scope) && scope == scope.to_ascii_lowercase(),
            "Invalid export domain"
        );
        let mut db = self
            .interactive
            .get()
            .await
            .context("Central annotations capacity unavailable")?;
        let tx = db
            .build_transaction()
            .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
            .start()
            .await
            .map_err(database_error)?;
        ensure!(tx.query_opt("SELECT username FROM noisefence.users WHERE username=$1 AND admin AND NOT disabled FOR SHARE", &[&user]).await.map_err(database_error)?.is_some(),"Adaptive export requires an enabled administrator");
        let protected = reservations(&tx).await?;
        let query=tx.prepare("SELECT m.id,m.created,m.scan,MIN(l.class),MAX(l.class),MAX(l.created) FROM noisefence.messages m JOIN noisefence.adaptive_labels l ON l.message_id=m.id JOIN noisefence.training_feedback tf ON tf.message_id=l.message_id AND tf.username=l.username JOIN noisefence.users u ON u.username=l.username WHERE m.created>=$1 AND m.created<$2 AND NOT m.is_dsn AND l.created>=$1 AND l.created<$2 AND l.domain=$3 AND NOT u.disabled AND EXISTS(SELECT 1 FROM noisefence.deliveries d JOIN noisefence.console_access a ON a.delivery_id=d.id WHERE d.message_id=m.id AND a.username=l.username AND lower(split_part(d.destination,'@',2))=$3) AND EXISTS(SELECT 1 FROM noisefence.deliveries d JOIN noisefence.console_access a ON a.delivery_id=d.id WHERE d.message_id=m.id AND a.username=$4 AND lower(split_part(d.destination,'@',2))=$3) AND NOT EXISTS(SELECT 1 FROM noisefence.deliveries d WHERE d.message_id=m.id AND lower(split_part(d.destination,'@',2))!=$3) GROUP BY m.id ORDER BY m.created,m.id LIMIT 5001").await.map_err(database_error)?;
        let portal = tx
            .bind(&query, &[&(now() - 30 * 86400), &now(), &scope, &user])
            .await
            .map_err(database_error)?;
        let mut out = Vec::new();
        let mut excluded = 0;
        let mut visited = 0;
        let mut bytes = 0;
        loop {
            let rows = tx.query_portal(&portal, 8).await.map_err(database_error)?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                visited += 1;
                ensure!(visited <= 5000, "Adaptive export exceeds 5000 rows");
                let min: String = row.get(3);
                let max: String = row.get(4);
                if min != max {
                    excluded += 1;
                    continue;
                }
                let scan = serde_json::from_value(row.get(2))?;
                match export_example(
                    &protected,
                    scope,
                    &row.get::<_, String>(0),
                    row.get(1),
                    row.get(5),
                    &min,
                    scan,
                )? {
                    Some(example) => {
                        let size = serde_json::to_vec(&example)?.len() + 1;
                        bytes += size;
                        ensure!(
                            size <= 128 * 1024 && bytes <= 128 * 1024 * 1024,
                            "Adaptive dataset size limit"
                        );
                        out.push(example);
                    }
                    None => excluded += 1,
                }
            }
        }
        Ok((out, excluded))
    }
}
