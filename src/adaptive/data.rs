//! Tenant-scoped human truth, private exports and current authorization checks.
use super::{Class, SCHEMA, WIDTH};
use crate::{native_filter::input::Features, now, store::Store};
use anyhow::{Result, ensure};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    path::Path,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Example {
    pub schema: String,
    pub scope: String,
    pub id: String,
    pub observed_at: i64,
    pub labelled_at: i64,
    pub class: Class,
    pub protocol_sha256: String,
    pub features: Features,
    pub vector: Vec<f64>,
}
impl Example {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == SCHEMA
                && crate::config::valid_domain(&self.scope)
                && self.scope == self.scope.to_ascii_lowercase()
                && super::hash(&self.id)
                && super::hash(&self.protocol_sha256)
                && self.observed_at > 0
                && self.labelled_at >= self.observed_at
                && self.labelled_at <= now()
                && super::valid_vector(&self.vector),
            "invalid adaptive learning example"
        );
        self.features.validate()
    }
}
pub(crate) fn private_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    Ok(options.open(path)?)
}
pub(crate) fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut f = private_file(path)?;
    serde_json::to_writer_pretty(&mut f, value)?;
    f.sync_all()?;
    Ok(())
}
pub fn read(path: &Path) -> Result<(Vec<Example>, String)> {
    let mut reader = BufReader::new(File::open(path)?);
    let mut rows = Vec::new();
    let mut total = Vec::new();
    loop {
        let mut line = Vec::new();
        let size = reader
            .by_ref()
            .take(128 * 1024 + 1)
            .read_until(b'\n', &mut line)?;
        if size == 0 {
            break;
        }
        ensure!(
            size <= 128 * 1024 && total.len() + size <= 128 * 1024 * 1024 && rows.len() < 5000,
            "adaptive dataset size limit"
        );
        let row: Example = serde_json::from_slice(&line)?;
        row.validate()?;
        rows.push(row);
        total.extend(line);
    }
    ensure!(!rows.is_empty(), "empty adaptive dataset");
    Ok((rows, crate::message::digest(&total)))
}

pub async fn labels(store: &Store, user: String, id: String) -> Result<Value> {
    store.read(move |db| {
        let mut q = db.prepare("SELECT DISTINCT lower(substr(d.destination,instr(d.destination,'@')+1)),l.class
          FROM deliveries d JOIN messages m ON m.id=d.message_id JOIN console_access a ON a.delivery_id=d.id
          JOIN users u ON u.username=a.username
          LEFT JOIN adaptive_labels l ON l.username=a.username AND l.message_id=m.id AND l.domain=lower(substr(d.destination,instr(d.destination,'@')+1))
          WHERE m.id=?1 AND a.username=?2 AND m.created>=?3 AND m.is_dsn=0 AND u.disabled=0 ORDER BY 1")?;
        let domains = q.query_map(params![id,user,now()-30*86400],|r| Ok(json!({"domain":r.get::<_,String>(0)?,"class":r.get::<_,Option<String>>(1)?})))?.collect::<rusqlite::Result<Vec<_>>>()?;
        ensure!(!domains.is_empty(), "message not found"); Ok(json!({"domains":domains,"observation_only":true}))
    }).await
}
pub async fn label(
    store: &Store,
    user: String,
    id: String,
    domain: String,
    class: Option<Class>,
) -> Result<()> {
    ensure!(
        crate::config::valid_domain(&domain) && domain == domain.to_ascii_lowercase(),
        "invalid adaptive domain"
    );
    store.run(move |db| {
        let tx = db.transaction()?;
        let allowed: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM deliveries d JOIN messages m ON m.id=d.message_id
          JOIN console_access a ON a.delivery_id=d.id JOIN users u ON u.username=a.username
          WHERE m.id=?1 AND a.username=?2 AND m.created>=?3 AND m.is_dsn=0 AND u.disabled=0
          AND lower(substr(d.destination,instr(d.destination,'@')+1))=?4)", params![id,user,now()-30*86400,domain], |r| r.get(0))?;
        ensure!(allowed,"message not found");
        if let Some(class) = class {
            let spam = matches!(class, Class::Spam | Class::Phishing | Class::Scam);
            // Updating ordinary feedback invalidates older detailed annotations.
            // Write this explicit refinement last, in the same transaction.
            tx.execute("INSERT INTO feedback(username,message_id,spam,created) VALUES(?1,?2,?3,?4)
              ON CONFLICT(username,message_id) DO UPDATE SET spam=excluded.spam,created=excluded.created",params![user,id,spam,now()])?;
            let category = if spam {"spam"} else if class == Class::Publicity {"publicity"} else {"legitimate"};
            tx.execute("INSERT INTO feedback_categories(username,message_id,category) VALUES(?1,?2,?3)
              ON CONFLICT(username,message_id) DO UPDATE SET category=excluded.category",params![user,id,category])?;
            tx.execute("INSERT INTO adaptive_labels(username,message_id,domain,class,created) VALUES(?1,?2,?3,?4,?5)
              ON CONFLICT(username,message_id,domain) DO UPDATE SET class=excluded.class,created=excluded.created",params![user,id,domain,class.as_str(),now()])?;
        } else {
            tx.execute("DELETE FROM adaptive_labels WHERE username=?1 AND message_id=?2 AND domain=?3",params![user,id,domain])?;
        }
        tx.execute("INSERT INTO audit(created,username,action,object_id) VALUES(?1,?2,'adaptive_label',?3)",params![now(),user,id])?;
        tx.commit()?; Ok(())
    }).await
}
pub async fn export(store: &Store, user: String, scope: String, output: &Path) -> Result<Value> {
    ensure!(
        crate::config::valid_domain(&scope) && scope == scope.to_ascii_lowercase(),
        "invalid export domain"
    );
    let (rows, excluded) = store.read(move |db| {
        let admin: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM users WHERE username=?1 AND admin=1 AND disabled=0)",[&user],|r| r.get(0))?;
        ensure!(admin,"adaptive export requires an enabled administrator");
        let mut q = db.prepare("SELECT m.id,m.created,m.scan,MIN(l.class),MAX(l.class),MAX(l.created)
          FROM messages m JOIN adaptive_labels l ON l.message_id=m.id JOIN users u ON u.username=l.username
          WHERE m.created>=?1 AND m.created<?2 AND m.is_dsn=0 AND l.created>=?1 AND l.created<?2 AND l.domain=?3 AND u.disabled=0
          AND EXISTS(SELECT 1 FROM deliveries d JOIN console_access a ON a.delivery_id=d.id WHERE d.message_id=m.id AND a.username=l.username AND lower(substr(d.destination,instr(d.destination,'@')+1))=?3)
          AND EXISTS(SELECT 1 FROM deliveries d JOIN console_access a ON a.delivery_id=d.id WHERE d.message_id=m.id AND a.username=?4 AND lower(substr(d.destination,instr(d.destination,'@')+1))=?3)
          AND NOT EXISTS(SELECT 1 FROM deliveries d WHERE d.message_id=m.id AND lower(substr(d.destination,instr(d.destination,'@')+1))!=?3)
          GROUP BY m.id ORDER BY m.created,m.id LIMIT 5001")?;
        let mut cursor = q.query(params![now()-30*86400,now(),scope,user])?;
        let mut rows = Vec::new(); let mut excluded = 0usize; let mut visited = 0usize;
        while let Some(row) = cursor.next()? {
            visited+=1; ensure!(visited<=5000,"adaptive export exceeds 5000 rows");
            let min: String=row.get(3)?; let max: String=row.get(4)?;
            if min != max { excluded+=1; continue; }
            let scan: crate::engine::Scan = serde_json::from_str(&row.get::<_,String>(2)?)?;
            let Some(native) = scan.native_filter else {excluded+=1;continue;};
            let (Some(features),Some(vector),Some(report)) = (native.features,native.adaptive_vector,native.report.adaptive) else {excluded+=1;continue;};
            if !scan.complete || native.report.status != crate::native_filter::Status::Complete || vector.len()!=WIDTH {excluded+=1;continue;}
            let class: Class = serde_json::from_value(json!(min))?;
            let row = Example { schema:SCHEMA.into(),scope:scope.clone(),id:crate::message::digest(row.get::<_,String>(0)?.as_bytes()),
                observed_at:row.get(1)?,labelled_at:row.get(5)?,class,protocol_sha256:report.protocol_sha256,features,vector };
            row.validate()?; rows.push(row);
        }
        Ok((rows,excluded))
    }).await?;
    let mut file = private_file(output)?;
    let mut classes = [0usize; 5];
    for row in &rows {
        classes[row.class.index()] += 1;
        serde_json::to_writer(&mut file, row)?;
        file.write_all(b"\n")?;
    }
    file.sync_all()?;
    Ok(
        json!({"exported":rows.len(),"excluded":excluded,"classes":classes,"contains_bodies":false,"observation_only":true}),
    )
}
