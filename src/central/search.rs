//! PostgreSQL history queries with recipient authorization before every match.
use super::{Central, database_error};
use anyhow::Result;
use tokio_postgres::types::ToSql;

struct Parameters(Vec<Box<dyn ToSql + Sync + Send>>);
impl Parameters {
    fn bind<T: ToSql + Sync + Send + 'static>(&mut self, value: T) -> String {
        self.0.push(Box::new(value));
        format!("${}", self.0.len())
    }
    fn values(&self) -> Vec<&(dyn ToSql + Sync)> {
        self.0
            .iter()
            .map(|v| v.as_ref() as &(dyn ToSql + Sync))
            .collect()
    }
}
const DOMAIN: &str = "($2='' OR lower(split_part(d.address,'@',2))=lower($2) OR lower(split_part(d.destination,'@',2))=lower($2))";
fn scope() -> String {
    format!("d.message_id=m.id AND g.username=$1 AND {DOMAIN}")
}
fn text_query(parameters: &mut Parameters, term: &crate::search::Term) -> String {
    let value = parameters.bind(term.literal.clone());
    if term.prefix() {
        // Only the output of PostgreSQL's literal phrase parser reaches tsquery
        // syntax. Operators entered by a user remain ordinary search text.
        format!(
            "CASE WHEN numnode(phraseto_tsquery('noisefence.search',{value}))=0 THEN ''::tsquery ELSE (phraseto_tsquery('noisefence.search',{value})::text||':*')::tsquery END"
        )
    } else {
        format!("phraseto_tsquery('noisefence.search',{value})")
    }
}

impl Central {
    pub async fn search_messages(
        &self,
        username: &str,
        options: &crate::search::Search,
        local_node: &str,
    ) -> Result<crate::search::Page> {
        let terms = options.validate()?;
        let mut p = Parameters(Vec::new());
        p.bind(username.to_owned());
        p.bind(options.domain.clone());
        p.bind(crate::now() - 30 * 86400);
        let mut predicates = vec![format!(
            "(m.created>=$3 OR m.raw_present) AND EXISTS(SELECT 1 FROM noisefence.deliveries d JOIN noisefence.console_access g ON g.delivery_id=d.id WHERE {})",
            scope()
        )];
        if !options.node.is_empty() {
            let node = p.bind(if options.node == "local" {
                local_node.to_owned()
            } else {
                options.node.clone()
            });
            predicates.push(format!("v.node={node}"));
        }
        for term in &terms {
            let query = text_query(&mut p, term);
            let literal = p.bind(term.literal.clone());
            predicates.push(format!("(m.search_document @@ ({query}) OR strpos(lower(m.id),lower({literal}))>0 OR EXISTS(SELECT 1 FROM noisefence.deliveries d JOIN noisefence.console_access g ON g.delivery_id=d.id WHERE {} AND (strpos(lower(d.address),lower({literal}))>0 OR strpos(lower(d.destination),lower({literal}))>0)))",scope()));
        }
        for (column, text) in [
            ("subject_search", &options.subject),
            ("rule_search", &options.rule),
        ] {
            for term in crate::search::terms(text)? {
                let query = text_query(&mut p, &term);
                predicates.push(format!("m.{column} @@ ({query})"));
            }
        }
        for (column, text) in [("sender", &options.sender), ("id", &options.id)] {
            if !text.is_empty() {
                let v = p.bind(text.clone());
                predicates.push(format!("strpos(lower(m.{column}),lower({v}))>0"));
            }
        }
        if !options.recipient.is_empty() || !options.status.is_empty() {
            let r = p.bind(options.recipient.clone());
            let s = p.bind(options.status.clone());
            predicates.push(format!("EXISTS(SELECT 1 FROM noisefence.deliveries d JOIN noisefence.console_access g ON g.delivery_id=d.id WHERE {} AND ({r}='' OR strpos(lower(d.address),lower({r}))>0 OR strpos(lower(d.destination),lower({r}))>0) AND ({s}='' OR d.status={s}))",scope()));
        }
        for (op, value) in [(">=", options.after), ("<", options.before)] {
            if let Some(value) = value {
                let v = p.bind(value);
                predicates.push(format!("m.created{op}{v}"));
            }
        }
        for (op, value) in [(">=", options.min_score), ("<=", options.max_score)] {
            if let Some(value) = value {
                let v = p.bind(value);
                predicates.push(format!("m.score{op}{v}"));
            }
        }
        let mut filtered = predicates.clone();
        let filter:String=match options.filter.as_str() {
            "spam"=>"m.category='spam'".into(),
            "publicity"=>"m.category='publicity'".into(),
            "legitimate"=>"m.category IN ('legitimate','undetermined')".into(),
            "review"=>"m.scan->>'complete'='true' AND m.category='undetermined'".into(),
            "incomplete"=>"m.scan->>'complete'='false'".into(),
            "publicity_signal"=>"m.scan#>>'{mailing,status}'='complete' AND m.scan#>>'{mailing,verdict}' IN ('promotion','newsletter')".into(),
            "pending"|"quarantined"=>format!("EXISTS(SELECT 1 FROM noisefence.deliveries d JOIN noisefence.console_access g ON g.delivery_id=d.id WHERE {} AND {})",scope(),if options.filter=="pending" {"d.status IN ('pending','sending')"}else{"d.status='quarantined'"}),
            "rspamd_all"=>"jsonb_typeof(m.scan->'rspamd')='object'".into(),
            "rspamd_disagreement"=>"m.scan#>>'{rspamd,status}'='complete' AND m.scan#>>'{rspamd,comparison}'='disagreement'".into(),
            "rspamd_inconclusive"=>"m.scan#>>'{rspamd,status}'='complete' AND m.scan#>>'{rspamd,comparison}'='inconclusive'".into(),
            "rspamd_unavailable"=>"COALESCE(m.scan#>>'{rspamd,status}','not_attempted')!='complete'".into(),
            _=>"true".into(),
        };
        filtered.push(format!("({filter})"));
        let predicate = filtered.join(" AND ");
        let base = "FROM noisefence.messages m JOIN noisefence.message_versions v ON v.id=m.id";
        let mut db = self
            .interactive
            .get()
            .await
            .map_err(|_| anyhow::anyhow!("Central search capacity unavailable"))?;
        let tx = db
            .build_transaction()
            .read_only(true)
            .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
            .start()
            .await
            .map_err(database_error)?;
        let total: i64 = tx
            .query_one(
                &format!("SELECT count(*) {base} WHERE {predicate}"),
                &p.values(),
            )
            .await
            .map_err(database_error)?
            .get(0);
        let comparison = if options.filter.starts_with("rspamd_") {
            let r = tx
                .query_one(
                    &format!(
                        include_str!("rspamd-summary.sql"),
                        scope = predicates.join(" AND ")
                    ),
                    &p.values(),
                )
                .await
                .map_err(database_error)?;
            Some(crate::rspamd::Summary {
                total: r.get::<_, i64>(0) as u64,
                completed: r.get::<_, i64>(1) as u64,
                agreements: r.get::<_, i64>(2) as u64,
                disagreements: r.get::<_, i64>(3) as u64,
                inconclusive: r.get::<_, i64>(4) as u64,
                pending: r.get::<_, i64>(5) as u64,
                rows: r.get::<_, i64>(6) as u64,
            })
        } else {
            None
        };
        let offset = p.bind(i64::from(options.offset));
        let rows=tx.query(&format!("SELECT m.id,m.created,m.sender,m.scan,(SELECT f.spam FROM noisefence.feedback f WHERE f.message_id=m.id AND f.username=$1),(SELECT f.category FROM noisefence.feedback f WHERE f.message_id=m.id AND f.username=$1),v.node,m.updated_at {base} WHERE {predicate} ORDER BY m.created DESC,m.id DESC LIMIT 50 OFFSET {offset}"),&p.values()).await.map_err(database_error)?;
        let mut messages = Vec::new();
        for row in rows {
            let id: String = row.get(0);
            let recipients=tx.query(&format!("SELECT d.address,d.status,d.held_until,d.released_at,d.action,d.filtering,(SELECT c.id FROM noisefence.queue_commands c WHERE c.message_id=d.message_id AND c.recipient=d.address AND c.finished IS NULL AND c.expires>$4) FROM noisefence.deliveries d JOIN noisefence.console_access g ON g.delivery_id=d.id WHERE g.username=$1 AND {DOMAIN} AND d.message_id=$3 ORDER BY d.id"), &[&username,&options.domain,&id,&crate::now()]).await.map_err(database_error)?.iter().map(|r|crate::store::VisibleRecipient {address:r.get(0),status:r.get(1),held_until:r.get(2),released_at:r.get(3),action:r.get(4),filtering:r.get(5),pending_command:r.get(6)}).collect();
            let node: String = row.get(6);
            messages.push(
                crate::store::MailMetadata {
                    id,
                    created: row.get(1),
                    sender: row.get(2),
                    feedback: row.get(4),
                    feedback_category: row
                        .get::<_, Option<String>>(5)
                        .as_deref()
                        .map(crate::mailing::FeedbackCategory::parse)
                        .transpose()?,
                    recipients,
                    origin: (node != local_node)
                        .then(|| (node, row.get::<_, Option<i64>>(7).unwrap_or(0))),
                }
                .visible(serde_json::from_value(row.get(3))?),
            );
        }
        tx.commit().await.map_err(database_error)?;
        Ok(crate::search::Page {
            comparison,
            has_more: u64::from(options.offset) + (messages.len() as u64) < total as u64,
            messages,
            total: total as u64,
            offset: options.offset,
        })
    }
}
