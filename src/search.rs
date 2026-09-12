//! Local search over retained metadata. Recipient matches always use live grants.
use anyhow::{Result, ensure};
use rusqlite::{Connection, types::Value};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Search {
    pub q: String,
    pub filter: String,
    pub offset: u32,
    pub domain: String,
    pub sender: String,
    pub recipient: String,
    pub subject: String,
    pub rule: String,
    pub id: String,
    pub status: String,
    pub after: Option<i64>,
    pub before: Option<i64>,
    pub min_score: Option<f64>,
    pub max_score: Option<f64>,
}
impl Default for Search {
    fn default() -> Self {
        Self {
            q: String::new(),
            filter: "all".into(),
            offset: 0,
            domain: String::new(),
            sender: String::new(),
            recipient: String::new(),
            subject: String::new(),
            rule: String::new(),
            id: String::new(),
            status: String::new(),
            after: None,
            before: None,
            min_score: None,
            max_score: None,
        }
    }
}
#[derive(Serialize)]
pub struct Page {
    pub messages: Vec<crate::store::VisibleMail>,
    pub total: u64,
    pub offset: u32,
    pub has_more: bool,
}
pub struct Term {
    literal: String,
    fts: String,
}

// Quote every term: user text can never introduce FTS operators or column names.
fn terms(text: &str) -> Result<Vec<Term>> {
    ensure!(
        text.len() <= 600 && !text.chars().any(char::is_control),
        "Recherche limitée à 600 octets, sans caractères de contrôle."
    );
    let mut chars = text.chars().peekable();
    let mut result = Vec::new();
    while let Some(c) = chars.next() {
        if c.is_whitespace() {
            continue;
        }
        let quoted = c == '"';
        let mut value = if quoted { String::new() } else { c.to_string() };
        let mut closed = !quoted;
        while let Some(&c) = chars.peek() {
            if quoted && c == '"' {
                chars.next();
                closed = true;
                break;
            }
            if !quoted && c.is_whitespace() {
                break;
            }
            ensure!(
                quoted || c != '"',
                "Séparez les expressions entre guillemets par un espace."
            );
            value.push(c);
            chars.next();
        }
        ensure!(closed, "Fermez les guillemets de la recherche.");
        ensure!(
            chars.peek().is_none_or(|c| c.is_whitespace()),
            "Séparez les expressions par un espace."
        );
        ensure!(
            value.chars().any(char::is_alphanumeric),
            "Chaque terme doit contenir une lettre ou un chiffre."
        );
        ensure!(
            value.len() <= 200 && result.len() < 12,
            "Utilisez au maximum 12 termes de 200 octets."
        );
        let fts = format!(
            "\"{}\"{}",
            value.replace('"', "\"\""),
            if quoted { "" } else { "*" }
        );
        result.push(Term {
            literal: value,
            fts,
        });
    }
    Ok(result)
}
impl Search {
    pub fn validate(&self) -> Result<Vec<Term>> {
        ensure!(self.offset <= 10_000_000, "Page hors limites.");
        ensure!(
            self.domain.is_empty() || crate::config::valid_domain(&self.domain),
            "Domaine invalide."
        );
        ensure!(
            [
                "all",
                "spam",
                "publicity",
                "publicity_signal",
                "review",
                "incomplete",
                "pending",
                "quarantined",
                "legitimate"
            ]
            .contains(&self.filter.as_str()),
            "Classement invalide."
        );
        ensure!(
            [
                "",
                "pending",
                "sending",
                "delivered",
                "failed",
                "notified",
                "quarantined",
                "discarded"
            ]
            .contains(&self.status.as_str()),
            "État de livraison invalide."
        );
        for value in [
            &self.sender,
            &self.recipient,
            &self.subject,
            &self.rule,
            &self.id,
        ] {
            ensure!(
                value.len() <= 256 && !value.chars().any(char::is_control),
                "Un critère dépasse 256 octets ou contient un caractère de contrôle."
            );
        }
        for score in [self.min_score, self.max_score].into_iter().flatten() {
            ensure!(
                score.is_finite() && (0.0..=100.0).contains(&score),
                "Le score doit être compris entre 0 et 100."
            );
        }
        ensure!(
            !matches!((self.min_score,self.max_score),(Some(a),Some(b)) if a>b),
            "Le score minimum dépasse le maximum."
        );
        ensure!(
            [self.after, self.before]
                .into_iter()
                .flatten()
                .all(|v| (0..=253402300799).contains(&v)),
            "Date hors limites."
        );
        ensure!(
            !matches!((self.after,self.before),(Some(a),Some(b)) if a>=b),
            "La date de début doit précéder la fin."
        );
        terms(&self.subject)?;
        terms(&self.rule)?;
        terms(&self.q)
    }
    pub(crate) fn predicate(&self, terms: &[Term], values: &mut Vec<Value>) -> String {
        fn bind(values: &mut Vec<Value>, value: impl Into<Value>) -> String {
            values.push(value.into());
            format!("?{}", values.len())
        }
        let mut predicates = vec!["1".to_owned()];
        let scope = "d.message_id=m.id AND g.username=?1 AND (?6='' OR lower(substr(d.address,-length(?6)-1))='@'||lower(?6) OR lower(substr(d.destination,-length(?6)-1))='@'||lower(?6))";
        for term in terms {
            let fts = bind(values, term.fts.clone());
            let literal = bind(values, term.literal.clone());
            predicates.push(format!("(m.rowid IN (SELECT rowid FROM message_search WHERE message_search MATCH {fts}) OR instr(lower(m.id),lower({literal}))>0 OR EXISTS(SELECT 1 FROM deliveries d JOIN console_access g ON g.delivery_id=d.id WHERE {scope} AND (instr(lower(d.address),lower({literal}))>0 OR instr(lower(d.destination),lower({literal}))>0)))"));
        }
        for (column, text) in [("subject", &self.subject), ("rules", &self.rule)] {
            if !text.trim().is_empty() {
                // Validation has already bounded and parsed these expressions.
                let query = terms_for_column(column, text);
                let p = bind(values, query);
                predicates.push(format!(
                    "m.rowid IN (SELECT rowid FROM message_search WHERE message_search MATCH {p})"
                ));
            }
        }
        for (column, text) in [("m.sender", &self.sender), ("m.id", &self.id)] {
            if !text.is_empty() {
                let p = bind(values, text.clone());
                predicates.push(format!("instr(lower({column}),lower({p}))>0"));
            }
        }
        if !self.recipient.is_empty() || !self.status.is_empty() {
            let r = bind(values, self.recipient.clone());
            let s = bind(values, self.status.clone());
            predicates.push(format!("EXISTS(SELECT 1 FROM deliveries d JOIN console_access g ON g.delivery_id=d.id WHERE {scope} AND ({r}='' OR instr(lower(d.address),lower({r}))>0 OR instr(lower(d.destination),lower({r}))>0) AND ({s}='' OR d.status={s}))"));
        }
        for (column, op, value) in [
            ("m.created", ">=", self.after.map(Value::from)),
            ("m.created", "<", self.before.map(Value::from)),
            (SCORE, ">=", self.min_score.map(Value::from)),
            (SCORE, "<=", self.max_score.map(Value::from)),
        ] {
            if let Some(value) = value {
                let p = bind(values, value);
                predicates.push(format!("{column}{op}{p}"));
            }
        }
        predicates.join(" AND ")
    }
}
fn terms_for_column(column: &str, text: &str) -> String {
    let expressions = terms(text)
        .expect("validated search")
        .into_iter()
        .map(|t| t.fts)
        .collect::<Vec<_>>()
        .join(" AND ");
    format!("{column} : ({expressions})")
}
// Same numeric value as the console, including partial scores; a missing score
// does not become zero, and an antivirus verdict is not a probability.
const SCORE: &str = "(CASE WHEN COALESCE(json_extract(m.scan,'$.decision.source'),'legacy')!='antivirus' AND json_type(m.scan,'$.decision.score') IN ('real','integer') AND json_extract(m.scan,'$.decision.score') BETWEEN 0 AND 100 THEN json_extract(m.scan,'$.decision.score') WHEN json_type(m.scan,'$.score') IN ('real','integer') AND json_extract(m.scan,'$.score') BETWEEN 0 AND 100 THEN json_extract(m.scan,'$.score') END)";

pub(crate) fn migrate(db: &Connection) -> Result<()> {
    let exists: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='message_search')",
        [],
        |r| r.get(0),
    )?;
    if !exists {
        db.execute_batch(include_str!("search-schema.sql"))?;
    }
    Ok(())
}
