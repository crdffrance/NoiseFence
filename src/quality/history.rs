//! Time-limited sender memory, based only on earlier authorized human labels.
use crate::{
    engine::Scan,
    evidence::{AuthResult, Source, State},
};
use rusqlite::{Connection, OpenFlags, params};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path, time::Duration};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Report {
    pub status: String,
    /// Private join key: authenticated From address AND recipient-domain scope.
    pub key: Option<String>,
    pub legitimate_campaigns: usize,
    pub unwanted_campaigns: usize,
    pub observed_days: usize,
    pub conflict: bool,
    pub established: bool,
    #[serde(default)]
    pub behavior: Option<super::behavior::Report>,
}
impl Default for Report {
    fn default() -> Self {
        Self {
            status: "not_run".into(),
            key: None,
            legitimate_campaigns: 0,
            unwanted_campaigns: 0,
            observed_days: 0,
            conflict: false,
            established: false,
            behavior: None,
        }
    }
}
pub async fn inspect(root: &Path, raw: &[u8], scan: &Scan, scopes: &[String]) -> Report {
    inspect_with_context(root, raw, scan, scopes, &[], &Default::default()).await
}
pub async fn inspect_with_context(
    root: &Path,
    raw: &[u8],
    scan: &Scan,
    scopes: &[String],
    recipients: &[crate::config::Recipient],
    targets: &crate::protection::Targets,
) -> Report {
    let mut report = Report::default();
    let Some(e) = &scan.evidence else {
        return report;
    };
    if raw.len() > 2 * 1024 * 1024
        || scopes.len() != 1
        || e.source != Source::SmtpSession
        || e.authentication.dmarc_state != State::Complete
        || e.authentication.dmarc_dkim != Some(AuthResult::Pass)
    {
        return report;
    }
    let Some(mail) = mail_parser::MessageParser::default().parse(raw) else {
        return report;
    };
    if mail.header_values(mail_parser::HeaderName::From).count() != 1 {
        return report;
    }
    let Some(from) = mail
        .from()
        .filter(|a| a.iter().count() == 1)
        .and_then(|a| a.first())
        .and_then(|a| a.address())
    else {
        return report;
    };
    if from.len() > 320 || from.chars().any(char::is_control) {
        return report;
    }
    let Some((local, domain)) = from.rsplit_once('@') else {
        return report;
    };
    let Ok(domain) = idna::domain_to_ascii_strict(domain) else {
        return report;
    };
    // Preserve the local-part's case; no invented equivalence between mailboxes.
    let key = crate::message::digest(
        format!(
            "sender-history-1\0{}\0{local}@{}",
            scopes[0].to_ascii_lowercase(),
            domain.to_ascii_lowercase()
        )
        .as_bytes(),
    );
    report.key = Some(key.clone());
    let behavior = super::behavior::capture(&key, scan, recipients, targets);
    report.behavior = Some(behavior.clone());
    let path = root.join("state.sqlite3");
    let (send, receive) = tokio::sync::oneshot::channel();
    let task = tokio::task::spawn_blocking(move || -> anyhow::Result<Report> {
        let db = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        db.busy_timeout(Duration::from_millis(50))?;
        if send.send(db.get_interrupt_handle()).is_err() {
            anyhow::bail!("cancelled sender memory");
        }
        let now = crate::now();
        let mut query=db.prepare("SELECT json_extract(m.scan,'$.fingerprint'),m.created,MIN(f.spam),MAX(f.spam), json_extract(m.scan,'$.sender_history.behavior.sample')
          FROM messages m JOIN (SELECT username,message_id,spam,created FROM feedback UNION ALL SELECT username,message_id,CASE risk WHEN 'spam' THEN 1 ELSE 0 END,created FROM quality_labels WHERE risk IN ('spam','legitimate')) f ON f.message_id=m.id JOIN users u ON u.username=f.username
          WHERE m.created>=?1 AND m.created<?2 AND m.is_dsn=0 AND f.created<?2 AND u.admin=1 AND u.disabled=0
          AND (CASE WHEN json_valid(m.scan) THEN json_extract(m.scan,'$.sender_history.key') END)=?3
          AND EXISTS(SELECT 1 FROM deliveries d JOIN console_access g ON g.delivery_id=d.id WHERE d.message_id=m.id AND g.username=f.username)
          GROUP BY m.id ORDER BY m.created DESC LIMIT 2001")?;
        let mut result = Report {
            status: "complete".into(),
            key: Some(key.clone()),
            behavior: Some(behavior),
            ..Default::default()
        };
        let rows = query.query_map(params![now - 30 * 86400, now, key], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, bool>(2)?,
                r.get::<_, bool>(3)?,
                r.get::<_, Option<String>>(4)?,
            ))
        })?;
        let mut campaigns: BTreeMap<String, (bool, bool)> = BTreeMap::new();
        let mut behavior_history = super::behavior::History::default();
        let mut days = std::collections::BTreeSet::new();
        for (index, row) in rows.enumerate() {
            if index == 2000 {
                result.status = "limited".into();
                return Ok(result);
            }
            let (fingerprint, created, min, max, sample) = row?;
            if fingerprint.len() != 64 {
                continue;
            }
            behavior_history.add(fingerprint.clone(), created, !min, max, sample);
            let entry = campaigns.entry(fingerprint).or_default();
            entry.0 |= !min;
            entry.1 |= max;
            days.insert(created / 86400);
        }
        behavior_history.finish(result.behavior.as_mut().unwrap());
        result.observed_days = days.len();
        for (legit, spam) in campaigns.values() {
            result.conflict |= *legit && *spam;
            if *legit && !spam {
                result.legitimate_campaigns += 1;
            }
            if *spam && !legit {
                result.unwanted_campaigns += 1;
            }
        }
        result.established = result.legitimate_campaigns >= 5
            && result.observed_days >= 3
            && result.unwanted_campaigns == 0
            && !result.conflict;
        Ok(result)
    });
    struct Interrupt(Option<rusqlite::InterruptHandle>);
    impl Drop for Interrupt {
        fn drop(&mut self) {
            if let Some(h) = &self.0 {
                h.interrupt();
            }
        }
    }
    let work = async {
        let _interrupt = Interrupt(receive.await.ok());
        tokio::time::timeout(Duration::from_millis(150), task).await
    };
    match tokio::time::timeout(Duration::from_millis(200), work).await {
        Ok(Ok(Ok(Ok(result)))) => result,
        _ => {
            report.status = "unavailable".into();
            if let Some(b) = &mut report.behavior {
                b.status = "unavailable".into();
            }
            report
        }
    }
}
