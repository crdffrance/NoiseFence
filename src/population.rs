//! A complete retained population snapshot, including unusable/unlabelled rows.
//! Administrator CLI only; no bodies, recipients or content vectors are read out.
use crate::{engine::Scan, evidence::Source, fusion, message, store::Store};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{BufWriter, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

pub const SCHEMA: &str = "noisefence-population-1";
const MAX_ROWS: usize = 50_000;
const MAX_BYTES: usize = 512 * 1024 * 1024;

#[derive(Default, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub considered: usize,
    pub automatic_dsn: usize,
    pub exported: usize,
    pub labelled: usize,
    pub unlabelled: usize,
    pub conflicting_labels: usize,
    pub invalid_labels: usize,
    pub ignored_feedback: usize,
    pub incomplete: usize,
    pub invalid_scan: usize,
    pub missing_raw_hash: usize,
    pub missing_campaign: usize,
    pub missing_evidence: usize,
    pub non_smtp_evidence: usize,
    pub invalid_evidence: usize,
    pub smtp_evidence: usize,
}

struct Partial(PathBuf);
impl Drop for Partial {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn line(writer: &mut impl Write, value: &impl Serialize, bytes: &mut usize) -> Result<()> {
    let encoded = serde_json::to_vec(value)?;
    *bytes += encoded.len() + 1;
    ensure!(
        encoded.len() <= 16 * 1024 * 1024 && *bytes <= MAX_BYTES,
        "population export too large; use a shorter interval"
    );
    writer.write_all(&encoded)?;
    writer.write_all(b"\n")?;
    Ok(())
}

/// since is inclusive, until exclusive. The scope is retained accepted mail,
/// not SMTP refusals nor metadata already removed under the retention policy.
pub async fn export(store: &Store, output: &Path, since: i64, until: i64) -> Result<Report> {
    let captured_at = crate::now();
    ensure!(
        since > 0 && since < until && since >= captured_at - 30 * 86400 && until <= captured_at + 1,
        "population interval must be within the last 30 days"
    );
    if let Some(central) = store.management() {
        return central
            .population_export(output, since, until, captured_at)
            .await;
    }
    let output = output.to_owned();
    store.run(move |db| {
        let mut writer=Writer::new(&output,since,until,captured_at)?;
        let mut report=Report::default();
        let tx=db.transaction()?;
        {
            // Revalidate every vote against the current account and grants in
            // the same SQLite snapshot. Never multiply rows by Bcc recipients.
            let mut query = tx.prepare("WITH votes AS (
                SELECT f.message_id,f.spam,f.created,
                  u.disabled=0 AND EXISTS(SELECT 1 FROM deliveries d JOIN console_access g ON g.delivery_id=d.id
                    WHERE d.message_id=f.message_id AND g.username=f.username) AS allowed
                FROM feedback f JOIN users u ON u.username=f.username
            ) SELECT m.id,m.created,m.scan,m.is_dsn,
                COUNT(v.message_id),COUNT(CASE WHEN v.allowed THEN 1 END),
                MIN(CASE WHEN v.allowed THEN v.spam END),MAX(CASE WHEN v.allowed THEN v.spam END),
                MAX(CASE WHEN v.allowed THEN v.created END)
              FROM messages m LEFT JOIN votes v ON v.message_id=m.id
              WHERE m.created>=?1 AND m.created<?2 GROUP BY m.id ORDER BY m.created,m.id")?;
            let mut rows = query.query(rusqlite::params![since, until])?;
            while let Some(row) = rows.next()? {
                let input=Row{id:row.get(0)?,created:row.get(1)?,scan:row.get(2)?,is_dsn:row.get(3)?,total_votes:row.get(4)?,votes:row.get(5)?,min:row.get(6)?,max:row.get(7)?,labelled_at:row.get(8)?};
                if let Some(value)=project(input,&mut report)? {writer.row(&value)?;}

            }
        }
        tx.commit()?;
        writer.finish(&report)?;
        Ok(report)
    }).await
}

pub(crate) struct Row {
    pub id: String,
    pub created: i64,
    pub scan: String,
    pub is_dsn: bool,
    pub total_votes: usize,
    pub votes: usize,
    pub min: Option<i64>,
    pub max: Option<i64>,
    pub labelled_at: Option<i64>,
}
pub(crate) fn project(row: Row, report: &mut Report) -> Result<Option<serde_json::Value>> {
    report.considered += 1;
    ensure!(
        report.considered <= MAX_ROWS,
        "population exceeds 50000 rows; use a shorter interval"
    );
    if row.is_dsn {
        report.automatic_dsn += 1;
        return Ok(None);
    }
    report.exported += 1;
    let votes: usize = row.votes;
    let ignored = row.total_votes - votes;
    report.ignored_feedback += ignored;
    let min: Option<i64> = row.min;
    let max: Option<i64> = row.max;
    let (label_status, unwanted) = match (min, max) {
        (None, None) => {
            report.unlabelled += 1;
            ("unlabelled", None)
        }
        (Some(a), Some(b)) if !(0..=1).contains(&a) || !(0..=1).contains(&b) => {
            report.invalid_labels += 1;
            ("invalid", None)
        }
        (Some(a), Some(b)) if a == b => {
            report.labelled += 1;
            ("consensus", Some(a == 1))
        }
        _ => {
            report.conflicting_labels += 1;
            ("conflicting", None)
        }
    };
    let stored: String = row.scan;
    let scan = (stored.len() <= 16 * 1024 * 1024)
        .then(|| serde_json::from_str::<Scan>(&stored).ok())
        .flatten();
    if scan.is_none() {
        report.invalid_scan += 1;
    }
    let raw_sha256 = scan
        .as_ref()
        .and_then(|s| s.raw_sha256.as_deref())
        .filter(|s| fusion::valid_hash(s));
    let fingerprint = scan
        .as_ref()
        .map(|s| s.fingerprint.as_str())
        .filter(|s| fusion::valid_hash(s));
    let simhash = scan
        .as_ref()
        .and_then(|s| s.campaign_simhash.as_deref())
        .filter(|s| {
            s.len() == 16
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        });
    if raw_sha256.is_none() {
        report.missing_raw_hash += 1;
    }
    if fingerprint.is_none() || simhash.is_none() {
        report.missing_campaign += 1;
    }
    let complete = scan.as_ref().is_some_and(|s| s.complete);
    if !complete {
        report.incomplete += 1;
    }
    let (evidence_status, evidence) = match scan.as_ref().and_then(|s| s.evidence.as_ref()) {
        None => {
            report.missing_evidence += 1;
            ("missing", None)
        }
        Some(e) if e.source != Source::SmtpSession => {
            report.non_smtp_evidence += 1;
            ("non_smtp", None)
        }
        Some(e) if fusion::features(e).is_err() => {
            report.invalid_evidence += 1;
            ("invalid", None)
        }
        Some(e) => {
            report.smtp_evidence += 1;
            ("smtp", Some(e))
        }
    };
    Ok(Some(
        serde_json::json!({"type":"row","id":message::digest(row.id.as_bytes()),
                    "observed_at":row.created,"raw_sha256":raw_sha256,"fingerprint":fingerprint,"simhash":simhash,
                    "complete":complete,"features_complete":scan.as_ref().and_then(|s| s.features_complete),
                    "decision":scan.as_ref().and_then(|s| s.decision.as_ref()),
                    "tagged":scan.as_ref().is_some_and(|s| s.tagged),
                    "label":{"status":label_status,"unwanted":unwanted,"labelled_at":row.labelled_at,
                        "authorized_votes":votes,"ignored_votes":ignored},
                    "evidence_status":evidence_status,"evidence":evidence}),
    ))
}
pub(crate) struct Writer {
    output: PathBuf,
    parent: PathBuf,
    partial: Partial,
    writer: BufWriter<File>,
    bytes: usize,
}
impl Writer {
    pub(crate) fn new(output: &Path, since: i64, until: i64, captured_at: i64) -> Result<Self> {
        let parent = output
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."))
            .to_owned();
        let temporary = parent.join(format!(".population-{}.partial", uuid::Uuid::new_v4()));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        let mut result = Self {
            output: output.to_owned(),
            parent,
            partial: Partial(temporary),
            writer: BufWriter::new(file),
            bytes: 0,
        };
        result.row(&serde_json::json!({"type":"header","schema":SCHEMA,"since":since,"until":until,"captured_at":captured_at,"scope":"retained_accepted_messages","sampling":"unreviewed","contains_bodies":false}))?;
        Ok(result)
    }
    pub(crate) fn row(&mut self, value: &serde_json::Value) -> Result<()> {
        line(&mut self.writer, value, &mut self.bytes)
    }
    pub(crate) fn finish(mut self, report: &Report) -> Result<()> {
        self.row(&serde_json::json!({"type":"footer","schema":SCHEMA,"report":report}))?;
        self.writer.flush()?;
        self.writer.get_ref().sync_all()?;
        fs::hard_link(&self.partial.0, &self.output)?;
        fs::remove_file(&self.partial.0)?;
        File::open(&self.parent)?.sync_all()?;
        Ok(())
    }
}
