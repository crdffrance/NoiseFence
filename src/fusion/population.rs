//! Predict every retained population row, without treating absent evidence as ham.
//! Offline only: a hypothetical candidate decision is not a delivery outcome.
use super::{Model, availability_profile, runtime::Decision, valid_hash};
use crate::{
    evidence::{Evidence, Source},
    population::{Report, SCHEMA},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, BufWriter, Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

pub const PREDICTIONS_SCHEMA: &str = "noisefence-population-predictions-1";
const MAX_LINE: u64 = 16 * 1024 * 1024;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Header {
    schema: String,
    since: i64,
    until: i64,
    captured_at: i64,
    scope: String,
    sampling: String,
    contains_bodies: bool,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Label {
    status: LabelStatus,
    unwanted: Option<bool>,
    labelled_at: Option<i64>,
    authorized_votes: usize,
    ignored_votes: usize,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum LabelStatus {
    Unlabelled,
    Invalid,
    Consensus,
    Conflicting,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum EvidenceStatus {
    Missing,
    NonSmtp,
    Invalid,
    Smtp,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Row {
    id: String,
    observed_at: i64,
    raw_sha256: Option<String>,
    fingerprint: Option<String>,
    simhash: Option<String>,
    complete: bool,
    features_complete: Option<bool>,
    decision: Option<Decision>,
    tagged: bool,
    label: Label,
    evidence_status: EvidenceStatus,
    evidence: Option<Evidence>,
}
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Record {
    Header(Header),
    Row(Box<Row>),
    Footer { schema: String, report: Report },
}
#[derive(Default, Debug, Serialize)]
pub struct PredictionReport {
    pub rows: usize,
    pub assessed: usize,
    pub unassessable: usize,
    pub artifact_mismatch: usize,
    pub ineligible_to_tag: usize,
    pub unsupported_profiles: usize,
    pub would_tag: usize,
}
struct Partial(PathBuf);
impl Drop for Partial {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
fn write(writer: &mut impl Write, value: impl Serialize) -> Result<()> {
    serde_json::to_writer(&mut *writer, &value)?;
    writer.write_all(b"\n")?;
    Ok(())
}
fn validate(row: &Row, header: &Header, count: &mut Report) -> Result<()> {
    ensure!(
        valid_hash(&row.id) && row.observed_at >= header.since && row.observed_at < header.until,
        "invalid population identity or timestamp"
    );
    ensure!(
        [&row.raw_sha256, &row.fingerprint]
            .into_iter()
            .all(|v| v.as_deref().is_none_or(valid_hash))
            && row.simhash.as_ref().is_none_or(|v| v.len() == 16
                && v.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))),
        "invalid population fingerprint"
    );
    count.exported += 1;
    count.incomplete += usize::from(!row.complete);
    count.missing_raw_hash += usize::from(row.raw_sha256.is_none());
    count.missing_campaign += usize::from(row.fingerprint.is_none() || row.simhash.is_none());
    count.ignored_feedback = count
        .ignored_feedback
        .checked_add(row.label.ignored_votes)
        .context("feedback count overflow")?;
    let label = &row.label;
    ensure!(
        label
            .labelled_at
            .is_none_or(|t| t >= row.observed_at && t <= header.captured_at),
        "invalid feedback time"
    );
    match label.status {
        LabelStatus::Consensus => {
            ensure!(
                label.unwanted.is_some()
                    && label.authorized_votes > 0
                    && label.labelled_at.is_some(),
                "invalid consensus"
            );
            count.labelled += 1;
        }
        LabelStatus::Unlabelled => {
            ensure!(
                label.unwanted.is_none()
                    && label.authorized_votes == 0
                    && label.labelled_at.is_none(),
                "invalid unlabelled row"
            );
            count.unlabelled += 1;
        }
        LabelStatus::Conflicting | LabelStatus::Invalid => {
            ensure!(
                label.unwanted.is_none()
                    && label.authorized_votes > 0
                    && label.labelled_at.is_some(),
                "invalid unresolved label"
            );
            if matches!(label.status, LabelStatus::Conflicting) {
                ensure!(
                    label.authorized_votes >= 2,
                    "conflict requires multiple votes"
                );
                count.conflicting_labels += 1;
            } else {
                count.invalid_labels += 1;
            }
        }
    }
    match (&row.evidence_status, &row.evidence) {
        (EvidenceStatus::Missing, None) => count.missing_evidence += 1,
        (EvidenceStatus::NonSmtp, None) => count.non_smtp_evidence += 1,
        (EvidenceStatus::Invalid, None) => count.invalid_evidence += 1,
        (EvidenceStatus::Smtp, Some(e)) => {
            ensure!(
                e.source == Source::SmtpSession,
                "population evidence is not SMTP"
            );
            super::features(e)?;
            count.smtp_evidence += 1;
        }
        _ => anyhow::bail!("inconsistent population evidence status"),
    }
    Ok(())
}

/// Includes every row, including unknown truth and evidence. The model hash is
/// bound to the exact parsed bytes; the footer binds all input bytes (not a path).
pub fn predict(input: &Path, model_path: &Path, output: &Path) -> Result<PredictionReport> {
    let (model, model_sha256) = Model::load_bound(model_path)?;
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let partial = Partial(parent.join(format!(
        ".population-predict-{}.partial",
        uuid::Uuid::new_v4()
    )));
    let mut writer = BufWriter::new(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&partial.0)?,
    );
    let mut reader = BufReader::new(File::open(input)?);
    let mut digest = Sha256::new();
    let (mut header, mut footer) = (None, None);
    let mut counts = Report::default();
    let mut report = PredictionReport::default();
    let mut ids = HashSet::new();
    let mut total = 0u64;
    loop {
        let mut line = Vec::new();
        let n = (&mut reader)
            .take(MAX_LINE + 1)
            .read_until(b'\n', &mut line)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        ensure!(
            n as u64 <= MAX_LINE && total <= 512 * 1024 * 1024,
            "population exceeds size limit"
        );
        ensure!(footer.is_none(), "data after population footer");
        digest.update(&line);
        // Typed decoding rejects duplicate keys, unknown fields, and nonfinite numbers.
        match serde_json::from_slice::<Record>(&line).context("invalid population record")? {
            Record::Header(h) => {
                ensure!(
                    header.is_none()
                        && h.schema == SCHEMA
                        && h.scope == "retained_accepted_messages"
                        && h.sampling == "unreviewed"
                        && !h.contains_bodies
                        && h.since > 0
                        && h.since < h.until
                        && h.captured_at > 0
                        && h.until <= h.captured_at.saturating_add(1)
                        && h.since >= h.captured_at.saturating_sub(30 * 86400),
                    "invalid population header"
                );
                write(
                    &mut writer,
                    serde_json::json!({"type":"header","schema":PREDICTIONS_SCHEMA,
                    "source":h,"protocol_sha256":super::protocol_sha256(),"model_sha256":model_sha256,
                    "manifest_sha256":model.manifest_sha256,"hypothetical":true,"production_eligible":false}),
                )?;
                header = Some(h);
            }
            Record::Row(row) => {
                ensure!(report.rows < 50_000, "population exceeds row limit");
                validate(
                    &row,
                    header.as_ref().context("population row before header")?,
                    &mut counts,
                )?;
                ensure!(ids.insert(row.id.clone()), "duplicate population identity");
                report.rows += 1;
                let (status, prediction) = match &row.evidence {
                    None => ("missing_or_invalid_evidence", None),
                    Some(e) if !e.artifacts.equivalent(&model.artifacts) => {
                        report.artifact_mismatch += 1;
                        ("artifact_mismatch", None)
                    }
                    Some(e) => {
                        // Use original detector completeness, not a previous fusion
                        // candidate's stored decision/completeness or old threshold.
                        let p = model.predict(e)?;
                        report.ineligible_to_tag += usize::from(!p.tag_eligible);
                        report.unsupported_profiles += usize::from(!p.profile_supported);
                        report.would_tag += usize::from(p.would_tag);
                        ("assessed", Some(p))
                    }
                };
                report.assessed += usize::from(prediction.is_some());
                report.unassessable += usize::from(prediction.is_none());
                write(
                    &mut writer,
                    serde_json::json!({"type":"row","id":row.id,"observed_at":row.observed_at,
                    "raw_sha256":row.raw_sha256,"fingerprint":row.fingerprint,"simhash":row.simhash,
                    "complete":row.complete,"features_complete":row.features_complete,"decision":row.decision,
                    "tagged":row.tagged,"label":row.label,"evidence_status":row.evidence_status,
                    "availability_profile":row.evidence.as_ref().map(availability_profile),
                    "assessment":status,"prediction":prediction}),
                )?;
            }
            Record::Footer {
                schema,
                report: source,
            } => {
                ensure!(
                    header.is_some()
                        && schema == SCHEMA
                        && source.considered <= 50_000
                        && source.considered.checked_sub(source.automatic_dsn)
                            == Some(counts.exported)
                        && source.invalid_scan <= counts.incomplete
                        && source.invalid_scan <= counts.missing_evidence
                        && source.invalid_scan <= counts.missing_raw_hash
                        && source.invalid_scan <= counts.missing_campaign,
                    "invalid population footer"
                );
                // v1 excludes DSN rows and does not expose invalid_scan per row.
                // These two counts can only be bounded, not independently reconstructed.
                counts.considered = source.considered;
                counts.automatic_dsn = source.automatic_dsn;
                counts.invalid_scan = source.invalid_scan;
                ensure!(source == counts, "population footer coverage mismatch");
                footer = Some(source);
            }
        }
    }
    let source = footer.context("truncated population: missing footer")?;
    write(
        &mut writer,
        serde_json::json!({"type":"footer","schema":PREDICTIONS_SCHEMA,
        "population_sha256":format!("{:x}",digest.finalize()),"source_counts":source,"counts":report}),
    )?;
    writer.flush()?;
    writer.get_ref().sync_all()?;
    fs::hard_link(&partial.0, output)?;
    fs::remove_file(&partial.0)?;
    File::open(parent)?.sync_all()?;
    Ok(report)
}
