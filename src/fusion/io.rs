//! Offline, bounded conversion of trusted learning exports. No bodies or DNS.
use super::Model;
use crate::evidence::{Artifacts, Evidence, Source};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, BufWriter, Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

// Deliberate allow-list: only typed Evidence feeds the selected native protocol.
// Sibling content vectors, free-form reports and text never enter these features.
#[derive(Deserialize)]
struct Input {
    schema: String,
    source: String,
    id: String,
    observed_at: i64,
    labelled_at: i64,
    feature_version: u32,
    spam: bool,
    fingerprint: String,
    simhash: String,
    evidence: Option<Evidence>,
}
#[derive(Default, Serialize, Debug)]
pub struct Report {
    pub considered: usize,
    pub exported: usize,
    pub missing_evidence: usize,
    pub non_smtp_evidence: usize,
    pub ineligible_to_tag: usize,
}
struct Partial(PathBuf);
impl Drop for Partial {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
fn json_line(writer: &mut impl Write, value: impl Serialize) -> Result<()> {
    serde_json::to_writer(&mut *writer, &value)?;
    writer.write_all(b"\n")?;
    Ok(())
}

/// A successful export has one header and one footer. Mixed detector cohorts or
/// invalid observations abort atomically; omitted old/diagnostic rows are counted.
/// Predictions use the same original evidence as training, not a Python encoder.
pub fn convert(input: &Path, output: &Path, model: Option<&Model>) -> Result<Report> {
    convert_version(
        input,
        output,
        model,
        model.map(Model::feature_version).transpose()?.unwrap_or(1),
    )
}
pub fn convert_version(
    input: &Path,
    output: &Path,
    model: Option<&Model>,
    version: u8,
) -> Result<Report> {
    let protocol_hash = super::protocol_hash_for(version)?;
    if let Some(model) = model {
        model.validate()?;
        ensure!(
            model.feature_version()? == version,
            "prediction feature version differs from model"
        );
    }
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let temporary = Partial(parent.join(format!(".fusion-{}.partial", uuid::Uuid::new_v4())));
    let mut writer = BufWriter::new(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary.0)?,
    );
    let mut reader = BufReader::new(File::open(input)?);
    let mut report = Report::default();
    let mut total = 0;
    let mut ids = HashSet::new();
    let mut artifacts: Option<Artifacts> = None;
    let mut local_binding: Option<super::local::Binding> = None;
    loop {
        let mut line = Vec::new();
        let count = (&mut reader)
            .take(16 * 1024 * 1024 + 1)
            .read_until(b'\n', &mut line)?;
        if count == 0 {
            break;
        }
        total += count;
        ensure!(
            count <= 16 * 1024 * 1024 && total <= 512 * 1024 * 1024 && report.considered < 50_000,
            "fusion input exceeds size limit"
        );
        report.considered += 1;
        let row: Input = serde_json::from_slice(&line)
            .with_context(|| format!("invalid learning row {}", report.considered))?;
        ensure!(
            row.schema == "noisefence-learning-1"
                && row.source == "local_human_feedback"
                && row.feature_version == crate::features::VERSION
                && super::valid_hash(&row.id)
                && super::valid_hash(&row.fingerprint)
                && row.simhash.len() == 16
                && row
                    .simhash
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                && row.observed_at > 0
                && row.labelled_at >= row.observed_at,
            "invalid learning provenance at row {}",
            report.considered
        );
        ensure!(ids.insert(row.id.clone()), "duplicate learning identity");
        let Some(evidence) = row.evidence else {
            report.missing_evidence += 1;
            continue;
        };
        if evidence.source != Source::SmtpSession {
            report.non_smtp_evidence += 1;
            continue;
        }
        if version == 2 && evidence.local.is_none() {
            report.missing_evidence += 1;
            continue;
        }
        let vector = super::features_for(&evidence, version)
            .with_context(|| format!("invalid observations at row {}", report.considered))?;
        if let Some(artifacts) = &artifacts {
            ensure!(
                artifacts == &evidence.artifacts,
                "mixed detector cohorts: export one artifact cohort at a time"
            );
            if version == 2 {
                ensure!(
                    local_binding.as_ref() == evidence.local.as_ref().map(|l| &l.binding),
                    "mixed local detector cohorts"
                );
            }
        } else {
            artifacts = Some(evidence.artifacts.clone());
            let mut header = serde_json::json!({
                "type":"header", "schema": if model.is_some() {"noisefence-fusion-predictions-1"} else {"noisefence-fusion-vectors-1"},
                "protocol_sha256":protocol_hash, "artifacts":artifacts
            });
            if version == 2 {
                local_binding = evidence.local.as_ref().map(|l| l.binding.clone());
                header["local_binding"] = serde_json::to_value(&local_binding)?;
            }
            json_line(&mut writer, header)?;
        }
        if !super::eligible_for(&evidence, version) {
            report.ineligible_to_tag += 1;
        }
        let mut output = serde_json::json!({"type":"row", "id":row.id,
            "fingerprint":row.fingerprint,"simhash":row.simhash,"observed_at":row.observed_at,
            "labelled_at":row.labelled_at,"source":row.source,"spam":row.spam,
            "availability_profile":super::profile_for(&evidence, version)?,"tag_eligible":super::eligible_for(&evidence, version),
            "legacy_score":evidence.legacy_score});
        if let Some(model) = model {
            output["prediction"] = serde_json::to_value(model.predict(&evidence)?)?;
        } else {
            output["values"] = serde_json::to_value(vector)?;
        }
        json_line(&mut writer, output)?;
        report.exported += 1;
    }
    ensure!(
        report.exported > 0,
        "no trusted SMTP observations available: {report:?}"
    );
    json_line(
        &mut writer,
        serde_json::json!({"type":"footer","counts":report}),
    )?;
    writer.flush()?;
    writer.get_ref().sync_all()?;
    // Atomic create without replacing an existing dataset, including a symlink.
    fs::hard_link(&temporary.0, output)?;
    File::open(parent)?.sync_all()?;
    Ok(report)
}
