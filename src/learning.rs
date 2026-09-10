//! Private, versioned human feedback export. Never reads message bodies.
use crate::{engine::SemanticStatus, features, message, store::Store};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{BufWriter, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

pub const ENCODER_ID: &str = "intfloat/multilingual-e5-small";
pub const ENCODER_REVISION: &str = "614241f622f53c4eeff9890bdc4f31cfecc418b3";
pub const DIMENSION: usize = 384;
pub const MAX_TOKENS: usize = 256;

/// Persist the embedding protocol, not just its mutable model-hub name.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SemanticProtocol {
    pub encoder: String,
    pub revision: String,
    pub dimensions: usize,
    pub max_tokens: usize,
    pub text_schema: u32,
    pub prefix: String,
    pub pooling: String,
}
impl SemanticProtocol {
    pub fn pinned() -> Self {
        Self {
            encoder: ENCODER_ID.into(),
            revision: ENCODER_REVISION.into(),
            dimensions: DIMENSION,
            max_tokens: MAX_TOKENS,
            text_schema: features::VERSION,
            prefix: "query: ".into(),
            pooling: "attention-mask mean then L2".into(),
        }
    }
}

#[derive(Serialize)]
pub struct SemanticExample {
    pub protocol: SemanticProtocol,
    pub features: Vec<f32>,
}
#[derive(Serialize)]
pub struct LearningExample {
    pub schema: &'static str,
    pub source: &'static str,
    pub id: String,
    pub observed_at: i64,
    pub labelled_at: i64,
    pub feature_version: u32,
    pub spam: bool,
    /// Explicit subtype only. Historical non-spam votes do not imply non-publicity.
    pub category: Option<crate::mailing::FeedbackCategory>,
    pub fingerprint: String,
    pub simhash: String,
    pub features: Vec<(usize, f64)>,
    pub semantic: Option<SemanticExample>,
    /// Additive to learning-1; old content trainers ignore this field. Fusion
    /// consumers must require a supported schema and an observed SMTP session.
    pub evidence: Option<crate::evidence::Evidence>,
    pub protection: Option<crate::protection::Report>,
    pub heuristics: Option<crate::heuristics::Report>,
    pub content_inspection: Option<crate::content_inspection::Report>,
    pub research_execution: Option<crate::research_engines::Execution>,
    pub mailing: Option<crate::mailing::Report>,
}
#[derive(Default, Debug, Serialize)]
pub struct ExportReport {
    pub considered: usize,
    pub exported: usize,
    pub conflicting: usize,
    pub incomplete: usize,
    pub unsupported_features: usize,
    pub missing_campaign: usize,
    pub missing_semantic_protocol: usize,
    pub semantic_exported: usize,
    pub exported_with_incomplete_checks: usize,
    pub evidence_exported: usize,
    pub missing_evidence: usize,
    pub non_smtp_evidence: usize,
    pub conflicting_categories: usize,
}

fn hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
// Only this uniquely created partial file is removed, including on DB/IO errors.
struct Partial(PathBuf);
impl Drop for Partial {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

pub async fn export(store: &Store, output: &Path, require_semantic: bool) -> Result<ExportReport> {
    let output = output.to_owned();
    store
        .run(move |db| {
            let parent = output
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            let temporary = parent.join(format!(".learning-{}.partial", uuid::Uuid::new_v4()));
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)?;
            let partial = Partial(temporary);
            let mut writer = BufWriter::new(file);
            let mut report = ExportReport::default();
            // A single SQLite read transaction gives a coherent label snapshot in WAL.
            // Re-check current grants; expired metadata and automatic DSNs are excluded.
            let tx = db.transaction()?;
            {
                let mut query = tx.prepare(
                    "SELECT m.id,m.created,m.scan,MIN(f.spam),MAX(f.spam),MAX(f.created),MIN(c.category),MAX(c.category),COUNT(c.category),COUNT(*)
                FROM messages m JOIN feedback f ON f.message_id=m.id
                JOIN users u ON u.username=f.username AND u.disabled=0
                LEFT JOIN feedback_categories c ON c.message_id=f.message_id AND c.username=f.username
                WHERE m.is_dsn=0 AND m.created>=?1 AND EXISTS (
                    SELECT 1 FROM deliveries d JOIN console_access g ON g.delivery_id=d.id
                    WHERE d.message_id=m.id AND g.username=f.username)
                GROUP BY m.id ORDER BY m.id",
                )?;
                let mut rows = query.query([crate::now() - 30 * 86400])?;
                while let Some(row) = rows.next()? {
                    report.considered += 1;
                    let min: i64 = row.get(3)?;
                    let max: i64 = row.get(4)?;
                    ensure!(
                        (0..=1).contains(&min) && (0..=1).contains(&max),
                        "invalid human label"
                    );
                    if min != max {
                        report.conflicting += 1;
                        continue;
                    }
                    let first: Option<String> = row.get(6)?;
                    let last: Option<String> = row.get(7)?;
                    let explicit: i64 = row.get(8)?;
                    let votes: i64 = row.get(9)?;
                    let category = if min == 1 {
                        Some(crate::mailing::FeedbackCategory::Spam)
                    } else if first != last {
                        report.conflicting_categories += 1;
                        None
                    } else if explicit == votes {
                        first.as_deref().map(crate::mailing::FeedbackCategory::parse).transpose()?
                    } else { None };
                    let scan: crate::engine::Scan =
                        serde_json::from_str(&row.get::<_, String>(2)?)?;
                    // External availability must not select the local training data.
                    // Old incomplete rows remain excluded: their extraction state is unknown.
                    if !scan.features_complete.unwrap_or(scan.complete) || scan.features.is_empty()
                    {
                        report.incomplete += 1;
                        continue;
                    }
                    if scan.feature_version != features::VERSION {
                        report.unsupported_features += 1;
                        continue;
                    }
                    let Some(simhash) = scan.campaign_simhash else {
                        report.missing_campaign += 1;
                        continue;
                    };
                    ensure!(
                        hex(&scan.fingerprint, 64) && hex(&simhash, 16),
                        "invalid campaign fingerprint"
                    );
                    let mut indices = HashSet::new();
                    ensure!(
                        scan.features.len() <= features::DIMENSION
                            && scan.features.iter().all(|(i, x)| *i < features::DIMENSION
                                && x.is_finite()
                                && *x > 0.0
                                && *x <= 1.0
                                && indices.insert(*i)),
                        "invalid lexical learning vector"
                    );
                    ensure!(
                        (scan.features.iter().map(|(_, x)| x * x).sum::<f64>() - 1.0).abs() < 0.001,
                        "lexical learning vector is not normalized"
                    );
                    let semantic = if scan.semantic.status == SemanticStatus::Complete
                        && scan.semantic.protocol.as_ref() == Some(&SemanticProtocol::pinned())
                        && scan.semantic.encoder == ENCODER_ID
                    {
                        let vector = scan.semantic.features;
                        ensure!(
                            vector.len() == DIMENSION
                                && vector.iter().all(|x| x.is_finite() && x.abs() <= 1.0)
                                && (vector.iter().map(|x| f64::from(*x).powi(2)).sum::<f64>()
                                    - 1.0)
                                    .abs()
                                    < 0.001,
                            "invalid semantic learning vector"
                        );
                        report.semantic_exported += 1;
                        Some(SemanticExample {
                            protocol: SemanticProtocol::pinned(),
                            features: vector,
                        })
                    } else {
                        if require_semantic {
                            report.missing_semantic_protocol += 1;
                            continue;
                        }
                        None
                    };
                    let id: String = row.get(0)?;
                    let evidence = match scan.evidence {
                        Some(evidence)
                            if evidence.source == crate::evidence::Source::SmtpSession =>
                        {
                            evidence.validate()?;
                            report.evidence_exported += 1;
                            Some(evidence)
                        }
                        Some(_) => {
                            report.non_smtp_evidence += 1;
                            None
                        }
                        None => {
                            report.missing_evidence += 1;
                            None
                        }
                    };
                    let example = LearningExample {
                        schema: "noisefence-learning-1",
                        source: "local_human_feedback",
                        id: message::digest(id.as_bytes()),
                        observed_at: row.get(1)?,
                        labelled_at: row.get(5)?,
                        feature_version: scan.feature_version,
                        spam: min == 1,
                        category,
                        fingerprint: scan.fingerprint,
                        simhash,
                        features: scan.features,
                        semantic,
                        evidence,
                        protection: scan.protection,
                        heuristics: scan.heuristics,
                        content_inspection: scan.content_inspection,
                        research_execution: scan.research_execution,
                        mailing: scan.mailing,
                    };
                    serde_json::to_writer(&mut writer, &example)?;
                    writer.write_all(b"\n")?;
                    report.exported += 1;
                    report.exported_with_incomplete_checks += usize::from(!scan.complete);
                }
            }
            tx.commit()?;
            writer.flush()?;
            writer.get_ref().sync_all()?;
            fs::rename(&partial.0, &output)?;
            File::open(parent)?.sync_all()?;
            Ok(report)
        })
        .await
}
