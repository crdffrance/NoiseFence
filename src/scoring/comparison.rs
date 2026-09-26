//! Offline counterfactual accounting over frozen inputs, never an accuracy test.
//! This module cannot load configuration, contact providers or alter receipts.
use super::{Report, combine_policy};
use crate::{
    engine::{Scan, SemanticResult, SemanticStatus, Signal},
    evidence::{self, Evidence, Source, State},
    llm::LlmResult,
    smtp_policy::PolicyResult,
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, BufWriter, Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

pub const INPUT_SCHEMA: &str = "noisefence-score-comparison-input-1";
const MAX_LINE: usize = 2 * 1024 * 1024;
const MAX_BYTES: usize = 512 * 1024 * 1024;
const MAX_ROWS: usize = 50_000;

// Select only consumed inputs. In particular historical score, labels, sender,
// subject, Rspamd and recipient decisions cannot become scoring features.
#[derive(Deserialize)]
struct Input {
    schema: String,
    id: String,
    scan: Frozen,
}
#[derive(Deserialize)]
struct Frozen {
    feature_version: Option<u32>,
    score: Option<f64>,
    evidence: Option<Evidence>,
    reasons: Option<Vec<Reason>>,
    semantic: Option<Semantic>,
    llm: Option<LlmResult>,
    smtp_policy: Option<PolicyResult>,
    message_context: Option<Context>,
}
#[derive(Deserialize)]
struct Reason {
    id: String,
    weight: f64,
}
#[derive(Deserialize)]
struct Semantic {
    status: SemanticStatus,
    contribution: Option<f64>,
}
#[derive(Deserialize)]
struct Context {
    encrypted: bool,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Skip {
    MissingEvidence,
    UnsupportedEvidence,
    NonSmtpEvidence,
    MissingInputs,
    UnknownLexicalInput,
    ContradictoryOpaqueInput,
}
#[derive(Default, Debug, Serialize)]
pub struct Counts {
    pub considered: usize,
    pub compared: usize,
    pub skipped: BTreeMap<Skip, usize>,
    pub invalid_combinations: usize,
    pub partial_lexical: usize,
    pub changed_rule_totals: usize,
    pub threshold_comparable: usize,
    pub unknown_score_precision: usize,
    pub crossed_up: usize,
    pub crossed_down: usize,
}
#[derive(Default, Debug, Serialize)]
pub struct Summary {
    pub counts: Counts,
    pub cohorts: BTreeMap<String, Counts>,
    pub input_sha256: String,
}

#[derive(Serialize)]
struct Compared {
    // This number is a receipt value, not the baseline of the counterfactual.
    historical_score: Option<f64>,
    feature_version: Option<u32>,
    partial_lexical: bool,
    reference: Report,
    candidate: Report,
    reference_reaches_threshold: Option<bool>,
    candidate_reaches_threshold: Option<bool>,
}

fn project(frozen: Frozen, threshold: f64) -> std::result::Result<Compared, Skip> {
    let evidence = frozen.evidence.ok_or(Skip::MissingEvidence)?;
    if evidence.schema != evidence::SCHEMA {
        return Err(Skip::UnsupportedEvidence);
    }
    if evidence.source != Source::SmtpSession {
        return Err(Skip::NonSmtpEvidence);
    }
    let context = frozen.message_context.ok_or(Skip::MissingInputs)?;
    let lexical = if context.encrypted {
        if evidence.lexical_logit.is_some()
            || !matches!(evidence.lexical_state, State::Limited | State::Disabled)
        {
            return Err(Skip::ContradictoryOpaqueInput);
        }
        None
    } else if matches!(evidence.lexical_state, State::Complete | State::Limited) {
        Some(
            evidence
                .lexical_logit
                .filter(|v| v.is_finite())
                .ok_or(Skip::UnknownLexicalInput)?,
        )
    } else if evidence.lexical_state == State::Disabled
        && evidence.lexical_logit.is_none()
        && evidence.artifacts.lexical_model_sha256.is_none()
    {
        None
    } else {
        return Err(Skip::UnknownLexicalInput);
    };
    let partial_lexical = lexical.is_some() && evidence.lexical_state == State::Limited;
    let semantic = frozen.semantic.ok_or(Skip::MissingInputs)?;
    let scan = Scan {
        // Unknown original precision is not guessed from a model name. The
        // logit remains comparable, but both score outputs are removed below.
        feature_version: frozen.feature_version.unwrap_or(crate::features::VERSION),
        reasons: frozen
            .reasons
            .ok_or(Skip::MissingInputs)?
            .into_iter()
            .map(|r| Signal {
                id: r.id,
                weight: r.weight,
                detail: String::new(),
            })
            .collect(),
        semantic: SemanticResult {
            status: semantic.status,
            contribution: semantic.contribution,
            ..Default::default()
        },
        llm: frozen.llm.ok_or(Skip::MissingInputs)?,
        smtp_policy: frozen.smtp_policy.ok_or(Skip::MissingInputs)?,
        evidence: Some(evidence),
        ..Default::default()
    };
    let mut reference = combine_policy(&scan, lexical, context.encrypted, false);
    let mut candidate = super::combine(&scan, lexical, context.encrypted);
    // Only schema 3's precision is supported by this experiment. In particular,
    // do not turn a missing/future schema into a rounded legacy score.
    if frozen.feature_version != Some(crate::features::VERSION) {
        reference.score = None;
        candidate.score = None;
    }
    Ok(Compared {
        historical_score: frozen
            .score
            .filter(|v| v.is_finite() && (0.0..=100.).contains(v)),
        feature_version: frozen.feature_version,
        partial_lexical,
        reference_reaches_threshold: reference.score.map(|v| v >= threshold),
        candidate_reaches_threshold: candidate.score.map(|v| v >= threshold),
        reference,
        candidate,
    })
}

impl Counts {
    fn observe(&mut self, result: &std::result::Result<Compared, Skip>) {
        self.considered += 1;
        let row = match result {
            Ok(row) => row,
            Err(reason) => {
                *self.skipped.entry(*reason).or_default() += 1;
                return;
            }
        };
        self.compared += 1;
        self.partial_lexical += usize::from(row.partial_lexical);
        if row.reference.total_logit.is_none() || row.candidate.total_logit.is_none() {
            self.invalid_combinations += 1;
        }
        if let (Some(a), Some(b)) = (row.reference.rules_total, row.candidate.rules_total) {
            self.changed_rule_totals += usize::from(a != b);
        }
        if row.feature_version != Some(crate::features::VERSION) {
            self.unknown_score_precision += 1;
        }
        if let (Some(a), Some(b)) = (
            row.reference_reaches_threshold,
            row.candidate_reaches_threshold,
        ) {
            self.threshold_comparable += 1;
            self.crossed_up += usize::from(!a && b);
            self.crossed_down += usize::from(a && !b);
        }
    }
}

struct Partial(PathBuf);
impl Drop for Partial {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
fn line(writer: &mut impl Write, value: impl Serialize) -> Result<()> {
    serde_json::to_writer(&mut *writer, &value)?;
    writer.write_all(b"\n")?;
    Ok(())
}
fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// A controlled v1/v2 aggregation comparison using identical current adapters.
/// The reference is NOT the engine/model/prompt that produced historical_score.
/// Hashed cohorts stay separate; no label or accuracy is inferred from scores.
pub fn compare(input: &Path, output: &Path, threshold: f64) -> Result<Summary> {
    ensure!(
        threshold.is_finite() && (0.0..=100.).contains(&threshold),
        "invalid comparison threshold"
    );
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let temporary = Partial(parent.join(format!(
        ".score-comparison-{}.partial",
        uuid::Uuid::new_v4()
    )));
    let mut writer = BufWriter::new(
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary.0)?,
    );
    line(
        &mut writer,
        serde_json::json!({
            "type":"header", "schema":"noisefence-score-comparison-1",
            "application":env!("CARGO_PKG_VERSION"),
            "detector_build_sha256":crate::compatibility::DETECTOR_BUILD_SHA256,
            "threshold":threshold, "reference":super::LEGACY_VERSION, "candidate":super::VERSION,
            "scope":"aggregation_only_current_adapters", "accuracy_evaluation":false,
            "historical_decisions_replayed":false
        }),
    )?;
    let mut reader = BufReader::new(File::open(input)?);
    let mut summary = Summary::default();
    let mut ids = HashSet::new();
    let mut hash = Sha256::new();
    let mut total = 0;
    loop {
        let mut bytes = Vec::new();
        let size = (&mut reader)
            .take((MAX_LINE + 1) as u64)
            .read_until(b'\n', &mut bytes)?;
        if size == 0 {
            break;
        }
        total += size;
        ensure!(
            size <= MAX_LINE && total <= MAX_BYTES && summary.counts.considered < MAX_ROWS,
            "score comparison input exceeds size limit"
        );
        // Error strings intentionally omit serde's potentially private values.
        let row: Input = serde_json::from_slice(&bytes).map_err(|_| {
            anyhow::anyhow!("invalid comparison row {}", summary.counts.considered + 1)
        })?;
        ensure!(
            row.schema == INPUT_SCHEMA && valid_hash(&row.id) && ids.insert(row.id.clone()),
            "invalid or duplicate comparison identity"
        );
        ensure!(
            row.scan.reasons.as_ref().is_none_or(|r| r.len() <= 2048),
            "too many comparison rules"
        );
        hash.update(&bytes);
        let cohort = row
            .scan
            .evidence
            .as_ref()
            .map(|e| serde_json::to_vec(&e.artifacts))
            .transpose()?
            .map(|b| crate::message::digest(&b))
            .unwrap_or_else(|| "missing_evidence".into());
        let result = project(row.scan, threshold);
        summary.counts.observe(&result);
        summary
            .cohorts
            .entry(cohort.clone())
            .or_default()
            .observe(&result);
        match result {
            Ok(comparison) => line(
                &mut writer,
                serde_json::json!({"type":"comparison","id":row.id,"cohort":cohort,"result":comparison}),
            )?,
            Err(reason) => line(
                &mut writer,
                serde_json::json!({"type":"skipped","id":row.id,"cohort":cohort,"reason":reason}),
            )?,
        }
    }
    ensure!(summary.counts.considered > 0, "empty comparison input");
    summary.input_sha256 = hex::encode(hash.finalize());
    line(
        &mut writer,
        serde_json::json!({"type":"footer","summary":summary}),
    )?;
    writer.flush()?;
    writer.get_ref().sync_all()?;
    fs::hard_link(&temporary.0, output)?;
    File::open(parent)?.sync_all()?;
    Ok(summary)
}
