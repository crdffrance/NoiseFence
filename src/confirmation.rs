//! Optional abstention for the uncalibrated legacy score. No learned probabilities.
use crate::{
    antivirus::AntivirusStatus,
    engine::{Scan, Signal},
    evidence::{self, AuthResult, State},
    fusion::runtime::{DecisionSource, Outcome},
};

pub const VERSION: &str = "confirmation-3";
pub const REVIEW_REASON: &str = "confirmation_missing";

/// Additional observations, not statistically independent votes. Weak SMTP
/// anomalies, SPF alone, HTML, OCR and two views of the same content model do
/// not corroborate a high score. Provider failures never count as detections.
pub fn corroborated(scan: &Scan) -> bool {
    if scan.antivirus.status == AntivirusStatus::Malware {
        return true;
    }
    // The LLM already contributes to the content score. Its self-declared
    // confidence is not a second, independent confirmation of that score.
    let Some(e) = &scan.evidence else {
        return false;
    };
    // Transport observations require actual envelope context; imported headers
    // and local content-only scans cannot supply authentication or reputation.
    if e.source == evidence::Source::ContentOnly {
        return false;
    }
    let auth = &e.authentication;
    if auth.dmarc_state == State::Complete
        && auth.dmarc_spf == Some(AuthResult::Fail)
        && auth.dmarc_dkim == Some(AuthResult::Fail)
    {
        return true;
    }
    let ip = &e.reputation.ip;
    // PBL / policy listings (10, 11) are not evidence of malicious content.
    if ip.state == State::Complete && evidence::malicious_ip(&ip.codes) {
        return true;
    }
    e.reputation.domains.iter().any(|d| {
        d.result.state == State::Complete
            && evidence::dqs_codes(&d.result.codes, evidence::Dataset::Dbl).is_ok()
            && evidence::malicious_domain(&d.result.codes)
    })
}

/// Apply only to a fresh, complete legacy decision. A separately validated
/// fusion keeps its own policy. Abstention preserves the original score and
/// extraction status, so training does not mistake caution for a failed scan.
pub fn apply(scan: &mut Scan, enabled: bool) {
    let already_reviewed = scan.reasons.iter().any(|r| r.id == REVIEW_REASON);
    scan.reasons.retain(|r| r.id != REVIEW_REASON);
    if !enabled || !scan.complete || corroborated(scan) {
        return;
    }
    let Some(decision) = &mut scan.decision else {
        return;
    };
    if decision.source == DecisionSource::Legacy
        && (decision.outcome == Outcome::Unwanted
            || (decision.outcome == Outcome::Undetermined && already_reviewed))
    {
        decision.outcome = Outcome::Undetermined;
        scan.tagged = false;
        scan.pub_tagged = false;
        scan.reasons.push(Signal {
            id: REVIEW_REASON.into(),
            detail: "Score élevé sans confirmation suffisante : message à vérifier, transmis sans préfixe. Ce résultat ne prouve pas sa légitimité.".into(),
            weight: 0.0,
        });
    }
}

#[derive(Default, serde::Serialize)]
pub struct Counts {
    pub spam_detected: usize,
    pub spam_missed: usize,
    pub spam_to_review: usize,
    pub legitimate: usize,
    pub false_positives: usize,
    pub legitimate_to_review: usize,
}
impl Counts {
    pub(crate) fn add(&mut self, outcome: Outcome, spam: bool) {
        let count = match (outcome, spam) {
            (Outcome::Unwanted, true) => &mut self.spam_detected,
            (Outcome::Legitimate, true) => &mut self.spam_missed,
            (Outcome::Undetermined, true) => &mut self.spam_to_review,
            (Outcome::Unwanted, false) => &mut self.false_positives,
            (Outcome::Legitimate, false) => &mut self.legitimate,
            (Outcome::Undetermined, false) => &mut self.legitimate_to_review,
        };
        *count += 1;
    }
}

#[derive(Default, serde::Serialize)]
pub struct Audit {
    pub diagnostics: crate::detection_diagnostics::Audit,
    pub considered: usize,
    pub evaluated: usize,
    pub conflicting: usize,
    pub unsupported: usize,
    pub before: Counts,
    pub with_confirmation: Counts,
    pub with_decision_policy: Counts,
    /// Arbitration alone, without enabling the optional corroboration gate.
    pub with_arbitration: Counts,
    pub recent: RecentAudit,
}

#[derive(Default, serde::Serialize)]
pub struct RecentAudit {
    pub considered: usize,
    pub unsupported: usize,
    pub transitions: Vec<Transition>,
}
#[derive(serde::Serialize)]
pub struct Transition {
    pub before: Outcome,
    pub after: Outcome,
    pub count: usize,
}

fn recent_audit(db: &rusqlite::Connection) -> anyhow::Result<RecentAudit> {
    let mut report = RecentAudit::default();
    let mut query = db.prepare("SELECT scan FROM messages WHERE is_dsn=0 AND created>=?1 ORDER BY created DESC,id DESC LIMIT 100")?;
    let mut rows = query.query([crate::now() - 30 * 86400])?;
    while let Some(row) = rows.next()? {
        report.considered += 1;
        let raw = row.get_ref(0)?.as_str()?;
        anyhow::ensure!(raw.len() <= 8 * 1024 * 1024, "oversized analysis snapshot");
        let mut scan: Scan = serde_json::from_str(raw)?;
        let Some(decision) = &scan.decision else {
            report.unsupported += 1;
            continue;
        };
        if !scan.complete || decision.source == DecisionSource::Fusion {
            report.unsupported += 1;
            continue;
        }
        let before = decision.outcome;
        crate::decision::apply(&mut scan, false);
        let after = scan.decision.unwrap().outcome;
        if let Some(t) = report
            .transitions
            .iter_mut()
            .find(|t| t.before == before && t.after == after)
        {
            t.count += 1;
        } else {
            report.transitions.push(Transition {
                before,
                after,
                count: 1,
            });
        }
    }
    Ok(report)
}

/// Aggregate an existing, bounded feedback snapshot on the server. Never opens
/// the spool, loads models, writes SQLite or exports identities/features/text.
/// Reuses recorded observations, so this does not evaluate a new LLM prompt.
pub fn audit(path: &std::path::Path) -> anyhow::Result<Audit> {
    use anyhow::ensure;
    let db =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    db.busy_timeout(std::time::Duration::from_millis(250))?;
    db.execute_batch("BEGIN")?;
    let mut query = db.prepare(
        "SELECT m.scan,MIN(f.spam),MAX(f.spam) FROM messages m
        JOIN feedback f ON f.message_id=m.id JOIN users u ON u.username=f.username
        WHERE u.disabled=0 AND m.is_dsn=0 AND m.created>=?1 AND EXISTS (
          SELECT 1 FROM deliveries d JOIN console_access a ON a.delivery_id=d.id
          WHERE d.message_id=m.id AND a.username=f.username)
        GROUP BY m.id LIMIT 10001",
    )?;
    let mut rows = query.query([crate::now() - 30 * 86400])?;
    let mut report = Audit::default();
    while let Some(row) = rows.next()? {
        report.considered += 1;
        ensure!(
            report.considered <= 10000,
            "feedback audit exceeds 10000 messages"
        );
        let min: i64 = row.get(1)?;
        let max: i64 = row.get(2)?;
        ensure!(
            (0..=1).contains(&min) && (0..=1).contains(&max),
            "invalid feedback label"
        );
        if min != max {
            report.conflicting += 1;
            continue;
        }
        let raw: &str = row.get_ref(0)?.as_str()?;
        ensure!(raw.len() <= 8 * 1024 * 1024, "oversized analysis snapshot");
        let mut scan: Scan = serde_json::from_str(raw)?;
        let Some(decision) = &scan.decision else {
            report.unsupported += 1;
            continue;
        };
        if !scan.complete || decision.source == DecisionSource::Fusion {
            report.unsupported += 1;
            continue;
        }
        report.evaluated += 1;
        report.before.add(decision.outcome, min == 1);
        let mut arbitrated = scan.clone();
        crate::decision::apply(&mut arbitrated, false);
        report.diagnostics.add(&arbitrated, min == 1);
        report
            .with_arbitration
            .add(arbitrated.decision.unwrap().outcome, min == 1);
        apply(&mut scan, true);
        report
            .with_confirmation
            .add(scan.decision.as_ref().unwrap().outcome, min == 1);
        crate::decision::apply(&mut scan, true);
        report
            .with_decision_policy
            .add(scan.decision.unwrap().outcome, min == 1);
    }
    report.recent = recent_audit(&db)?;
    Ok(report)
}
