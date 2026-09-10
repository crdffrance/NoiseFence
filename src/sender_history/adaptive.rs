//! Explicit per-recipient cutoff for the legacy classifier. No invented
//! probability or logit credit, and no bypass of mandatory content/auth checks.
use super::{Mode, Projection, Status};
use crate::{config::Config, engine::Scan, evidence::State};

pub const VERSION: &str = "sender-history-adaptive-1";
pub const REASON: &str = "sender_history_threshold";

/// Indices refer to the original SMTP recipient slice, never to headers or a
/// client-provided From. Empty means the common analysis/policy remains in force.
pub(crate) fn selected(
    scan: &Scan,
    config: &Config,
    projection: &Projection,
    llm_available: bool,
) -> Vec<usize> {
    let Some(policy) = &config.sender_history else {
        return vec![];
    };
    let Some(threshold) = policy.trusted_threshold else {
        return vec![];
    };
    let llm_would_run = llm_available
        && config
            .llm
            .as_ref()
            .is_some_and(|c| scan.score >= c.score_low && scan.score <= c.score_high);
    if policy.mode != Mode::Adaptive
        || config.fusion.is_some()
        || !scan.score.is_finite()
        || threshold <= config.filter.threshold
        || scan.score >= threshold
        || (scan.score < config.filter.threshold && !llm_would_run)
        || projection.epoch().is_none()
        || !eligible(scan, config)
    {
        return vec![];
    }
    projection
        .reports
        .iter()
        .enumerate()
        .filter_map(|(i, r)| {
            (r.status == Status::Complete && r.candidate_credit && !r.contradicted).then_some(i)
        })
        .collect()
}

fn eligible(scan: &Scan, config: &Config) -> bool {
    use crate::{antivirus::AntivirusStatus as Av, protection::Status as Provider};
    let Some(e) = &scan.evidence else {
        return false;
    };
    let finished = |s| matches!(s, State::Complete | State::Disabled);
    if !super::authenticated(scan)
        || !super::content_eligible(scan)
        || scan.features_complete != Some(true)
        || !e.analysis_complete
        || e.validate().is_err()
        || !finished(e.antivirus_state)
        || !finished(e.signatures_state)
        || !finished(e.smtp_policy_state)
        || !finished(e.reputation.state)
        || !finished(e.reputation.ip.state)
        || !e.reputation.ip.codes.is_empty()
        || e.reputation
            .domains
            .iter()
            .any(|d| !finished(d.result.state) || !d.result.codes.is_empty())
        || !matches!(scan.antivirus.status, Av::Disabled | Av::Clean)
        || !matches!(scan.signatures.status, Av::Disabled | Av::Clean)
        || e.antivirus
            .as_ref()
            .is_some_and(|r| !matches!(r.status, Av::Disabled | Av::Clean))
        || e.signatures
            .as_ref()
            .is_some_and(|r| !matches!(r.status, Av::Disabled | Av::Clean))
        || (config.antivirus.is_some()
            && (scan.antivirus.status != Av::Clean || e.antivirus_state != State::Complete))
        || (config.signatures.is_some()
            && (scan.signatures.status != Av::Clean || e.signatures_state != State::Complete))
        || scan
            .reasons
            .iter()
            .any(|s| s.id != "model_contribution" && (!s.weight.is_finite() || s.weight > 0.0))
        || scan.smtp_policy.candidate_weight > 0.0
        || scan.smtp_policy.checks.iter().any(|s| s.weight > 0.0)
        || scan.vision.credential_request
        || scan.vision.urgency
        || !matches!(
            scan.vision.status,
            crate::vision::Status::Disabled | crate::vision::Status::Complete
        )
    {
        return false;
    }
    if !finished(e.semantic_state)
        || (config.vision.is_some() && scan.vision.status != crate::vision::Status::Complete)
    {
        return false;
    }
    if config.heuristics.is_some() && scan.heuristics.is_none() {
        return false;
    }
    if (config.content_inspection.is_some() || config.sandbox_pipeline.is_some())
        && scan.content_inspection.is_none()
    {
        return false;
    }
    if scan
        .research_execution
        .as_ref()
        .is_some_and(|r| r.status != crate::research_engines::Status::Complete)
        || scan.heuristics.as_ref().is_some_and(|r| {
            !matches!(
                r.status,
                crate::heuristics::Status::Complete | crate::heuristics::Status::Disabled
            ) || !r.findings.is_empty()
        })
        || scan.content_inspection.as_ref().is_some_and(|r| {
            r.status != crate::content_inspection::Status::Complete
                || r.truncated
                || !r.findings.is_empty()
                || r.stats.office_documents > 0
        })
    {
        return false;
    }
    if config.protection.is_some() && scan.protection.is_none() {
        return false;
    }
    if let Some(p) = &scan.protection {
        if config
            .protection
            .as_ref()
            .is_some_and(|c| c.policy.follow_urls)
            && !p
                .url_resolution
                .as_ref()
                .is_some_and(|r| r.omitted == 0 && r.chains.iter().all(|c| c.complete))
        {
            return false;
        }
        let ready = |s: &Provider| matches!(s, Provider::Disabled | Provider::Complete);
        if !ready(&p.local_status)
            || !ready(&p.feed_status)
            || !ready(&p.campaign_status)
            || !ready(&p.crdf.status)
            || !ready(&p.virustotal.status)
            || p.campaign_match
            || p.campaign_conflict
            || !p.findings.is_empty()
            || p.crdf.malicious > 0
            || p.crdf.suspicious > 0
            || p.virustotal.malicious > 0
            || p.virustotal.suspicious > 0
        {
            return false;
        }
    }
    true
}

/// Call after ordinary scoring/decision and before subject rewriting/ARC.
/// Preserve the score, evidence and model; the applied cutoff is explicit.
pub(crate) fn apply(scan: &mut Scan, config: &Config, llm_omitted: bool) {
    let threshold = config
        .sender_history
        .as_ref()
        .and_then(|p| p.trusted_threshold)
        .expect("validated adaptive plan");
    scan.decision = Some(crate::fusion::runtime::Decision::legacy(scan, threshold));
    scan.reasons
        .retain(|r| r.id != crate::confirmation::REVIEW_REASON);
    crate::decision::apply(scan, config.filter.require_corroboration);
    if let Some(policy) = &mut scan.analysis_policy {
        policy.threshold = threshold;
    }
    scan.reasons.retain(|r| r.id != REASON);
    scan.reasons.push(crate::engine::Signal { id:REASON.into(),weight:0.0,
        detail:format!("Seuil de correspondance connue : {threshold:.2}, au lieu de {:.2}. Identité authentifiée, historique propre au destinataire ; aucune garantie d’innocuité.",config.filter.threshold) });
    if let Some(projection) = &mut scan.sender_history_projection {
        projection.applied(threshold, llm_omitted);
    }
}
