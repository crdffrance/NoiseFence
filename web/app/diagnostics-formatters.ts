export type HistoricalPolicy = {
  version: string;
  threshold: number;
  mode: 'observe' | 'tag' | 'enforce';
  require_corroboration: boolean;
  resolve_uncertain_by_score?: boolean;
  rule_weights: Record<string, number>;
};

// Only this projection of src/evidence.rs is displayed. Other evidence remains private.
export type AuthenticationEvidence = {
  state: string;
  spf_state: string;
  spf: string | null;
  dkim_state: string;
  dkim: string[] | null;
  dmarc_state: string;
  dmarc_spf: string | null;
  dmarc_dkim: string | null;
  arc_state: string;
  arc: string | null;
  arc_can_seal: boolean | null;
};

export type SmtpEvent = {
  phase: string;
  elapsed_ms: number;
  code: number | null;
  enhanced_code: string | null;
  response: string | null;
  detail: string | null;
};
export type SmtpLog = {
  id: number;
  attempt: number;
  route: string;
  peer: string | null;
  started: number;
  elapsed_ms: number;
  outcome: 'delivered' | 'temporary' | 'permanent';
  truncated: boolean;
  events: SmtpEvent[];
};
export type DiagnosticRecipient = {
  delivery_id: number;
  address: string;
  destination: string;
  status: string;
  attempts: number;
  next_attempt: number;
  last_error: string | null;
  logs_available: number;
  logs_truncated: boolean;
  logs: SmtpLog[];
};
export type RecipientHistory = DiagnosticRecipient;
export type MessageDiagnostics = {
  message_id: string;
  analysis: {
    observations?: import('./observations-format').ObservationReport | null;
    rspamd?: import('./rspamd-format').RspamdReport | null;
    elapsed_ms: number;
    feature_version: number;
    features_complete: boolean | null;
    policy: HistoricalPolicy | null;
    score_breakdown?: {families:Record<string,number|null>;reconstructed_score:number|null;matches_recorded_score:boolean;saturated:boolean};
    native_filter?: {
      version: string; mode: 'observe'; status: string; elapsed_ms: number;
      calibrated: boolean; affects_delivery: boolean;
      score: {total:number; families:Record<string,{raw:number;effective:number;capped:boolean}>;
        symbols:Array<{id:string;label:string;weight:number;family:string;absorbed_by:string[]}>} | null;
      bayes:{status:string;model:string|null;raw_log_odds:number|null;matched_features:number;calibrated:boolean};
      fuzzy:{status:string;matches:number;spam_examples:number;legitimate_examples:number;structural_matches:number;conflict:boolean;corroborated_spam:boolean};
    } | null;
    lexical_logit: number | null;
    semantic_contribution: number | null;
    rule_weight_total: number;
    evidence: {
      authentication?: AuthenticationEvidence;
      lexical_state?: string;
      semantic_state?: string;
    } | null;
  };
  recipients: DiagnosticRecipient[];
};
export type DiagnosticReason = { id: string; detail: string; weight: number };

export function recipientHistory(
  data: MessageDiagnostics,
  messageId: string,
  deliveryId: number,
  signal?: AbortSignal,
): RecipientHistory | null {
  if (signal?.aborted) return null;
  const recipient = data.recipients[0];
  if (
    data.message_id !== messageId ||
    data.recipients.length !== 1 ||
    recipient?.delivery_id !== deliveryId
  )
    throw new Error(
      "The received history does not match the selected recipient.",
    );
  // A targeted response must never replace the message's other recipients or analysis.
  return recipient;
}

export function mergeDiagnosticRecipient<T extends { delivery_id?: number }>(
  recipients: T[],
  updated: DiagnosticRecipient,
): T[] {
  return recipients.map((recipient) =>
    recipient.delivery_id === updated.delivery_id
      ? { ...recipient, ...updated }
      : recipient,
  );
}

const decimal = new Intl.NumberFormat('en-GB', { maximumFractionDigits: 3 });
export function duration(value: number | null | undefined) {
  if (value == null || !Number.isFinite(value) || value < 0) return 'Duration not recorded';
  return value < 1000 ? `${decimal.format(value)} ms` : `${decimal.format(value / 1000)} s`;
}
export function timestamp(value: number) {
  const date = new Date(value * 1000);
  return value > 0 && Number.isFinite(date.getTime())
    ? date.toLocaleString('en-GB', { timeZoneName: 'short' }) : 'Date not recorded';
}
export function contribution(value: number | null | undefined) {
  if (value == null || !Number.isFinite(value)) return 'Not recorded';
  const formatted = Math.abs(value) > 0 && Math.abs(value) < 0.001
    ? Math.abs(value).toExponential(2) : decimal.format(Math.abs(value));
  return `${value > 0 ? '+' : value < 0 ? '−' : ''}${formatted}`;
}
export function weightEffect(value: number) {
  if (!Number.isFinite(value)) return 'Effect not recorded';
  if (value > 0) return 'Increases risk in the recorded calculation';
  if (value < 0) return 'Reduces risk in the recorded calculation';
  return 'Advisory signal · no numerical effect';
}
export function decisionExplanation(source?: string) {
  if (source === 'antivirus') return 'Malware detection takes priority over content weights and fusion. These contributions do not determine the final decision.';
  if (source === 'fusion') return 'Fusion determines the decision. The content weights below do not determine the final fusion estimate.';
  if (source === 'legacy') return 'The recorded decision combines the lexical model, semantic contribution and rules, subject to corroboration policy.';
  return 'Decision source not recorded. The retained weights cannot establish the final decision.';
}
export function policySummary(policy: HistoricalPolicy | null) {
  if (!policy) return 'Historical threshold and mode not recorded. Current settings are not used to reconstruct this analysis.';
  const mode = { observe: 'Observation', tag: 'Tagging', enforce: 'Actions enabled' }[policy.mode] ?? 'Unknown mode';
  return `${mode} · Recorded content threshold ${decimal.format(policy.threshold)} / 100 · corroboration ${policy.require_corroboration ? 'required' : 'not required'}${policy.resolve_uncertain_by_score ? ' · uncertain results resolved by score' : ''}`;
}
export function deliveryStatus(status: string) {
  return ({ pending: 'Pending delivery', sending: 'Delivery in progress', delivered: 'Accepted by destination',
    failed: 'Delivery failed', notified: 'Failure notification handled', dsn_suppressed: 'Notification suppressed · backscatter protection',
    quarantined: 'Quarantined', discarded: 'Manually discarded', expired: 'Quarantine expired',
  } as Record<string, string>)[status] ?? `Unknown state (${status})`;
}
export function smtpOutcome(outcome: string) {
  return ({ delivered: 'Accepted by destination', temporary: 'Temporary failure', permanent: 'Permanent rejection' } as Record<string, string>)[outcome] ?? `Unknown outcome (${outcome})`;
}
export function nextRetry(status: string, nextAttempt: number, now = Date.now()) {
  if (status === 'sending') return 'Attempt in progress; next retry time unknown.';
  if (status !== 'pending') return 'No retry scheduled in this state.';
  if (!Number.isFinite(nextAttempt) || nextAttempt <= 0 || !Number.isFinite(new Date(nextAttempt * 1000).getTime())) return 'Next retry: date not recorded.';
  return nextAttempt * 1000 <= now ? `Retry due since ${timestamp(nextAttempt)}; waiting for a relay worker.` : `Next retry scheduled for ${timestamp(nextAttempt)}.`;
}
export function transcriptNotice(logCount: number, logsAvailable = logCount, logsTruncated = false) {
  if (logsTruncated || logsAvailable > logCount) return `Partial history: ${logCount} of ${logsAvailable} available SMTP logs loaded.`;
  if (!logCount) return 'No historical SMTP transcript recorded. Missing logs do not establish which exchanges took place.';
  return `${logCount} recorded SMTP log${logCount === 1 ? '' : 's'}.`;
}
export function smtpPhase(phase: string) {
  return ({ dns: 'DNS lookup', connect: 'TCP connection', greeting: 'SMTP greeting', ehlo: 'EHLO · server capabilities',
    starttls: 'STARTTLS · encryption request', tls: 'TLS · handshake and certificate verification', tls_verified: 'TLS · certificate verified',
    ehlo_tls: 'EHLO after TLS', mail: 'MAIL FROM · sender', mail_from: 'MAIL FROM · sender', rcpt: 'RCPT TO · recipient', rcpt_to: 'RCPT TO · recipient', rcpt_fallback: 'RCPT TO · unknown-recipient fallback',
    data: 'DATA · transfer start', data_result: 'Final response after transfer', data_end: 'Final response after transfer', final: 'Final response after transfer',
    final250: 'Final response after transfer', final_250: 'Final response after transfer', quit: 'QUIT · session close', error: 'Delivery error',
  } as Record<string, string>)[phase.toLowerCase()] ?? `Phase ${phase}`;
}
export function smtpReply(code: number | null, enhanced: string | null) {
  const kind = code == null ? 'SMTP code not recorded' : code >= 500 && code < 600 ? `${code} · permanent rejection`
    : code >= 400 && code < 500 ? `${code} · temporary failure` : code >= 300 && code < 400 ? `${code} · continue exchange`
      : code >= 200 && code < 300 ? `${code} · command accepted` : `${code} · SMTP response`;
  return enhanced ? `${kind} · ${enhanced}` : kind;
}
export function evidenceState(state?: string) {
  return ({ disabled: 'Disabled', not_run: 'Not run', complete: 'Complete', unavailable: 'Unavailable', busy: 'Capacity exhausted', skipped: 'Skipped', limited: 'Partial' } as Record<string, string>)[state ?? ''] ?? 'State not recorded';
}
export function authenticationResult(value: string | null | undefined) {
  return ({ pass: 'Pass', fail: 'Fail', soft_fail: 'Soft fail (softfail)', neutral: 'Neutral', none: 'No authentication result (none)', temp_error: 'Temporary error', perm_error: 'Permanent error' } as Record<string, string>)[value ?? ''] ?? 'Result not recorded';
}
