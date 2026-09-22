export type DetectorObservation = {
  id: string;
  family: string;
  role: string;
  state: string;
  scope: string;
  version: string | null;
  elapsed_ms: number | null;
  result: { kind: string; value: string | string[] } | null;
  measurements: Record<string, { value: number; unit: string }>;
  exclusion: string | null;
  group: string;
  queried_at?: number | null;
  cache_max_age_seconds?: number | null;
  analysis_max_age_seconds?: number | null;
};
export type ObservationReport = {
  version: number;
  provenance: string | null;
  observations: DetectorObservation[];
  groups: { key: string; family: string; observations: string[]; conflict: boolean }[];
  omitted: number;
};

export function observationState(state: string) {
  return ({ complete: 'Complete', partial: 'Partial', unavailable: 'Unavailable',
    timeout: 'Timed out', budget_exceeded: 'Budget or quota exhausted',
    disabled: 'Disabled', not_applicable: 'Not applicable' } as Record<string, string>)[state] ?? 'State not recorded';
}
export function observationRole(role: string) {
  return ({ decision_input: 'Decision input', safety: 'Malware safety check',
    advisory: 'Advisory', comparison: 'Comparison only', admission: 'SMTP admission only' } as Record<string, string>)[role] ?? 'Role not recorded';
}
export function observationExclusion(reason: string | null) {
  return ({ not_observed: 'Not observed', missing_envelope_context: 'Original SMTP context unavailable',
    unsupported_claims: 'Claims not supported by recorded evidence', inconsistent_opinion: 'Inconsistent opinion',
    invalid_result: 'Missing or invalid result', unavailable_result: 'Result unavailable for this observation' } as Record<string, string>)[reason ?? ''] ?? (reason ? 'Excluded result' : '');
}
export function observationScope(scope: string) {
  return ({ message: 'Message', message_excerpt: 'Message excerpt', message_images: 'Message images',
    smtp_authentication: 'SMTP authentication', smtp_session: 'SMTP session', peer_ip: 'Connecting IP',
    domain_role: 'Queried domain', provider_request: 'Provider request', host_lookup: 'Host-root lookup',
    domain: 'Domain reputation', file: 'File hash', url_navigation: 'URL navigation', family_aggregate: 'Rule family' } as Record<string, string>)[scope] ?? 'Scope not recorded';
}
const names: Record<string, string> = {content:'Content extraction',lexical:'Lexical model',semantic:'Semantic model',
  spf:'SPF',dkim:'DKIM',dmarc:'DMARC alignment',arc:'ARC',antivirus:'Antivirus',signatures:'Supplemental signatures',
  smtp_dns:'SMTP / DNS',llm:'LLM',vision:'OCR / QR',mail_kind:'Message kind',crdf:'CRDF',virustotal:'VirusTotal',
  native:'Native comparison',authentication:'Authentication',reputation:'Reputation',smtp:'SMTP / DNS',
  campaign:'Campaign memory',bayes:'Bayes',other:'Other rules'};
export function observationName(id: string) {
  if (names[id]) return names[id];
  const [parent, child] = id.split('.');
  if (parent === 'native' && names[child]) return `Native · ${names[child]}`;
  if (id === 'dqs.ip') return 'Spamhaus · connecting IP';
  if (/^dqs\.domain\.\d+$/.test(id)) return `Spamhaus · domain ${Number(id.split('.')[2]) + 1}`;
  if (/^(crdf|virustotal|rbl|redirect)\.\d+$/.test(id)) {
    const label = names[parent] ?? (parent === 'rbl' ? 'RBL check' : 'URL chain');
    return `${label} · ${Number(child) + 1}`;
  }
  return 'Other recorded detector';
}
export function observationResult(o: DetectorObservation) {
  if (o.exclusion) return observationExclusion(o.exclusion);
  if (!o.result) return 'No verdict recorded';
  if (o.state !== 'complete' && o.state !== 'partial') return 'No usable verdict';
  if (o.result.kind === 'authentication' && Array.isArray(o.result.value)) {
    if (!o.result.value.length) return o.id === 'dkim' ? 'No signatures found' : 'No authentication result';
    return o.result.value.map(v => ({pass:'Pass',fail:'Fail',soft_fail:'Soft fail',neutral:'Neutral',none:'No authentication result',
      temp_error:'Temporary error',perm_error:'Permanent error'} as Record<string,string>)[v] ?? 'Unknown result').join(' / ');
  }
  if (typeof o.result.value !== 'string') return 'Unknown result';
  return ({listed:'Listed',not_listed:'Not listed — safety not established',policy:'Policy listing',malicious:'Malicious indicator',
    suspicious:'Suspicious indicator',unknown:'Unknown to provider',stale:'Stale result',clean:'No malware detected',
    malware:'Malware detected',unscannable:'Not fully scannable',legitimate:'Legitimate',spam:'Spam',phishing:'Phishing',
    ambiguous:'Inconclusive opinion',none:'No message kind identified',promotion:'Promotion',newsletter:'Newsletter',
    transactional:'Transactional',conversation:'Conversation'} as Record<string,string>)[o.result.value] ?? 'Unknown result';
}
export function observationMeasurement(name: string, m: {value:number;unit:string}) {
  if (!Number.isFinite(m.value)) return 'Value not recorded';
  const unit = ({log_odds:'log-odds',points:'points',reported_probability:'self-reported, 0–1',count:'count'} as Record<string,string>)[m.unit];
  if (!unit || (m.unit === 'reported_probability' && (m.value < 0 || m.value > 1))) return 'Value not recorded';
  const label = ({logit:'Model output',contribution:'Contribution',applied_contribution:'Applied contribution',
    reported_probability:'Reported probability',reported_confidence:'Reported confidence',checked:'Checked targets',
    raw:'Before caps',retained:'After caps',capped_total:'Capped total',qr_codes:'QR codes',text_characters:'Text characters',hops:'Hops'} as Record<string,string>)[name] ?? 'Recorded value';
  return `${label}: ${new Intl.NumberFormat('en-GB',{maximumFractionDigits:3}).format(m.value)} ${unit}`;
}

export function sharedObservationGroups(report: ObservationReport) {
  return report.groups.filter(g => g.observations.length > 1);
}
