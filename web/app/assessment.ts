/** Versioned projection produced by src/assessment.rs, never used to change policy. */
export type Assessment = {
  score_boundary?: {
    version: 1;
    source: 'content' | 'fusion';
    value: number;
    cutoff: number;
    index_cutoff: number;
    above: boolean;
    model: string;
    model_sha256: string | null;
    calibration: {slope: number; intercept: number} | null;
  } | null;
  score_resolution?: {
    version: string;
    threshold: number;
    score: number | null;
    partial: boolean;
    projected: boolean;
    previous: {outcome: string};
    decision: {outcome: string};
  } | null;
  version: 1;
  score: {
    value: number | null;
    raw: number | null;
    decision: number | null;
    kind: 'unavailable' | 'partial' | 'internal' | 'advisory' | 'decision' | 'content';
    source: 'unavailable' | 'decision' | 'raw';
    model: string;
    scale: 100;
  };
  category: 'spam' | 'publicity' | 'legitimate' | 'undetermined';
  classification_source: 'recipient_policy' | 'recorded_decision' | 'historical_fallback' | 'score_threshold';
  decision: {source: 'legacy' | 'fusion' | 'antivirus'; outcome: 'legitimate' | 'unwanted' | 'undetermined'; score: number | null; model: string};
  decision_recorded: boolean;
  complete: boolean;
  incomplete_reasons: string[];
  supplementary_gaps?: string[];
  content_threshold: number | null;
  mode: 'observe' | 'tag' | 'enforce' | null;
  policy_version: string | null;
  action: {requested: string; effective: string; reason: string; quarantine_days: number; coverage?: import('./action-coverage').ActionCoverage | null} | null;
  subject_tag: 'none' | 'spam' | 'publicity';
};

/** Frozen at receipt, shared by API, SMTP headers and replicated queue copies. */
export type RecipientDecision = {
  activation_epoch?: import('./receipt-activation').ReceiptEpoch | null;
  policy_trace?: import('./policy-trace').PolicyTrace | null;
  version: 1 | 2;
  recorded_at: number;
  policy_sha256: string;
  profile: string | null;
  rule_ids: string[];
  classification: 'legitimate' | 'publicity' | 'spam' | 'phishing' | 'malware' | 'unassessed';
  coverage: 'complete' | 'partial' | 'unavailable';
  assessment: Assessment;
};

export function receiptDecision(mail: {recipient_decision?: RecipientDecision | null}) {
  const record = mail.recipient_decision;
  return record?.version === 1 || record?.version === 2 ? record : null;
}

export function receiptAssessment(mail: {assessment?: Assessment; recipient_decision?: RecipientDecision | null}) {
  return receiptDecision(mail)?.assessment ?? mail.assessment;
}

export const missingCheckLabels: Record<string, string> = {
  analysis_budget: 'content analysis budget',
  signature_budget: 'signature limit',
  checks_unavailable: 'checks or overall deadline',
  llm_unavailable: 'LLM analysis',
  semantic_unavailable: 'semantic analysis',
  encrypted_content: 'encrypted or opaque content',
  score_combination_invalid: 'Inconsistent score contributions',
  smtp_policy_unavailable: 'SMTP / DNS consistency',
  vision_incomplete: 'OCR / visual codes',
  complementary_signature_unavailable: 'complementary signatures',
  antivirus_unavailable: 'antivirus',
  antivirus_unscannable: 'antivirus',
  unspecified: 'unspecified check',
};

export function coveragePresentation(mail: {complete: boolean; assessment?: Assessment; recipient_decision?: RecipientDecision | null}) {
  const assessment = receiptAssessment(mail);
  const complete = assessment?.complete ?? mail.complete;
  const unavailable = receiptDecision(mail)?.coverage === 'unavailable';
  const names = [...new Set((assessment?.incomplete_reasons ?? [])
    .map(id => Object.hasOwn(missingCheckLabels, id) ? missingCheckLabels[id] : 'unspecified check'))];
  const optionalNames: Record<string, string> = {crdf: 'CRDF reputation', virustotal: 'VirusTotal reputation', link_inventory: 'link inventory', url_resolution: 'URL destinations', rbl: 'DNS blocklists', mailing: 'PUB classification'};
  const gaps = [...new Set((assessment?.supplementary_gaps ?? []).map(id => Object.hasOwn(optionalNames, id) ? optionalNames[id] : 'supplementary check'))];
  const additional = gaps.length ? ` Supplementary checks unavailable or limited: ${gaps.join(', ')}. Missing results do not establish safety or spam.` : '';
  return {
    complete,
    hasGaps: gaps.length > 0,
    label: unavailable ? 'Content analysis unavailable' : complete ? (gaps.length ? 'Core complete · limited checks' : 'Core analysis complete') : 'Partial analysis',
    detail: (complete ? 'Core analysis completed.' : `Missing or limited checks${names.length ? `: ${names.join(', ')}` : ''}. The risk index uses the available results.`) + additional,
  };
}
