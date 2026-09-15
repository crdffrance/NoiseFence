/** Versioned projection produced by src/assessment.rs, never used to change policy. */
export type Assessment = {
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
  classification_source: 'recipient_policy' | 'recorded_decision' | 'historical_fallback';
  decision: {source: 'legacy' | 'fusion' | 'antivirus'; outcome: 'legitimate' | 'unwanted' | 'undetermined'; score: number | null; model: string};
  decision_recorded: boolean;
  complete: boolean;
  incomplete_reasons: string[];
  content_threshold: number | null;
  mode: 'observe' | 'tag' | 'enforce' | null;
  policy_version: string | null;
  action: {requested: string; effective: string; reason: string; quarantine_days: number} | null;
  subject_tag: 'none' | 'spam' | 'publicity';
};

export const missingCheckLabels: Record<string, string> = {
  analysis_budget: 'content analysis budget',
  signature_budget: 'signature limit',
  checks_unavailable: 'checks or overall deadline',
  llm_unavailable: 'LLM analysis',
  semantic_unavailable: 'semantic analysis',
  encrypted_content: 'encrypted or opaque content',
  smtp_policy_unavailable: 'SMTP / DNS consistency',
  vision_incomplete: 'OCR / visual codes',
  complementary_signature_unavailable: 'complementary signatures',
  antivirus_unavailable: 'antivirus',
  antivirus_unscannable: 'antivirus',
  unspecified: 'unspecified check',
};

export function coveragePresentation(mail: {complete: boolean; assessment?: Assessment}) {
  const complete = mail.assessment?.complete ?? mail.complete;
  const names = [...new Set((mail.assessment?.incomplete_reasons ?? [])
    .map(id => Object.hasOwn(missingCheckLabels, id) ? missingCheckLabels[id] : 'unspecified check'))];
  return {
    complete,
    label: complete ? 'Complete' : 'Partial analysis',
    detail: complete ? 'Configured checks completed.' : `Missing or limited checks${names.length ? `: ${names.join(', ')}` : ''}. The risk index uses the available results.`,
  };
}
