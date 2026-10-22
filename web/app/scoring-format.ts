export type ScoringReport = {
  version: string;
  baseline: number | null;
  lexical: number | null;
  semantic: number | null;
  contributions: Array<{id:string;family:string;occurrences:number;proposed:number|null;retained:number|null;adjustment:string;subsumed_by?:string|null}>;
  invalid_inputs: number;
  rules_total: number | null;
  total_logit: number | null;
  score: number | null;
};
export function scoreAdjustment(value:string) {
  return ({none:'Applied once',duplicate:'Repeated signal counted once',detector_policy:'Reconciled with the usable detector opinion',
    conflicting_weights:'Conflicting weights — index unavailable',invalid_weight:'Invalid weight — index unavailable',
    unavailable_evidence:'Excluded — no usable supporting result',subsumed_evidence:'Already included in the composite finding'} as Record<string,string>)[value] ?? 'Unknown adjustment';
}
export function scoreValue(value:number|null|undefined) {
  return value != null && Number.isFinite(value) ? new Intl.NumberFormat('en-GB',{maximumFractionDigits:4}).format(value) : 'Not available';
}

export type FusionAccounting = {
  version:string;model_sha256?:string|null;policy_sha256:string;bias:number;total_logit:number;
  families:Record<string,{raw:number;retained:number;minimum:number;maximum:number}>;
};

// Arithmetic sensitivity of the recorded content index, not a new verdict or
// a calibrated alternative model. Never substitute current policy for history.
export function lexicalSensitivity(report: ScoringReport, threshold?: number | null) {
  const {lexical, semantic, rules_total: rules, total_logit: total, score} = report;
  if (threshold == null || !Number.isFinite(threshold) || threshold <= 0 || threshold >= 100
    || lexical == null || rules == null || total == null || score == null
    || ![lexical, rules, total, score].every(Number.isFinite)
    || (semantic != null && !Number.isFinite(semantic)) || report.invalid_inputs !== 0
    || score < 0 || score > 100 || report.baseline != null
    || Math.abs(lexical + (semantic ?? 0) + rules - total) > 1e-6) return null;
  const index = (value: number) => 100 / (1 + Math.exp(-value));
  // Legacy indices may be rounded; inconsistent ledgers cannot explain them.
  if (Math.abs(index(total) - score) > 0.051) return null;
  return {lexicalOnly: index(lexical), withoutLexical: index((semantic ?? 0) + rules),
    lexicalReachesThreshold: index(lexical) >= threshold,
    totalReachesThreshold: score >= threshold};
}
