export type ScoringReport = {
  version: string;
  baseline: number | null;
  lexical: number | null;
  semantic: number | null;
  contributions: Array<{id:string;family:string;occurrences:number;proposed:number|null;retained:number|null;adjustment:string}>;
  invalid_inputs: number;
  rules_total: number | null;
  total_logit: number | null;
  score: number | null;
};
export function scoreAdjustment(value:string) {
  return ({none:'Applied once',duplicate:'Repeated signal counted once',detector_policy:'Reconciled with the usable detector opinion',
    conflicting_weights:'Conflicting weights — index unavailable',invalid_weight:'Invalid weight — index unavailable'} as Record<string,string>)[value] ?? 'Unknown adjustment';
}
export function scoreValue(value:number|null|undefined) {
  return value != null && Number.isFinite(value) ? new Intl.NumberFormat('en-GB',{maximumFractionDigits:4}).format(value) : 'Not available';
}
