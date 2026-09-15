export type RspamdReport = {
  status: 'pending' | 'complete' | 'busy' | 'timeout' | 'unavailable' | 'invalid_response' | 'skipped' | 'oversize' | 'not_sampled' | 'interrupted';
  comparison: 'agreement' | 'disagreement' | 'inconclusive';
  score: number | null;
  required_score: number | null;
  action: string | null;
  symbols: { name: string; score: number }[];
  elapsed_ms: number;
  profile: string;
  settings_sha256: string;
  server: string | null;
  noisefence_outcome: 'legitimate' | 'unwanted' | 'undetermined' | null;
};
export type ComparisonSummary = {
  rows: number; total: number; completed: number; agreements: number; disagreements: number; inconclusive: number; pending: number;
};
export function comparisonLabel(report?: RspamdReport | null) {
  if (!report) return 'Not compared';
  if (report.status === 'complete') return {
    agreement: 'Engines agree', disagreement: 'Engines disagree', inconclusive: 'No comparable verdict',
  }[report.comparison];
  return {
    pending: 'Comparison pending', busy: 'Comparison capacity reached', timeout: 'Comparison timed out',
    unavailable: 'Rspamd unavailable', invalid_response: 'Invalid Rspamd response', skipped: 'Skipped by Rspamd',
    oversize: 'Above comparison size limit', not_sampled: 'Outside comparison sample', interrupted: 'Comparison interrupted',
  }[report.status];
}
export function comparisonPoints(value: number | null | undefined) {
  return typeof value === 'number' && Number.isFinite(value) ? value.toFixed(2) : '—';
}
export function agreementRate(summary: ComparisonSummary) {
  const comparable = summary.agreements + summary.disagreements;
  return comparable > 0 ? `${(100 * summary.agreements / comparable).toFixed(1)}%` : '—';
}
