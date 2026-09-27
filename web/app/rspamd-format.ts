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
  if (report.status === 'complete' && ['greylist', 'soft reject'].includes(report.action ?? '')) return 'Rspamd proposes deferral';
  if (report.status === 'complete') return {
    agreement: 'Engines agree', disagreement: 'Engines disagree', inconclusive: 'Second opinion recorded',
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

export function comparisonExplanation(report?: RspamdReport | null) {
  if (report?.status === 'complete' && ['greylist', 'soft reject'].includes(report.action ?? ''))
    return 'Rspamd proposes a temporary deferral, not a spam or legitimate verdict. This proposal is not executed and is excluded from binary agreement statistics.';
  if (report?.status === 'complete' && report.comparison === 'inconclusive')
    return 'The recorded opinions do not support a binary comparison. This does not make the NoiseFence decision pending.';
  return 'This second opinion is retained for research. Agreement or disagreement never changes the NoiseFence verdict or delivery.';
}
