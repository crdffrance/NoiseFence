import { comparisonLabel, comparisonExplanation, comparisonPoints, agreementRate, type RspamdReport, type ComparisonSummary } from './rspamd-format';
import { scorePresentation, type ScoreInput } from './presentation';

export function RspamdComparison({ report, mail, onRefresh }: { report?: RspamdReport | null; mail: ScoreInput; onRefresh: () => void }) {
  const native = scorePresentation(mail);
  return <section className="panel rspamd-comparison" aria-label="Rspamd engine comparison">
    <div className="rspamd-heading"><div><p className="eyebrow">RESEARCH · SECOND OPINION</p><h2>Rspamd — second opinion</h2></div>
      <span className="status">{comparisonLabel(report)}</span>
      {report?.status === 'pending' && <button type="button" onClick={onRefresh}>Refresh comparison</button>}
    </div>
    <p className="muted">NoiseFence decides independently. Rspamd checks the original message separately; its result never changes the NoiseFence verdict or delivery.</p>
    {report && (report.status === 'complete' || report.status === 'skipped') && report.score !== null ? <>
      {report.status === 'skipped' && <p>Rspamd skipped the full scan. Its returned points and early decision are shown for inspection and excluded from agreement statistics.</p>}
      <div className="rspamd-metrics">
        <div><span>NoiseFence · {native.label}</span><strong>{native.value?.toFixed(1) ?? '—'} <small>/ 100</small></strong></div>
        <div><span>Rspamd score</span><strong>{comparisonPoints(report.score)} <small>points</small></strong></div>
        <div><span>Reported threshold</span><strong>{comparisonPoints(report.required_score)} <small>points</small></strong></div>
        <div><span>Proposed action</span><strong>{report.action ?? '—'}</strong></div>
      </div>
      <p>NoiseFence engine verdict recorded for this comparison: <strong>{report.noisefence_outcome === 'unwanted' ? 'Unwanted' : report.noisefence_outcome === 'legitimate' ? 'Legitimate / marketing' : 'No decisive opinion'}</strong>. Recipient policies are shown in the delivery details.</p>
      <p className="notice">{comparisonExplanation(report)}</p>
      <p className="muted">Rspamd points and the NoiseFence index / 100 use different scales. The reported Rspamd threshold is not a universal boundary between legitimate mail and spam.</p>
      <details><summary>Rspamd symbols ({report.symbols.length})</summary>
        <div className="rspamd-symbols"><table><thead><tr><th>Symbol</th><th>Points</th></tr></thead><tbody>
          {report.symbols.map(symbol => <tr key={symbol.name}><td><code>{symbol.name}</code></td><td>{comparisonPoints(symbol.score)}</td></tr>)}
        </tbody></table></div>
      </details>
    </> : <p>{comparisonExplanation(report)} No Rspamd score is available. NoiseFence analysis remains independent. Comparisons start on new accepted SMTP messages; older messages are not replayed.</p>}
    {report && <details className="rspamd-provenance"><summary>Comparison provenance · {report.elapsed_ms} ms</summary>
      <dl><dt>Profile / installed version</dt><dd><code>{report.profile}</code></dd><dt>Server identification</dt><dd>{report.server ?? 'Not reported'}</dd><dt>Comparison settings SHA-256</dt><dd><code>{report.settings_sha256}</code></dd></dl>
      <p>Elapsed time includes waiting for a comparison worker. This asynchronous time is not added to the SMTP analysis time.</p>
    </details>}
  </section>;
}

export function RspamdOverview({ summary }: { summary: ComparisonSummary }) {
  return <section className="panel rspamd-comparison" aria-label="Engine comparison coverage">
    <div className="rspamd-heading"><h2>Engine comparison</h2><span className="status">Observation only</span></div>
    <div className="rspamd-metrics">
      <div><span>Completed / originals in scope</span><strong>{summary.completed} <small>/ {summary.total}</small></strong><small>{summary.rows} delivery variants</small></div>
      <div><span>Agreements / comparable verdicts</span><strong>{agreementRate(summary)}</strong><small>{summary.agreements} agree · {summary.disagreements} disagree</small></div>
      <div><span>Other outcomes</span><strong>{summary.inconclusive} <small>inconclusive</small></strong><small>{summary.total - summary.completed} not completed · {summary.pending} pending</small></div>
    </div>
    <p className="muted">Counts respect your access, domain and search criteria, across all comparison outcomes. Delivery variants sharing a comparison job count once. Historical rows without an original transaction ID are counted separately; skipped analyses remain in the coverage denominator. Use “Engines disagree” to select research examples; this creates no manual delivery task. Agreement is not a detection-quality metric.</p>
  </section>;
}
