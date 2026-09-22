import { scoreAdjustment, scoreValue, type ScoringReport, type FusionAccounting } from './scoring-format';

export function ScoreAccounting({report}:{report?:ScoringReport|null}) {
  if (!report) return <p className="diagnostic-muted">Exact score accounting was not recorded for this message.</p>;
  return <details className="diagnostic-section">
    <summary>How the content index was calculated</summary>
    <p className="diagnostic-muted">Recorded policy: <code>{report.version}</code>. Contributions below are log-odds inputs to an advisory index, not probabilities. Rspamd points and comparison engines are not added. This is the content calculation; a qualified fusion model or an explicit rule may determine the final classification.</p>
    <dl className="diagnostic-facts">
      {report.baseline != null && <div><dt>Fixed rules baseline · not a learned prior</dt><dd>{scoreValue(report.baseline)}</dd></div>}
      <div><dt>Lexical model</dt><dd>{scoreValue(report.lexical)}</dd></div>
      <div><dt>Semantic contribution</dt><dd>{scoreValue(report.semantic)}</dd></div>
      <div><dt>Retained rules</dt><dd>{scoreValue(report.rules_total)}</dd></div>
      <div><dt>Total log-odds input</dt><dd>{scoreValue(report.total_logit)}</dd></div>
      <div><dt>Content risk index · 0–100</dt><dd>{scoreValue(report.score)}</dd></div>
    </dl>
    {report.score == null && <p className="diagnostic-callout">No usable content index. Invalid or inconsistent inputs are not interpreted as zero risk.</p>}
    {report.invalid_inputs > 0 && <p className="diagnostic-callout">{report.invalid_inputs} unrecognized weighted inputs prevented this calculation.</p>}
    <div className="table-scroll"><table><thead><tr><th>Signal</th><th>Occurrences</th><th>Proposed</th><th>Retained</th><th>Treatment</th></tr></thead>
      <tbody>{report.contributions.map(entry => <tr key={entry.id}><td><code>{entry.id}</code></td><td>{entry.occurrences}</td><td>{scoreValue(entry.proposed)}</td><td>{scoreValue(entry.retained)}</td><td>{scoreAdjustment(entry.adjustment)}</td></tr>)}</tbody>
    </table></div>
    <p className="diagnostic-muted">Identical message-level signals count once. Distinct correlated signals still need joint calibration; deduplication alone does not establish independence. The LLM contribution is not an independent confirmation of this index.</p>
  </details>;
}

export function FusionAccountingView({report,decisionSource}:{report?:FusionAccounting|null;decisionSource?:string}) {
  if (!report) return null;
  return <details className="diagnostic-section"><summary>Fusion family limits</summary>
    <p className="diagnostic-callout">{decisionSource === 'fusion' ? 'This model supplied the recorded detector decision. Recipient rules and delivery constraints remain separate.' : decisionSource ? 'This calculation did not supply the final detector decision.' : 'The role of this calculation in the decision was not recorded.'}</p>
    <p className="diagnostic-muted">Recorded model policy: <code>{report.version}</code>. These limits apply to learned log-odds contributions before calibration. They are separate from native-rule points. Observation mode does not change delivery.</p>
    <div className="table-scroll"><table><thead><tr><th>Family</th><th>Raw</th><th>Retained</th><th>Minimum</th><th>Maximum</th></tr></thead>
      <tbody>{Object.entries(report.families).map(([name, f]) => <tr key={name}><td>{name.replaceAll('_',' ')}</td><td>{scoreValue(f.raw)}</td><td>{scoreValue(f.retained)}{f.raw !== f.retained && ' · capped'}</td><td>{scoreValue(f.minimum)}</td><td>{scoreValue(f.maximum)}</td></tr>)}</tbody>
    </table></div><p>Model bias: {scoreValue(report.bias)} · Retained log-odds total: {scoreValue(report.total_logit)}</p>
    {report.model_sha256 && <p className="diagnostic-muted">Model fingerprint: <code>{report.model_sha256}</code></p>}
    <p className="diagnostic-muted">Policy fingerprint: <code>{report.policy_sha256}</code>. Changing a limit requires refitting, calibration and a new validation bound to the model. Family limits do not establish independent evidence or accuracy.</p>
  </details>;
}
