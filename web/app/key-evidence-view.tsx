import { keyEvidence } from './key-evidence';
import { scoreValue } from './scoring-format';
import type { MessageDiagnostics, DiagnosticReason } from './diagnostics-formatters';

export function KeyEvidenceSummary({ analysis, reasons, source }: {
  analysis: MessageDiagnostics['analysis']; reasons: DiagnosticReason[]; source?: string;
}) {
  const inputs = keyEvidence(source, reasons, analysis.scoring, analysis.fusion_combination);
  return <section className="diagnostic-section" aria-label="Leading recorded inputs">
    <h3>Leading recorded inputs</h3>
    {source === 'antivirus'
      ? <p>Malware protection takes priority over the content index.</p>
      : inputs.length ? <ol className="key-evidence-list">{inputs.map(input => <li key={input.id}>
        <strong>{input.label}</strong><span className={input.value > 0 ? 'evidence-raises' : 'evidence-lowers'}>
          {input.value > 0 ? '+' : ''}{scoreValue(input.value)} log-odds · {input.value > 0 ? 'raises' : 'lowers'} index
        </span><p>{input.detail}</p>
      </li>)}</ol> : <p>No comparable retained contributions were recorded.</p>}
    <p className="diagnostic-muted">Up to three largest recorded contributions in this calculation. Context safeguards and recipient rules can take precedence; their decision and action appear above. These contributions are not probabilities. Rspamd is excluded.</p>
  </section>;
}
