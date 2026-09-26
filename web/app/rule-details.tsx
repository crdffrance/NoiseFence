import {
  contribution,
  decisionExplanation,
  weightEffect,
  type DiagnosticReason,
} from './diagnostics-formatters';
import { scoreAdjustment, type ScoringReport } from './scoring-format';

export function RuleDetails({
  reasons,
  source,
  scoring,
}: {
  reasons: DiagnosticReason[];
  source?: string;
  scoring?: ScoringReport | null;
}) {
  const seen = new Set<string>();
  const entries = new Map(
    scoring?.contributions.map((entry) => [entry.id, entry]),
  );
  return (
    <div className="rule-diagnostics">
      <h3 className="subheading">Triggered signals</h3>
      <p>{decisionExplanation(source)}</p>
      <p className="diagnostic-muted">
        {scoring
          ? 'Retained weights come from the recorded calculation. Proposed weights may be excluded or already included in another finding.'
          : 'These are proposed signal weights. Exact retained contributions have not been loaded or were not recorded.'}{' '}
        They are not percentage points or independent votes, and do not sum to
        100.
      </p>
      {reasons.length ? (
        <ul className="diagnostic-rules">
          {reasons.map((reason, index) => {
            const entry = entries.get(reason.id);
            const duplicate = seen.has(reason.id);
            seen.add(reason.id);
            const summary = reason.id === 'model_contribution';
            const value = entry
              ? duplicate && entry.retained != null
                ? 0
                : entry.retained
              : scoring && !summary
                ? reason.weight === 0
                  ? 0
                  : null
                : reason.weight;
            return (
              <li key={`${reason.id}-${index}`}>
                <details className="signal-detail">
                  <summary>
                    <span className="signal-name">
                      <span>{reason.id.replaceAll('_', ' ')}</span>
                      <code className="diagnostic-rule-id">{reason.id}</code>
                    </span>
                    <span className="diagnostic-weight">
                      {reason.id === 'malware_priority' ? (
                        'Priority'
                      ) : (
                        <>
                          <strong>{contribution(value)}</strong>
                          <small>
                            {summary
                              ? 'model summary'
                              : scoring
                                ? 'retained log-odds'
                                : 'proposed log-odds'}
                          </small>
                        </>
                      )}
                    </span>
                  </summary>
                  <div className="signal-evidence">
                    <p>{reason.detail}</p>
                    <p className="diagnostic-muted">
                      {reason.id === 'malware_priority'
                        ? 'Antivirus priority · This signal is not a probabilistic weight.'
                        : summary
                          ? 'Model summary · already included; not an additional rule.'
                          : !scoring
                            ? 'Proposed weight · retained contribution not recorded.'
                            : entry
                              ? duplicate
                                ? 'Repeated occurrence · counted once in the recorded calculation.'
                                : scoreAdjustment(entry.adjustment)
                              : 'Diagnostic signal · not a retained weighted rule.'}
                      {entry?.subsumed_by && (
                        <>
                          {' '}
                          Included in <code>{entry.subsumed_by}</code>.
                        </>
                      )}
                      {entry && !duplicate && (
                        <> {weightEffect(value ?? Number.NaN)}</>
                      )}
                    </p>
                    {reason.id === 'model_contribution' && (
                      <p className="diagnostic-muted">
                        Summary of the lexical and semantic model already included
                        in the calculation; do not add it a second time.
                      </p>
                    )}
                  </div>
                </details>
              </li>
            );
          })}
        </ul>
      ) : (
        <p className="diagnostic-muted">
          No filter signal was recorded for this message.
        </p>
      )}
    </div>
  );
}
