import {
  contribution,
  decisionExplanation,
  weightEffect,
  type DiagnosticReason,
} from './diagnostics-formatters';

export function RuleDetails({
  reasons,
  source,
}: {
  reasons: DiagnosticReason[];
  source?: string;
}) {
  return (
    <div className="rule-diagnostics">
      <h3 className="subheading">Triggered filters and signals</h3>
      <p>{decisionExplanation(source)}</p>
      <p className="diagnostic-muted">
        Log-odds contributions affect the calculation before conversion to a risk index. They are not percentage points or independent votes, and do not sum to 100.
      </p>
      {reasons.length ? (
        <ul className="diagnostic-rules">
          {reasons.map((reason, index) => (
            <li key={`${reason.id}-${index}`}>
              <div>
                <code className="diagnostic-rule-id">{reason.id}</code>
                <p>{reason.detail}</p>
                <p className="diagnostic-muted">
                  {reason.id === 'malware_priority'
                    ? "Antivirus priority · This signal is not a probabilistic weight."
                    : weightEffect(reason.weight)}
                </p>
                {reason.id === 'model_contribution' && (
                  <p className="diagnostic-muted">
                    Summary of the lexical and semantic model already included in the calculation; do not add it a second time.
                  </p>
                )}
              </div>
              <span className="diagnostic-weight">
                {reason.id === 'malware_priority' ? (
                  "Priority"
                ) : (
                  <>
                    <strong>{contribution(reason.weight)}</strong>
                    <small>log-odds</small>
                  </>
                )}
              </span>
            </li>
          ))}
        </ul>
      ) : (
        <p className="diagnostic-muted">
          No filter signal was recorded for this message.
        </p>
      )}
    </div>
  );
}
