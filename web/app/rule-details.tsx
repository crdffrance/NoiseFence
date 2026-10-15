import {
  contribution,
  decisionExplanation,
  weightEffect,
  type DiagnosticReason,
} from './diagnostics-formatters';
import { scoreAdjustment, type ScoringReport } from './scoring-format';
import { useId, useState } from 'react';
import { Search } from 'lucide-react';
import {
  effectLabels,
  evidenceRows,
  matchesEvidence,
  signalName,
  type EffectFilter,
} from './filter-evidence';

export function RuleDetails({
  reasons,
  source,
  scoring,
}: {
  reasons: DiagnosticReason[];
  source?: string;
  scoring?: ScoringReport | null;
}) {
  const searchId = useId();
  const [query, setQuery] = useState('');
  const [effect, setEffect] = useState<EffectFilter>('all');
  const rows = evidenceRows(reasons, scoring);
  const visible = rows.filter((row) => matchesEvidence(row, query, effect));
  return (
    <div className="rule-diagnostics">
      <div className="filter-section-title">
        <h3>Signals & explanations</h3>
        <span className="signal-count" aria-live="polite">
          {visible.length} of {rows.length}
        </span>
      </div>
      <p className="filter-coverage-note">{decisionExplanation(source)}</p>
      {!scoring && rows.length > 0 && (
        <p className="filter-coverage-note">
          Proposed effects only — the retained calculation is unavailable.
        </p>
      )}
      {rows.length > 0 && (
        <div className="signal-toolbar">
          <label className="signal-search" htmlFor={searchId}>
            <Search size={17} aria-hidden="true" />
            <span className="sr-only">Search filter signals</span>
            <input
              id={searchId}
              type="search"
              placeholder="Search signals or evidence…"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
            />
          </label>
          <div className="signal-filters" aria-label="Filter signals by effect">
            {Object.entries(effectLabels).map(([key, label]) => (
              <button
                type="button"
                key={key}
                aria-pressed={effect === key}
                onClick={() => setEffect(key as EffectFilter)}
              >
                {label}
                <span>
                  {
                    rows.filter((row) => key === 'all' || row.effect === key)
                      .length
                  }
                </span>
              </button>
            ))}
          </div>
        </div>
      )}
      <details className="signal-weight-help">
        <summary>How to read signal weights</summary>
        <p className="diagnostic-muted">
          {scoring
            ? 'Retained weights come from the recorded calculation. Proposed weights may be excluded or already included in another finding.'
            : 'These are proposed signal weights. Exact retained contributions have not been loaded or were not recorded.'}{' '}
          They are not percentage points or independent votes, and do not sum to
          100.
        </p>
      </details>
      {reasons.length ? (
        <ul className="diagnostic-rules">
          {visible.map(
            ({
              reason,
              index,
              entry,
              duplicate,
              summary,
              value,
              effect: rowEffect,
            }) => {
              return (
                <li
                  key={`${reason.id}-${index}`}
                  className={`signal-row ${rowEffect}`}
                >
                  <details className="signal-detail">
                    <summary>
                      <span className="signal-name">
                        <span>{signalName(reason.id)}</span>
                        <span className="signal-effect">
                          {reason.id === 'malware_priority'
                            ? 'Malware priority'
                            : summary
                              ? 'Model summary'
                              : duplicate
                                ? 'Repeated occurrence'
                                : rowEffect === 'raises'
                                  ? 'Raises the index'
                                  : rowEffect === 'lowers'
                                    ? 'Lowers the index'
                                    : value === null
                                      ? 'Weight not recorded'
                                      : 'Context or excluded contribution'}
                        </span>
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
                      <code className="diagnostic-rule-id">{reason.id}</code>
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
                          Summary of the lexical and semantic model already
                          included in the calculation; do not add it a second
                          time.
                        </p>
                      )}
                    </div>
                  </details>
                </li>
              );
            },
          )}
        </ul>
      ) : (
        <p className="diagnostic-muted">
          No filter signal was recorded for this message.
        </p>
      )}
      {rows.length > 0 && visible.length === 0 && (
        <p className="filter-empty">
          No signals match these filters.{' '}
          <button
            type="button"
            onClick={() => {
              setQuery('');
              setEffect('all');
            }}
          >
            Clear filters
          </button>
        </p>
      )}
    </div>
  );
}
