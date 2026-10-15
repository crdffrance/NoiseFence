import { Activity, ChevronDown } from 'lucide-react';
import { detectorGroups } from './filter-evidence';
import { duration } from './diagnostics-formatters';
import {
  observationName,
  observationResult,
  observationRole,
  observationScope,
  observationState,
  type ObservationReport,
} from './observations-format';

export function FilterOverview({
  report,
  loading,
  unavailable = false,
}: {
  report?: ObservationReport | null;
  loading: boolean;
  unavailable?: boolean;
}) {
  const groups = detectorGroups(report);
  return (
    <section className="filter-overview" aria-label="Recorded filter checks">
      <div className="filter-section-title">
        <h3>Checks at a glance</h3>
        <span className="muted small">
          Execution coverage, not a safety verdict
        </span>
      </div>
      {!groups.length ? (
        <p className="filter-empty">
          <Activity size={18} aria-hidden="true" />
          {loading
            ? 'Loading recorded filter checks…'
            : unavailable
              ? 'Detailed checks could not be loaded. Use Retry above; available signals remain below.'
              : report && ![1, 2, 3].includes(report.version)
                ? 'This detector report version is not supported by this console.'
                : 'No per-detector report was recorded. Available signals are listed below.'}
        </p>
      ) : (
        <div className="filter-check-grid">
          {groups.map((group) => (
            <details
              className={`filter-check ${group.state.toLowerCase()}`}
              key={group.id}
            >
              <summary>
                <span className="filter-check-title">
                  {group.label}
                  <small>
                    {group.observations.length}{' '}
                    {group.observations.length === 1 ? 'check' : 'checks'}
                    {group.inactive > 0 && ` · ${group.inactive} inactive`}
                    {group.excluded > 0 && ` · ${group.excluded} excluded`}
                  </small>
                </span>
                <span className="check-state">{group.state}</span>
                <ChevronDown size={15} aria-hidden="true" />
              </summary>
              <ul>
                {group.observations.map((observation, index) => (
                  <li key={`${observation.id}-${index}`}>
                    <div>
                      <strong>{observationName(observation.id)}</strong>
                      <span>{observationState(observation.state)}</span>
                    </div>
                    <p>{observationResult(observation)}</p>
                    <small>
                      {observationRole(observation.role)} ·{' '}
                      {observationScope(observation.scope)} ·{' '}
                      {duration(observation.elapsed_ms)}
                    </small>
                  </li>
                ))}
              </ul>
            </details>
          ))}
        </div>
      )}
      {!!report?.omitted && (
        <p className="filter-coverage-note">
          {report.omitted} additional observations were not retained in this
          bounded report.
        </p>
      )}
      {!!report?.observations.some((o) => o.role === 'comparison') && (
        <p className="filter-coverage-note">
          Comparison-only detectors are kept in the detailed observations.
          Rspamd is shown separately below.
        </p>
      )}
    </section>
  );
}
