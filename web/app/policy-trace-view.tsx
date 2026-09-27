import {
  orderingDescription,
  thresholdSource,
  traceOutcome,
  type PolicyTrace,
} from './policy-trace';

export function PolicyTraceDetails({ trace }: { trace?: PolicyTrace | null }) {
  if (!trace)
    return (
      <p className="muted small">Policy inheritance trace was not recorded.</p>
    );
  if (trace.version !== 'recipient-policy-trace-1')
    return (
      <p className="muted small">This policy trace requires a newer console.</p>
    );
  const name = (id: string) => trace.rules.find((r) => r.id === id)?.name ?? id;
  return (
    <details className="panel">
      <summary>Policy inheritance and rule decisions</summary>
      <p className="muted small">{orderingDescription(trace.ordering)}</p>
      <p>
        Threshold source: <strong>{thresholdSource(trace)}</strong>
      </p>
      <ol>
        {trace.profiles.map((p) => (
          <li key={`${p.scope}:${p.id}`}>
            <strong>{p.name}</strong> · {p.scope} ·{' '}
            {p.origin === 'personal' ? 'Personal' : 'Administrator'}
            {p.selected ? ' · Selected actions' : ''} ·{' '}
            {p.threshold == null
              ? 'Inherit threshold'
              : `Threshold ${p.threshold}`}
          </li>
        ))}
      </ol>
      {trace.malware_override ? (
        <p>Primary malware evidence overrides custom rule effects.</p>
      ) : (
        <p>
          Classification:{' '}
          {trace.category_rule
            ? `set by ${name(trace.category_rule)}`
            : 'engine and profile policy'}
          . Requested action:{' '}
          {trace.action_rule
            ? `set by ${name(trace.action_rule)}`
            : 'profile or global policy'}
          .
        </p>
      )}
      {trace.stopped_by && (
        <p>
          Processing stopped by <strong>{name(trace.stopped_by)}</strong>.
        </p>
      )}
      <ol>
        {trace.rules.map((r) => (
          <li key={r.id}>
            <strong>{r.name}</strong> · {r.scope} · {r.origin} · priority{' '}
            {r.priority}: {traceOutcome(r.outcome)}
            {r.outcome === 'matched' && (
              <span>
                {' '}
                · {r.category_before} → {r.category_after}; requested action{' '}
                {r.action_before} → {r.action_after}
              </span>
            )}
            {r.unavailable.length > 0 && (
              <span> · unavailable: {r.unavailable.join(', ')}</span>
            )}
          </li>
        ))}
      </ol>
      <p className="muted small">
        Rule effects precede operational action restrictions. Engine-category
        conditions use the original engine classification, not earlier rule
        overrides. Rule values and message contents are not included in this
        trace.
      </p>
    </details>
  );
}
