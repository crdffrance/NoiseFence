import type { CustomPolicy } from './custom-filtering';

type Change = {
  section: string;
  key: string;
  change: string;
  fields: string[];
};
function canonical(value: unknown): string {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value && typeof value === 'object')
    return (
      '{' +
      Object.entries(value)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([key, item]) => JSON.stringify(key) + ':' + canonical(item))
        .join(',') +
      '}'
    );
  return JSON.stringify(value) ?? 'null';
}
export function policyChanges(
  saved: CustomPolicy | null,
  draft: CustomPolicy,
): Change[] {
  const changes: Change[] = [];
  if (
    (saved?.ordering ?? 'legacy_priority') !==
    (draft.ordering ?? 'legacy_priority')
  )
    changes.push({
      section: 'Ordering',
      key: 'policy',
      change: `${saved?.ordering ?? 'legacy_priority'} → ${draft.ordering ?? 'legacy_priority'}`,
      fields: [],
    });
  for (const section of ['profiles', 'bindings', 'rules'] as const) {
    const key = (row: Record<string, unknown>) =>
      String(section === 'bindings' ? row.scope : row.id);
    const previous = new Map(
      (saved?.[section] ?? []).map((row) => [
        key(row),
        row as Record<string, unknown>,
      ]),
    );
    const proposed = new Map(
      draft[section].map((row) => [key(row), row as Record<string, unknown>]),
    );
    for (const id of new Set([...previous.keys(), ...proposed.keys()])) {
      const before = previous.get(id),
        after = proposed.get(id);
      if (canonical(before) === canonical(after)) continue;
      const fields =
        before && after
          ? [...new Set([...Object.keys(before), ...Object.keys(after)])]
              .filter(
                (field) => canonical(before[field]) !== canonical(after[field]),
              )
              .sort()
          : [];
      changes.push({
        section,
        key: id,
        change: !before ? 'Added' : !after ? 'Removed' : 'Changed',
        fields,
      });
    }
  }
  return changes;
}
export function PolicyDraftChanges({
  saved,
  draft,
}: {
  saved: CustomPolicy | null;
  draft: CustomPolicy;
}) {
  const changes = policyChanges(saved, draft);
  return (
    <section className="panel" aria-label="Custom policy draft changes">
      <h3>Changes in this custom policy draft</h3>
      {changes.length ? (
        <ul>
          {changes.map((row) => (
            <li key={`${row.section}:${row.key}`}>
              <strong>
                {row.section} · {row.key}
              </strong>
              : {row.change}
              {row.fields.length ? ` (${row.fields.join(', ')})` : ''}
            </li>
          ))}
        </ul>
      ) : (
        <p>No custom profile, binding, rule or ordering changes.</p>
      )}
      <p className="muted small">
        Compared with the saved custom policy loaded in this editor. Global
        detector settings and personal preferences are outside this summary. Run
        the sample comparison to inspect affected classifications and effective
        actions; this list alone does not establish safety.
      </p>
    </section>
  );
}
