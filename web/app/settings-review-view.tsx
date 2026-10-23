import { useId, useMemo, useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  canonicalSetting,
  settingChanges,
  changePath,
  settingValue,
  settingSections,
  settingTitle,
} from './settings-review';
export function SettingsComparison({
  before,
  after,
  beforeLabel,
  afterLabel,
}: {
  before: unknown;
  after: unknown;
  beforeLabel: string;
  afterLabel: string;
}) {
  const searchId = useId();
  const [query, setQuery] = useState(''),
    [page, setPage] = useState(0);
  const a = canonicalSetting(before),
    b = canonicalSetting(after);
  const changes = useMemo(
    () =>
      settingChanges(
        a === undefined ? undefined : JSON.parse(a),
        b === undefined ? undefined : JSON.parse(b),
      ),
    [a, b],
  );
  const matching = changes.filter((row) =>
    `${settingSections[row.path[0]] ?? ''} ${changePath(row.path)}`
      .toLowerCase()
      .includes(query.toLowerCase().trim()),
  );
  const current = Math.min(
    page,
    Math.max(0, Math.ceil(matching.length / 20) - 1),
  );
  return (
    <section
      className="settings-comparison"
      aria-label="Configuration value comparison"
    >
      <p>
        <strong>{changes.length} changed values</strong> · {beforeLabel} →{' '}
        {afterLabel}.
      </p>
      <details className="settings-comparison-scope">
        <summary>Scope and consequences</summary>
        <p className="small muted">
          These are normalized configuration values, not message predictions or
          proof of activation. Array indexes start at zero and preserve rule and
          route order. Host installation settings and provider key bytes are
          outside this comparison.
        </p>
        {changes.some(
          (row) => row.path[0] === 'domains' || row.path[0] === 'gateways',
        ) && (
          <p className="notice">
            Domain and route changes affect future SMTP transactions.
            Destination verification refuses unknown mailboxes and defers
            unavailable checks. A fallback changes who receives mail; accepting
            every address does not create an upstream mailbox.
          </p>
        )}
        {changes.some((row) => row.path[0] === 'actions') && (
          <p className="small muted">
            Quarantine retention applies to newly held deliveries; expiry
            discards them. Existing deadlines remain unchanged. Observation
            records intended actions while delivering unchanged; tagging still
            requires Proton and ARC validation.
          </p>
        )}
      </details>
      {changes.length > 0 && (
        <>
          <label htmlFor={searchId}>
            Find a changed field
            <Input
              id={searchId}
              value={query}
              onChange={(e) => {
                setQuery(e.target.value);
                setPage(0);
              }}
              placeholder="Domain, threshold, quota, rule…"
            />
          </label>
          <p className="small muted">
            {matching.length} matching changes. Showing{' '}
            {matching.length ? current * 20 + 1 : 0}–
            {Math.min(matching.length, (current + 1) * 20)}.
          </p>
          <div className="settings-change-list">
            {matching.slice(current * 20, (current + 1) * 20).map((row) => (
              <article key={changePath(row.path)}>
                <p>
                  <strong>
                    {settingSections[row.path[0]] ?? 'Configuration'}
                  </strong>
                </p>
                <p className="settings-field-name">{settingTitle(row.path)}</p>
                <code>{changePath(row.path)}</code>
                <div className="settings-values">
                  {[
                    [beforeLabel, row.before],
                    [afterLabel, row.after],
                  ].map(([label, value], i) => (
                    <div key={i}>
                      <strong>{String(label)}</strong>
                      <pre>{settingValue(value)}</pre>
                    </div>
                  ))}
                </div>
              </article>
            ))}
          </div>
          {matching.length > 20 && (
            <div className="pagination">
              <Button
                variant="outline"
                disabled={current === 0}
                onClick={() => setPage(current - 1)}
              >
                Previous changes
              </Button>
              <span>
                Page {current + 1} of {Math.ceil(matching.length / 20)}
              </span>
              <Button
                variant="outline"
                disabled={(current + 1) * 20 >= matching.length}
                onClick={() => setPage(current + 1)}
              >
                Next changes
              </Button>
            </div>
          )}
        </>
      )}
      {!changes.length && (
        <p>
          No configuration value changes. Any explicit model-file selection is
          shown separately.
        </p>
      )}
    </section>
  );
}
