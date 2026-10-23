import { useEffect, useId, useRef, useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { api } from './client';
import { ConfirmDialog } from './console-ui';
import type { Settings } from './admin';
import { restoreDefaults } from './policies';
import { SettingsComparison } from './settings-review-view';
import { auditDescription, auditRevision } from './settings-review';
type Revision = { id: number; created: number; username: string };
type Audit = {
  created: number;
  username: string;
  action: string;
  object: string;
};
type Read<T> = { key: string; value: T | null; error: string; at: number };
const date = (at: number) => new Date(at * 1000).toLocaleString('en-GB');
export function SettingsHistory({
  owner,
  revision,
  settings,
  epoch,
  dirty,
  busy,
  onLoad,
}: {
  owner: string;
  revision: number;
  settings: Settings;
  epoch: number;
  dirty: boolean;
  busy: boolean;
  onLoad: (value: Settings, label: string) => void;
}) {
  const auditSearchId = useId();
  const [refresh, setRefresh] = useState(0),
    [revisions, setRevisions] = useState<Read<Revision[]> | null>(null),
    [audit, setAudit] = useState<Read<Audit[]> | null>(null);
  const [query, setQuery] = useState(''),
    [category, setCategory] = useState('all');
  const [preview, setPreview] = useState<{
      id: number;
      label: string;
      settings: Settings;
      base: number;
    } | null>(null),
    [previewError, setPreviewError] = useState(''),
    [loading, setLoading] = useState(false),
    [replace, setReplace] = useState(false);
  const previewRef = useRef<HTMLElement>(null),
    trigger = useRef<HTMLButtonElement | null>(null),
    request = useRef<AbortController | null>(null);
  const key = JSON.stringify([owner, epoch, refresh]);
  const history = revisions?.key === key ? revisions : null,
    log = audit?.key === key ? audit : null;
  useEffect(() => {
    const controller = new AbortController();
    async function read<T>(path: string, set: (v: Read<T>) => void) {
      try {
        const value = await api<T>(path, undefined, undefined, {
          signal: controller.signal,
          cache: 'no-store',
        });
        if (!controller.signal.aborted)
          set({ key, value, error: '', at: Date.now() / 1000 });
      } catch (e) {
        if (!controller.signal.aborted)
          set({
            key,
            value: null,
            error: (e as Error).message,
            at: Date.now() / 1000,
          });
      }
    }
    void read('/admin/revisions', setRevisions);
    void read('/admin/audit', setAudit);
    return () => controller.abort();
  }, [key]);
  useEffect(() => () => request.current?.abort(), []);
  useEffect(() => {
    if (preview || previewError) previewRef.current?.focus();
  }, [preview, previewError]);
  async function inspect(id: number, button: HTMLButtonElement) {
    request.current?.abort();
    const controller = new AbortController();
    request.current = controller;
    trigger.current = button;
    setLoading(true);
    setPreview(null);
    setPreviewError('');
    setReplace(false);
    try {
      const value = await api<Settings>(
        `/admin/revisions/${id}`,
        undefined,
        undefined,
        { signal: controller.signal, cache: 'no-store' },
      );
      if (!controller.signal.aborted)
        setPreview({
          id,
          label: id === 0 ? 'Base configuration' : `Revision ${id}`,
          settings: restoreDefaults(value),
          base: revision,
        });
    } catch (e) {
      if (!controller.signal.aborted) setPreviewError((e as Error).message);
    } finally {
      if (!controller.signal.aborted) setLoading(false);
    }
  }
  function close() {
    request.current?.abort();
    setPreview(null);
    setPreviewError('');
    setLoading(false);
    setReplace(false);
    requestAnimationFrame(() => trigger.current?.focus());
  }
  function load() {
    if (!preview || preview.base !== revision || busy) return;
    onLoad(preview.settings, preview.label);
    close();
  }
  const rows = (log?.value ?? []).filter(
    (row) =>
      (category === 'all' ||
        (category === 'configuration'
          ? row.action.startsWith('configuration') ||
            row.action.startsWith('model_set')
          : !row.action.startsWith('configuration') &&
            !row.action.startsWith('model_set'))) &&
      `${auditDescription(row.action)} ${row.action} ${row.username} ${row.object}`
        .toLowerCase()
        .includes(query.toLowerCase().trim()),
  );
  return (
    <section
      aria-label="Configuration history and administration audit"
      className="settings-history"
    >
      <div className="activation-heading">
        <div>
          <h2>Configuration history & audit</h2>
          <p className="small muted">
            Loaded editor: revision {revision}. Recorded events are not proof
            that every MX installed a policy. Check the activation panel.
          </p>
        </div>
        <Button
          variant="outline"
          disabled={busy}
          onClick={() => setRefresh((v) => v + 1)}
        >
          Refresh history & audit
        </Button>
      </div>
      <div className="admin-two-columns">
        <section className="panel">
          <h3>Retained configurations</h3>
          <p className="small muted">
            Up to 100 revisions. Previewing does not replace your draft or apply
            settings. Old schemas use current compatibility defaults; current
            provider credentials are preserved.
          </p>
          {!history && <output>Loading retained configurations…</output>}
          {history?.error && (
            <p role="alert" className="error">
              {history.error} Revision history is unavailable.
            </p>
          )}
          <Button
            variant="outline"
            disabled={busy || loading}
            onClick={(e) => void inspect(0, e.currentTarget)}
          >
            Preview base configuration
          </Button>
          <p className="small muted">
            Current bootstrap policy on local deployments; retained revision 0
            with central management.
          </p>
          {history?.value && (
            <>
              <p className="small muted">
                Checked {date(history.at)} · {history.value.length} retained
                revisions returned.
              </p>
              {!history.value.length && (
                <p>No saved revisions were returned.</p>
              )}
              <div className="revision-list">
                {history.value.map((row) => (
                  <div key={row.id}>
                    <span>
                      <strong>
                        Revision {row.id}
                        {row.id === revision ? ' · loaded here' : ''}
                      </strong>
                      <small>
                        {date(row.created)} · {row.username}
                      </small>
                    </span>
                    <Button
                      variant="ghost"
                      disabled={busy || loading}
                      onClick={(e) => void inspect(row.id, e.currentTarget)}
                    >
                      Preview revision {row.id}
                    </Button>
                  </div>
                ))}
              </div>
            </>
          )}
        </section>
        <section className="panel">
          <h3>Administration audit</h3>
          <p className="small muted">
            Most recent 200 retained events from this management backend. Search
            applies only to this loaded window; local MX events are not
            automatically aggregated.
          </p>
          {!log && <output>Loading audit…</output>}
          {log?.error && (
            <p role="alert" className="error">
              {log.error} Audit history is unavailable.
            </p>
          )}
          {log?.value && (
            <>
              <p className="small muted">
                Checked {date(log.at)} · {log.value.length} events returned.
              </p>
              <label htmlFor={auditSearchId}>
                Search loaded audit events
                <Input
                  id={auditSearchId}
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="Actor, action or reference"
                />
              </label>
              <label>
                Event type
                <select
                  value={category}
                  onChange={(e) => setCategory(e.target.value)}
                >
                  <option value="all">All recorded events</option>
                  <option value="configuration">Configuration & models</option>
                  <option value="other">Other administration</option>
                </select>
              </label>
              <p className="small muted">{rows.length} matching events.</p>
              <div className="audit-list">
                {rows.map((row, i) => {
                  const id = auditRevision(row.action, row.object);
                  return (
                    <article key={i}>
                      <strong>{auditDescription(row.action)}</strong>
                      <p>
                        {row.username} · {date(row.created)}
                      </p>
                      <p className="small muted">
                        Event: <code>{row.action}</code>
                        {row.object && (
                          <>
                            {' '}
                            · Reference: <code>{row.object}</code>
                          </>
                        )}
                      </p>
                      {id !== null && (
                        <Button
                          variant="outline"
                          disabled={busy || loading}
                          onClick={(e) => void inspect(id, e.currentTarget)}
                        >
                          Inspect revision {id}
                        </Button>
                      )}
                    </article>
                  );
                })}
              </div>
              {!rows.length && (
                <p>
                  No matching event in this loaded window. This does not prove
                  that no earlier event occurred.
                </p>
              )}
            </>
          )}
        </section>
      </div>
      {(loading || preview || previewError) && (
        <section
          ref={previewRef}
          tabIndex={-1}
          className="panel revision-preview"
          aria-label="Retained configuration preview"
        >
          <div className="activation-heading">
            <h3>
              {preview ? `${preview.label} preview` : 'Configuration preview'}
            </h3>
            <Button variant="outline" disabled={busy} onClick={close}>
              Close revision preview
            </Button>
          </div>
          {loading && <output>Loading the retained configuration…</output>}
          {previewError && (
            <p role="alert" className="error">
              {previewError} No draft or configuration was changed.
            </p>
          )}
          {preview && (
            <>
              <SettingsComparison
                before={settings}
                after={preview.settings}
                beforeLabel={`Loaded revision ${revision}`}
                afterLabel={preview.label}
              />
              <p className="notice">
                Loading this configuration creates an unsaved draft. Review it
                before applying it as a new revision. It does not restore old
                provider keys, model files, messages or databases.
              </p>
              {preview.base !== revision && (
                <p role="alert" className="error">
                  The loaded revision changed. Preview again before replacing
                  the draft.
                </p>
              )}
              <Button
                disabled={busy || preview.base !== revision}
                onClick={() => (dirty ? setReplace(true) : load())}
              >
                Use {preview.label.toLowerCase()} as draft
              </Button>
            </>
          )}
        </section>
      )}
      {replace && preview && (
        <ConfirmDialog
          title="Replace your unsaved configuration?"
          confirmLabel="Replace draft"
          busy={busy}
          danger
          onCancel={() => setReplace(false)}
          onConfirm={load}
        >
          <p>
            Load {preview.label.toLowerCase()} instead of the current unsaved
            draft. This does not apply it. Model-file selections will be
            cleared.
          </p>
        </ConfirmDialog>
      )}
    </section>
  );
}
