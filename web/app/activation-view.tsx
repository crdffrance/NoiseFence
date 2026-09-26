'use client';
import { useCallback, useEffect, useRef, useState } from 'react';
import { Button } from '@/components/ui/button';
import { api, type User } from './client';
import {
  activationLabel,
  incidentDescription,
  type Activation,
} from './activation';

export function useActivation(user: User, administrator: boolean) {
  const [view, setView] = useState<Activation | null>(null);
  const [error, setError] = useState('');
  const requestId = useRef(0);
  const path = administrator
    ? '/admin/cluster/activation/view'
    : '/preferences/activation';
  const refresh = useCallback(
    async (signal?: AbortSignal) => {
      const id = ++requestId.current;
      try {
        const next = await api<Activation>(path, undefined, undefined, {
          signal,
        });
        if (!signal?.aborted && id === requestId.current) {
          setView(next);
          setError('');
        }
      } catch (e) {
        if (!signal?.aborted && id === requestId.current)
          setError((e as Error).message);
      }
    },
    [path],
  );
  useEffect(() => {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    async function poll() {
      await refresh(controller.signal);
      if (!controller.signal.aborted)
        timer = setTimeout(() => void poll(), 3000);
    }
    void poll();
    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, [refresh, user.username]);
  return { view, error, refresh };
}
export function ActivationPanel({
  state,
  user,
  administrator = false,
  allowEnrollment = false,
}: {
  state: ReturnType<typeof useActivation>;
  user: User;
  administrator?: boolean;
  allowEnrollment?: boolean;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const { view } = state;
  async function change(operation: 'abort' | 'recover' | 'enroll') {
    if (!view) return;
    setBusy(true);
    setError('');
    try {
      if (operation === 'enroll') {
        const current = await api<{ revision: number; settings: unknown }>(
          '/admin/config',
        );
        await api(
          '/admin/cluster/activation',
          { revision: current.revision, settings: current.settings },
          user.csrf,
        );
      } else {
        await api(
          `/admin/cluster/activation/${operation}`,
          { epoch: view.epoch },
          user.csrf,
        );
      }
      await state.refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  if (!view && !state.error)
    return <output>Checking policy activation…</output>;
  if (view && !view.coordinated && !allowEnrollment && !state.error)
    return null;
  return (
    <section
      className="management-card activation-panel"
      aria-label="Policy activation"
    >
      <div className="activation-heading">
        <div>
          <p className="eyebrow">POLICY ACTIVATION</p>
          <h2>
            {view && !state.error
              ? activationLabel(view)
              : 'Activation status unavailable'}
          </h2>
        </div>
        <Button
          variant="outline"
          disabled={busy}
          onClick={() => void state.refresh()}
        >
          Refresh status
        </Button>
      </div>
      {(state.error || error) && (
        <p role="alert" className="error">
          {state.error || error} Status may be stale; reload before saving.
        </p>
      )}
      {view?.coordinated && (
        <>
          {view.pending && (
            <p className="small muted">
              The form shows installed settings. Submitted changes appear there
              after activation; unsaved drafts are preserved.
            </p>
          )}
          {administrator ? (
            <dl className="activation-facts">
              <div>
                <dt>Installed here</dt>
                <dd>Revision {view.installed_revision}</dd>
              </div>
              <div>
                <dt>Committed centrally</dt>
                <dd>
                  {view.committed_revision === null
                    ? 'Not recorded'
                    : `Revision ${view.committed_revision}`}
                </dd>
              </div>
              <div>
                <dt>Proposed revision</dt>
                <dd>{view.epoch?.revision ?? 'Not recorded'}</dd>
              </div>
              <div>
                <dt>Local SMTP admission</dt>
                <dd>{view.smtp_ready ? 'Ready' : 'Temporarily deferred'}</dd>
              </div>
            </dl>
          ) : (
            <p>
              {view.pending
                ? 'A policy change is in progress. Further preference saves will be available after it resolves.'
                : 'Preferences can be saved for future messages.'}
            </p>
          )}
          {view.personal_change && (
            <p>
              Your change for <strong>{view.personal_change.scope}</strong>:
              revision {view.personal_change.revision} ·{' '}
              {view.personal_change.phase}.
            </p>
          )}
          {view.incident && (
            <p role="alert" className="error">
              The activation step failed at{' '}
              {new Date(view.incident.at * 1000).toLocaleString('en-GB')}.{' '}
              {incidentDescription(view.incident.code, administrator)}
            </p>
          )}
          {administrator && view.participants && (
            <>
              <ul className="activation-members">
                {Object.entries(view.participants).map(([id, progress]) => (
                  <li key={id}>
                    <strong>{id}</strong>
                    <span>
                      {progress === 'waiting'
                        ? 'Waiting for preparation'
                        : progress === 'prepared'
                          ? 'Prepared · not installed yet'
                          : 'Installed · acknowledged'}
                    </span>
                  </li>
                ))}
              </ul>
              <p className="small muted">
                An installed policy can still be fenced. Release is authorized
                only after all MXs acknowledge installation; local SMTP
                readiness is shown separately. Accepted messages keep their
                recorded decisions.
              </p>
            </>
          )}
          {administrator && (
            <div className="activation-controls">
              {view.abortable && (
                <Button
                  variant="outline"
                  disabled={busy || !!state.error}
                  onClick={() => void change('abort')}
                >
                  Cancel staged change
                </Button>
              )}
              {view.recoverable && (
                <Button
                  variant="outline"
                  disabled={busy || !!state.error}
                  onClick={() => void change('recover')}
                >
                  Restore previous policy
                </Button>
              )}
              {view.recoverable && (
                <p className="small muted">
                  Restoration creates a new coordinated revision. SMTP
                  acceptance resumes after every MX installs it.
                </p>
              )}
            </div>
          )}
        </>
      )}
      {view &&
        !view.coordinated &&
        allowEnrollment &&
        administrator &&
        view.coordinator && (
          <>
            <p>
              Coordinate future settings and personal preference changes across
              all registered MXs. Each change temporarily defers new SMTP
              acceptance until every MX is ready. Existing queued deliveries
              continue.
            </p>
            <p className="small muted">
              Every enabled MX must report this protocol and the same current
              policy. This action enrolls the cluster with its current settings;
              it does not change filtering or observation mode.
            </p>
            <Button
              disabled={busy || !!state.error}
              onClick={() => void change('enroll')}
            >
              {busy ? 'Submitting…' : 'Enable coordinated changes'}
            </Button>
          </>
        )}
    </section>
  );
}
