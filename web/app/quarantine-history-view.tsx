import { useEffect, useRef, useState } from 'react';
import { Button } from '@/components/ui/button';
import { api } from './client';
import { deliveryStatus } from './diagnostics-formatters';
import {
  holdState,
  receiptAwaitingState,
  requestSummary,
  quarantineEvent,
  type HeldRecipient,
  type QuarantineHistory,
} from './quarantine-history';
const date = (value: number) => new Date(value * 1000).toLocaleString('en-GB');
export function QuarantineLifecycle({
  messageId,
  recipient,
  revision,
  focusRequest,
  busy,
  onRequest,
  onCurrent,
}: {
  messageId: string;
  recipient: HeldRecipient;
  revision: number;
  focusRequest: number;
  busy: boolean;
  onRequest: (address: string, action: 'release' | 'delete') => void;
  onCurrent: (view: QuarantineHistory) => void;
}) {
  const [open, setOpen] = useState(false),
    [response, setResponse] = useState<{
      key: string;
      view: QuarantineHistory | null;
      error: string;
    } | null>(null),
    [reload, setReload] = useState(0),
    [at, setAt] = useState(() => Date.now() / 1000);
  const sequence = useRef(0);
  const summary = useRef<HTMLElement>(null);
  useEffect(() => {
    if (focusRequest > 0) summary.current?.focus({ preventScroll: true });
  }, [focusRequest]);
  const requestKey = JSON.stringify([
    messageId,
    recipient.address,
    revision,
    reload,
  ]);
  const current = response?.key === requestKey ? response : null;
  const view = current?.view ?? null,
    error = current?.error ?? '',
    loading = open && !current;
  useEffect(() => {
    const deadlines = [
      ...(recipient.status === 'quarantined' && recipient.held_until != null
        ? [recipient.held_until]
        : []),
      ...(view?.requests ?? [])
        .filter((r) => r.result === 'pending')
        .map((r) => r.expires_at),
    ].filter((t) => Number.isFinite(t) && t > at);
    if (!deadlines.length) return;
    const delay = Math.max(0, Math.min(...deadlines) * 1000 - Date.now() + 50);
    const timer = setTimeout(
      () => setAt(Date.now() / 1000),
      Math.min(delay, 2147483647),
    );
    return () => clearTimeout(timer);
  }, [recipient.status, recipient.held_until, view, at]);
  useEffect(() => {
    if (!open) return;
    const controller = new AbortController(),
      id = ++sequence.current;
    api<QuarantineHistory>(
      `/messages/${encodeURIComponent(messageId)}/quarantine?recipient=${encodeURIComponent(recipient.address)}`,
      undefined,
      undefined,
      { signal: controller.signal, cache: 'no-store' },
    )
      .then((next) => {
        if (controller.signal.aborted || sequence.current !== id) return;
        if (
          next.schema !== 'quarantine-history-1' ||
          next.message_id !== messageId ||
          next.recipient !== recipient.address
        )
          throw new Error(
            'The history does not match this recipient. Refresh before continuing.',
          );
        setResponse({ key: requestKey, view: next, error: '' });
        setAt(Date.now() / 1000);
        onCurrent(next);
      })
      .catch((e) => {
        if (!controller.signal.aborted && sequence.current === id)
          setResponse({
            key: requestKey,
            view: null,
            error: (e as Error).message,
          });
      });
    return () => controller.abort();
  }, [open, messageId, recipient.address, requestKey, onCurrent]);
  const state = holdState(recipient, at);
  const awaitingState = receiptAwaitingState(view);
  const eligible =
    recipient.status === 'quarantined' ||
    recipient.held_until != null ||
    recipient.released_at != null ||
    ['expired', 'discarded'].includes(recipient.status);
  if (!eligible) return null;
  return (
    <div className="quarantine-lifecycle">
      {recipient.status === 'quarantined' && (
        <>
          <p className={state === 'held' ? 'small muted' : 'notice'}>
            {state === 'elapsed'
              ? 'Retention deadline passed. Release and discard are unavailable; cleanup may still be pending.'
              : state === 'unknown'
                ? 'The retention deadline is unavailable. Refresh history or contact the administrator before acting.'
                : state === 'pending'
                  ? 'Command requested; execution is not yet confirmed by the MX.'
                  : `Held until ${date(recipient.held_until!)}.`}
          </p>
          {awaitingState && (
            <p className="notice">
              The MX confirmed a command, but this delivery snapshot still shows
              quarantine. Refresh history before requesting another action.
            </p>
          )}
          <div className="feedback-actions">
            <Button
              disabled={busy || state !== 'held' || loading || awaitingState}
              onClick={() => onRequest(recipient.address, 'release')}
            >
              Release and transmit
            </Button>
            <Button
              variant="outline"
              className="danger"
              disabled={busy || state !== 'held' || loading || awaitingState}
              onClick={() => onRequest(recipient.address, 'delete')}
            >
              Discard delivery
            </Button>
          </div>
        </>
      )}
      <details
        onToggle={(e) => {
          setOpen(e.currentTarget.open);
          if (e.currentTarget.open) setReload((v) => v + 1);
        }}
      >
        <summary ref={summary}>
          Quarantine history · {recipient.address}
        </summary>
        {open && (
          <>
            <p className="small muted">
              Only this authorized recipient is shown. Requests, MX receipts and
              delivery state are separate; no message content is loaded.
            </p>
            <Button
              variant="outline"
              disabled={loading || busy}
              onClick={() => setReload((v) => v + 1)}
            >
              {loading ? 'Loading history…' : 'Refresh quarantine history'}
            </Button>
            {error && (
              <p role="alert" className="error">
                {error} History is unavailable; this is not evidence of
                successful execution.
              </p>
            )}
            {view && (
              <>
                <p>
                  Last checked {date(view.checked_at)}
                  {view.node ? ` · ${view.node}` : ''}. Recorded delivery:{' '}
                  <strong>{deliveryStatus(view.status)}</strong>.
                </p>
                {view.source !== 'local' && (
                  <p className="small muted">
                    Delivery snapshot last synchronized:{' '}
                    {view.snapshot_at == null
                      ? 'unavailable'
                      : date(view.snapshot_at)}
                    . The owning MX may have newer state.
                  </p>
                )}
                {view.held_until != null && (
                  <p>
                    Original quarantine deadline: {date(view.held_until)}.{' '}
                    {view.released_at != null
                      ? 'This deadline no longer applies after release.'
                      : view.status === 'quarantined'
                        ? 'Expiry ends the hold without transmitting this delivery.'
                        : 'This delivery is no longer held.'}{' '}
                    Shared payload cleanup and backup retention are separate.
                  </p>
                )}
                {view.released_at != null && (
                  <p>
                    Release recorded: {date(view.released_at)}. The SMTP retry
                    period starts at release.
                  </p>
                )}
                <p className="small muted">
                  {view.raw_available
                    ? 'Payload recorded as available in the active queue.'
                    : 'Payload recorded as unavailable in the active queue.'}{' '}
                  This does not describe every replica or backup.
                </p>
                {view.events.length > 0 && (
                  <>
                    <h3>Recorded local actions</h3>
                    <ol>
                      {view.events.map((e, i) => (
                        <li key={i}>
                          <strong>
                            {quarantineEvent[e.action] ?? 'Unrecognized action'}
                          </strong>
                          <p className="small muted">
                            {date(e.at)} · {e.actor}
                          </p>
                        </li>
                      ))}
                    </ol>
                  </>
                )}
                {view.requests.length > 0 && (
                  <>
                    <h3>Remote requests and receipts</h3>
                    <ol>
                      {view.requests.map((r) => (
                        <li key={r.id}>
                          <strong>
                            {r.action === 'release'
                              ? 'Release requested'
                              : 'Discard requested'}
                          </strong>
                          <p className="small muted">
                            {date(r.requested_at)} · {r.actor} · {r.node}
                          </p>
                          <p>
                            {requestSummary(r, Math.max(at, view.checked_at))}
                          </p>
                          {r.finished_at != null && (
                            <p className="small muted">
                              Request closure recorded: {date(r.finished_at)}.
                            </p>
                          )}
                          {r.acknowledged_at != null && (
                            <p className="small muted">
                              MX receipt recorded: {date(r.acknowledged_at)}.
                            </p>
                          )}
                          <code>{r.id}</code>
                        </li>
                      ))}
                    </ol>
                  </>
                )}
                {!view.events.length && !view.requests.length && (
                  <p>
                    No retained action or request is available for this
                    recipient.
                  </p>
                )}
                <p className="small muted">
                  Only actions explicitly linked to this message and recipient
                  are shown. Older actions may be unavailable. History is
                  retained for up to 30 days and limited to 50 local actions and
                  50 requests.
                  {view.events_truncated || view.requests_truncated
                    ? ' Older entries were omitted from this view.'
                    : ''}
                  {view.source !== 'local'
                    ? ' Local MX audit entries are not replicated here; recorded recipient state and central command receipts remain available.'
                    : ''}
                </p>
              </>
            )}
          </>
        )}
      </details>
    </div>
  );
}
