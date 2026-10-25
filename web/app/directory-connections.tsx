import type { Source } from './directory';
export type CollectionSchedule = {
  id: string;
  expires: number;
  interval_seconds: number;
  next_due: number;
  revoked_at: number | null;
  state: string;
  last_run: {
    request: { id: string; revision: number; deadline: number };
    state: string;
    completed_at: number | null;
  } | null;
};
export type SavedConnection = {
  source: Source;
  generation: string;
  owner: string;
  created: number;
  expires: number;
  status: string;
  schedule?: CollectionSchedule | null;
};
export type ConnectionsView = {
  revision: number;
  catalog_sha256: string | null;
  vault: string;
  connections: SavedConnection[];
};
export function connectionStatus(status: string) {
  return (
    (
      {
        configured: 'Access stored',
        expired: 'Expired',
        revoked: 'Revoked',
        authorization_changed: 'Administrator authorization changed',
        not_yet_valid: 'Not yet valid',
        key_unavailable: 'Encryption key unavailable',
        configuration_changed: 'Source configuration changed',
        directory_unavailable: 'Installed directory unavailable',
      } as Record<string, string>
    )[status] ?? 'Unavailable'
  );
}
export function canCollectSaved(
  value: SavedConnection,
  now = Math.floor(Date.now() / 1000),
) {
  return (
    value.status === 'configured' && value.created <= now && value.expires > now
  );
}
export function connectionLifetimeError(provider: string, minutes: number) {
  const maximum = ['entra', 'active_directory'].includes(provider)
    ? 90 * 24 * 60
    : 60;
  return !Number.isInteger(minutes) || minutes < 1 || minutes > maximum
    ? `Choose a whole number from 1 to ${maximum.toLocaleString('en-US')} minutes.`
    : null;
}
export function scheduleStatus(state: string) {
  return (
    (
      {
        scheduled: 'Scheduled',
        running: 'Collecting',
        awaiting_review: 'Candidate awaiting review',
        backoff: 'Retry delayed',
        stopped: 'Stopped',
        expired: 'Authorization expired',
        not_yet_valid: 'Not yet valid',
        outcome_unknown: 'Previous outcome unknown',
        access_unavailable: 'Access unavailable',
      } as Record<string, string>
    )[state] ?? 'Unavailable'
  );
}
export function scheduleError(
  entry: SavedConnection,
  username: string,
  minutes: number,
  expires: number,
  now = Math.floor(Date.now() / 1000),
) {
  if (entry.source.provider === 'active_directory')
    return 'AD exports are collected internally and uploaded with a signature; a public key cannot authorize a pull.';
  if (!canCollectSaved(entry, now))
    return 'Reload or replace unavailable access before scheduling.';
  if (entry.owner !== username)
    return 'Only the administrator who stored this access can authorize automatic collection.';
  if (!Number.isInteger(minutes) || minutes < 15 || minutes > 1440)
    return 'Choose an interval from 15 to 1,440 whole minutes.';
  if (!Number.isInteger(expires) || expires <= now || expires > entry.expires)
    return 'Choose an end time in the future, no later than the stored access expiry.';
  return null;
}
export function SavedConnections({
  value,
  busy,
  onCollect,
  onReplace,
  onRevoke,
  username,
  onSchedule,
  onStopSchedule,
  onInspect,
}: {
  value: ConnectionsView | null;
  busy: boolean;
  onCollect: (value: SavedConnection) => void;
  onReplace: (value: SavedConnection) => void;
  onRevoke: (value: SavedConnection) => void;
  username: string;
  onSchedule: (value: SavedConnection) => void;
  onStopSchedule: (value: SavedConnection) => void;
  onInspect: (id: string) => void;
}) {
  if (!value)
    return (
      <p className="muted small">
        Saved connection status is not available yet.
      </p>
    );
  return (
    <section
      className="directory-saved-connections"
      aria-label="Saved directory access"
    >
      <h4>
        Saved directory access{' '}
        <span className="muted">{value.connections.length} / 16</span>
      </h4>
      <p className="muted small">
        Encrypted on the management server. Stored access does not mean a
        provider login succeeded. Automatic collection needs a separate,
        expiring authorization. Every candidate still requires review and policy
        activation.
      </p>
      {value.vault === 'unavailable' && (
        <p className="alert error">
          The directory encryption key is unavailable. Restore the original key
          on the management server; it will not be replaced automatically.
        </p>
      )}
      {value.connections.length === 0 && (
        <p className="notice">
          No access is stored. Use the provider form to save an encrypted
          connection.
        </p>
      )}
      {value.connections.map((entry) => (
        <article className="directory-saved-connection" key={entry.source.id}>
          <header>
            <strong>{entry.source.label}</strong>
            <span className="badge">{connectionStatus(entry.status)}</span>
          </header>
          <p className="small muted">
            {entry.source.authority} · {entry.source.scopes.join(', ')}
          </p>
          <dl>
            <div>
              <dt>Provider</dt>
              <dd>
                {entry.source.provider === 'entra'
                  ? 'Microsoft Entra ID'
                  : entry.source.provider === 'google'
                    ? 'Google Workspace'
                    : entry.source.provider === 'aws_identity_store'
                      ? 'AWS Identity Store'
                      : entry.source.provider === 'active_directory'
                        ? 'Active Directory'
                        : entry.source.provider === 'okta'
                          ? 'Okta'
                          : entry.source.provider}
              </dd>
            </div>
            <div>
              <dt>Stored by</dt>
              <dd>{entry.owner}</dd>
            </div>
            <div>
              <dt>Expires</dt>
              <dd>{new Date(entry.expires * 1000).toLocaleString('en-GB')}</dd>
            </div>
          </dl>
          {entry.source.provider !== 'active_directory' && (
            <section
              className="directory-schedule-status"
              aria-label={`Collection schedule for ${entry.source.label}`}
            >
              <strong>
                {entry.schedule
                  ? scheduleStatus(entry.schedule.state)
                  : 'Automatic collection off'}
              </strong>
              {entry.schedule && (
                <>
                  <p className="small muted">
                    Every {entry.schedule.interval_seconds / 60} minutes ·
                    authorized until{' '}
                    {new Date(entry.schedule.expires * 1000).toLocaleString(
                      'en-GB',
                    )}
                  </p>
                  {['scheduled', 'backoff', 'outcome_unknown'].includes(
                    entry.schedule.state,
                  ) && (
                    <p className="small">
                      Next attempt no earlier than{' '}
                      {new Date(entry.schedule.next_due * 1000).toLocaleString(
                        'en-GB',
                      )}
                      .
                    </p>
                  )}
                  {entry.schedule.state === 'awaiting_review' && (
                    <p className="notice">
                      Review the collected candidate before applying the policy.
                      Nothing has been activated automatically.
                    </p>
                  )}
                  {entry.schedule.last_run && (
                    <button
                      type="button"
                      className="secondary"
                      disabled={busy}
                      onClick={() =>
                        onInspect(entry.schedule!.last_run!.request.id)
                      }
                    >
                      View last collection
                    </button>
                  )}
                </>
              )}
              <div className="actions">
                <button
                  type="button"
                  className="secondary"
                  disabled={
                    busy || !canCollectSaved(entry) || entry.owner !== username
                  }
                  onClick={() => onSchedule(entry)}
                >
                  {entry.schedule
                    ? 'Review schedule settings'
                    : 'Set up automatic collection'}
                </button>
                {entry.schedule && entry.schedule.revoked_at === null && (
                  <button
                    type="button"
                    className="secondary"
                    disabled={busy}
                    onClick={() => onStopSchedule(entry)}
                  >
                    Stop automatic collection
                  </button>
                )}
              </div>
              {entry.owner !== username && (
                <p className="small muted">
                  The access owner can enable a schedule. Any administrator can
                  stop it.
                </p>
              )}
            </section>
          )}
          {entry.source.provider === 'active_directory' && (
            <p className="notice">
              Public verification key only. Run the collector inside your
              organization, then upload its signed export within 15 minutes.
              Review is required before activation.
            </p>
          )}
          <details>
            <summary>Access generation</summary>
            <code>{entry.generation}</code>
            <p className="small muted">
              Reference only. The credential is never returned to this page.
            </p>
          </details>
          <div className="actions">
            <button
              type="button"
              disabled={busy || !canCollectSaved(entry)}
              onClick={() => onCollect(entry)}
            >
              {entry.source.provider === 'active_directory'
                ? 'Upload signed AD export'
                : 'Collect using saved access'}
            </button>
            <button
              type="button"
              className="secondary"
              disabled={busy || value.vault !== 'ready'}
              onClick={() => onReplace(entry)}
            >
              {entry.source.provider === 'active_directory'
                ? 'Replace verification key'
                : 'Replace access'}
            </button>
            <button
              type="button"
              className="secondary"
              disabled={busy || entry.status === 'revoked'}
              onClick={() => onRevoke(entry)}
            >
              Revoke access
            </button>
          </div>
        </article>
      ))}
    </section>
  );
}
