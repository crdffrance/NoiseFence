import type { Source } from './directory';
export type SavedConnection = {
  source: Source;
  generation: string;
  owner: string;
  created: number;
  expires: number;
  status: string;
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
  const maximum = provider === 'entra' ? 90 * 24 * 60 : 60;
  return !Number.isInteger(minutes) || minutes < 1 || minutes > maximum
    ? `Choose a whole number from 1 to ${maximum.toLocaleString('en-US')} minutes.`
    : null;
}
export function SavedConnections({
  value,
  busy,
  onCollect,
  onReplace,
  onRevoke,
}: {
  value: ConnectionsView | null;
  busy: boolean;
  onCollect: (value: SavedConnection) => void;
  onReplace: (value: SavedConnection) => void;
  onRevoke: (value: SavedConnection) => void;
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
        provider login succeeded. Collections still require a click and a
        review.
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
                    : 'Okta'}
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
              Collect using saved access
            </button>
            <button
              type="button"
              className="secondary"
              disabled={busy || value.vault !== 'ready'}
              onClick={() => onReplace(entry)}
            >
              Replace access
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
