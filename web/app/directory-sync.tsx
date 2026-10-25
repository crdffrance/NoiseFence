import { useEffect, useState } from 'react';
import { CloudDownload, RefreshCw } from 'lucide-react';
import { api, type User } from './client';
import {
  preparedMatches,
  sourceError,
  type Source,
  type SourceStatus,
  type DirectoryPrepared,
} from './directory';
export type SyncStatus = {
  id: string;
  source_id: string;
  started_at: number;
  deadline: number;
  state: string;
  reason: string | null;
  stale: boolean;
  installed: boolean;
  prepared: DirectoryPrepared | null;
};
export function syncMessage(job: SyncStatus) {
  if (job.state === 'ready' && job.installed)
    return 'This collected directory is installed. Future changes require a new collection and review.';
  if (job.state === 'running')
    return 'Collecting directory records. The installed directory remains active.';
  if (job.state === 'outcome_unknown')
    return 'No completion receipt was recorded before the deadline. Check status again before retrying; no result has been activated.';
  if (job.state === 'ready' && job.stale)
    return 'Collection completed against an older configuration. Reload settings and collect again before review.';
  if (job.state === 'ready')
    return 'Collection completed. Review the candidate and apply the policy to activate it.';
  const failures: Record<string, string> = {
    collection:
      'Collection failed or the provider refused access. Check the tenant, read permissions and credential.',
    stale:
      'The configuration changed or another policy operation was in progress. Reload settings before collecting again.',
    preparation:
      'The candidate could not be prepared. Check storage, source consistency and protected identities that may be missing.',
    authorization:
      'The administrator session expired or its privileges changed. Sign in again.',
    deadline:
      'The synchronization deadline expired. No result has been activated.',
  };
  return (
    failures[job.reason ?? ''] ??
    'Synchronization result unavailable. The installed directory is unchanged.'
  );
}
export function canReviewSync(
  job: SyncStatus,
  revision: number,
  installed: string | null,
) {
  return (
    job.state === 'ready' &&
    !job.installed &&
    !job.stale &&
    !!job.prepared &&
    preparedMatches(job.prepared, revision, installed)
  );
}
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export function entraFormError(
  source: Source,
  domains: string[],
  client: string,
  secret: string,
) {
  return source.provider !== 'entra'
    ? 'Choose a Microsoft Entra source.'
    : sourceError({ ...source, provider: 'manual' }, domains) ||
        (!uuid.test(source.authority) || !uuid.test(client)
          ? 'Enter the tenant and application UUIDs.'
          : !secret || new TextEncoder().encode(secret).length > 4096
            ? 'Enter an application secret of at most 4 KiB.'
            : null);
}
export function oktaFormError(
  source: Source,
  domains: string[],
  token: string,
) {
  const org =
    /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.(?:okta\.com|okta-emea\.com|oktapreview\.com)$/;
  return source.provider !== 'okta'
    ? 'Choose an Okta source.'
    : sourceError({ ...source, provider: 'manual' }, domains) ||
        (!org.test(source.authority)
          ? 'Enter the standard Okta org hostname, without https:// or a path.'
          : !/^[A-Za-z0-9._~+/=-]{1,8192}$/.test(token)
            ? 'Enter a scoped OAuth access token of at most 8 KiB, without the Bearer prefix.'
            : null);
}
export function DirectorySync({
  user,
  revision,
  installed,
  domains,
  sources,
  disabled,
  visible,
  onPrepared,
  onDirty,
  onBusy,
}: {
  user: User;
  revision: number;
  installed: string | null;
  domains: string[];
  sources: SourceStatus[];
  disabled: boolean;
  visible: boolean;
  onPrepared: (value: DirectoryPrepared) => void;
  onDirty: (value: boolean) => void;
  onBusy: (value: boolean) => void;
}) {
  const storageKey = `noisefence-directory-sync:${user.username}`;
  const [open, setOpen] = useState(false),
    [existing, setExisting] = useState(''),
    [provider, setProvider] = useState<'entra' | 'okta'>('entra'),
    [label, setLabel] = useState(''),
    [sourceId, setSourceId] = useState(''),
    [tenant, setTenant] = useState(''),
    [scopes, setScopes] = useState<string[]>(
      domains.length === 1 ? [...domains] : [],
    ),
    [client, setClient] = useState(''),
    [secret, setSecret] = useState(''),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(''),
    [job, setJob] = useState<SyncStatus | null>(null),
    [attempt, setAttempt] = useState(0);
  const [jobId, setJobId] = useState(() => {
    try {
      const value = sessionStorage.getItem(storageKey) ?? '';
      return uuid.test(value) ? value : '';
    } catch {
      return '';
    }
  });
  const selected = sources.find(
    (s) => s.source.id === existing && s.source.provider === provider,
  );
  const source: Source = selected?.source ?? {
    id: sourceId,
    label,
    provider,
    authority: tenant,
    scopes,
    stale_after_seconds: 86400,
  };
  const problem =
    (provider === 'entra'
      ? entraFormError(source, domains, client, secret)
      : oktaFormError(source, domains, secret)) ||
    (!selected && sources.some((s) => s.source.id === sourceId)
      ? 'This source ID already exists. Select the installed source or use a new ID.'
      : null);
  const dirty = !!(client || secret || sourceId || label || tenant);
  useEffect(() => {
    onDirty(dirty);
    return () => onDirty(false);
  }, [dirty, onDirty]);
  useEffect(() => {
    onBusy(busy);
    return () => onBusy(false);
  }, [busy, onBusy]);
  useEffect(() => {
    if (!visible || !jobId || busy) return;
    const abort = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    async function poll() {
      try {
        const next = await api<SyncStatus>(
          `/admin/identity/sync/${encodeURIComponent(jobId)}`,
          undefined,
          undefined,
          { signal: abort.signal, cache: 'no-store' },
        );
        if (abort.signal.aborted) return;
        setJob(next);
        setError('');
        if (next.state === 'running')
          timer = setTimeout(() => void poll(), 3000);
      } catch (e) {
        if (!abort.signal.aborted) setError((e as Error).message);
      }
    }
    void poll();
    return () => {
      abort.abort();
      if (timer) clearTimeout(timer);
    };
  }, [jobId, attempt, visible, revision, busy]);
  async function start() {
    if (disabled || busy || problem) return;
    setBusy(true);
    setError('');
    const operation = crypto.randomUUID();
    setJobId(operation);
    setJob(null);
    try {
      sessionStorage.setItem(storageKey, operation);
    } catch {
      /* Only the receipt ID is retained. */
    }
    const credential = secret;
    setSecret('');
    try {
      const result = await api<{ id: string; deadline: number }>(
        `/admin/identity/sync/${provider}`,
        {
          operation,
          revision,
          catalog_sha256: installed,
          source,
          ...(provider === 'entra'
            ? { client_id: client, client_secret: credential }
            : { access_token: credential }),
        },
        user.csrf,
      );
      setJob(null);
      setJobId(result.id);
      setClient('');
      setSourceId('');
      setLabel('');
      setTenant('');
      setOpen(false);
      try {
        sessionStorage.setItem(storageKey, result.id);
      } catch {
        /* Receipt remains available server-side. */
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <section
      className="card directory-sync"
      aria-label="Directory synchronization"
    >
      <div className="directory-heading">
        <div>
          <h3>
            <CloudDownload size={18} aria-hidden="true" /> Directory
            synchronization
          </h3>
          <p className="muted small">
            Collect identities from Microsoft Entra or Okta. Review every
            candidate before activation.
          </p>
        </div>
        <button
          type="button"
          className="secondary"
          disabled={disabled || busy}
          aria-expanded={open}
          onClick={() => setOpen(!open)}
        >
          {open ? 'Hide connection form' : 'Collect from a provider'}
        </button>
      </div>
      <p className="muted small">
        This is a one-time collection. The credential is used in memory for this
        request only; it is not saved in settings, history or browser storage.
        Scheduled synchronization is not enabled.
      </p>
      {open && (
        <fieldset disabled={disabled || busy} className="directory-sync-form">
          <legend>Read-only connection</legend>
          <label>
            Provider
            <select
              value={provider}
              onChange={(e) => {
                setProvider(e.target.value as 'entra' | 'okta');
                setExisting('');
                setTenant('');
                setClient('');
                setSecret('');
              }}
            >
              <option value="entra">Microsoft Entra ID</option>
              <option value="okta">Okta</option>
            </select>
          </label>
          <label>
            Source
            <select
              value={existing}
              onChange={(e) => setExisting(e.target.value)}
            >
              <option value="">
                New {provider === 'entra' ? 'Entra' : 'Okta'} source
              </option>
              {sources
                .filter((s) => s.source.provider === provider)
                .map((s) => (
                  <option key={s.source.id} value={s.source.id}>
                    {s.source.label}
                  </option>
                ))}
            </select>
          </label>
          {!selected && (
            <>
              <label>
                Stable source ID
                <input
                  value={sourceId}
                  maxLength={100}
                  onChange={(e) => setSourceId(e.target.value)}
                  placeholder={`${provider}-organization`}
                />
              </label>
              <label>
                Source name
                <input
                  value={label}
                  maxLength={200}
                  onChange={(e) => setLabel(e.target.value)}
                />
              </label>
              <label>
                {provider === 'entra' ? 'Tenant ID' : 'Okta org hostname'}
                <input
                  value={tenant}
                  maxLength={provider === 'entra' ? 36 : 256}
                  placeholder={
                    provider === 'okta' ? 'company.okta.com' : undefined
                  }
                  onChange={(e) => setTenant(e.target.value)}
                  autoComplete="off"
                />
              </label>
              <fieldset>
                <legend>Receiving domains</legend>
                {domains.map((domain) => (
                  <label className="check" key={domain}>
                    <input
                      type="checkbox"
                      checked={scopes.includes(domain)}
                      onChange={(e) =>
                        setScopes(
                          e.target.checked
                            ? [...scopes, domain]
                            : scopes.filter((d) => d !== domain),
                        )
                      }
                    />
                    {domain}
                  </label>
                ))}
              </fieldset>
              <p className="muted small">
                New sources become stale after 24 hours. Existing source scope
                and protection assignments are preserved.
              </p>
            </>
          )}
          {selected && (
            <p className="notice">
              Authority {selected.source.authority} ·{' '}
              {selected.source.scopes.join(', ')}. Existing source settings
              cannot be changed by this collection.
            </p>
          )}
          {provider === 'entra' && (
            <label>
              Application (client) ID
              <input
                value={client}
                maxLength={36}
                autoComplete="off"
                onChange={(e) => setClient(e.target.value)}
              />
            </label>
          )}
          <label>
            {provider === 'entra' ? 'Application secret' : 'OAuth access token'}
            <input
              type="password"
              value={secret}
              maxLength={provider === 'entra' ? 4096 : 8192}
              autoComplete="new-password"
              spellCheck={false}
              onChange={(e) => setSecret(e.target.value)}
            />
          </label>
          <p className="muted small">
            {provider === 'entra'
              ? 'The Entra administrator must grant User.Read.All and GroupMember.Read.All application permissions with tenant admin consent. No mailbox access is requested.'
              : 'Use an OAuth token with okta.users.read and okta.groups.read, and an admin role/resource set covering the intended directory. Login names and recovery addresses are not imported as aliases. Custom org domains and API tokens (SSWS) are not supported.'}
          </p>
          {problem && <p className="muted small">{problem}</p>}
          <button
            type="button"
            disabled={!!problem}
            onClick={() => void start()}
          >
            {busy ? 'Starting…' : 'Start read-only collection'}
          </button>
          <button
            type="button"
            className="secondary"
            onClick={() => {
              setClient('');
              setSecret('');
              setSourceId('');
              setLabel('');
              setTenant('');
              setExisting('');
              setOpen(false);
            }}
          >
            Discard connection draft
          </button>
        </fieldset>
      )}
      {error && (
        <p className="alert error" role="alert">
          {error}
        </p>
      )}
      {jobId && (
        <div className="directory-sync-result" aria-live="polite">
          <strong>{job?.source_id ?? 'Synchronization receipt'}</strong>
          <p>
            {job
              ? syncMessage(job)
              : error
                ? 'The receipt could not be read. Check status before starting another collection.'
                : 'Loading synchronization status…'}
          </p>
          <code>{jobId}</code>
          <div className="actions">
            <button
              type="button"
              className="secondary"
              onClick={() => setAttempt((n) => n + 1)}
            >
              <RefreshCw size={14} /> Check status
            </button>
            {job && canReviewSync(job, revision, installed) && (
              <button
                type="button"
                disabled={disabled || busy}
                onClick={() => onPrepared(job.prepared!)}
              >
                Review collected changes
              </button>
            )}
          </div>
        </div>
      )}
    </section>
  );
}
